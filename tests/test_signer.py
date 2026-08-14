"""
Unit tests covering the three lab tasks:
    1. RSA keypair generation
    2. Signing a message/artifact
    3. Verifying a signature (valid, tampered, and wrong-key cases)

Run with:
    pytest -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from release_signer.crypto_utils import load_private_key, load_public_key
from release_signer.keygen import generate_keypair
from release_signer.signer import sign_file, write_signature
from release_signer.verifier import verify_file

# Use a small key size in tests to keep the suite fast; production use
# should stick to the 3072-bit default in keygen.py.
TEST_KEY_SIZE = 2048


@pytest.fixture
def keypair(tmp_path: Path):
    """Generate a fresh RSA keypair for each test."""
    priv_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"
    generate_keypair(priv_path, pub_path, key_size=TEST_KEY_SIZE)
    return priv_path, pub_path


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    """A small fake 'release artifact' to sign."""
    path = tmp_path / "app.bin"
    path.write_bytes(b"this is a fake release binary\x00\x01\x02" * 100)
    return path


class TestKeygen:
    def test_generates_two_pem_files(self, keypair):
        priv_path, pub_path = keypair
        assert priv_path.is_file()
        assert pub_path.is_file()
        assert priv_path.read_text().startswith("-----BEGIN PRIVATE KEY-----")
        assert pub_path.read_text().startswith("-----BEGIN PUBLIC KEY-----")

    def test_keys_are_loadable_and_match(self, keypair):
        priv_path, pub_path = keypair
        private_key = load_private_key(priv_path)
        public_key = load_public_key(pub_path)

        # The public key derived from the private key must match the one
        # written to disk (same modulus).
        assert private_key.public_key().public_numbers() == public_key.public_numbers()

    def test_rejects_undersized_keys(self, tmp_path):
        with pytest.raises(ValueError):
            generate_keypair(tmp_path / "p.pem", tmp_path / "pub.pem", key_size=1024)

    def test_encrypted_private_key_requires_password(self, tmp_path):
        priv_path = tmp_path / "private.pem"
        pub_path = tmp_path / "public.pem"
        generate_keypair(priv_path, pub_path, key_size=TEST_KEY_SIZE, password=b"hunter2")

        # Loading without a password should fail.
        with pytest.raises(TypeError):
            load_private_key(priv_path)

        # Loading with the correct password should succeed.
        key = load_private_key(priv_path, password=b"hunter2")
        assert key.key_size == TEST_KEY_SIZE


class TestSignAndVerify:
    def test_valid_signature_verifies(self, keypair, artifact, tmp_path):
        priv_path, pub_path = keypair
        private_key = load_private_key(priv_path)
        public_key = load_public_key(pub_path)

        record = sign_file(artifact, private_key)
        sig_path = tmp_path / "app.bin.sig"
        write_signature(record, sig_path)

        result = verify_file(artifact, sig_path, public_key)
        assert result.is_valid is True

    def test_tampered_artifact_fails_verification(self, keypair, artifact, tmp_path):
        priv_path, pub_path = keypair
        private_key = load_private_key(priv_path)
        public_key = load_public_key(pub_path)

        record = sign_file(artifact, private_key)
        sig_path = tmp_path / "app.bin.sig"
        write_signature(record, sig_path)

        # Tamper with the artifact AFTER signing.
        with artifact.open("ab") as f:
            f.write(b"malicious appended bytes")

        result = verify_file(artifact, sig_path, public_key)
        assert result.is_valid is False
        assert "hash mismatch" in result.reason.lower()

    def test_wrong_public_key_fails_verification(self, keypair, artifact, tmp_path):
        priv_path, _pub_path = keypair
        private_key = load_private_key(priv_path)

        # A completely different keypair's public key should NOT verify
        # this signature, even though the artifact itself is untouched.
        other_priv = tmp_path / "other_private.pem"
        other_pub = tmp_path / "other_public.pem"
        generate_keypair(other_priv, other_pub, key_size=TEST_KEY_SIZE)
        wrong_public_key = load_public_key(other_pub)

        record = sign_file(artifact, private_key)
        sig_path = tmp_path / "app.bin.sig"
        write_signature(record, sig_path)

        result = verify_file(artifact, sig_path, wrong_public_key)
        assert result.is_valid is False

    def test_missing_signature_file_raises(self, keypair, artifact, tmp_path):
        _priv_path, pub_path = keypair
        public_key = load_public_key(pub_path)
        missing_sig = tmp_path / "does_not_exist.sig"

        with pytest.raises(FileNotFoundError):
            verify_file(artifact, missing_sig, public_key)

    def test_missing_artifact_returns_invalid_result(self, keypair, tmp_path):
        _priv_path, pub_path = keypair
        public_key = load_public_key(pub_path)
        fake_sig = tmp_path / "ghost.sig"
        fake_sig.write_text('{"sha256_hex": "aa", "signature_b64": "bb"}')

        result = verify_file(tmp_path / "ghost.bin", fake_sig, public_key)
        assert result.is_valid is False
        assert "not found" in result.reason.lower()
