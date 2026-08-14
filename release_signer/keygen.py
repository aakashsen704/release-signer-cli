"""
keygen.py

Task 1: Generate RSA Keys.

Generates an RSA private/public keypair and writes each half to its own
PEM file, mirroring how a real release-signing identity would be
provisioned: a private key kept secret by the signer (e.g. a CI runner
with restricted access), and a public key distributed freely to anyone
who needs to verify artifacts.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_KEY_SIZE = 3072  # NIST-recommended minimum for RSA beyond 2030
DEFAULT_PUBLIC_EXPONENT = 65537


def generate_keypair(
    private_key_path: Path,
    public_key_path: Path,
    key_size: int = DEFAULT_KEY_SIZE,
    password: bytes | None = None,
) -> None:
    """
    Generate an RSA keypair and write it to disk as two PEM files.

    Args:
        private_key_path: destination path for the PEM private key.
        public_key_path: destination path for the PEM public key.
        key_size: RSA modulus size in bits (2048 minimum, 3072 default).
        password: if provided, the private key PEM is encrypted with it
            using PKCS#8 + BestAvailableEncryption. If None, the private
            key is written unencrypted (fine for lab/demo use, but real
            signing identities should always set a password or rely on
            an HSM / KMS instead of a bare file).

    Raises:
        ValueError: if key_size is smaller than 2048 bits.
    """
    if key_size < 2048:
        raise ValueError("key_size must be >= 2048 bits for adequate security")

    private_key = rsa.generate_private_key(
        public_exponent=DEFAULT_PUBLIC_EXPONENT,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key_path.write_bytes(private_bytes)
    public_key_path.write_bytes(public_bytes)

    # Private key should not be world-readable. chmod is a no-op on
    # platforms that don't support POSIX permissions (e.g. some
    # Windows filesystems), so this is best-effort.
    try:
        private_key_path.chmod(0o600)
    except (NotImplementedError, OSError):
        pass
