"""
signer.py

Task 2: Sign a Message (here, a release artifact file).

Computes the SHA-256 digest of the target artifact and signs that digest
with an RSA private key using RSA-PSS padding, producing a base64-encoded
detached signature plus a small JSON metadata sidecar (hash, algorithm,
timestamp, key size) -- similar in spirit to a Cosign / Sigstore
signature bundle.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from release_signer.crypto_utils import sha256_of_file

ALGORITHM = "RSASSA-PSS-SHA256"


@dataclass(frozen=True)
class SignatureRecord:
    """Structured representation of a detached signature."""

    file_name: str
    sha256_hex: str
    signature_b64: str
    algorithm: str
    key_size_bits: int
    signed_at_utc: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2) + "\n"


def sign_file(artifact_path: Path, private_key: RSAPrivateKey) -> SignatureRecord:
    """
    Sign an artifact file with an RSA private key.

    The artifact is hashed once with SHA-256; the resulting digest (not
    the raw file bytes) is what actually gets signed. This keeps signing
    fast and memory-light regardless of artifact size, and is the same
    pattern real signing tools (git, cosign, jarsigner, ...) use.

    Args:
        artifact_path: path to the file to sign (e.g. a release binary).
        private_key: RSA private key used to produce the signature.

    Returns:
        A SignatureRecord containing the base64 signature and metadata
        needed later to verify it.
    """
    digest = sha256_of_file(artifact_path)

    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        Prehashed(hashes.SHA256()),
    )

    return SignatureRecord(
        file_name=artifact_path.name,
        sha256_hex=digest.hex(),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        algorithm=ALGORITHM,
        key_size_bits=private_key.key_size,
        signed_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def write_signature(record: SignatureRecord, sig_path: Path) -> None:
    """Write a SignatureRecord to disk as a `.sig` JSON sidecar file."""
    sig_path.parent.mkdir(parents=True, exist_ok=True)
    sig_path.write_text(record.to_json(), encoding="utf-8")
