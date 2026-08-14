"""
crypto_utils.py

Low-level helpers shared by keygen / signer / verifier:
    - streaming SHA-256 hashing of arbitrary-size files
    - PEM (de)serialization for RSA keys

Kept separate from the higher-level modules so the "pure cryptography"
surface area of the project is easy to review and unit test in isolation.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

# Read files in fixed-size chunks so we never load a large artifact
# (e.g. a multi-GB binary) fully into memory just to hash it.
_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def sha256_of_file(path: Path) -> bytes:
    """
    Compute the raw SHA-256 digest of a file on disk.

    Args:
        path: path to the file to hash.

    Returns:
        Raw 32-byte digest (not hex-encoded).

    Raises:
        FileNotFoundError: if `path` does not exist.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Cannot hash: '{path}' is not a file")

    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.digest()


def load_private_key(path: Path, password: bytes | None = None) -> RSAPrivateKey:
    """
    Load an RSA private key from a PEM file.

    Args:
        path: path to the PEM-encoded private key.
        password: optional password if the key is encrypted.

    Raises:
        FileNotFoundError: if the key file does not exist.
        ValueError: if the file is not a valid RSA private key.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Private key not found: '{path}'")

    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError(f"'{path}' does not contain an RSA private key")
    return key


def load_public_key(path: Path) -> RSAPublicKey:
    """
    Load an RSA public key from a PEM file.

    Args:
        path: path to the PEM-encoded public key.

    Raises:
        FileNotFoundError: if the key file does not exist.
        ValueError: if the file is not a valid RSA public key.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Public key not found: '{path}'")

    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, RSAPublicKey):
        raise ValueError(f"'{path}' does not contain an RSA public key")
    return key
