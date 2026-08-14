"""
verifier.py

Task 3: Verify the Signature.

Recomputes the SHA-256 digest of a (possibly re-downloaded) artifact and
checks it against a signature record using the corresponding RSA public
key. Returns a simple boolean result plus a human-readable reason, so
callers (CLI, CI pipeline, other Python code) can decide what to do next
-- e.g. abort a deployment on failure.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from release_signer.crypto_utils import sha256_of_file


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of a verify operation, with enough detail to explain why."""

    is_valid: bool
    reason: str


def _load_signature_record(sig_path: Path) -> dict:
    if not sig_path.is_file():
        raise FileNotFoundError(f"Signature file not found: '{sig_path}'")
    try:
        return json.loads(sig_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Signature file '{sig_path}' is not valid JSON") from exc


def verify_file(
    artifact_path: Path,
    sig_path: Path,
    public_key: RSAPublicKey,
) -> VerificationResult:
    """
    Verify that `artifact_path` matches the signature stored in `sig_path`,
    using `public_key`.

    This performs two independent checks:
        1. Hash check: does the artifact's current SHA-256 match the hash
           recorded at signing time? (catches accidental corruption /
           truncated downloads even before touching crypto)
        2. Signature check: does the recorded signature actually verify
           against that hash under the given public key? (catches
           tampering and forged/mismatched keys)

    Args:
        artifact_path: path to the artifact to verify.
        sig_path: path to the `.sig` JSON sidecar produced by `sign_file`.
        public_key: RSA public key corresponding to the signer's private key.

    Returns:
        VerificationResult with `is_valid=True` only if both checks pass.
    """
    if not artifact_path.is_file():
        return VerificationResult(False, f"Artifact not found: '{artifact_path}'")

    record = _load_signature_record(sig_path)

    required_fields = {"sha256_hex", "signature_b64"}
    missing = required_fields - record.keys()
    if missing:
        return VerificationResult(
            False, f"Signature file is missing required field(s): {sorted(missing)}"
        )

    actual_digest = sha256_of_file(artifact_path)
    expected_digest_hex = record["sha256_hex"]

    if actual_digest.hex() != expected_digest_hex:
        return VerificationResult(
            False,
            "Hash mismatch: artifact contents do not match what was signed "
            "(file may have been modified or corrupted in transit).",
        )

    try:
        signature = base64.b64decode(record["signature_b64"])
    except (ValueError, TypeError):
        return VerificationResult(False, "Signature field is not valid base64.")

    try:
        public_key.verify(
            signature,
            actual_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            Prehashed(hashes.SHA256()),
        )
    except InvalidSignature:
        return VerificationResult(
            False,
            "Invalid signature: hash matches, but the signature does not "
            "verify against the provided public key (wrong key, or "
            "signature was forged/altered).",
        )

    return VerificationResult(True, "Signature is valid. Artifact is authentic and unmodified.")
