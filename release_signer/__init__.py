"""
release_signer
===============

A small, focused CLI for signing and verifying software release artifacts
using RSA digital signatures (RSA-PSS + SHA-256), in the spirit of tools
like Sigstore / Cosign.

Core building blocks:
    - crypto_utils : hashing + low-level key I/O helpers
    - keygen        : RSA keypair generation
    - signer        : detached signature creation
    - verifier      : detached signature verification
    - cli           : command-line entrypoint tying it all together
"""

__version__ = "1.0.0"
