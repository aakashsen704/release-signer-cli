# keys/

This directory is where `release-signer keygen` writes keys by default.

Real private keys should **never** be committed to version control.
The `.gitignore` in this repo excludes `*.pem` files for that reason.

For a CI pipeline (see `.github/workflows/release-sign-verify.yml`), the
private key is stored as an encrypted GitHub Actions secret instead, and
only the public key (`release_public.pem`) is committed here so
verification jobs can use it.
