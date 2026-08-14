# release-signer

A small CLI for signing and verifying software release artifacts using **RSA
digital signatures** (RSA-PSS + SHA-256) — the same core idea behind tools
like [Sigstore](https://www.sigstore.dev/) / [Cosign](https://github.com/sigstore/cosign),
scoped down to something you can fully read, test, and explain.

```
[ Developer / CI Pipeline ]
       |
       |-> Compute SHA-256 hash of artifact (app.bin)
       |-> Sign hash with RSA private key (RSA-PSS)
       `-> Write detached signature (app.bin.sig)
                |
                v
[ Deployment Server / User ]
       |
       |-> Download app.bin + app.bin.sig
       |-> Recompute SHA-256 hash of downloaded app.bin
       |-> Verify signature against public key (release_public.pem)
       `-> Result: PASS (deploy) or FAIL (abort)
```

## What's in this repo

```
release-signer-cli/
├── release_signer/
│   ├── __init__.py
│   ├── cli.py             # argparse CLI: keygen / sign / verify subcommands
│   ├── crypto_utils.py     # SHA-256 hashing + PEM key loading
│   ├── keygen.py            # Task 1: RSA keypair generation
│   ├── signer.py             # Task 2: sign an artifact -> detached signature
│   └── verifier.py            # Task 3: verify an artifact against a signature
├── tests/
│   └── test_signer.py     # pytest suite: keygen, sign+verify, tamper, wrong key
├── examples/
│   └── sample_artifact.bin  # a file you can sign/verify immediately
├── keys/
│   └── README.md            # explains why real keys aren't committed here
├── .github/workflows/
│   └── release-sign-verify.yml  # demo CI pipeline: sign in one job, verify in another
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

## How it maps to the lab tasks

| Lab task | Where it's implemented |
|---|---|
| Task 1: Generate RSA keys | `release_signer/keygen.py` → `generate_keypair()` |
| Task 2: Sign a message | `release_signer/signer.py` → `sign_file()` |
| Task 3: Verify the signature | `release_signer/verifier.py` → `verify_file()` |

Design notes, in case you get asked about it:

- **Hash-then-sign, not sign-the-whole-file.** The file is hashed once with
  SHA-256 (streamed in 1 MiB chunks, so it works on huge files without
  loading them into memory); only the 32-byte digest is actually signed.
  This is what every real signing tool does.
- **RSA-PSS**, not the older PKCS#1 v1.5 padding, because PSS is the
  padding scheme current best practice recommends for new RSA signatures.
- **Detached signatures** — the signature lives in a separate `.sig` file
  (JSON: hash, base64 signature, algorithm, key size, timestamp) rather
  than being embedded in the artifact. This mirrors Cosign's `.sig`
  sidecar files and means you never have to modify the artifact itself.
- **Two independent checks on verify**: a hash comparison (catches
  corruption cheaply, before touching any crypto) and a signature
  verification (catches tampering / wrong key). Both must pass.

## Setup (Windows, Anaconda)

You mentioned working primarily on Windows with Anaconda — these steps
assume that, but they're the same on macOS/Linux with any Python 3.10+.

1. **Open Anaconda Prompt** and create an isolated environment:

   ```bash
   conda create -n release-signer python=3.12 -y
   conda activate release-signer
   ```

2. **Unzip this project** somewhere, then `cd` into it:

   ```bash
   cd path\to\release-signer-cli
   ```

3. **Install the package** (this also installs `cryptography` and `pytest`,
   and registers the `release-signer` command in your environment):

   ```bash
   pip install -e ".[dev]"
   ```

   If you'd rather not install it as a package, `pip install -r requirements.txt`
   and run everything as `python -m release_signer.cli <command>` instead of
   `release-signer <command>`.

4. **Run the test suite** to confirm everything works on your machine:

   ```bash
   pytest -v
   ```

   You should see 9 passed.

## Usage: the 3 lab tasks end to end

### Task 1 — Generate RSA keys

```bash
release-signer keygen --out-dir keys/
```

Produces `keys/release_private.pem` (keep secret) and
`keys/release_public.pem` (safe to share). Add `--encrypt` to password-protect
the private key file, or `--key-size 4096` for a larger key.

### Task 2 — Sign a message / artifact

```bash
release-signer sign --key keys/release_private.pem --file examples/sample_artifact.bin
```

Writes `examples/sample_artifact.bin.sig` — a JSON file containing the
SHA-256 hash, the base64-encoded RSA-PSS signature, and metadata. Prints the
hash to your terminal too, e.g.:

```
Artifact signed successfully.
  Artifact:  examples/sample_artifact.bin
  SHA-256:   4f31927...
  Signature: examples/sample_artifact.bin.sig
```

### Task 3 — Verify the signature

```bash
release-signer verify --key keys/release_public.pem --file examples/sample_artifact.bin --sig examples/sample_artifact.bin.sig
```

Expected output:

```
PASS - Signature is valid. Artifact is authentic and unmodified.
```

**Prove it catches tampering** — edit the artifact (or append a byte) and
verify again:

```bash
echo tampered >> examples/sample_artifact.bin
release-signer verify --key keys/release_public.pem --file examples/sample_artifact.bin --sig examples/sample_artifact.bin.sig
```

```
FAIL - Hash mismatch: artifact contents do not match what was signed (file may have been modified or corrupted in transit).
```

The command also exits with status code `1` on failure and `0` on success,
so it's directly usable as a pipeline gate:

```bash
release-signer verify --key keys/release_public.pem --file app.bin --sig app.bin.sig && echo "deploy" || echo "ABORT deployment"
```

## CI/CD demo (for your resume / GitHub)

`.github/workflows/release-sign-verify.yml` shows the two-job pattern
described at the top of this README:

- **`build-and-sign`** — runs on a trusted runner, restores the private key
  from a GitHub Actions secret (`RELEASE_PRIVATE_KEY`), signs the build
  artifact, uploads `app.bin` + `app.bin.sig`, then deletes the private key
  from disk.
- **`deploy-and-verify`** — downloads the artifact + signature, verifies
  using only the *public* key committed to the repo, and only proceeds to
  the "deploy" step if verification passes.

To make this workflow actually run in your own fork/repo:

1. Generate a real keypair: `release-signer keygen --out-dir keys/`
2. Commit `keys/release_public.pem` to the repo.
3. Copy the contents of `keys/release_private.pem` into a repository secret
   named `RELEASE_PRIVATE_KEY` (GitHub repo → Settings → Secrets and
   variables → Actions).
4. Push to `main`, or trigger it manually from the Actions tab.

## Extending this project (good "next step" talking points)

- Swap RSA for **ECDSA (P-256)** — smaller keys/signatures, same interface.
- Add **timestamped signatures** or a simple transparency log (append-only
  log of signature records) to get closer to what Sigstore's Rekor does.
- Support **signing multiple artifacts at once** with a manifest file
  (hash-of-hashes), the way `sha256sum.txt` + a single signature works for
  Linux distro release checksums.
- Add a **`revoke`** subcommand and a small revoked-keys list, so verify can
  reject artifacts signed with a since-revoked key even if the signature is
  cryptographically valid.
