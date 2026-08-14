"""
cli.py

Command-line entrypoint for the release-signer tool.

Usage:
    release-signer keygen  --out-dir keys/
    release-signer sign    --key keys/release_private.pem --file app.bin
    release-signer verify  --key keys/release_public.pem  --file app.bin --sig app.bin.sig

Run `release-signer <command> --help` for details on any subcommand.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from release_signer import __version__
from release_signer.crypto_utils import load_private_key, load_public_key
from release_signer.keygen import DEFAULT_KEY_SIZE, generate_keypair
from release_signer.signer import sign_file, write_signature
from release_signer.verifier import verify_file

# ANSI colors, disabled automatically on non-TTY output (e.g. piped/CI logs)
_USE_COLOR = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def _green(text: str) -> str:
    return _c(text, "92")


def _red(text: str) -> str:
    return _c(text, "91")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="release-signer",
        description="Sign and verify software release artifacts with RSA digital signatures.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- keygen ---------------------------------------------------------
    p_keygen = subparsers.add_parser("keygen", help="Generate a new RSA keypair")
    p_keygen.add_argument(
        "--out-dir", type=Path, default=Path("keys"), help="Directory to write keys into (default: keys/)"
    )
    p_keygen.add_argument(
        "--private-name", default="release_private.pem", help="Private key filename"
    )
    p_keygen.add_argument("--public-name", default="release_public.pem", help="Public key filename")
    p_keygen.add_argument(
        "--key-size", type=int, default=DEFAULT_KEY_SIZE, help=f"RSA key size in bits (default: {DEFAULT_KEY_SIZE})"
    )
    p_keygen.add_argument(
        "--encrypt",
        action="store_true",
        help="Prompt for a password and encrypt the private key at rest",
    )

    # --- sign -------------------------------------------------------------
    p_sign = subparsers.add_parser("sign", help="Sign a release artifact")
    p_sign.add_argument("--key", type=Path, required=True, help="Path to RSA private key (PEM)")
    p_sign.add_argument("--file", type=Path, required=True, help="Path to the artifact to sign")
    p_sign.add_argument(
        "--out", type=Path, default=None, help="Output signature path (default: <file>.sig)"
    )
    p_sign.add_argument(
        "--password",
        action="store_true",
        help="Prompt for a password if the private key is encrypted",
    )

    # --- verify -------------------------------------------------------
    p_verify = subparsers.add_parser("verify", help="Verify a release artifact against a signature")
    p_verify.add_argument("--key", type=Path, required=True, help="Path to RSA public key (PEM)")
    p_verify.add_argument("--file", type=Path, required=True, help="Path to the artifact to verify")
    p_verify.add_argument(
        "--sig", type=Path, default=None, help="Path to the signature file (default: <file>.sig)"
    )

    return parser


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_path = args.out_dir / args.private_name
    public_path = args.out_dir / args.public_name

    password = None
    if args.encrypt:
        pw1 = getpass.getpass("Enter password for private key: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print(_red("Error: passwords do not match."), file=sys.stderr)
            return 1
        if not pw1:
            print(_red("Error: password cannot be empty when --encrypt is set."), file=sys.stderr)
            return 1
        password = pw1.encode("utf-8")

    generate_keypair(private_path, public_path, key_size=args.key_size, password=password)

    print(_green("Keypair generated successfully."))
    print(f"  Private key: {private_path}  (keep this secret!)")
    print(f"  Public key:  {public_path}  (safe to distribute)")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    password = getpass.getpass("Private key password: ").encode("utf-8") if args.password else None

    try:
        private_key = load_private_key(args.key, password=password)
    except (FileNotFoundError, ValueError) as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        return 1

    if not args.file.is_file():
        print(_red(f"Error: artifact not found: '{args.file}'"), file=sys.stderr)
        return 1

    out_path = args.out or args.file.with_suffix(args.file.suffix + ".sig")

    record = sign_file(args.file, private_key)
    write_signature(record, out_path)

    print(_green("Artifact signed successfully."))
    print(f"  Artifact:  {args.file}")
    print(f"  SHA-256:   {record.sha256_hex}")
    print(f"  Signature: {out_path}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        public_key = load_public_key(args.key)
    except (FileNotFoundError, ValueError) as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        return 1

    sig_path = args.sig or args.file.with_suffix(args.file.suffix + ".sig")

    try:
        result = verify_file(args.file, sig_path, public_key)
    except (FileNotFoundError, ValueError) as exc:
        print(_red(f"Error: {exc}"), file=sys.stderr)
        return 1

    if result.is_valid:
        print(_green("PASS") + f" - {result.reason}")
        return 0
    else:
        print(_red("FAIL") + f" - {result.reason}")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    handlers = {
        "keygen": _cmd_keygen,
        "sign": _cmd_sign,
        "verify": _cmd_verify,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
