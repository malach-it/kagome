#!/usr/bin/env python3
"""Generate a local AAuth provider key and print its public Kagome config."""

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


DEFAULT_KEY = Path(__file__).resolve().parents[1] / ".agent-keys/example-provider-ed25519.pem"


def https_issuer(value):
    host = value.removeprefix("https://")
    if host == value or len(host) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise argparse.ArgumentTypeError("expected a lowercase HTTPS URL with only a host")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output", nargs="?", type=Path, default=DEFAULT_KEY,
        help="private PEM path (default: .agent-keys/example-provider-ed25519.pem)",
    )
    parser.add_argument(
        "--issuer", type=https_issuer, default="https://agents.example",
        help="provider issuer (default: %(default)s)",
    )
    args = parser.parse_args()

    key = Ed25519PrivateKey.generate()
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    x = base64.urlsafe_b64encode(public_bytes).decode("ascii").rstrip("=")
    kid = "example-" + hashlib.sha256(public_bytes).hexdigest()[:16]
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    try:
        args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(pem)
    except FileExistsError:
        parser.exit(1, f"refusing to overwrite {args.output}\n")
    except OSError as error:
        parser.exit(1, f"could not write {args.output}: {error.strerror}\n")

    print(f"Private key saved to {args.output}", file=sys.stderr)
    print(f"""agent_providers:
  - issuer: {args.issuer}
    jwks:
      keys:
        - kid: {kid}
          alg: Ed25519
          kty: OKP
          crv: Ed25519
          x: '{x}'""")


if __name__ == "__main__":
    main()
