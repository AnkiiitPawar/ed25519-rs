"""Cross-check against OpenSSL, through the Python `cryptography` package.

1. Writes tests/data/openssl_vectors.txt: keys and signatures made by OpenSSL
   for deterministic seeds and messages of many lengths. Ed25519 signing is
   deterministic, so the Rust code must reproduce every byte.
2. Writes docs/openssl_edge_cases.json: how this OpenSSL build answers the
   speccheck and Wycheproof edge cases, for comparison in the README figure.

    pip install cryptography
    python3 scripts/openssl_crosscheck.py
"""

import hashlib
import json
import pathlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"

# Lengths straddle SHA-512 block boundaries for both hashes in signing:
# prefix(32) || M and R(32) || A(32) || M, with 17 bytes of padding.
LENGTHS = [0, 1, 2, 31, 32, 33, 46, 47, 48, 63, 64, 65, 78, 79, 80, 95, 96, 97, 110, 111, 112,
           127, 128, 129, 174, 175, 176, 200, 238, 239, 240, 255, 256, 257, 300, 366, 367, 368,
           383, 384, 385, 511, 512, 513, 1000, 1023, 1024, 1025, 2047, 2048]


def vectors() -> str:
    lines = [f"# seed public message signature, signed by {backend.openssl_version_text()}"]
    for i, n in enumerate(LENGTHS):
        seed = hashlib.sha512(f"openssl-seed/{i}".encode()).digest()[:32]
        msg = bytes((131 * j + 17 * i + 5) % 256 for j in range(n))
        key = Ed25519PrivateKey.from_private_bytes(seed)
        pk = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        lines.append(f"{seed.hex()} {pk.hex()} {msg.hex() or '-'} {key.sign(msg).hex()}")
    return "\n".join(lines) + "\n"


def accepts(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def edge_cases() -> dict:
    spec = []
    for line in (DATA / "speccheck_cases.txt").read_text().splitlines():
        if line.startswith("#"):
            continue
        _, pk, msg, sig = line.split("|")
        spec.append("V" if accepts(bytes.fromhex(pk), bytes.fromhex(msg.strip("-")), bytes.fromhex(sig)) else "X")
    wy = {}
    for line in (DATA / "wycheproof_ed25519.txt").read_text().splitlines():
        if line.startswith("#"):
            continue
        _, result, flags, pk, msg, sig, _ = line.split("|")
        ok = accepts(bytes.fromhex(pk.strip("-")), bytes.fromhex(msg.strip("-")), bytes.fromhex(sig.strip("-")))
        for flag in flags.split(","):
            entry = wy.setdefault(f"{flag}|{result}", [0, 0])
            entry[ok] += 1
    return {"openssl": backend.openssl_version_text(), "speccheck": spec,
            "wycheproof_rejected_accepted": wy}


if __name__ == "__main__":
    (DATA / "openssl_vectors.txt").write_text(vectors())
    out = ROOT / "docs" / "openssl_edge_cases.json"
    out.parent.mkdir(exist_ok=True)
    result = edge_cases()
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(result["openssl"])
    print("speccheck:", " ".join(result["speccheck"]))
    for k, v in sorted(result["wycheproof_rejected_accepted"].items()):
        print(f"  {k:35} rejected {v[0]:3}  accepted {v[1]:3}")
