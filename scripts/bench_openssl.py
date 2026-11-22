"""Reference timings for OpenSSL's Ed25519 on the same machine, through the
Python `cryptography` package. Each figure includes the Python call
overhead (well under a microsecond), so OpenSSL itself is slightly faster.

    python3 scripts/bench_openssl.py   # writes docs/bench_openssl.json
"""

import json
import pathlib
import statistics
import time

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parent.parent


def per_call_us(fn, iters=4000):
    """Best of three rounds of the median single-call time, as in examples/bench.rs."""
    best = float("inf")
    for _ in range(3):
        for i in range(iters // 10):
            fn(i)
        samples = []
        for i in range(iters):
            t0 = time.perf_counter_ns()
            fn(i)
            samples.append(time.perf_counter_ns() - t0)
        best = min(best, statistics.median(samples) / 1000.0)
    return best


seeds = [bytes([(i * 37 + 1) % 256]) * 32 for i in range(64)]
keys = [Ed25519PrivateKey.from_private_bytes(s) for s in seeds]
pubs = [k.public_key() for k in keys]
msg = b"\x42" * 64
sigs = [k.sign(msg) for k in keys]

rows = {
    "key generation": per_call_us(lambda i: Ed25519PrivateKey.from_private_bytes(seeds[i % 64])
                                  .public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
    "sign (64-byte message)": per_call_us(lambda i: keys[i % 64].sign(msg)),
    "verify": per_call_us(lambda i: pubs[i % 64].verify(sigs[i % 64], msg)),
}
out = {"openssl": backend.openssl_version_text(), "unit": "microseconds per call (median)", "rows": rows}
(ROOT / "docs" / "bench_openssl.json").write_text(json.dumps(out, indent=2) + "\n")
print(out)
