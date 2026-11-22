"""Regenerate the derived test vectors in tests/data/.

Every expected value here comes from Python integers and hashlib, which share
no code with the Rust implementation under test. Inputs are derived from
SHA-512 of a counter, so the output is identical on every Python version.

    python3 scripts/gen_vectors.py           # write the files
    python3 scripts/gen_vectors.py --check   # exit 1 if any file would change
"""

import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def rand_int(label: str, i: int, bits: int) -> int:
    """Deterministic pseudo-random integer below 2**bits."""
    out = b""
    counter = 0
    while len(out) * 8 < bits:
        out += hashlib.sha512(f"{label}/{i}/{counter}".encode()).digest()
        counter += 1
    return int.from_bytes(out, "little") % (1 << bits)


def le(x: int, n: int) -> str:
    return x.to_bytes(n, "little").hex()


# ---------------------------------------------------------------- curve, affine
def recover_x(y: int, sign: int):
    """RFC 8032 section 5.1.3 decoding of x from y and the sign bit, or None."""
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if x & 1 != sign:
        x = P - x
    return x


def add(p1, p2):
    """Affine addition on -x^2 + y^2 = 1 + d x^2 y^2 (complete for Ed25519)."""
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, P) % P,
            (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P)


def mul(k: int, pt):
    acc = (0, 1)
    while k:
        if k & 1:
            acc = add(acc, pt)
        pt = add(pt, pt)
        k >>= 1
    return acc


def encode(pt) -> str:
    x, y = pt
    return le(y | ((x & 1) << 255), 32)


def decode(b: bytes):
    v = int.from_bytes(b, "little")
    y, sign = v & ((1 << 255) - 1), v >> 255
    x = recover_x(y, sign)
    return None if x is None else (x, y)


BASE_Y = 4 * pow(5, -1, P) % P
BASE = (recover_x(BASE_Y, 0), BASE_Y)


# ---------------------------------------------------------------- generators
def sha512_lengths():
    yield "# n sha512(bytes((31*i + 7) % 256 for i in range(n))), from Python hashlib"
    for n in range(301):
        msg = bytes((31 * i + 7) % 256 for i in range(n))
        yield f"{n} {hashlib.sha512(msg).hexdigest()}"
    yield f"million-a {hashlib.sha512(b'a' * 1_000_000).hexdigest()}"


def field_vectors():
    yield "# a b a+b a-b a*b a^2 a^-1 (all mod p = 2^255-19, 32-byte little-endian; 0^-1 = 0)"
    edges = [0, 1, 2, 19, P - 1, P, P + 1, P + 18, 2**255 - 1, 2**254, 2**51, 2**51 - 1, 2**204]
    cases = [(a, b) for a in edges for b in (0, 1, P - 1, 2**255 - 1)]
    cases += [(rand_int("fe-a", i, 255), rand_int("fe-b", i, 255)) for i in range(300)]
    for a, b in cases:
        inv = pow(a, P - 2, P)
        yield " ".join([le(a, 32), le(b, 32), le((a + b) % P, 32), le((a - b) % P, 32),
                        le(a * b % P, 32), le(a * a % P, 32), le(inv, 32)])


def scalar_vectors():
    yield "# reduce x(64 bytes) x mod l(32 bytes)  |  muladd a b c (a*b+c) mod l, little-endian"
    wide_edges = [0, 1, L - 1, L, L + 1, 2 * L, 2**252, 2**256 - 1, L * L - 1, L * L,
                  2**512 - 1, (2**512 // L) * L, (2**512 // L) * L - 1]
    for i, x in enumerate(wide_edges + [rand_int("sc-wide", i, 512) for i in range(300)]):
        yield f"reduce {le(x, 64)} {le(x % L, 32)}"
    small_edges = [0, 1, L - 1, L, 2**255 - 1, 2**256 - 1]
    triples = [(a, b, c) for a in small_edges for b in small_edges for c in (0, L - 1, 2**256 - 1)]
    triples += [(rand_int("sc-a", i, 256), rand_int("sc-b", i, 256), rand_int("sc-c", i, 256))
                for i in range(300)]
    for a, b, c in triples:
        yield f"muladd {le(a, 32)} {le(b, 32)} {le(c, 32)} {le((a * b + c) % L, 32)}"


def mulbase_vectors():
    yield "# k(32 bytes) encode([k]B), with k used as a full 256-bit integer"
    edges = [0, 1, 2, 3, 8, 15, 16, L - 1, L, L + 1, 2 * L, 8 * L, 2**252, 2**254 + 8, 2**255 - 1, 2**256 - 1]
    for k in edges + [rand_int("mulbase", i, 256) for i in range(40)]:
        yield f"{le(k, 32)} {encode(mul(k, BASE))}"


def torsion_points():
    """The eight points of order dividing 8, as multiples of one point of order 8."""
    i = 0
    while True:
        y = rand_int("torsion", i, 255)
        i += 1
        pt = decode(y.to_bytes(32, "little"))
        if pt is None:
            continue
        t = mul(L, pt)                      # kills the prime-order part
        if mul(4, t) != (0, 1):             # order exactly 8
            break
    yield "# i encode([i]T) for a point T of order 8 (i = 0 is the identity)"
    for j in range(8):
        yield f"{j} {encode(mul(j, t))}"


def decompress_vectors():
    yield "# bytes expected  (expected = canonical re-encoding, or 'none' if decoding must fail)"
    p_bytes = P.to_bytes(32, "little")
    edges = [
        p_bytes,                                                  # y = p: non-canonical
        (P + 1).to_bytes(32, "little"),                           # y = p + 1: non-canonical 1
        (2**255 - 1).to_bytes(32, "little"),                      # y = 2^255 - 1
        (1 | 1 << 255).to_bytes(32, "little"),                    # identity with sign bit set
        ((P - 1) | 1 << 255).to_bytes(32, "little"),              # (0, -1) with sign bit set
        (1).to_bytes(32, "little"),                               # identity
        (P - 1).to_bytes(32, "little"),                           # (0, -1)
        (0).to_bytes(32, "little"),                               # y = 0: (sqrt(-1), 0)
        (1 << 255).to_bytes(32, "little"),                        # y = 0 with sign bit
        bytes.fromhex(encode(BASE)),
    ]
    randoms = [rand_int("decomp", i, 256).to_bytes(32, "little") for i in range(300)]
    for b in edges + randoms:
        pt = decode(b)
        yield f"{b.hex()} {'none' if pt is None else encode(pt)}"


FILES = {
    "sha512_lengths.txt": sha512_lengths,
    "field_vectors.txt": field_vectors,
    "scalar_vectors.txt": scalar_vectors,
    "mulbase_vectors.txt": mulbase_vectors,
    "torsion_points.txt": torsion_points,
    "decompress_vectors.txt": decompress_vectors,
}


def main() -> int:
    check = "--check" in sys.argv
    stale = []
    for name, gen in FILES.items():
        text = "\n".join(gen()) + "\n"
        path = DATA / name
        if check:
            if not path.exists() or path.read_text() != text:
                stale.append(name)
        else:
            path.write_text(text)
            print(f"wrote {path.relative_to(ROOT)} ({text.count(chr(10))} lines)")
    if stale:
        print("out of date:", ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
