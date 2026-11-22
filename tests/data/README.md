# Test data

| File | What it is | Where it comes from |
|---|---|---|
| `supercop_sign_input.txt` | 128 known-answer vectors: seed, public key, message, signature | The `sign.input` file of the public-domain Ed25519 reference software (SUPERCOP), as copied in the ed25519-dalek repository. Lines 1 to 3 are TEST 1 to 3 of RFC 8032 section 7.1, which says its vectors were taken from this file. |
| `wycheproof_ed25519_test.json` | 210 verification cases, with expected results | Project Wycheproof, `testvectors_v1/ed25519_test.json` (C2SP/wycheproof). Apache-2.0, see `WYCHEPROOF-LICENSE.txt`. |
| `speccheck_cases.json` | 12 edge cases on which implementations disagree | ed25519-speccheck `cases.json` (novifinancial/ed25519-speccheck), from Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs", SSR 2020. Apache-2.0, see `SPECCHECK-LICENSE.txt`. |
| `wycheproof_ed25519.txt`, `speccheck_cases.txt` | The two JSON files above, one case per line | `scripts/convert_vectors.py`, so the Rust tests need no JSON parser. CI checks they are up to date. |
| `openssl_vectors.txt` | 50 keys and signatures, messages of 0 to 2048 bytes | Signed by OpenSSL 4.0.2 through Python's `cryptography` package: `scripts/openssl_crosscheck.py`. |
| `sha512_lengths.txt`, `field_vectors.txt`, `scalar_vectors.txt`, `mulbase_vectors.txt`, `decompress_vectors.txt`, `torsion_points.txt` | Expected values for the building blocks | `scripts/gen_vectors.py`, using only Python integers and `hashlib`. Inputs come from SHA-512 of a counter, so the files are identical on every machine; CI regenerates and compares them. |
