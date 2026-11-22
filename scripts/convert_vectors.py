"""Convert the third-party JSON test vectors into one-line-per-case text files,
so the Rust tests need no JSON parser and no dependencies.

    python3 scripts/convert_vectors.py           # write the .txt files
    python3 scripts/convert_vectors.py --check   # exit 1 if they would change

Line format (fields separated by '|', '-' for an empty message):
    wycheproof_ed25519.txt   tcId|result|flags|public key|message|signature|comment
    speccheck_cases.txt      index|public key|message|signature
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"


def field(s: str) -> str:
    assert "|" not in s, s
    return s if s else "-"


def wycheproof() -> str:
    doc = json.loads((DATA / "wycheproof_ed25519_test.json").read_text())
    lines = [f"# {doc['algorithm']} {doc['schema']}: {doc['numberOfTests']} tests, "
             "converted by scripts/convert_vectors.py"]
    count = 0
    for group in doc["testGroups"]:
        pk = group["publicKey"]["pk"]
        for t in group["tests"]:
            lines.append("|".join([str(t["tcId"]), t["result"], ",".join(t["flags"]), field(pk),
                                   field(t["msg"]), field(t["sig"]), field(t["comment"])]))
            count += 1
    assert count == doc["numberOfTests"], (count, doc["numberOfTests"])
    return "\n".join(lines) + "\n"


def speccheck() -> str:
    cases = json.loads((DATA / "speccheck_cases.json").read_text())
    lines = ["# ed25519-speccheck cases.json (Chalkias, Garillot, Nikolaenko 2020), "
             "converted by scripts/convert_vectors.py"]
    for i, c in enumerate(cases):
        lines.append("|".join([str(i), c["pub_key"], field(c["message"]), c["signature"]]))
    return "\n".join(lines) + "\n"


def main() -> int:
    check = "--check" in sys.argv
    stale = []
    for name, text in [("wycheproof_ed25519.txt", wycheproof()), ("speccheck_cases.txt", speccheck())]:
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
