//! Run the Wycheproof and ed25519-speccheck vectors through all three
//! verification rules and write the outcomes to docs/edge_cases.json.
//!
//!     cargo run --release --example edge_cases

use ed25519_rs::{Error, Signature, VerifyingKey};
use std::collections::BTreeMap;
use std::fmt::Write as _;

const WYCHEPROOF: &str = include_str!("../tests/data/wycheproof_ed25519.txt");
const SPECCHECK: &str = include_str!("../tests/data/speccheck_cases.txt");
const MODES: [&str; 3] = ["verify", "verify_strict", "verify_cofactored"];

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Outcome of one mode: Ok or the reason for rejection.
fn run(pk: &[u8], msg: &[u8], sig: &[u8]) -> [Result<(), Error>; 3] {
    let key = <[u8; 32]>::try_from(pk)
        .map_err(|_| Error::InvalidLength)
        .and_then(|b| VerifyingKey::from_bytes(&b));
    let sig = Signature::from_slice(sig);
    let (key, sig) = match (key, sig) {
        (Ok(k), Ok(s)) => (k, s),
        (Err(e), _) | (_, Err(e)) => return [Err(e); 3],
    };
    [
        key.verify(msg, &sig),
        key.verify_strict(msg, &sig),
        key.verify_cofactored(msg, &sig),
    ]
}

fn main() {
    // Wycheproof: count accept/reject per (flag, expected result, mode).
    let mut counts: BTreeMap<(String, String), [[u32; 2]; 3]> = BTreeMap::new();
    let mut acceptable_detail = Vec::new();
    for line in WYCHEPROOF.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split('|').collect();
        let (id, result, flags, comment) = (f[0], f[1], f[2], f[6]);
        let outcome = run(&hex(f[3]), &hex(f[4]), &hex(f[5]));
        for flag in flags.split(',') {
            let entry = counts
                .entry((flag.to_string(), result.to_string()))
                .or_default();
            for (m, o) in outcome.iter().enumerate() {
                entry[m][o.is_ok() as usize] += 1;
            }
        }
        if result == "acceptable" {
            let marks: Vec<String> = outcome.iter().map(|o| format!("{o:?}")).collect();
            acceptable_detail.push(format!("{id} [{flags}] {comment}: {}", marks.join(" / ")));
        }
    }
    println!("Wycheproof (rejected, accepted) per mode: {MODES:?}");
    for ((flag, result), c) in &counts {
        println!("  {flag:22} {result:10} {c:?}");
    }
    println!("Acceptable cases:");
    for d in &acceptable_detail {
        println!("  {d}");
    }

    // speccheck: V/X per case per mode.
    let mut spec_rows = Vec::new();
    println!("speccheck: case  {MODES:?}");
    for line in SPECCHECK.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split('|').collect();
        let outcome = run(&hex(f[1]), &hex(f[2]), &hex(f[3]));
        let marks: Vec<&str> = outcome
            .iter()
            .map(|o| if o.is_ok() { "V" } else { "X" })
            .collect();
        println!("  {:>2}  {}  {:?}", f[0], marks.join(" "), outcome);
        spec_rows.push(marks);
    }

    // JSON for scripts/figures.py
    let mut json =
        String::from("{\n  \"modes\": [\"verify\", \"verify_strict\", \"verify_cofactored\"],\n");
    json.push_str("  \"speccheck\": {\n");
    for (m, mode) in MODES.iter().enumerate() {
        let row: Vec<String> = spec_rows.iter().map(|r| format!("\"{}\"", r[m])).collect();
        let sep = if m + 1 < MODES.len() { "," } else { "" };
        writeln!(json, "    \"{mode}\": [{}]{sep}", row.join(", ")).unwrap();
    }
    json.push_str("  },\n  \"wycheproof\": [\n");
    let n = counts.len();
    for (i, ((flag, result), c)) in counts.iter().enumerate() {
        let accepted: Vec<String> = c.iter().map(|m| m[1].to_string()).collect();
        let total = c[0][0] + c[0][1];
        let sep = if i + 1 < n { "," } else { "" };
        writeln!(
            json,
            "    {{\"flag\": \"{flag}\", \"expected\": \"{result}\", \"total\": {total}, \"accepted\": [{}]}}{sep}",
            accepted.join(", ")
        )
        .unwrap();
    }
    json.push_str("  ]\n}\n");
    std::fs::create_dir_all("docs").unwrap();
    std::fs::write("docs/edge_cases.json", json).unwrap();
    println!("wrote docs/edge_cases.json");
}
