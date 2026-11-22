"""Draw the README figures from the JSON written by the examples and scripts.

    cargo run --release --example edge_cases
    cargo run --release --example timing
    cargo run --release --example bench
    python3 scripts/openssl_crosscheck.py
    python3 scripts/bench_openssl.py
    (cd scripts/compare_dalek && cargo run --release)
    python3 scripts/figures.py
"""

import json
import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Rectangle  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

SURFACE, INK, INK2, MUTED = "#fcfcfb", "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, NEUTRAL = "#e1e0d9", "#c3c2b7", "#f0efec"
BLUE, ORANGE, AQUA, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#6250d6"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
    "axes.titlesize": 11, "axes.titleweight": "bold", "axes.titlecolor": INK,
})

# ed25519-speccheck README, "Results" table (Chalkias, Garillot, Nikolaenko 2020).
PUBLISHED = {
    "BoringSSL": "VVVVXXXXXXXV",
    "Go": "VVVVXXXXXXXV",
    "Dalek": "VVVVXXXXXXXV",
    "Dalek strict": "XXXVXXXXXXXX",
    "LibSodium": "XXXVXXXXXXXX",
    "ref10": "VVVVXXVXXXXV",
    "Zebra": "VVVVVVXXXVVV",
    "BouncyCastle": "VVVVXXXXXXXX",
}
# Short column labels; (a) = the hash used the canonical re-encoding, (b) = the bytes as given.
CASES = ["S = 0\nsmall\nA, R", "small\nA", "small\nR", "mixed\nA, R", "cofac-\ntored\nonly", "8k mod ℓ\ntrap",
         "S > ℓ", "S ≫ ℓ", "R non-\ncanon.\n(a)", "R non-\ncanon.\n(b)", "A non-\ncanon.\n(a)", "A non-\ncanon.\n(b)"]


def cell(ax, x, y, accepted, text=None):
    ax.add_patch(Rectangle((x + 0.04, y + 0.06), 0.92, 0.88, color=BLUE if accepted else NEUTRAL, lw=0))
    label = text if text is not None else ("✓" if accepted else "✗")
    ax.text(x + 0.5, y + 0.5, label, ha="center", va="center", fontsize=10 if text else 12,
            color="#ffffff" if accepted else INK2, fontweight="bold" if not text else "normal")


def edge_cases():
    ours = json.loads((DOCS / "edge_cases.json").read_text())
    ossl = json.loads((DOCS / "openssl_edge_cases.json").read_text())
    rows = [(f"this crate · {m}", "".join(ours["speccheck"][m])) for m in ours["modes"]]
    rows.append((ossl["openssl"].rsplit(" ", 3)[0] + " (run here)", "".join(ossl["speccheck"])))
    published = list(PUBLISHED.items())

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(14.5, 6.8), gridspec_kw={"width_ratios": [3.1, 1.25], "wspace": 0.42})
    n = len(rows) + len(published) + 1
    y = n - 1
    labels = []
    for name, marks in rows:
        for c, m in enumerate(marks):
            cell(ax, c, y, m == "V")
        labels.append((y, name, INK))
        y -= 1
    ax.axhline(y + 0.5, color=AXIS, lw=0.8, xmin=0, xmax=1)
    ax.text(12.1, y + 0.5, "published, 2020", ha="left", va="center", fontsize=8.5, color=MUTED, style="italic")
    y -= 1
    for name, marks in published:
        for c, m in enumerate(marks):
            cell(ax, c, y, m == "V")
        labels.append((y, name, INK2))
        y -= 1
    ax.set_xlim(0, 12)
    ax.set_ylim(y + 1, n)
    ax.set_yticks([l[0] + 0.5 for l in labels], [l[1] for l in labels])
    for tick, (_, _, color) in zip(ax.get_yticklabels(), labels):
        tick.set_color(color)
    ax.set_xticks([c + 0.5 for c in range(12)], [f"{c}\n{CASES[c]}" for c in range(12)], fontsize=8.5)
    ax.xaxis.tick_top()
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("ed25519-speccheck: 12 cases where RFC 8032 implementations disagree\n"
                 "✓ accepted   ✗ rejected", loc="left", pad=66)

    # Wycheproof, grouped by expected result.
    groups = [("valid", "valid", None), ("invalid", "invalid", None),
              ("acceptable:\nsmall-order key", "acceptable", "SmallOrderPublicKey"),
              ("acceptable:\nmixed-order key", "acceptable", "MixedOrderPublicKey")]
    cols = ["verify", "verify_\nstrict", "verify_\ncofactored", "OpenSSL"]
    for gi, (label, result, flag) in enumerate(groups):
        yy = len(groups) - 1 - gi
        ours_acc, total = [0, 0, 0], 0
        for e in ours["wycheproof"]:
            if e["expected"] == result and (flag is None or e["flag"] == flag):
                total += e["total"]
                ours_acc = [a + b for a, b in zip(ours_acc, e["accepted"])]
        ossl_acc = sum(v[1] for k, v in ossl["wycheproof_rejected_accepted"].items()
                       if k.split("|")[1] == result and (flag is None or k.split("|")[0] == flag))
        for ci, acc in enumerate(ours_acc + [ossl_acc]):
            cell(ax2, ci, yy, acc == total and acc > 0, f"{acc}/{total}")
    ax2.set_xlim(0, 4)
    ax2.set_ylim(0, len(groups))
    ax2.set_yticks([len(groups) - 0.5 - i for i in range(len(groups))], [g[0] for g in groups])
    ax2.set_xticks([c + 0.5 for c in range(4)], cols, fontsize=8.5)
    ax2.set_aspect(0.8)
    ax2.set_anchor("N")
    ax2.xaxis.tick_top()
    ax2.tick_params(length=0)
    for s in ax2.spines.values():
        s.set_visible(False)
    ax2.set_title("Wycheproof: 210 cases\naccepted / total", loc="left", pad=40)
    fig.savefig(DOCS / "edge_cases.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def timing():
    d = json.loads((DOCS / "timing.json").read_text())
    leaky, ct = d["runs"]
    fig, axes = plt.subplots(1, 3, figsize=(14.5, 4.2), gridspec_kw={"wspace": 0.3})
    for ax, run, title in [(axes[0], leaky, "Textbook double-and-add"), (axes[1], ct, "Constant-time 4-bit window")]:
        lo, w = run["low_ns"], run["bin_width_ns"]
        xs = [(lo + i * w) / 1000 for i in range(len(run["hist_fixed"]) + 1)]
        # Random first, fixed on top and thinner, so both stay visible where they coincide.
        for hist, color, name, lw in [(run["hist_random"], ORANGE, "fresh random scalars", 2.4),
                                      (run["hist_fixed"], BLUE, "fixed scalar (eight 1 bits)", 1.5)]:
            ax.stairs(hist, xs, color=color, alpha=0.16, fill=True)
            ax.stairs(hist, xs, color=color, lw=lw, label=name)
        ax.set_title(title, loc="left")
        ax.set_xlabel("time per call (µs)")
        ax.set_yticks([])
        ax.spines["left"].set_visible(False)
        verdict = "leak detected" if abs(run["t_cropped"]) > d["threshold"] else "no leak detected"
        ax.text(0.98, 0.95, f"means {run['mean_fixed_ns'] / 1000:.2f} vs {run['mean_random_ns'] / 1000:.2f} µs\n"
                f"t = {run['t_cropped']:.2f}: {verdict}", transform=ax.transAxes, ha="right", va="top",
                fontsize=9, color=INK2)
    axes[0].legend(frameon=False, loc="upper left", fontsize=8.5, bbox_to_anchor=(0.0, 0.8))

    ax = axes[2]
    for run, color, name in [(leaky, VIOLET, "double-and-add"), (ct, AQUA, "4-bit window")]:
        xs = [p[0] / 1000 for p in run["trajectory"]]
        ys = [max(abs(p[1]), 0.01) for p in run["trajectory"]]
        ax.plot(xs, ys, color=color, lw=2)
        ax.text(xs[-1] * 1.01, ys[-1], name, color=INK2, va="center", fontsize=9)
    ax.axhline(d["threshold"], color=MUTED, lw=1, ls=(0, (4, 3)))
    ax.text(2, d["threshold"] * 1.3, "|t| = 4.5 threshold", color=MUTED, fontsize=8.5)
    ax.set_yscale("log")
    ax.set_ylim(0.01, 2000)
    ax.set_xlim(0, max(p[0] for p in leaky["trajectory"]) / 1000 * 1.32)
    ax.set_xlabel("measurements (thousands)")
    ax.set_ylabel("|Welch t|")
    ax.grid(axis="y", color=GRID, lw=0.6)
    ax.set_title("Evidence grows only for the leaky code", loc="left")
    fig.text(0.01, -0.06, f"{leaky['samples']:,} calls per routine, classes interleaved at random, slowest 1% dropped. "
             f"CPU: {d['cpu']}.", fontsize=8.5, color=MUTED)
    fig.savefig(DOCS / "timing.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def bench():
    ours = {r["name"]: r for r in json.loads((DOCS / "bench.json").read_text())["rows"]}
    dalek = json.loads((DOCS / "bench_dalek.json").read_text())
    ossl = json.loads((DOCS / "bench_openssl.json").read_text())
    ops = ["key generation", "sign (64-byte message)", "verify"]
    libs = [("this crate", BLUE, [ours[o]["median"] for o in ops]),
            (dalek["library"].split(" (")[0], ORANGE, [dalek["rows"][o] for o in ops]),
            (ossl["openssl"].rsplit(" ", 3)[0] + " via Python", AQUA, [ossl["rows"][o] for o in ops])]
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(14.5, 4.4), gridspec_kw={"wspace": 0.55})
    h = 0.26
    for li, (name, color, vals) in enumerate(libs):
        ys = [i + (li - 1) * (h + 0.02) for i in range(len(ops))]
        ax.barh(ys, vals, height=h, color=color, label=name)
        for y, v in zip(ys, vals):
            ax.text(v + 1.5, y, f"{v:.0f}", va="center", fontsize=8.5, color=INK2)
    ax.set_yticks(range(len(ops)), ["key generation", "sign\n(64-byte message)", "verify"])
    ax.invert_yaxis()
    ax.set_xlabel("µs per call (median, lower is better)")
    ax.grid(axis="x", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="upper right", fontsize=8.5)
    ax.set_title("Same machine, same method", loc="left")

    parts = [("field multiply", "multiply"), ("field inversion", "invert"), ("SHA-512, 1 KiB", "SHA-512, 1 KiB"),
             ("[k]B, constant time", "[k]B constant time"), ("[k]B, double-and-add", "[k]B double-and-add"),
             ("[a]A + [b]B, for verify", "[a]A + [b]B (verify)")]
    vals = [ours[k]["median"] for _, k in parts]
    ax2.barh(range(len(parts)), vals, height=0.55, color=BLUE)
    for y, v in enumerate(vals):
        ax2.text(v * 1.12, y, f"{v * 1000:.0f} ns" if v < 1 else f"{v:.1f} µs", va="center", fontsize=8.5, color=INK2)
    ax2.set_yticks(range(len(parts)), [p for p, _ in parts])
    ax2.invert_yaxis()
    ax2.set_xscale("log")
    ax2.set_xlim(0.01, 400)
    ax2.set_xlabel("µs per call (log scale)")
    ax2.grid(axis="x", color=GRID, lw=0.6)
    ax2.set_axisbelow(True)
    ax2.set_title("Where this crate's time goes", loc="left")
    fig.text(0.01, -0.07, "Median per call, best of three rounds; Intel Xeon @ 2.10 GHz, 2-vCPU cloud VM. "
             "The OpenSSL figures include the Python call.", fontsize=8.5, color=MUTED)
    fig.savefig(DOCS / "bench.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    edge_cases()
    timing()
    bench()
    print("wrote docs/edge_cases.png, docs/timing.png, docs/bench.png")
