from __future__ import annotations

import json
import math
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "benchmarks" / "results" / "p11" / "p11_frozen_results.jsonl"
OUT = ROOT / "benchmarks" / "results" / "p11" / "p11_paired_significance.md"

CONFIGS = ["B0", "B1", "B2", "B3", "B4", "B5"]


def wilson(k: int, n: int, z: float = 1.959963984540054):
    if n == 0:
        return 0.0, 0.0

    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (
        z
        * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
        / denom
    )
    return max(0.0, center - half), min(1.0, center + half)


def exact_mcnemar(new_catches: int, regressions: int) -> float:
    n = new_catches + regressions
    if n == 0:
        return 1.0

    m = min(new_catches, regressions)
    tail = sum(math.comb(n, i) for i in range(m + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def main():
    rows = [
        json.loads(line)
        for line in SRC.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]

    lines = [
        "# P11 Paired Significance and Wilson 95% Confidence Intervals",
        "",
        "## Overall signal detection",
        "",
        "| Config | Detected | Total | DR | Wilson 95% CI |",
        "|---|---:|---:|---:|---:|",
    ]

    for cfg in CONFIGS:
        group = [r for r in mal if r["config"] == cfg]
        k = sum(bool(r["signal"]) for r in group)
        n = len(group)
        rate = k / n
        lo, hi = wilson(k, n)

        lines.append(
            f"| {cfg} | {k} | {n} | {rate:.3f} | "
            f"[{lo:.3f}, {hi:.3f}] |"
        )

    lines += [
        "",
        "## Benign signal FPR",
        "",
        "| Config | False signals | Total benign | FPR | Wilson 95% CI |",
        "|---|---:|---:|---:|---:|",
    ]

    for cfg in CONFIGS:
        group = [r for r in ben if r["config"] == cfg]
        k = sum(bool(r["signal"]) for r in group)
        n = len(group)
        rate = k / n
        lo, hi = wilson(k, n)

        lines.append(
            f"| {cfg} | {k} | {n} | {rate:.3f} | "
            f"[{lo:.3f}, {hi:.3f}] |"
        )

    by_cfg = defaultdict(dict)
    for r in mal:
        by_cfg[r["config"]][r["case_id"]] = bool(r["signal"])

    ids = sorted(set.intersection(*(set(by_cfg[c]) for c in CONFIGS)))

    lines += [
        "",
        "## Paired incremental contribution",
        "",
        "| Comparison | Both miss | New catches | Regressions | Both hit | McNemar p |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for a, b in zip(CONFIGS[:-1], CONFIGS[1:]):
        n00 = n01 = n10 = n11 = 0

        for cid in ids:
            x = by_cfg[a][cid]
            y = by_cfg[b][cid]

            if not x and not y:
                n00 += 1
            elif not x and y:
                n01 += 1
            elif x and not y:
                n10 += 1
            else:
                n11 += 1

        p = exact_mcnemar(n01, n10)

        lines.append(
            f"| {a} -> {b} | {n00} | {n01} | {n10} | "
            f"{n11} | {p:.12g} |"
        )

    lines += [
        "",
        "## B5 malicious-category Wilson intervals",
        "",
        "| Category | Detected | N | DR | Wilson 95% CI |",
        "|---|---:|---:|---:|---:|",
    ]

    b5 = [r for r in mal if r["config"] == "B5"]

    for category in sorted({r["category"] for r in b5}):
        group = [r for r in b5 if r["category"] == category]
        k = sum(bool(r["signal"]) for r in group)
        n = len(group)
        rate = k / n
        lo, hi = wilson(k, n)

        lines.append(
            f"| {category} | {k} | {n} | {rate:.3f} | "
            f"[{lo:.3f}, {hi:.3f}] |"
        )

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote: {OUT}")


if __name__ == "__main__":
    main()
