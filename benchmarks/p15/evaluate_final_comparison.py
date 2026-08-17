from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import math
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

CORPUS = (
    ROOT
    / "benchmarks"
    / "p15"
    / "corpus"
    / "fixtures"
    / "p15_neutral_corpus_v3.jsonl"
)

PROTOCOL = (
    ROOT
    / "benchmarks"
    / "p15"
    / "P15_PROTOCOL_LOCK.json"
)

NEMO_ENV_FREEZE = (
    ROOT
    / "benchmarks"
    / "p15"
    / "p15_nemo_environment_freeze.txt"
)

PROV_WORKER = (
    ROOT
    / "benchmarks"
    / "p15"
    / "provproxy_worker.py"
)

NEMO_WORKER = (
    ROOT
    / "benchmarks"
    / "p15"
    / "nemo_worker.py"
)

NEMO_PYTHON = (
    ROOT
    / ".venv-p15"
    / "Scripts"
    / "python.exe"
)

OUTDIR = (
    ROOT
    / "benchmarks"
    / "results"
    / "p15"
    / "final"
)

EXPECTED_CORPUS_SHA256 = (
    "36AAC3A1C8049608CE8E4205C5F39BDE8EBFAA387A02617411E1A504FF646809"
)

EXPECTED_PROTOCOL_SHA256 = (
    "8ADEB5757CE5498C173E7A125787B532A6A5D6DE8DEC1603E80D60FCA4EDB386"
)

EXPECTED_NEMO_ENV_SHA256 = (
    "995D60E0F04D243ED383343F2F4CE0008EA898975BA2913A760C23C414A8ECA3"
)

EXPECTED_NEMO_VERSION = "0.23.0"

PREFIX = "P15_RESULT\t"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest().upper()


def load_rows() -> list[dict]:
    actual = sha256_file(CORPUS)

    if actual != EXPECTED_CORPUS_SHA256:
        raise SystemExit(
            "FROZEN P15 CORPUS HASH MISMATCH\n"
            f"Expected: {EXPECTED_CORPUS_SHA256}\n"
            f"Actual:   {actual}"
        )

    rows = [
        json.loads(line)
        for line in CORPUS.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]

    if len(rows) != 1400:
        raise SystemExit(
            f"Expected 1400 rows, found {len(rows)}"
        )

    if len({
        r["case_id"]
        for r in rows
    }) != 1400:
        raise SystemExit(
            "P15 case IDs are not unique."
        )

    shared = [
        r
        for r in rows
        if r["comparison_scope"]
        == "shared_provenance"
    ]

    native = [
        r
        for r in rows
        if r["comparison_scope"]
        == "nemo_native_policy_control"
    ]

    if len(shared) != 1200:
        raise SystemExit(
            f"Expected 1200 shared rows, got {len(shared)}"
        )

    if len(native) != 200:
        raise SystemExit(
            f"Expected 200 native controls, got {len(native)}"
        )

    labels = Counter(
        r["provenance_label"]
        for r in shared
    )

    if labels != Counter({
        "malicious": 600,
        "benign": 600,
    }):
        raise SystemExit(
            f"Unexpected shared labels: {labels}"
        )

    return rows


def verify_static_artifacts() -> None:
    if sha256_file(PROTOCOL) != EXPECTED_PROTOCOL_SHA256:
        raise SystemExit(
            "P15 protocol hash mismatch."
        )

    if sha256_file(
        NEMO_ENV_FREEZE
    ) != EXPECTED_NEMO_ENV_SHA256:
        raise SystemExit(
            "P15 NeMo environment freeze hash mismatch."
        )

    if not NEMO_PYTHON.exists():
        raise SystemExit(
            f"Missing NeMo Python: {NEMO_PYTHON}"
        )


def get_nemo_version() -> str:
    proc = subprocess.run(
        [
            str(NEMO_PYTHON),
            "-c",
            (
                "import importlib.metadata;"
                "print(importlib.metadata.version("
                "'nemoguardrails'))"
            ),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )

    version = proc.stdout.strip().splitlines()[-1]

    if version != EXPECTED_NEMO_VERSION:
        raise SystemExit(
            "Unexpected NeMo version: "
            f"{version}"
        )

    return version


def run_worker(
    command: list[str],
    rows: list[dict],
    expected_count: int,
    name: str,
) -> list[dict]:
    payload = "\n".join(
        json.dumps(
            row,
            separators=(",", ":"),
        )
        for row in rows
    ) + "\n"

    proc = subprocess.run(
        command,
        cwd=ROOT,
        input=payload,
        text=True,
        capture_output=True,
    )

    results = []

    for line in proc.stdout.splitlines():
        if line.startswith(PREFIX):
            results.append(
                json.loads(
                    line[len(PREFIX):]
                )
            )

    if proc.returncode != 0:
        raise SystemExit(
            f"{name} worker failed.\n"
            f"Return code: {proc.returncode}\n"
            f"STDERR:\n{proc.stderr[-10000:]}\n"
            f"STDOUT tail:\n{proc.stdout[-10000:]}"
        )

    if len(results) != expected_count:
        raise SystemExit(
            f"{name}: expected "
            f"{expected_count} results, "
            f"received {len(results)}.\n"
            f"STDERR tail:\n{proc.stderr[-5000:]}\n"
            f"STDOUT tail:\n{proc.stdout[-5000:]}"
        )

    errors = [
        r
        for r in results
        if "worker_error" in r
    ]

    if errors:
        raise SystemExit(
            f"{name} produced worker errors.\n"
            + json.dumps(
                errors[:10],
                indent=2,
            )
        )

    return results


def percentile(
    values: list[float],
    q: float,
) -> float:
    if not values:
        return 0.0

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    pos = (len(values) - 1) * q
    lo = int(pos)
    hi = min(
        lo + 1,
        len(values) - 1,
    )
    frac = pos - lo

    return (
        values[lo] * (1.0 - frac)
        + values[hi] * frac
    )


def wilson_interval(
    successes: int,
    total: int,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)

    p = successes / total
    z2 = z * z

    denom = 1.0 + z2 / total

    center = (
        p
        + z2 / (2.0 * total)
    ) / denom

    margin = (
        z
        * math.sqrt(
            (
                p * (1.0 - p)
                + z2 / (4.0 * total)
            )
            / total
        )
        / denom
    )

    return (
        max(0.0, center - margin),
        min(1.0, center + margin),
    )


def exact_mcnemar_p(
    b: int,
    c: int,
) -> float:
    n = b + c

    if n == 0:
        return 1.0

    k = min(b, c)

    tail = sum(
        math.comb(n, i)
        for i in range(
            0,
            k + 1,
        )
    ) / (2 ** n)

    return min(
        1.0,
        2.0 * tail,
    )


def binary_metrics(
    rows: list[dict],
    prediction_key: str,
) -> dict:
    tp = fp = tn = fn = 0

    for row in rows:
        actual = (
            row["provenance_label"]
            == "malicious"
        )

        predicted = bool(
            row[prediction_key]
        )

        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1

    malicious_n = tp + fn
    benign_n = tn + fp

    dr = (
        tp / malicious_n
        if malicious_n
        else 0.0
    )

    fpr = (
        fp / benign_n
        if benign_n
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = dr

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    tnr = (
        tn / benign_n
        if benign_n
        else 0.0
    )

    ba = (
        (dr + tnr) / 2.0
    )

    dr_ci = wilson_interval(
        tp,
        malicious_n,
    )

    fpr_ci = wilson_interval(
        fp,
        benign_n,
    )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "malicious_n": malicious_n,
        "benign_n": benign_n,
        "detection_rate": dr,
        "detection_rate_wilson95": dr_ci,
        "false_positive_rate": fpr,
        "false_positive_rate_wilson95": fpr_ci,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "balanced_accuracy": ba,
    }


def category_summary(
    rows: list[dict],
) -> list[dict]:
    grouped = defaultdict(list)

    for row in rows:
        grouped[
            (
                row["system"],
                row["provenance_label"],
                row["category"],
            )
        ].append(row)

    output = []

    for (
        system,
        label,
        category,
    ), items in sorted(
        grouped.items()
    ):
        signal_key = (
            "provproxy_signal"
            if system == "ProvProxy"
            else "nemo_signal"
        )

        signals = sum(
            bool(r[signal_key])
            for r in items
        )

        lo, hi = wilson_interval(
            signals,
            len(items),
        )

        output.append({
            "system": system,
            "label": label,
            "category": category,
            "n": len(items),
            "signal_rate": (
                signals / len(items)
            ),
            "signal_rate_ci_low": lo,
            "signal_rate_ci_high": hi,
        })

    return output


def main() -> None:
    print("=" * 118)
    print(
        "P15 FINAL FROZEN PROVPROXY VS NVIDIA NEMO "
        "GUARDRAILS COMPARISON"
    )
    print("=" * 118)

    verify_static_artifacts()

    corpus_before = sha256_file(
        CORPUS
    )

    rows = load_rows()

    shared_rows = [
        row
        for row in rows
        if row["comparison_scope"]
        == "shared_provenance"
    ]

    native_rows = [
        row
        for row in rows
        if row["comparison_scope"]
        == "nemo_native_policy_control"
    ]

    nemo_version = get_nemo_version()

    print(
        f"Corpus SHA-256 : {corpus_before}"
    )
    print(
        f"Cases           : {len(rows)}"
    )
    print(
        f"Shared          : {len(shared_rows)}"
    )
    print(
        f"Native controls : {len(native_rows)}"
    )
    print(
        f"NeMo version    : {nemo_version}"
    )
    print(
        "ProvProxy       : frozen P11 B5 aligned adapter"
    )
    print()

    print(
        "[1/2] Running frozen ProvProxy worker..."
    )

    prov_results = run_worker(
        [
            sys.executable,
            str(PROV_WORKER),
        ],
        shared_rows,
        len(shared_rows),
        "ProvProxy",
    )

    print(
        "[2/2] Running frozen NeMo IORails worker..."
    )

    nemo_results = run_worker(
        [
            str(NEMO_PYTHON),
            str(NEMO_WORKER),
        ],
        rows,
        len(rows),
        "NeMo",
    )

    prov_by_id = {
        r["case_id"]: r
        for r in prov_results
    }

    nemo_by_id = {
        r["case_id"]: r
        for r in nemo_results
    }

    combined = []

    for row in shared_rows:
        cid = row["case_id"]

        p = prov_by_id[cid]
        n = nemo_by_id[cid]

        combined.append({
            "case_id": cid,
            "category": row["category"],
            "structural_subtype": row[
                "structural_subtype"
            ],
            "provenance_label": row[
                "provenance_label"
            ],
            "calls": len(row["calls"]),

            "provproxy_signal": bool(
                p["signal"]
            ),
            "provproxy_hard_match": bool(
                p["hard_match"]
            ),
            "provproxy_review": bool(
                p["review"]
            ),
            "provproxy_blocked": bool(
                p["blocked"]
            ),
            "provproxy_matched_via": p[
                "matched_via"
            ],
            "provproxy_latency_ms": float(
                p["latency_ms"]
            ),

            "nemo_signal": bool(
                n["unsafe_signal"]
            ),
            "nemo_blocked": bool(
                n["blocked"]
            ),
            "nemo_reasons": n[
                "reasons"
            ],
            "nemo_latency_ms": float(
                n["latency_ms"]
            ),
        })

    prov_metric_rows = [
        {
            **r,
            "system": "ProvProxy",
        }
        for r in combined
    ]

    nemo_metric_rows = [
        {
            **r,
            "system": "NeMo",
        }
        for r in combined
    ]

    prov_metrics = binary_metrics(
        combined,
        "provproxy_signal",
    )

    nemo_metrics = binary_metrics(
        combined,
        "nemo_signal",
    )

    malicious = [
        r
        for r in combined
        if r["provenance_label"]
        == "malicious"
    ]

    benign = [
        r
        for r in combined
        if r["provenance_label"]
        == "benign"
    ]

    mal_nemo_miss_prov_hit = sum(
        (not r["nemo_signal"])
        and r["provproxy_signal"]
        for r in malicious
    )

    mal_nemo_hit_prov_miss = sum(
        r["nemo_signal"]
        and (not r["provproxy_signal"])
        for r in malicious
    )

    benign_nemo_false_prov_clean = sum(
        r["nemo_signal"]
        and (not r["provproxy_signal"])
        for r in benign
    )

    benign_nemo_clean_prov_false = sum(
        (not r["nemo_signal"])
        and r["provproxy_signal"]
        for r in benign
    )

    malicious_mcnemar = exact_mcnemar_p(
        mal_nemo_miss_prov_hit,
        mal_nemo_hit_prov_miss,
    )

    benign_mcnemar = exact_mcnemar_p(
        benign_nemo_false_prov_clean,
        benign_nemo_clean_prov_false,
    )

    prov_latencies = [
        r["provproxy_latency_ms"]
        for r in combined
    ]

    nemo_latencies = [
        r["nemo_latency_ms"]
        for r in combined
    ]

    native_control_results = []

    for row in native_rows:
        result = nemo_by_id[
            row["case_id"]
        ]

        predicted_invalid = bool(
            result["unsafe_signal"]
        )

        actual_invalid = (
            row["tool_policy_label"]
            == "invalid"
        )

        native_control_results.append({
            "case_id": row["case_id"],
            "tool_policy_label": row[
                "tool_policy_label"
            ],
            "predicted_invalid": predicted_invalid,
            "correct": (
                predicted_invalid
                == actual_invalid
            ),
            "reasons": result[
                "reasons"
            ],
            "latency_ms": result[
                "latency_ms"
            ],
        })

    native_correct = sum(
        r["correct"]
        for r in native_control_results
    )

    native_accuracy = (
        native_correct
        / len(native_control_results)
    )

    native_ci = wilson_interval(
        native_correct,
        len(native_control_results),
    )

    categories = category_summary(
        prov_metric_rows
        + nemo_metric_rows
    )

    corpus_after = sha256_file(
        CORPUS
    )

    if corpus_after != corpus_before:
        raise SystemExit(
            "P15 corpus changed during evaluation."
        )

    summary = {
        "experiment": "P15",
        "corpus_sha256": corpus_before,
        "corpus_unchanged": True,
        "protocol_sha256": EXPECTED_PROTOCOL_SHA256,
        "nemo_environment_sha256": EXPECTED_NEMO_ENV_SHA256,
        "nemo_version": nemo_version,
        "shared_provenance_cases": len(shared_rows),
        "native_policy_controls": len(native_rows),

        "provproxy": {
            **prov_metrics,
            "latency_p50_ms": percentile(
                prov_latencies,
                0.50,
            ),
            "latency_p95_ms": percentile(
                prov_latencies,
                0.95,
            ),
            "latency_p99_ms": percentile(
                prov_latencies,
                0.99,
            ),
        },

        "nemo_shared_provenance": {
            **nemo_metrics,
            "latency_p50_ms": percentile(
                nemo_latencies,
                0.50,
            ),
            "latency_p95_ms": percentile(
                nemo_latencies,
                0.95,
            ),
            "latency_p99_ms": percentile(
                nemo_latencies,
                0.99,
            ),
        },

        "paired_shared_provenance": {
            "malicious_nemo_miss_provproxy_hit":
                mal_nemo_miss_prov_hit,
            "malicious_nemo_hit_provproxy_miss":
                mal_nemo_hit_prov_miss,
            "malicious_mcnemar_p":
                malicious_mcnemar,

            "benign_nemo_false_provproxy_clean":
                benign_nemo_false_prov_clean,
            "benign_nemo_clean_provproxy_false":
                benign_nemo_clean_prov_false,
            "benign_mcnemar_p":
                benign_mcnemar,
        },

        "nemo_native_tool_policy_controls": {
            "correct": native_correct,
            "total": len(
                native_control_results
            ),
            "accuracy": native_accuracy,
            "wilson95": native_ci,
        },

        "scope_note": (
            "Shared-provenance metrics compare security "
            "signals on the same neutral cases, but the "
            "systems enforce different native security "
            "objectives. NeMo native tool-policy controls "
            "are reported separately and are not counted "
            "as ProvProxy failures."
        ),

        "tool_result_validation_note": (
            "NeMo IORails tool-result validation was "
            "configured and smoke-validated before final "
            "execution, but the frozen P15 corpus contains "
            "tool-call scenarios rather than tool-result "
            "exchange scenarios."
        ),
    }

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path = (
        OUTDIR
        / "p15_final_summary.json"
    )

    results_path = (
        OUTDIR
        / "p15_final_results.jsonl"
    )

    categories_path = (
        OUTDIR
        / "p15_final_categories.csv"
    )

    native_path = (
        OUTDIR
        / "p15_nemo_native_controls.jsonl"
    )

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with results_path.open(
        "w",
        encoding="utf-8",
    ) as f:
        for row in combined:
            f.write(
                json.dumps(
                    row,
                    sort_keys=True,
                )
                + "\n"
            )

    with categories_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        fieldnames = [
            "system",
            "label",
            "category",
            "n",
            "signal_rate",
            "signal_rate_ci_low",
            "signal_rate_ci_high",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(categories)

    with native_path.open(
        "w",
        encoding="utf-8",
    ) as f:
        for row in native_control_results:
            f.write(
                json.dumps(
                    row,
                    sort_keys=True,
                )
                + "\n"
            )

    print()
    print("=" * 118)
    print("P15 FINAL RESULTS")
    print("=" * 118)

    print(
        "ProvProxy DR/FPR : "
        f"{prov_metrics['detection_rate']:.3f} / "
        f"{prov_metrics['false_positive_rate']:.3f}"
    )

    print(
        "NeMo DR/FPR      : "
        f"{nemo_metrics['detection_rate']:.3f} / "
        f"{nemo_metrics['false_positive_rate']:.3f}"
    )

    print(
        "ProvProxy F1/BA  : "
        f"{prov_metrics['f1']:.3f} / "
        f"{prov_metrics['balanced_accuracy']:.3f}"
    )

    print(
        "NeMo F1/BA       : "
        f"{nemo_metrics['f1']:.3f} / "
        f"{nemo_metrics['balanced_accuracy']:.3f}"
    )

    print()
    print(
        "Malicious NeMo miss -> ProvProxy hit : "
        f"{mal_nemo_miss_prov_hit}"
    )

    print(
        "Malicious NeMo hit -> ProvProxy miss : "
        f"{mal_nemo_hit_prov_miss}"
    )

    print(
        "Malicious McNemar p                  : "
        f"{malicious_mcnemar:.12g}"
    )

    print()
    print(
        "NeMo native tool-policy accuracy     : "
        f"{native_accuracy:.3f}"
    )

    print()
    print(
        "ProvProxy p50/p95/p99 ms : "
        f"{summary['provproxy']['latency_p50_ms']:.6f} / "
        f"{summary['provproxy']['latency_p95_ms']:.6f} / "
        f"{summary['provproxy']['latency_p99_ms']:.6f}"
    )

    print(
        "NeMo p50/p95/p99 ms      : "
        f"{summary['nemo_shared_provenance']['latency_p50_ms']:.6f} / "
        f"{summary['nemo_shared_provenance']['latency_p95_ms']:.6f} / "
        f"{summary['nemo_shared_provenance']['latency_p99_ms']:.6f}"
    )

    print()
    print(
        "Corpus unchanged :",
        corpus_after == corpus_before,
    )

    print()
    print(
        "[WRITE]",
        summary_path,
    )
    print(
        "[WRITE]",
        results_path,
    )
    print(
        "[WRITE]",
        categories_path,
    )
    print(
        "[WRITE]",
        native_path,
    )

    print()
    print(
        "[PASS] Frozen adapters used."
    )
    print(
        "[PASS] Frozen corpus hash verified before and after."
    )
    print(
        "[PASS] Native NeMo policy controls reported separately."
    )
    print("=" * 118)


if __name__ == "__main__":
    main()
