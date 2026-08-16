import json
import math
from pathlib import Path

RESULTS = Path("benchmarks/results/p12/p12_results.jsonl")
OUT_JSON = Path("benchmarks/results/p12/p12_posthoc_threshold_analysis.json")
OUT_MD = Path("benchmarks/results/p12/p12_posthoc_threshold_analysis.md")

rows = [
    json.loads(line)
    for line in RESULTS.read_text(encoding="utf-8-sig").splitlines()
    if line.strip()
]

print("=" * 100)
print("P12 POST-HOC THRESHOLD CHARACTERIZATION")
print("=" * 100)
print(f"Rows loaded: {len(rows)}")

# Discover the actual score/label field names before making assumptions.
if not rows:
    raise SystemExit("ERROR: no P12 result rows found.")

print("\nAvailable fields:")
for key in sorted(rows[0].keys()):
    print(" ", key)

def find_field(candidates):
    for name in candidates:
        if name in rows[0]:
            return name
    return None

label_field = find_field(["label", "ground_truth", "class"])
score_field = find_field([
    "semantic_score",
    "score",
    "best_semantic_score",
    "semantic_similarity",
    "similarity"
])

if label_field is None:
    raise SystemExit(
        "ERROR: could not identify label field. "
        "Inspect the fields printed above."
    )

if score_field is None:
    raise SystemExit(
        "ERROR: could not identify semantic score field. "
        "Inspect the fields printed above."
    )

print(f"\nLabel field : {label_field}")
print(f"Score field : {score_field}")

def is_malicious(row):
    value = row[label_field]
    if isinstance(value, bool):
        return value
    return str(value).lower() in {
        "malicious", "true", "1", "positive", "attack"
    }

malicious = [r for r in rows if is_malicious(r)]
benign = [r for r in rows if not is_malicious(r)]

print(f"Malicious   : {len(malicious)}")
print(f"Benign      : {len(benign)}")

if len(malicious) != 600 or len(benign) != 600:
    print(
        "WARNING: expected frozen P12 split of "
        "600 malicious / 600 benign."
    )

def metrics(threshold):
    tp = sum(float(r[score_field]) >= threshold for r in malicious)
    fn = len(malicious) - tp
    fp = sum(float(r[score_field]) >= threshold for r in benign)
    tn = len(benign) - fp

    tpr = tp / len(malicious) if malicious else 0.0
    fpr = fp / len(benign) if benign else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    specificity = tn / len(benign) if benign else 0.0
    balanced_accuracy = (tpr + specificity) / 2.0
    f1 = (
        2 * precision * tpr / (precision + tpr)
        if precision + tpr
        else 0.0
    )

    return {
        "threshold": threshold,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "tpr_detection_rate": tpr,
        "fpr": fpr,
        "precision": precision,
        "specificity": specificity,
        "balanced_accuracy": balanced_accuracy,
        "f1": f1,
    }

# Fine-grained characterization only.
# This is explicitly POST-HOC and does not replace threshold 0.60.
thresholds = [
    round(x / 100, 2)
    for x in range(30, 96)
]

sweep = [metrics(t) for t in thresholds]

primary = next(x for x in sweep if x["threshold"] == 0.60)

# Descriptive optima — NOT new selected operating points.
best_balanced = max(
    sweep,
    key=lambda x: (
        x["balanced_accuracy"],
        x["precision"],
        x["threshold"],
    ),
)

best_f1 = max(
    sweep,
    key=lambda x: (
        x["f1"],
        x["precision"],
        x["threshold"],
    ),
)

# Best achievable TPR under several FPR budgets.
budgets = {}
for budget in [0.00, 0.01, 0.05, 0.10, 0.20]:
    eligible = [x for x in sweep if x["fpr"] <= budget]
    if eligible:
        best = max(
            eligible,
            key=lambda x: (
                x["tpr_detection_rate"],
                x["precision"],
                -x["threshold"],
            ),
        )
        budgets[f"{budget:.2f}"] = best
    else:
        budgets[f"{budget:.2f}"] = None

# Score-distribution quantiles.
def quantile(values, q):
    values = sorted(values)
    if not values:
        return None
    pos = (len(values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return values[lo]
    return (
        values[lo] * (hi - pos)
        + values[hi] * (pos - lo)
    )

mal_scores = [float(r[score_field]) for r in malicious]
ben_scores = [float(r[score_field]) for r in benign]

distribution = {
    "malicious": {
        "p10": quantile(mal_scores, 0.10),
        "p25": quantile(mal_scores, 0.25),
        "p50": quantile(mal_scores, 0.50),
        "p75": quantile(mal_scores, 0.75),
        "p90": quantile(mal_scores, 0.90),
    },
    "benign": {
        "p10": quantile(ben_scores, 0.10),
        "p25": quantile(ben_scores, 0.25),
        "p50": quantile(ben_scores, 0.50),
        "p75": quantile(ben_scores, 0.75),
        "p90": quantile(ben_scores, 0.90),
    },
}

output = {
    "analysis": "P12 post-hoc threshold characterization",
    "status": "DESCRIPTIVE_ONLY_NO_RETUNING",
    "primary_threshold_remains": 0.60,
    "primary_result": primary,
    "descriptive_best_balanced_accuracy": best_balanced,
    "descriptive_best_f1": best_f1,
    "best_detection_under_fpr_budgets": budgets,
    "score_distribution": distribution,
    "threshold_sweep": sweep,
    "interpretation_constraint": (
        "All threshold values other than 0.60 are post-hoc "
        "characterizations. They MUST NOT be reported as replacement "
        "P12 operating points or used to overwrite the preregistered "
        "primary result."
    ),
}

OUT_JSON.write_text(
    json.dumps(output, indent=2),
    encoding="utf-8",
)

lines = [
    "# P12 Post-Hoc Threshold Characterization",
    "",
    "**Status:** descriptive analysis only; no threshold retuning.",
    "",
    "The preregistered P12 primary threshold remains **0.60**.",
    "",
    "## Frozen primary operating point",
    "",
    f"- Detection: {primary['tp']}/{len(malicious)} "
    f"({primary['tpr_detection_rate']:.3f})",
    f"- Benign review FPR: {primary['fp']}/{len(benign)} "
    f"({primary['fpr']:.3f})",
    f"- Precision: {primary['precision']:.3f}",
    "",
    "## Descriptive post-hoc optima",
    "",
    f"- Best balanced-accuracy threshold: "
    f"{best_balanced['threshold']:.2f}",
    f"- Detection at that point: "
    f"{best_balanced['tpr_detection_rate']:.3f}",
    f"- FPR at that point: {best_balanced['fpr']:.3f}",
    f"- Precision at that point: {best_balanced['precision']:.3f}",
    "",
    f"- Best F1 threshold: {best_f1['threshold']:.2f}",
    f"- Detection at that point: "
    f"{best_f1['tpr_detection_rate']:.3f}",
    f"- FPR at that point: {best_f1['fpr']:.3f}",
    "",
    "## Detection achievable under benign-review budgets",
    "",
    "| Maximum FPR | Threshold | Detection | Precision |",
    "|---:|---:|---:|---:|",
]

for budget, item in budgets.items():
    if item is None:
        lines.append(f"| {budget} | - | - | - |")
    else:
        lines.append(
            f"| {budget} | {item['threshold']:.2f} | "
            f"{item['tpr_detection_rate']:.3f} | "
            f"{item['precision']:.3f} |"
        )

lines += [
    "",
    "## Interpretation rule",
    "",
    "These results characterize the frozen scorer after the experiment. "
    "They do not replace the preregistered threshold of 0.60 and must "
    "not be presented as retuned P12 headline results.",
]

OUT_MD.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print("\n" + "-" * 100)
print("FROZEN PRIMARY")
print("-" * 100)
print(json.dumps(primary, indent=2))

print("\n" + "-" * 100)
print("BEST BALANCED ACCURACY — POST-HOC ONLY")
print("-" * 100)
print(json.dumps(best_balanced, indent=2))

print("\n" + "-" * 100)
print("BEST F1 — POST-HOC ONLY")
print("-" * 100)
print(json.dumps(best_f1, indent=2))

print("\n" + "-" * 100)
print("FPR-BUDGET ANALYSIS")
print("-" * 100)
for budget, item in budgets.items():
    print(f"FPR <= {budget}: {item}")

print("\n" + "-" * 100)
print("SCORE DISTRIBUTIONS")
print("-" * 100)
print(json.dumps(distribution, indent=2))

print("\n[PASS] Frozen P12 results read only.")
print("[PASS] Semantic model was NOT executed.")
print("[PASS] Primary threshold remains 0.60.")
print("[PASS] Analysis is explicitly post-hoc.")
print(f"[WRITE] {OUT_JSON}")
print(f"[WRITE] {OUT_MD}")
print("=" * 100)
