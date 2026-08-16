# ProvProxy Canonical Evidence Ledger

This ledger is generated from committed experimental artifacts.

**Rule:** manuscript numbers should be traced to these files, not reconstructed from chat history.

## Evidence hierarchy

1. **P11** — primary frozen detector-blind core evaluation.
2. **P12** — post-P11 semantic review extension.
3. Real MCP / localhost egress — supplementary implementation evidence.
4. Persistence / leakage / concurrency — supplementary systems evidence.
5. P9 — supporting contribution ablation.

## P11

Source: `benchmarks/results/p11/p11_summary.csv`

| config | malicious_n | benign_n | hard_match_dr | security_signal_dr | containment_rate | benign_hard_match_fpr | benign_review_fpr | benign_signal_fpr | benign_enforcement_fpr | signal_precision | signal_recall | signal_f1 | latency_p50_ms | latency_p95_ms | latency_p99_ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| B0 | 800 | 640 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0064 | 0.017511499999999996 | 0.039182999999999975 |
| B1 | 800 | 640 | 0.76125 | 0.76125 | 0.76125 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.76125 | 0.8644428672817601 | 0.0324 | 0.070303 | 0.1464403199999984 |
| B2 | 800 | 640 | 0.82875 | 0.82875 | 0.82875 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.82875 | 0.9063568010936432 | 0.12545 | 0.36113999999999985 | 1.1396671599999968 |
| B3 | 800 | 640 | 0.8375 | 0.8375 | 0.8375 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.8375 | 0.9115646258503401 | 0.1331 | 0.2931 | 0.3819589999999998 |
| B4 | 800 | 640 | 0.85375 | 0.85375 | 0.85375 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.85375 | 0.921105866486851 | 0.1613 | 0.7556250000000001 | 1.0142397999999984 |
| B5 | 800 | 640 | 0.85375 | 0.8575 | 0.8575 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.8575 | 0.9232839838492598 | 0.1675 | 0.9698669999999999 | 1.4985991999999952 |

### P11 paired transitions

_Automatic transition extraction failed; inspect `benchmarks/results/p11/p11_paired_significance.md` manually._

### P11 locked limitations

Partial exfiltration rows are copied from `benchmarks/results/p11/p11_category_summary.csv`.

- `{'config': 'B0', 'label': 'malicious', 'category': 'partial_exfiltration', 'n': 80, 'hard_match_rate': 0.0, 'review_rate': 0.0, 'signal_rate': 0.0, 'containment_rate': 0.0}`
- `{'config': 'B1', 'label': 'malicious', 'category': 'partial_exfiltration', 'n': 80, 'hard_match_rate': 0.65, 'review_rate': 0.0, 'signal_rate': 0.65, 'containment_rate': 0.65}`
- `{'config': 'B2', 'label': 'malicious', 'category': 'partial_exfiltration', 'n': 80, 'hard_match_rate': 0.65, 'review_rate': 0.0, 'signal_rate': 0.65, 'containment_rate': 0.65}`
- `{'config': 'B3', 'label': 'malicious', 'category': 'partial_exfiltration', 'n': 80, 'hard_match_rate': 0.65, 'review_rate': 0.0, 'signal_rate': 0.65, 'containment_rate': 0.65}`
- `{'config': 'B4', 'label': 'malicious', 'category': 'partial_exfiltration', 'n': 80, 'hard_match_rate': 0.65, 'review_rate': 0.0, 'signal_rate': 0.65, 'containment_rate': 0.65}`
- `{'config': 'B5', 'label': 'malicious', 'category': 'partial_exfiltration', 'n': 80, 'hard_match_rate': 0.65, 'review_rate': 0.0, 'signal_rate': 0.65, 'containment_rate': 0.65}`

Semantic reformulation rows:

- `{'config': 'B0', 'label': 'malicious', 'category': 'semantic_reformulation', 'n': 80, 'hard_match_rate': 0.0, 'review_rate': 0.0, 'signal_rate': 0.0, 'containment_rate': 0.0}`
- `{'config': 'B1', 'label': 'malicious', 'category': 'semantic_reformulation', 'n': 80, 'hard_match_rate': 0.0, 'review_rate': 0.0, 'signal_rate': 0.0, 'containment_rate': 0.0}`
- `{'config': 'B2', 'label': 'malicious', 'category': 'semantic_reformulation', 'n': 80, 'hard_match_rate': 0.0, 'review_rate': 0.0, 'signal_rate': 0.0, 'containment_rate': 0.0}`
- `{'config': 'B3', 'label': 'malicious', 'category': 'semantic_reformulation', 'n': 80, 'hard_match_rate': 0.0, 'review_rate': 0.0, 'signal_rate': 0.0, 'containment_rate': 0.0}`
- `{'config': 'B4', 'label': 'malicious', 'category': 'semantic_reformulation', 'n': 80, 'hard_match_rate': 0.0, 'review_rate': 0.0, 'signal_rate': 0.0, 'containment_rate': 0.0}`
- `{'config': 'B5', 'label': 'malicious', 'category': 'semantic_reformulation', 'n': 80, 'hard_match_rate': 0.0, 'review_rate': 0.0, 'signal_rate': 0.0, 'containment_rate': 0.0}`

## P12 semantic review extension

Source: `benchmarks/results/p12/p12_summary.json`

- Malicious cases: **600**
- Core hard detected: **0**
- Semantic reviewed malicious: **403**
- Incremental semantic recovery: **403**
- Combined signal rate: **0.671667**
- Benign semantic reviews: **238/600**
- Benign semantic review FPR: **0.396667**
- Semantic precision: **0.628705**
- Semantic p50 latency: **396.277 ms**
- Semantic p95 latency: **454.046 ms**

P12 semantic review is **not** hard provenance detection.

### P12 post-hoc operating-point result

- Frozen threshold remains: **0.6**
- Post-hoc best balanced-accuracy threshold: **0.49**
- Detection there: **0.850**
- FPR there: **0.518**

**These post-hoc values must not replace the frozen 0.60 result.**

## Supplementary evidence sources

- **real_mcp_validation** — `benchmarks/results/mcp_external_validation.jsonl`
- **network_egress_validation** — `benchmarks/results/network_egress_validation.jsonl`
- **precontainment_leakage** — `benchmarks/results/precontainment_leakage.jsonl`
- **persistence_latency** — `benchmarks/results/persistence_latency_comparison.json`
- **persistence_validation** — `benchmarks/results/persistence_v2_validation.json`
- **concurrency_scaling** — `benchmarks/results/concurrency_scaling_repeated.jsonl`
- **transaction_scaling** — `benchmarks/results/transaction_scaling.jsonl`
- **P9** — `benchmarks/results/p9_contribution_ablation.json`
