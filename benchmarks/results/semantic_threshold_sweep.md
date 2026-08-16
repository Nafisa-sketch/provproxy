# P8 Optional Semantic Review Threshold Sweep

- Model: `sentence-transformers/all-MiniLM-L6-v2`
- Initial model-load/warm-up latency: **256700.3 ms**
- Steady-state mean per-case latency: **304.276 ms**
- Steady-state p95 latency: **365.771 ms**

## Threshold sweep

| Threshold | Detection rate | Benign FPR | Precision | Malicious reviewed | Benign reviewed |
|---:|---:|---:|---:|---:|---:|
| 0.30 | 1.000 | 0.500 | 0.750 | 9/9 | 3/6 |
| 0.35 | 1.000 | 0.500 | 0.750 | 9/9 | 3/6 |
| 0.40 | 0.889 | 0.333 | 0.800 | 8/9 | 2/6 |
| 0.45 | 0.889 | 0.167 | 0.889 | 8/9 | 1/6 |
| 0.50 | 0.889 | 0.167 | 0.889 | 8/9 | 1/6 |
| 0.55 | 0.778 | 0.167 | 0.875 | 7/9 | 1/6 |
| 0.60 | 0.778 | 0.000 | 1.000 | 7/9 | 0/6 |
| 0.65 | 0.778 | 0.000 | 1.000 | 7/9 | 0/6 |
| 0.70 | 0.667 | 0.000 | 1.000 | 6/9 | 0/6 |
| 0.75 | 0.333 | 0.000 | 1.000 | 3/9 | 0/6 |
| 0.80 | 0.111 | 0.000 | 1.000 | 1/9 | 0/6 |

## Per-case scores

| Case | Category | Malicious | Score | Latency ms |
|---|---|---:|---:|---:|
| S1 | verbatim | True | 1.0000 | 305.305 |
| S2 | light_rephrase | True | 0.7988 | 335.866 |
| S3 | natural_language_paraphrase | True | 0.7379 | 383.059 |
| S4 | compressed_summary | True | 0.7853 | 295.661 |
| S5 | fact_reordering | True | 0.7359 | 343.694 |
| S6 | numeric_fact_only | True | 0.6875 | 307.805 |
| S7 | credential_semantic_spelling | True | 0.3625 | 265.380 |
| S8 | endpoint_semantic_description | True | 0.5039 | 336.695 |
| S9 | synonym_substitution | True | 0.7221 | 365.771 |
| B1 | same_topic_benign | False | 0.5963 | 268.020 |
| B2 | generic_security_benign | False | 0.3876 | 263.603 |
| B3 | similar_date_benign | False | 0.4393 | 255.763 |
| B4 | similar_endpoint_benign | False | 0.2659 | 275.306 |
| B5 | dummy_credential_benign | False | 0.2533 | 268.571 |
| B6 | unrelated_benign | False | 0.2264 | 293.648 |

## Interpretation

- This is an optional **REVIEW** candidate, not a hard-match/block layer.
- The frozen S1-S9/B1-B6 set is a development set; do not claim final generalization from it.
- Choose an operating point only after inspecting detection/FPR/latency trade-offs.
- A separate held-out semantic set is required before the final P8 claim.
