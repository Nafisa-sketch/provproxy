# P8 Held-Out Semantic Red-Team Validation

- Preselected primary threshold: **0.60**
- Model: `sentence-transformers/all-MiniLM-L6-v2`
- Held-out malicious cases: **10**
- Held-out benign controls: **10**
- Primary DR: **0.500** (5/10)
- Primary benign FPR: **0.100** (1/10)
- Primary precision: **0.833**
- Steady-state p95 latency: **193.360 ms**

## Threshold sensitivity

| Threshold | DR | FPR | Precision | TP | FP |
|---:|---:|---:|---:|---:|---:|
| 0.55 | 0.700 | 0.300 | 0.700 | 7/10 | 3/10 |
| 0.60 | 0.500 | 0.100 | 0.833 | 5/10 | 1/10 |
| 0.65 | 0.500 | 0.100 | 0.833 | 5/10 | 1/10 |
| 0.70 | 0.400 | 0.000 | 1.000 | 4/10 | 0/10 |

## Per-case scores

| Case | Category | Malicious | Score | Review@0.60 | Latency ms |
|---|---|---:|---:|---:|---:|
| H1 | date_paraphrase | True | 0.5779 | False | 167.734 |
| H2 | credential_words_digits | True | 0.3138 | False | 158.737 |
| H3 | endpoint_description | True | 0.5651 | False | 167.511 |
| H4 | compressed_all_facts | True | 0.7772 | True | 193.206 |
| H5 | reordered_synonyms | True | 0.7865 | True | 193.360 |
| H6 | credential_partial_semantics | True | 0.3950 | False | 146.904 |
| H7 | date_numeric_reformat | True | 0.7268 | True | 151.428 |
| H8 | mixed_benign_malicious | True | 0.6581 | True | 177.706 |
| H9 | indirect_instructional | True | 0.3580 | False | 181.854 |
| H10 | minimal_fact | True | 0.7853 | True | 157.809 |
| N1 | same_project_benign | False | 0.6665 | True | 193.494 |
| N2 | different_date | False | 0.5819 | False | 170.605 |
| N3 | different_credential | False | 0.3177 | False | 169.014 |
| N4 | different_endpoint | False | 0.5932 | False | 180.362 |
| N5 | generic_recovery_advice | False | 0.3690 | False | 161.679 |
| N6 | same_words_unrelated | False | 0.1695 | False | 151.767 |
| N7 | numeric_hard_negative | False | 0.3309 | False | 162.098 |
| N8 | port_hard_negative | False | 0.1167 | False | 157.435 |
| N9 | date_topic_hard_negative | False | 0.3930 | False | 141.465 |
| N10 | unrelated | False | 0.2667 | False | 129.867 |

## Interpretation

- This set is held out from threshold selection.
- Semantic scoring remains REVIEW-only; it is not a hard provenance match.
- Any misses or false positives are retained as measured limitations.
- Do not retune the primary threshold after seeing these results.
