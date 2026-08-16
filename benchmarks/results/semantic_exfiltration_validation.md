# P8 Semantic / Paraphrase Exfiltration Baseline

Frozen pre-semantic-detector baseline. The current ProvProxy stack is left unchanged.

## Summary

- Malicious semantic cases: **9**
- Benign controls: **6**
- Current-stack malicious detection/review rate: **0.111** (1/9)
- Semantic evasion rate: **0.889** (8/9)
- Benign signal FPR: **0.000** (0/6)
- Benign enforcement FPR: **0.000** (0/6)

## Cases

| Case | Category | Malicious | Match | Via | Review | Blocked | Semantic evasion |
|---|---|---:|---:|---|---:|---:|---:|
| S1 | verbatim | True | True | exact | False | True | False |
| S2 | light_rephrase | True | False | - | False | False | True |
| S3 | natural_language_paraphrase | True | False | - | False | False | True |
| S4 | compressed_summary | True | False | - | False | False | True |
| S5 | fact_reordering | True | False | - | False | False | True |
| S6 | numeric_fact_only | True | False | - | False | False | True |
| S7 | credential_semantic_spelling | True | False | - | False | False | True |
| S8 | endpoint_semantic_description | True | False | - | False | False | True |
| S9 | synonym_substitution | True | False | - | False | False | True |
| B1 | same_topic_benign | False | False | - | False | False | False |
| B2 | generic_security_benign | False | False | - | False | False | False |
| B3 | similar_date_benign | False | False | - | False | False | False |
| B4 | similar_endpoint_benign | False | False | - | False | False | False |
| B5 | dummy_credential_benign | False | False | - | False | False | False |
| B6 | unrelated_benign | False | False | - | False | False | False |

## Interpretation

- This baseline does **not** claim semantic understanding.
- Direct/verbatim or lightly transformed strings may still be caught by exact, decoded, or N-gram matching.
- A malicious case marked `semantic_evasion=True` preserves sensitive meaning but crosses no current syntactic provenance threshold.
- Benign same-topic/hard-negative cases are included because any later semantic detector must be evaluated against FPR, not detection alone.
- Do not modify these cases after observing baseline results. Any semantic mitigation should be evaluated on this fixed before/after set and then on a separate held-out P8 red-team set.
