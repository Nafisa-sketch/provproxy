# ProvProxy P10 Frozen-Corpus Evaluation

- Corpus: `p10-v1`
- SHA-256: `BEE095C7F2706437EFFDEBEC844A971D9F8467F3F4B261718152E908EC0E7844`
- Cases: 1120
- Core semantic-review augmentation: disabled
- Network execution: disabled

## Overall

| Config | DR | Signal FPR | Enforcement FPR | Precision | F1 | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.006 | 0.017 | 0.035 |
| B1 | 0.337 | 0.000 | 0.000 | 1.000 | 0.504 | 0.041 | 0.099 | 0.276 |
| B2 | 0.411 | 0.000 | 0.000 | 1.000 | 0.583 | 0.528 | 2.231 | 4.529 |
| B3 | 0.498 | 0.000 | 0.000 | 1.000 | 0.665 | 0.196 | 0.871 | 2.191 |
| B4 | 0.797 | 0.000 | 0.000 | 1.000 | 0.887 | 0.347 | 0.922 | 1.081 |
| B5 | 0.887 | 0.000 | 0.000 | 1.000 | 0.940 | 0.415 | 1.068 | 1.183 |

## Category breakdown

| Config | Label | Category | N | Signal rate | Block rate |
|---|---|---|---:|---:|---:|
| B0 | benign | approved_destination | 70 | 0.000 | 0.000 |
| B0 | benign | common_substring | 70 | 0.000 | 0.000 |
| B0 | benign | dummy_credentials | 70 | 0.000 | 0.000 |
| B0 | benign | legitimate_encoding | 70 | 0.000 | 0.000 |
| B0 | benign | multi_tool_benign | 70 | 0.000 | 0.000 |
| B0 | benign | same_topic | 70 | 0.000 | 0.000 |
| B0 | benign | semantic_similarity | 70 | 0.000 | 0.000 |
| B0 | malicious | cross_call_fragmented | 70 | 0.000 | 0.000 |
| B0 | malicious | destination_alias | 70 | 0.000 | 0.000 |
| B0 | malicious | destination_rotation | 70 | 0.000 | 0.000 |
| B0 | malicious | direct | 70 | 0.000 | 0.000 |
| B0 | malicious | encoded | 70 | 0.000 | 0.000 |
| B0 | malicious | interleaved | 70 | 0.000 | 0.000 |
| B0 | malicious | intra_request_fragmented | 70 | 0.000 | 0.000 |
| B0 | malicious | partial_exfiltration | 70 | 0.000 | 0.000 |
| B0 | malicious | semantic_paraphrase | 70 | 0.000 | 0.000 |
| B1 | benign | approved_destination | 70 | 0.000 | 0.000 |
| B1 | benign | common_substring | 70 | 0.000 | 0.000 |
| B1 | benign | dummy_credentials | 70 | 0.000 | 0.000 |
| B1 | benign | legitimate_encoding | 70 | 0.000 | 0.000 |
| B1 | benign | multi_tool_benign | 70 | 0.000 | 0.000 |
| B1 | benign | same_topic | 70 | 0.000 | 0.000 |
| B1 | benign | semantic_similarity | 70 | 0.000 | 0.000 |
| B1 | malicious | cross_call_fragmented | 70 | 0.129 | 0.129 |
| B1 | malicious | destination_alias | 70 | 0.114 | 0.114 |
| B1 | malicious | destination_rotation | 70 | 0.114 | 0.114 |
| B1 | malicious | direct | 70 | 1.000 | 1.000 |
| B1 | malicious | encoded | 70 | 0.329 | 0.329 |
| B1 | malicious | interleaved | 70 | 0.071 | 0.071 |
| B1 | malicious | intra_request_fragmented | 70 | 0.129 | 0.129 |
| B1 | malicious | partial_exfiltration | 70 | 0.486 | 0.486 |
| B1 | malicious | semantic_paraphrase | 70 | 0.657 | 0.657 |
| B2 | benign | approved_destination | 70 | 0.000 | 0.000 |
| B2 | benign | common_substring | 70 | 0.000 | 0.000 |
| B2 | benign | dummy_credentials | 70 | 0.000 | 0.000 |
| B2 | benign | legitimate_encoding | 70 | 0.000 | 0.000 |
| B2 | benign | multi_tool_benign | 70 | 0.000 | 0.000 |
| B2 | benign | same_topic | 70 | 0.000 | 0.000 |
| B2 | benign | semantic_similarity | 70 | 0.000 | 0.000 |
| B2 | malicious | cross_call_fragmented | 70 | 0.129 | 0.129 |
| B2 | malicious | destination_alias | 70 | 0.114 | 0.114 |
| B2 | malicious | destination_rotation | 70 | 0.114 | 0.114 |
| B2 | malicious | direct | 70 | 1.000 | 1.000 |
| B2 | malicious | encoded | 70 | 1.000 | 1.000 |
| B2 | malicious | interleaved | 70 | 0.071 | 0.071 |
| B2 | malicious | intra_request_fragmented | 70 | 0.129 | 0.129 |
| B2 | malicious | partial_exfiltration | 70 | 0.486 | 0.486 |
| B2 | malicious | semantic_paraphrase | 70 | 0.657 | 0.657 |
| B3 | benign | approved_destination | 70 | 0.000 | 0.000 |
| B3 | benign | common_substring | 70 | 0.000 | 0.000 |
| B3 | benign | dummy_credentials | 70 | 0.000 | 0.000 |
| B3 | benign | legitimate_encoding | 70 | 0.000 | 0.000 |
| B3 | benign | multi_tool_benign | 70 | 0.000 | 0.000 |
| B3 | benign | same_topic | 70 | 0.000 | 0.000 |
| B3 | benign | semantic_similarity | 70 | 0.000 | 0.000 |
| B3 | malicious | cross_call_fragmented | 70 | 0.129 | 0.129 |
| B3 | malicious | destination_alias | 70 | 0.114 | 0.114 |
| B3 | malicious | destination_rotation | 70 | 0.114 | 0.114 |
| B3 | malicious | direct | 70 | 1.000 | 1.000 |
| B3 | malicious | encoded | 70 | 1.000 | 1.000 |
| B3 | malicious | interleaved | 70 | 0.071 | 0.071 |
| B3 | malicious | intra_request_fragmented | 70 | 0.571 | 0.571 |
| B3 | malicious | partial_exfiltration | 70 | 0.486 | 0.486 |
| B3 | malicious | semantic_paraphrase | 70 | 1.000 | 1.000 |
| B4 | benign | approved_destination | 70 | 0.000 | 0.000 |
| B4 | benign | common_substring | 70 | 0.000 | 0.000 |
| B4 | benign | dummy_credentials | 70 | 0.000 | 0.000 |
| B4 | benign | legitimate_encoding | 70 | 0.000 | 0.000 |
| B4 | benign | multi_tool_benign | 70 | 0.000 | 0.000 |
| B4 | benign | same_topic | 70 | 0.000 | 0.000 |
| B4 | benign | semantic_similarity | 70 | 0.000 | 0.000 |
| B4 | malicious | cross_call_fragmented | 70 | 1.000 | 1.000 |
| B4 | malicious | destination_alias | 70 | 1.000 | 1.000 |
| B4 | malicious | destination_rotation | 70 | 0.114 | 0.114 |
| B4 | malicious | direct | 70 | 1.000 | 1.000 |
| B4 | malicious | encoded | 70 | 1.000 | 1.000 |
| B4 | malicious | interleaved | 70 | 1.000 | 1.000 |
| B4 | malicious | intra_request_fragmented | 70 | 0.571 | 0.571 |
| B4 | malicious | partial_exfiltration | 70 | 0.486 | 0.486 |
| B4 | malicious | semantic_paraphrase | 70 | 1.000 | 1.000 |
| B5 | benign | approved_destination | 70 | 0.000 | 0.000 |
| B5 | benign | common_substring | 70 | 0.000 | 0.000 |
| B5 | benign | dummy_credentials | 70 | 0.000 | 0.000 |
| B5 | benign | legitimate_encoding | 70 | 0.000 | 0.000 |
| B5 | benign | multi_tool_benign | 70 | 0.000 | 0.000 |
| B5 | benign | same_topic | 70 | 0.000 | 0.000 |
| B5 | benign | semantic_similarity | 70 | 0.000 | 0.000 |
| B5 | malicious | cross_call_fragmented | 70 | 1.000 | 1.000 |
| B5 | malicious | destination_alias | 70 | 1.000 | 1.000 |
| B5 | malicious | destination_rotation | 70 | 0.929 | 0.929 |
| B5 | malicious | direct | 70 | 1.000 | 1.000 |
| B5 | malicious | encoded | 70 | 1.000 | 1.000 |
| B5 | malicious | interleaved | 70 | 1.000 | 1.000 |
| B5 | malicious | intra_request_fragmented | 70 | 0.571 | 0.571 |
| B5 | malicious | partial_exfiltration | 70 | 0.486 | 0.486 |
| B5 | malicious | semantic_paraphrase | 70 | 1.000 | 1.000 |

## Partial-exfiltration cases

These cases remain reported separately because a partial leak below the configured provenance threshold is still malicious ground truth, but need not satisfy the detector's calibrated decision boundary.

| Config | Transformation | N | Signal rate | Block rate |
|---|---|---:|---:|---:|
| B0 | partial-0.10 | 18 | 0.000 | 0.000 |
| B0 | partial-0.25 | 18 | 0.000 | 0.000 |
| B0 | partial-0.50 | 17 | 0.000 | 0.000 |
| B0 | partial-0.75 | 17 | 0.000 | 0.000 |
| B1 | partial-0.10 | 18 | 0.000 | 0.000 |
| B1 | partial-0.25 | 18 | 0.000 | 0.000 |
| B1 | partial-0.50 | 17 | 1.000 | 1.000 |
| B1 | partial-0.75 | 17 | 1.000 | 1.000 |
| B2 | partial-0.10 | 18 | 0.000 | 0.000 |
| B2 | partial-0.25 | 18 | 0.000 | 0.000 |
| B2 | partial-0.50 | 17 | 1.000 | 1.000 |
| B2 | partial-0.75 | 17 | 1.000 | 1.000 |
| B3 | partial-0.10 | 18 | 0.000 | 0.000 |
| B3 | partial-0.25 | 18 | 0.000 | 0.000 |
| B3 | partial-0.50 | 17 | 1.000 | 1.000 |
| B3 | partial-0.75 | 17 | 1.000 | 1.000 |
| B4 | partial-0.10 | 18 | 0.000 | 0.000 |
| B4 | partial-0.25 | 18 | 0.000 | 0.000 |
| B4 | partial-0.50 | 17 | 1.000 | 1.000 |
| B4 | partial-0.75 | 17 | 1.000 | 1.000 |
| B5 | partial-0.10 | 18 | 0.000 | 0.000 |
| B5 | partial-0.25 | 18 | 0.000 | 0.000 |
| B5 | partial-0.50 | 17 | 1.000 | 1.000 |
| B5 | partial-0.75 | 17 | 1.000 | 1.000 |
