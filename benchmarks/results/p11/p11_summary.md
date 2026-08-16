# P11 Generator-Independent Frozen Evaluation

- Corpus SHA-256: `2BB245B0CEDA6462253B3D25E7E76B6676FB91A6A4BA4B965EA3C8B35E8B63E4`
- Frozen before detector execution: yes
- Detector tuning on P11: none
- Network execution: disabled
- Semantic augmentation: excluded from B0-B5
- Tool/destination aliases normalized only at evaluator adapter boundary

| Config | Hard DR | Signal DR | Containment | Signal FPR | Enforcement FPR | Precision | F1 | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.018 |
| B1 | 0.761 | 0.761 | 0.761 | 0.000 | 0.000 | 1.000 | 0.864 | 0.070 |
| B2 | 0.829 | 0.829 | 0.829 | 0.000 | 0.000 | 1.000 | 0.906 | 0.361 |
| B3 | 0.838 | 0.838 | 0.838 | 0.000 | 0.000 | 1.000 | 0.912 | 0.293 |
| B4 | 0.854 | 0.854 | 0.854 | 0.000 | 0.000 | 1.000 | 0.921 | 0.756 |
| B5 | 0.854 | 0.858 | 0.858 | 0.000 | 0.000 | 1.000 | 0.923 | 0.970 |

## Category summary

| Config | Label | Category | N | Hard match | Review | Signal | Containment |
|---|---|---|---:|---:|---:|---:|---:|
| B0 | benign | approved_destination | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | benign | common_substring | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | cross_call_fragmented | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | destination_alias | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | destination_rotation | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | direct | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | benign | dummy_credentials | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | encoded | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | benign | fragment_like_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | interleaved | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | intra_request_fragmented | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | benign | legitimate_encoding | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | multi_source | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | benign | multi_tool_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | partial_exfiltration | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | benign | same_structure_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | malicious | semantic_reformulation | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B0 | benign | semantic_similarity | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | benign | approved_destination | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | benign | common_substring | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | malicious | cross_call_fragmented | 80 | 0.875 | 0.000 | 0.875 | 0.875 |
| B1 | malicious | destination_alias | 80 | 0.925 | 0.000 | 0.925 | 0.925 |
| B1 | malicious | destination_rotation | 80 | 0.963 | 0.000 | 0.963 | 0.963 |
| B1 | malicious | direct | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B1 | benign | dummy_credentials | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | malicious | encoded | 80 | 0.325 | 0.000 | 0.325 | 0.325 |
| B1 | benign | fragment_like_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | malicious | interleaved | 80 | 0.963 | 0.000 | 0.963 | 0.963 |
| B1 | malicious | intra_request_fragmented | 80 | 0.912 | 0.000 | 0.912 | 0.912 |
| B1 | benign | legitimate_encoding | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | malicious | multi_source | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B1 | benign | multi_tool_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | malicious | partial_exfiltration | 80 | 0.650 | 0.000 | 0.650 | 0.650 |
| B1 | benign | same_structure_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | malicious | semantic_reformulation | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B1 | benign | semantic_similarity | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | benign | approved_destination | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | benign | common_substring | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | malicious | cross_call_fragmented | 80 | 0.875 | 0.000 | 0.875 | 0.875 |
| B2 | malicious | destination_alias | 80 | 0.925 | 0.000 | 0.925 | 0.925 |
| B2 | malicious | destination_rotation | 80 | 0.963 | 0.000 | 0.963 | 0.963 |
| B2 | malicious | direct | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B2 | benign | dummy_credentials | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | malicious | encoded | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B2 | benign | fragment_like_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | malicious | interleaved | 80 | 0.963 | 0.000 | 0.963 | 0.963 |
| B2 | malicious | intra_request_fragmented | 80 | 0.912 | 0.000 | 0.912 | 0.912 |
| B2 | benign | legitimate_encoding | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | malicious | multi_source | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B2 | benign | multi_tool_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | malicious | partial_exfiltration | 80 | 0.650 | 0.000 | 0.650 | 0.650 |
| B2 | benign | same_structure_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | malicious | semantic_reformulation | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B2 | benign | semantic_similarity | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | benign | approved_destination | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | benign | common_substring | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | malicious | cross_call_fragmented | 80 | 0.875 | 0.000 | 0.875 | 0.875 |
| B3 | malicious | destination_alias | 80 | 0.925 | 0.000 | 0.925 | 0.925 |
| B3 | malicious | destination_rotation | 80 | 0.963 | 0.000 | 0.963 | 0.963 |
| B3 | malicious | direct | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B3 | benign | dummy_credentials | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | malicious | encoded | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B3 | benign | fragment_like_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | malicious | interleaved | 80 | 0.963 | 0.000 | 0.963 | 0.963 |
| B3 | malicious | intra_request_fragmented | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B3 | benign | legitimate_encoding | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | malicious | multi_source | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B3 | benign | multi_tool_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | malicious | partial_exfiltration | 80 | 0.650 | 0.000 | 0.650 | 0.650 |
| B3 | benign | same_structure_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | malicious | semantic_reformulation | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B3 | benign | semantic_similarity | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | benign | approved_destination | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | benign | common_substring | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | malicious | cross_call_fragmented | 80 | 0.925 | 0.000 | 0.925 | 0.925 |
| B4 | malicious | destination_alias | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B4 | malicious | destination_rotation | 80 | 0.963 | 0.000 | 0.963 | 0.963 |
| B4 | malicious | direct | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B4 | benign | dummy_credentials | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | malicious | encoded | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B4 | benign | fragment_like_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | malicious | interleaved | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B4 | malicious | intra_request_fragmented | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B4 | benign | legitimate_encoding | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | malicious | multi_source | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B4 | benign | multi_tool_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | malicious | partial_exfiltration | 80 | 0.650 | 0.000 | 0.650 | 0.650 |
| B4 | benign | same_structure_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | malicious | semantic_reformulation | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B4 | benign | semantic_similarity | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | benign | approved_destination | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | benign | common_substring | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | malicious | cross_call_fragmented | 80 | 0.925 | 0.000 | 0.925 | 0.925 |
| B5 | malicious | destination_alias | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B5 | malicious | destination_rotation | 80 | 0.963 | 0.275 | 1.000 | 1.000 |
| B5 | malicious | direct | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B5 | benign | dummy_credentials | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | malicious | encoded | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B5 | benign | fragment_like_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | malicious | interleaved | 80 | 1.000 | 0.312 | 1.000 | 1.000 |
| B5 | malicious | intra_request_fragmented | 80 | 1.000 | 0.000 | 1.000 | 1.000 |
| B5 | benign | legitimate_encoding | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | malicious | multi_source | 80 | 1.000 | 0.263 | 1.000 | 1.000 |
| B5 | benign | multi_tool_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | malicious | partial_exfiltration | 80 | 0.650 | 0.000 | 0.650 | 0.650 |
| B5 | benign | same_structure_benign | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | malicious | semantic_reformulation | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
| B5 | benign | semantic_similarity | 80 | 0.000 | 0.000 | 0.000 | 0.000 |
