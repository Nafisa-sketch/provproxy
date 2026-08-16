# P11 Paired Significance and Wilson 95% Confidence Intervals

## Overall signal detection

| Config | Detected | Total | DR | Wilson 95% CI |
|---|---:|---:|---:|---:|
| B0 | 0 | 800 | 0.000 | [0.000, 0.005] |
| B1 | 609 | 800 | 0.761 | [0.731, 0.789] |
| B2 | 663 | 800 | 0.829 | [0.801, 0.853] |
| B3 | 670 | 800 | 0.838 | [0.810, 0.861] |
| B4 | 683 | 800 | 0.854 | [0.828, 0.877] |
| B5 | 686 | 800 | 0.858 | [0.832, 0.880] |

## Benign signal FPR

| Config | False signals | Total benign | FPR | Wilson 95% CI |
|---|---:|---:|---:|---:|
| B0 | 0 | 640 | 0.000 | [0.000, 0.006] |
| B1 | 0 | 640 | 0.000 | [0.000, 0.006] |
| B2 | 0 | 640 | 0.000 | [0.000, 0.006] |
| B3 | 0 | 640 | 0.000 | [0.000, 0.006] |
| B4 | 0 | 640 | 0.000 | [0.000, 0.006] |
| B5 | 0 | 640 | 0.000 | [0.000, 0.006] |

## Paired incremental contribution

| Comparison | Both miss | New catches | Regressions | Both hit | McNemar p |
|---|---:|---:|---:|---:|---:|
| B0 -> B1 | 191 | 609 | 0 | 0 | 9.41374947306e-184 |
| B1 -> B2 | 137 | 54 | 0 | 609 | 1.11022302463e-16 |
| B2 -> B3 | 130 | 7 | 0 | 663 | 0.015625 |
| B3 -> B4 | 117 | 13 | 0 | 670 | 0.000244140625 |
| B4 -> B5 | 114 | 3 | 0 | 683 | 0.25 |

## B5 malicious-category Wilson intervals

| Category | Detected | N | DR | Wilson 95% CI |
|---|---:|---:|---:|---:|
| cross_call_fragmented | 74 | 80 | 0.925 | [0.846, 0.965] |
| destination_alias | 80 | 80 | 1.000 | [0.954, 1.000] |
| destination_rotation | 80 | 80 | 1.000 | [0.954, 1.000] |
| direct | 80 | 80 | 1.000 | [0.954, 1.000] |
| encoded | 80 | 80 | 1.000 | [0.954, 1.000] |
| interleaved | 80 | 80 | 1.000 | [0.954, 1.000] |
| intra_request_fragmented | 80 | 80 | 1.000 | [0.954, 1.000] |
| multi_source | 80 | 80 | 1.000 | [0.954, 1.000] |
| partial_exfiltration | 52 | 80 | 0.650 | [0.541, 0.745] |
| semantic_reformulation | 0 | 80 | 0.000 | [0.000, 0.046] |
