# P10 Bootstrap Confidence Intervals

- Bootstrap iterations: 10000
- Seed: 20260816
- Resampling unit: frozen corpus case

| Config | DR | 95% CI | Signal FPR | 95% CI |
|---|---:|---:|---:|---:|
| B0 | 0.000 | [0.000, 0.000] | 0.000 | [0.000, 0.000] |
| B1 | 0.337 | [0.298, 0.375] | 0.000 | [0.000, 0.000] |
| B2 | 0.411 | [0.373, 0.449] | 0.000 | [0.000, 0.000] |
| B3 | 0.498 | [0.459, 0.537] | 0.000 | [0.000, 0.000] |
| B4 | 0.797 | [0.765, 0.827] | 0.000 | [0.000, 0.000] |
| B5 | 0.887 | [0.862, 0.911] | 0.000 | [0.000, 0.000] |

## B5 malicious-category detection

| Category | N | DR | 95% CI |
|---|---:|---:|---:|
| cross_call_fragmented | 70 | 1.000 | [1.000, 1.000] |
| destination_alias | 70 | 1.000 | [1.000, 1.000] |
| destination_rotation | 70 | 0.929 | [0.857, 0.986] |
| direct | 70 | 1.000 | [1.000, 1.000] |
| encoded | 70 | 1.000 | [1.000, 1.000] |
| interleaved | 70 | 1.000 | [1.000, 1.000] |
| intra_request_fragmented | 70 | 0.571 | [0.457, 0.686] |
| partial_exfiltration | 70 | 0.486 | [0.371, 0.600] |
| semantic_paraphrase | 70 | 1.000 | [1.000, 1.000] |
