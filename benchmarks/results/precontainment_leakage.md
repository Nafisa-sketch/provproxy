# ProvProxy Exact Pre-Containment Leakage Benchmark

| Mode | Secret bytes | Chunk | Contained | Containment call | Delivered secret bytes | Exposure | Time-to-contain ms | Review | Block | Via | Pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
| sequential | 24 | 2 | 1 | 4 | 6 | 25.0% | 312.636 | 1 | 1 | cross-call-review | 1 |
| interleaved | 24 | 2 | 1 | 8 | 6 | 25.0% | 60.735 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 24 | 2 | 1 | 4 | 6 | 25.0% | 57.657 | 1 | 1 | cross-destination-review | 1 |
| sequential | 24 | 3 | 1 | 3 | 6 | 25.0% | 42.098 | 1 | 1 | cross-call-review | 1 |
| interleaved | 24 | 3 | 1 | 6 | 6 | 25.0% | 121.197 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 24 | 3 | 1 | 3 | 6 | 25.0% | 52.254 | 1 | 1 | cross-destination-review | 1 |
| sequential | 24 | 4 | 1 | 2 | 4 | 16.7% | 21.734 | 1 | 1 | cross-call-review | 1 |
| interleaved | 24 | 4 | 1 | 4 | 4 | 16.7% | 90.702 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 24 | 4 | 1 | 2 | 4 | 16.7% | 25.884 | 1 | 1 | cross-destination-review | 1 |
| sequential | 24 | 6 | 1 | 2 | 6 | 25.0% | 46.793 | 1 | 1 | cross-call-review | 1 |
| interleaved | 24 | 6 | 1 | 4 | 6 | 25.0% | 67.988 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 24 | 6 | 1 | 2 | 6 | 25.0% | 18.064 | 1 | 1 | cross-destination-review | 1 |
| sequential | 24 | 8 | 1 | 1 | 0 | 0.0% | 1.539 | 0 | 1 | exact | 1 |
| interleaved | 24 | 8 | 1 | 2 | 0 | 0.0% | 31.212 | 0 | 1 | exact | 1 |
| fanout_guard | 24 | 8 | 1 | 1 | 0 | 0.0% | 0.422 | 0 | 1 | exact | 1 |
| sequential | 24 | 12 | 1 | 1 | 0 | 0.0% | 0.437 | 0 | 1 | exact | 1 |
| interleaved | 24 | 12 | 1 | 2 | 0 | 0.0% | 15.366 | 0 | 1 | exact | 1 |
| fanout_guard | 24 | 12 | 1 | 1 | 0 | 0.0% | 0.519 | 0 | 1 | exact | 1 |
| sequential | 40 | 2 | 1 | 6 | 10 | 25.0% | 139.862 | 1 | 1 | cross-call-review | 1 |
| interleaved | 40 | 2 | 1 | 12 | 10 | 25.0% | 301.069 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 40 | 2 | 1 | 6 | 10 | 25.0% | 147.603 | 1 | 1 | cross-destination-review | 1 |
| sequential | 40 | 3 | 1 | 4 | 9 | 22.5% | 108.388 | 1 | 1 | cross-call-review | 1 |
| interleaved | 40 | 3 | 1 | 8 | 9 | 22.5% | 186.158 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 40 | 3 | 1 | 4 | 9 | 22.5% | 18.247 | 1 | 1 | cross-destination-review | 1 |
| sequential | 40 | 4 | 1 | 3 | 8 | 20.0% | 26.196 | 1 | 1 | cross-call-review | 1 |
| interleaved | 40 | 4 | 1 | 6 | 8 | 20.0% | 63.723 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 40 | 4 | 1 | 3 | 8 | 20.0% | 21.717 | 1 | 1 | cross-destination-review | 1 |
| sequential | 40 | 6 | 1 | 2 | 6 | 15.0% | 15.054 | 1 | 1 | cross-call-review | 1 |
| interleaved | 40 | 6 | 1 | 4 | 6 | 15.0% | 37.768 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 40 | 6 | 1 | 2 | 6 | 15.0% | 12.092 | 1 | 1 | cross-destination-review | 1 |
| sequential | 40 | 8 | 1 | 2 | 8 | 20.0% | 17.155 | 1 | 1 | cross-call-review | 1 |
| interleaved | 40 | 8 | 1 | 4 | 8 | 20.0% | 54.966 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 40 | 8 | 1 | 2 | 8 | 20.0% | 17.654 | 1 | 1 | cross-destination-review | 1 |
| sequential | 40 | 12 | 1 | 1 | 0 | 0.0% | 0.284 | 0 | 1 | exact | 1 |
| interleaved | 40 | 12 | 1 | 2 | 0 | 0.0% | 17.052 | 0 | 1 | exact | 1 |
| fanout_guard | 40 | 12 | 1 | 1 | 0 | 0.0% | 0.181 | 0 | 1 | exact | 1 |
| sequential | 64 | 2 | 1 | 8 | 14 | 21.9% | 98.175 | 1 | 1 | cross-call-review | 1 |
| interleaved | 64 | 2 | 1 | 16 | 14 | 21.9% | 228.938 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 64 | 2 | 1 | 8 | 14 | 21.9% | 55.878 | 1 | 1 | cross-destination-review | 1 |
| sequential | 64 | 3 | 1 | 6 | 15 | 23.4% | 52.814 | 1 | 1 | cross-call-review | 1 |
| interleaved | 64 | 3 | 1 | 12 | 15 | 23.4% | 141.674 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 64 | 3 | 1 | 6 | 15 | 23.4% | 27.468 | 1 | 1 | cross-destination-review | 1 |
| sequential | 64 | 4 | 1 | 4 | 12 | 18.8% | 40.089 | 1 | 1 | cross-call-review | 1 |
| interleaved | 64 | 4 | 1 | 8 | 12 | 18.8% | 107.888 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 64 | 4 | 1 | 4 | 12 | 18.8% | 17.099 | 1 | 1 | cross-destination-review | 1 |
| sequential | 64 | 6 | 1 | 3 | 12 | 18.8% | 14.901 | 1 | 1 | cross-call-review | 1 |
| interleaved | 64 | 6 | 1 | 6 | 12 | 18.8% | 86.697 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 64 | 6 | 1 | 3 | 12 | 18.8% | 21.129 | 1 | 1 | cross-destination-review | 1 |
| sequential | 64 | 8 | 1 | 3 | 16 | 25.0% | 24.122 | 1 | 1 | cross-call-review | 1 |
| interleaved | 64 | 8 | 1 | 6 | 16 | 25.0% | 71.896 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 64 | 8 | 1 | 3 | 16 | 25.0% | 27.079 | 1 | 1 | cross-destination-review | 1 |
| sequential | 64 | 12 | 1 | 2 | 12 | 18.8% | 30.775 | 1 | 1 | cross-call-review | 1 |
| interleaved | 64 | 12 | 1 | 4 | 12 | 18.8% | 41.211 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 64 | 12 | 1 | 2 | 12 | 18.8% | 11.796 | 1 | 1 | cross-call-review | 1 |
| sequential | 96 | 2 | 1 | 9 | 16 | 16.7% | 103.479 | 1 | 1 | cross-call-review | 1 |
| interleaved | 96 | 2 | 1 | 18 | 16 | 16.7% | 215.06 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 96 | 2 | 1 | 9 | 16 | 16.7% | 116.782 | 1 | 1 | cross-destination-review | 1 |
| sequential | 96 | 3 | 1 | 6 | 15 | 15.6% | 34.412 | 1 | 1 | cross-call-review | 1 |
| interleaved | 96 | 3 | 1 | 12 | 15 | 15.6% | 164.945 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 96 | 3 | 1 | 6 | 15 | 15.6% | 27.507 | 1 | 1 | cross-destination-review | 1 |
| sequential | 96 | 4 | 1 | 5 | 16 | 16.7% | 48.021 | 1 | 1 | cross-call-review | 1 |
| interleaved | 96 | 4 | 1 | 10 | 16 | 16.7% | 98.274 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 96 | 4 | 1 | 5 | 16 | 16.7% | 23.412 | 1 | 1 | cross-destination-review | 1 |
| sequential | 96 | 6 | 1 | 3 | 12 | 12.5% | 23.802 | 1 | 1 | cross-call-review | 1 |
| interleaved | 96 | 6 | 1 | 6 | 12 | 12.5% | 59.438 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 96 | 6 | 1 | 3 | 12 | 12.5% | 22.858 | 1 | 1 | cross-destination-review | 1 |
| sequential | 96 | 8 | 1 | 3 | 16 | 16.7% | 30.285 | 1 | 1 | cross-call-review | 1 |
| interleaved | 96 | 8 | 1 | 6 | 16 | 16.7% | 68.049 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 96 | 8 | 1 | 3 | 16 | 16.7% | 23.638 | 1 | 1 | cross-destination-review | 1 |
| sequential | 96 | 12 | 1 | 2 | 12 | 12.5% | 14.997 | 1 | 1 | cross-call-review | 1 |
| interleaved | 96 | 12 | 1 | 4 | 12 | 12.5% | 44.456 | 1 | 1 | cross-call-review | 1 |
| fanout_guard | 96 | 12 | 1 | 2 | 12 | 12.5% | 16.263 | 1 | 1 | cross-call-review | 1 |

## Metric definition

**Exposure ratio = exact synthetic source bytes observed by the HTTP receiver before containment / source length.**

This is receiver-side ground truth. Benign interleaved bodies are excluded from secret-byte exposure.