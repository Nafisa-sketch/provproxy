# ProvProxy Concurrency Scaling Benchmark

Requests per worker level: `1000`
Worker levels: `1, 8, 16, 32, 64`

| Workers | Pass | Errors | Match | Review | Block | p50 ms | p95 ms | p99 ms | Max ms | Throughput req/s |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 1 | 1 | 2 | 0.421 | 0.661 | 1.865 | 18.474 | 1745.5 |
| 8 | 1 | 0 | 1 | 1 | 2 | 5.225 | 16.952 | 37.132 | 47.267 | 1076.5 |
| 16 | 1 | 0 | 1 | 1 | 2 | 58.390 | 78.637 | 128.556 | 290.851 | 264.0 |
| 32 | 1 | 0 | 1 | 1 | 2 | 4.479 | 161.672 | 186.252 | 194.189 | 256.1 |
| 64 | 1 | 0 | 1 | 1 | 2 | 235.586 | 309.882 | 333.679 | 338.468 | 247.1 |

## Interpretation notes

- This benchmark measures one heavily contended shared session/destination.
- Higher latency at high worker counts is expected because updates to shared provenance state must serialize safely.
- Throughput measured on one development laptop must not be generalized to enterprise hardware.
- A run passes only when there are zero evaluation errors and at least one containment signal is observed.