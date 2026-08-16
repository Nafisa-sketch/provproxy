# ProvProxy Repeated Concurrency Scaling

Requests per run: `1000`
Repeats per worker level: `5`
Worker levels: `1, 8, 16, 32, 64`

| Workers | Failed runs | Total errors | Median p50 ms | Median p95 ms | Median p99 ms | Median req/s | Throughput CV | p99 CV | Max observed p99 ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 0.483 | 2.682 | 4.812 | 1169.7 | 0.631 | 0.482 | 8.023 |
| 8 | 0 | 0 | 4.476 | 5.354 | 6.593 | 1687.7 | 0.493 | 1.124 | 67.158 |
| 16 | 0 | 0 | 8.971 | 10.011 | 11.136 | 1683.5 | 0.023 | 0.047 | 11.796 |
| 32 | 0 | 0 | 0.560 | 19.894 | 24.303 | 1616.8 | 0.014 | 0.153 | 30.087 |
| 64 | 0 | 0 | 0.484 | 0.665 | 0.776 | 1581.9 | 0.020 | 0.031 | 0.781 |

## Notes

- The workload intentionally uses one shared session and one shared destination to maximize state contention.
- Correctness requires zero evaluation errors and at least one containment signal in every run.
- CV is coefficient of variation (standard deviation / mean); larger values indicate noisier measurements.
- Results are development-laptop measurements, not universal deployment throughput.