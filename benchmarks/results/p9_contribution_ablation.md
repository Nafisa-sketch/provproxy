# P9 Contribution-Isolating Ablation

> **Scope:** controlled ProvProxy functional variants; not external products.

| Config | Capability | DR | Enforcement FPR | p50 ms | p95 ms | p99 ms | Peak KB | Distributed-destination exposure |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| B0 / V0 | Stateless policy baseline | 0.000 | 0.000 | 0.003 | 0.005 | 0.007 | 80.847 | N/M |
| B1 / V1 | Exact provenance | 0.250 | 0.000 | 0.017 | 0.027 | 0.308 | 80.911 | N/M |
| B2 / V2 | Exact + transformation-aware | 0.500 | 0.000 | 0.082 | 0.224 | 0.352 | 80.870 | N/M |
| B3 / V3 | Exact + transform + approximate | 0.750 | 0.000 | 0.129 | 0.297 | 0.377 | 82.345 | N/M |
| B4 / V4 | Exact + transform + approximate + cross-call | 1.000 | 0.000 | 0.238 | 0.439 | 0.569 | 86.916 | 100.0% |
| B5 / V4+fanout | V4 + cross-destination REVIEW | 1.000 | 0.000 | N/M | N/M | N/M | N/M | 29.3% |

## Interpretation

- V0-V4 isolate the marginal security gain of stateful provenance capabilities.
- B5 evaluates a separate review-only fan-out control for distributed-destination rotation.
- `N/M` means **not measured**; the table deliberately avoids carrying metrics across experiments where they were not measured.
- This table must not be described as an external-tool comparison.

## Next P9 step

Run independently implemented/reproducible external baselines on the same frozen attack corpus where their interfaces permit a fair comparison.
