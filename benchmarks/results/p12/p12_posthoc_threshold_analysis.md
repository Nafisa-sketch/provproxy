# P12 Post-Hoc Threshold Characterization

**Status:** descriptive analysis only; no threshold retuning.

The preregistered P12 primary threshold remains **0.60**.

## Frozen primary operating point

- Detection: 403/600 (0.672)
- Benign review FPR: 238/600 (0.397)
- Precision: 0.629

## Descriptive post-hoc optima

- Best balanced-accuracy threshold: 0.49
- Detection at that point: 0.850
- FPR at that point: 0.518
- Precision at that point: 0.621

- Best F1 threshold: 0.49
- Detection at that point: 0.850
- FPR at that point: 0.518

## Detection achievable under benign-review budgets

| Maximum FPR | Threshold | Detection | Precision |
|---:|---:|---:|---:|
| 0.00 | 0.76 | 0.000 | 1.000 |
| 0.01 | 0.76 | 0.000 | 1.000 |
| 0.05 | 0.72 | 0.007 | 0.129 |
| 0.10 | 0.71 | 0.018 | 0.200 |
| 0.20 | 0.68 | 0.115 | 0.373 |

## Interpretation rule

These results characterize the frozen scorer after the experiment. They do not replace the preregistered threshold of 0.60 and must not be presented as retuned P12 headline results.
