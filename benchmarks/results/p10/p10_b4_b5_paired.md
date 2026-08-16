# P10 Paired B4 ? B5 Contribution Analysis

- Paired malicious cases: 630
- B4 detection rate: 0.797
- B5 detection rate: 0.887
- Absolute detection-rate gain: 0.090

| Outcome | Count |
|---|---:|
| Both miss | 71 |
| B4 miss / B5 hit | 57 |
| B4 hit / B5 miss | 0 |
| Both hit | 502 |

- Exact two-sided McNemar/binomial p-value: `1.38777878078e-17`

Interpretation must remain paired: B4 and B5 were evaluated on the same frozen malicious cases.
