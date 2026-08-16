# P11 Generator-Independent Frozen Evaluation

- Corpus SHA-256: `2BB245B0CEDA6462253B3D25E7E76B6676FB91A6A4BA4B965EA3C8B35E8B63E4`
- Frozen before detector execution: yes
- Network execution: disabled
- Detector tuning on P11: none
- Semantic augmentation: excluded from core B0-B5

| Config | Hard DR | Signal DR | Containment | Signal FPR | Enforcement FPR | Precision | F1 | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.006 |
| B1 | 0.761 | 0.761 | 0.096 | 0.000 | 0.000 | 1.000 | 0.864 | 0.037 |
| B2 | 0.829 | 0.829 | 0.102 | 0.000 | 0.000 | 1.000 | 0.906 | 0.236 |
| B3 | 0.838 | 0.838 | 0.102 | 0.000 | 0.000 | 1.000 | 0.912 | 0.260 |
| B4 | 0.838 | 0.838 | 0.102 | 0.000 | 0.000 | 1.000 | 0.912 | 0.271 |
| B5 | 0.838 | 0.838 | 0.102 | 0.000 | 0.000 | 1.000 | 0.912 | 0.259 |
