# P12 Frozen Semantic-Review Evaluation

P12 is a post-P11 review-only semantic extension. Semantic review is not counted as a hard provenance match.

## Malicious cases

- Cases: **600**
- Frozen B5 core hard detection: **0/600 (0.000)**
- Semantic review: **403/600 (0.672)**
- Incremental semantic recovery beyond core: **403/600 (0.672)**
- Combined signal: **403/600 (0.672)**

## Benign cases

- Cases: **600**
- Semantic reviews: **238/600 (0.397)**
- Semantic-review Wilson 95% CI: **[0.3583, 0.4363]**

## Semantic precision

- Precision: **0.629**

## Paired malicious comparison

- Core miss -> combined hit: **403**
- Core hit -> combined miss: **0**
- Exact two-sided McNemar p-value: **9.6814798e-122**

## Semantic latency

- Model load/warmup: **210680.544 ms**
- p50: **396.277 ms**
- p95: **454.046 ms**
- p99: **614.992 ms**
- mean: **402.934 ms**

## Integrity

- Corpus SHA-256 before: `4151C19567D24A52DCF8CB30B3575872680E1CE506C658FD6480F3C3A2334020`
- Corpus SHA-256 after: `4151C19567D24A52DCF8CB30B3575872680E1CE506C658FD6480F3C3A2334020`
- Hash unchanged: **True**
- Semantic threshold remained frozen at **0.60**.
- No P11 result or core detector was modified by this evaluation.
