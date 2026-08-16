# P10 B5 Failure-Surface Analysis

- Malicious cases: 630
- Detected: 559
- Missed: 71
- Miss rate: 0.113

## Misses by category

| Category | Misses | Total | Miss rate | Share of all misses |
|---|---:|---:|---:|---:|
| destination_rotation | 5 | 70 | 0.071 | 0.070 |
| intra_request_fragmented | 30 | 70 | 0.429 | 0.423 |
| partial_exfiltration | 36 | 70 | 0.514 | 0.507 |

## Available result fields

`blocked`, `calls`, `case_id`, `category`, `config`, `correct_enforcement`, `correct_signal`, `first_block_call`, `first_signal_call`, `label`, `latency_p50_call_ms`, `latency_p95_call_ms`, `latency_p99_call_ms`, `latency_total_ms`, `matched`, `matched_via`, `max_coverage`, `review_required`, `signal`, `transformation`

## Misses by `transformation`

| Value | Count |
|---|---:|
| field-fragmentation | 30 |
| partial-0.10 | 18 |
| partial-0.25 | 18 |
| cross-destination-fragmentation | 5 |
