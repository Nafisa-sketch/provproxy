# ProvProxy Fan-Out Validation

| Mode | Pass | Forwarded | Receiver observed | Containment call | Review | Match | Via | Exposure |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| strict_destination_only | 1 | 14 | 14 | - | 0 | 0 | - | 100.0% |
| fanout_guard | 1 | 4 | 4 | 5 | 1 | 0 | cross-destination-review | 29.3% |

Baseline intentionally demonstrates the strict-destination isolation limitation; the optional fan-out guard mitigates it with REVIEW/HOLD rather than a hard provenance match.
