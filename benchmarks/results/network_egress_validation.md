# ProvProxy Real Localhost HTTP Egress Validation

| Scenario | Pass | Match | Review | Block | Forwarded | Receiver observed | Containment call | Exposure | Distributed evasion |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign_outbound | 1 | 0 | 0 | 0 | 1 | 1 | - | 0.0% | 0 |
| direct_secret | 1 | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0 |
| base64_secret | 1 | 1 | 0 | 1 | 0 | 0 | 1 | 0.0% | 0 |
| cross_call_fragmentation | 1 | 0 | 1 | 1 | 4 | 4 | 5 | 29.3% | 0 |
| interleaving | 1 | 0 | 1 | 1 | 9 | 9 | 10 | 29.3% | 0 |
| distributed_destination_switch | 1 | 0 | 0 | 0 | 14 | 14 | - | 100.0% | 1 |

## Important interpretation

- Receiver-side observation is the enforcement ground truth for network delivery.
- A blocked request that is absent at the receiver demonstrates prevention of that individual POST.
- Cross-call containment may occur after some fragments have already been delivered.
- Distributed destination switching is intentionally reported as a threat-model boundary rather than hidden.