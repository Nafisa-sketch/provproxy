# ProvProxy Real MCP External Validation

External server: `@modelcontextprotocol/server-filesystem`
Protocol version: `2025-06-18`
Sandbox: `C:\Users\Nafeesa\Desktop\provproxy_mcp_sandbox`
Synthetic source SHA-256 prefix: `f625400c`

| Case | Expected | Pass | Matched | Review | Blocked | Forwarded | Side effect | Via | Trigger call | Latency ms |
|---|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| benign_control | allow+side_effect | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 12.538 |
| direct_secret | block+no_side_effect | 1 | 1 | 0 | 1 | 0 | 0 | exact | 1 | 0.213 |
| base64_secret | block+no_side_effect | 1 | 1 | 0 | 1 | 0 | 0 | exact-decoded | 1 | 0.490 |
| intra_request_fragmentation | block+no_side_effect | 1 | 1 | 0 | 1 | 0 | 0 | approximate | 1 | 0.689 |
| cross_call_fragmentation | early_hold_or_block | 1 | 0 | 1 | 1 | 1 | 1 | cross-call-review | 4 | 28.887 |
| destination_isolation | no_cross_destination_merge | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 110.445 |
| session_isolation | no_cross_session_merge | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 89.047 |
| hard_negative | allow+side_effect | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 5.854 |

**Passed: 8/8 cases.**
