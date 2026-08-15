# ProvProxy Real MCP External Validation

External server: `@modelcontextprotocol/server-filesystem`
Protocol version: `2025-06-18`
Sandbox: `C:\Users\Nafeesa\Desktop\provproxy_mcp_sandbox`
Synthetic source SHA-256 prefix: `f625400c`

| Case | Expected | Pass | Matched | Review | Blocked | Forwarded | Side effect | Via | Trigger call | Latency ms |
|---|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| benign_control | allow+side_effect | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 15.156 |
| direct_secret | block+no_side_effect | 1 | 1 | 0 | 1 | 0 | 0 | exact | 1 | 0.882 |
| base64_secret | block+no_side_effect | 1 | 1 | 0 | 1 | 0 | 0 | exact-decoded | 1 | 0.518 |
| intra_request_fragmentation | block+no_side_effect | 1 | 1 | 0 | 1 | 0 | 0 | approximate | 1 | 1.934 |
| cross_call_fragmentation | early_hold_or_block | 1 | 0 | 1 | 1 | 1 | 1 | cross-call-review | 4 | 30.936 |
| destination_isolation | no_cross_destination_merge | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 107.957 |
| session_isolation | no_cross_session_merge | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 105.375 |
| hard_negative | allow+side_effect | 1 | 0 | 0 | 0 | 1 | 1 | - | - | 6.199 |

**Passed: 8/8 cases.**
