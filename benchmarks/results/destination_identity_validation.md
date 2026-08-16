# P7 Destination Identity Evasion Baseline

This is a frozen **pre-mitigation** baseline. Failures are evidence, not test noise.

## Summary

- Same-endpoint canonicalization passes: **2/6**
- Intentionally-distinct canonicalization passes: **1/2**
- Same-endpoint strict-V4 representation evasions: **4/6**
- Same-endpoint cases contained by optional fan-out guard: **6/6**
- Threat-model boundary cases: **3**

## Case table

| Case | Category | Key A | Key B | Equal | Expected | Canon | Strict V4 | Fan-out | Representation evasion |
|---|---|---|---|---:|---|---|---|---|---:|
| D1 | host_case | `Example.COM` | `example.com` | False | same | FAIL | MISS | REVIEW | True |
| D2 | trailing_dot | `example.com` | `example.com.` | False | same | FAIL | MISS | REVIEW | True |
| D3 | default_https_port | `example.com` | `example.com:443` | False | same | FAIL | MISS | REVIEW | True |
| D4 | default_http_port | `example.com` | `example.com:80` | False | same | FAIL | MISS | REVIEW | True |
| D5 | path_variation | `example.com` | `example.com` | True | same | PASS | MATCH | MATCH | False |
| D6 | query_fragment_variation | `example.com` | `example.com` | True | same | PASS | MATCH | MATCH | False |
| D7 | scheme_change | `example.com:8080` | `example.com:8080` | True | different | FAIL | MATCH | MATCH | False |
| D8 | port_change | `example.com:443` | `example.com:8443` | False | different | PASS | MISS | REVIEW | False |
| D9 | localhost_ip_alias | `localhost:8765` | `127.0.0.1:8765` | False | boundary | N/A | MISS | REVIEW | False |
| D10 | ipv6_textual_alias | `[::1]:8765` | `[0:0:0:0:0:0:0:1]:8765` | False | boundary | N/A | MISS | REVIEW | False |
| D11 | hostname_alias | `api.example.test` | `alias.example.test` | False | boundary | N/A | MISS | REVIEW | False |

## Interpretation rules

- `expected_relation=same`: identity should normally canonicalize to one destination key.
- `expected_relation=different`: identity should remain separate under the stated scheme+host+port model.
- `expected_relation=boundary`: DNS/IP alias equivalence requires resolution-aware policy or network-adapter observability; the baseline records behavior without declaring it automatically wrong.
- A strict-V4 representation evasion means semantically equivalent endpoint spelling split accumulation state enough to avoid a hard/review signal.
- Fan-out results are reported separately because fan-out is intentionally review-only and does not redefine strict destination identity.

## Frozen P7 baseline principle

Do not modify these cases after seeing results. If mitigation is added, rerun this same suite as the before/after comparison and create a separate held-out P7 set for final validation.
