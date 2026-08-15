# P7 Destination Identity Evasion Baseline

This is a frozen **pre-mitigation** baseline. Failures are evidence, not test noise.

## Summary

- Same-endpoint canonicalization passes: **6/6**
- Intentionally-distinct canonicalization passes: **2/2**
- Same-endpoint strict-V4 representation evasions: **0/6**
- Same-endpoint cases contained by optional fan-out guard: **6/6**
- Threat-model boundary cases: **3**

## Case table

| Case | Category | Key A | Key B | Equal | Expected | Canon | Strict V4 | Fan-out | Representation evasion |
|---|---|---|---|---:|---|---|---|---|---:|
| D1 | host_case | `http_request|https|example.com|443` | `http_request|https|example.com|443` | True | same | PASS | MATCH | MATCH | False |
| D2 | trailing_dot | `http_request|https|example.com|443` | `http_request|https|example.com|443` | True | same | PASS | MATCH | MATCH | False |
| D3 | default_https_port | `http_request|https|example.com|443` | `http_request|https|example.com|443` | True | same | PASS | MATCH | MATCH | False |
| D4 | default_http_port | `http_request|http|example.com|80` | `http_request|http|example.com|80` | True | same | PASS | MATCH | MATCH | False |
| D5 | path_variation | `http_request|https|example.com|443` | `http_request|https|example.com|443` | True | same | PASS | MATCH | MATCH | False |
| D6 | query_fragment_variation | `http_request|https|example.com|443` | `http_request|https|example.com|443` | True | same | PASS | MATCH | MATCH | False |
| D7 | scheme_change | `http_request|http|example.com|8080` | `http_request|https|example.com|8080` | False | different | PASS | MISS | REVIEW | False |
| D8 | port_change | `http_request|https|example.com|443` | `http_request|https|example.com|8443` | False | different | PASS | MISS | REVIEW | False |
| D9 | localhost_ip_alias | `http_request|http|localhost|8765` | `http_request|http|127.0.0.1|8765` | False | boundary | N/A | MISS | REVIEW | False |
| D10 | ipv6_textual_alias | `http_request|http|::1|8765` | `http_request|http|::1|8765` | True | boundary | N/A | MATCH | MATCH | False |
| D11 | hostname_alias | `http_request|https|api.example.test|443` | `http_request|https|alias.example.test|443` | False | boundary | N/A | MISS | REVIEW | False |

## Interpretation rules

- `expected_relation=same`: identity should normally canonicalize to one destination key.
- `expected_relation=different`: identity should remain separate under the stated scheme+host+port model.
- `expected_relation=boundary`: DNS/IP alias equivalence requires resolution-aware policy or network-adapter observability; the baseline records behavior without declaring it automatically wrong.
- A strict-V4 representation evasion means semantically equivalent endpoint spelling split accumulation state enough to avoid a hard/review signal.
- Fan-out results are reported separately because fan-out is intentionally review-only and does not redefine strict destination identity.

## Frozen P7 baseline principle

Do not modify these cases after seeing results. If mitigation is added, rerun this same suite as the before/after comparison and create a separate held-out P7 set for final validation.
