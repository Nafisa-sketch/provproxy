# Phase 4 — Benchmark Leakage Audit

**Audit date:** Before held-out robustness evaluation (commit `c8ac3b1`, tag `v0.2-frozen-baseline`)

## Method
```
grep -rn "fixture|chunk_size|category|expected_label|expected_min_tier|_SEED|N_VARIANTS|M1-|M2-|M3-|M4-|B1-|B2-|B3-|B4-|B5-|scenario_id|is_malicious" provproxy/
grep -rn "AKIA|attacker.example|frag-|sensitive-" provproxy/ --include="*.py"
```

## Result: **NO LEAKAGE FOUND**

- 4 matches total, all inside **docstrings/comments** explaining design rationale (e.g. `config.py`'s note that the granularity boundary was "empirically measured" against M3/M4 — descriptive text, not a code dependency).
- Zero production files (`provproxy/*.py`) read fixture IDs, categories, expected labels, chunk_size values, or any `benchmarks/fixtures.py` constant.
- `_KV_VALUE_RE = re.compile(r"\w+=(\S+)")` (the evidence-reconstruction regex in `approx.py`) is a general-purpose `key=value` pattern — not tuned to any specific fixture's field-naming scheme (`fixtures.py` uses names like `field`, `chunk`, `part`, `segment`, `frag`, `block` — the regex doesn't reference any of these).
- `relay.py`'s `fragment_id = f"sensitive-{req.id}"` is an internal runtime naming scheme for live MCP sessions, unrelated to `benchmarks/fixtures.py`'s `frag-{fx.id}` naming (which only exists in test/benchmark code).

**Conclusion:** the detector genuinely cannot see fixture identity, category, or expected label. Any detection behavior — on the frozen benchmark or the held-out suite — reflects the actual algorithm, not memorization.
