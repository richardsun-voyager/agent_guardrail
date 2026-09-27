# Agent Guardrail — Strengths & Weaknesses Review

Reviewed components:

| Component | Role | Enforcement point |
|---|---|---|
| `before-tool-guard-service/tool_guard_service.py` | Python policy sidecar (v1.1) | HTTP `POST /evaluate_tool_call` |
| `before-tool-guard/src/index.ts` | OpenClaw plugin bridge | `before_tool_call` hook |
| `hermes-tool-guard/__init__.py` | Native Hermes plugin | `pre_tool_call` hook |
| `shell_layer_defense/*.py` | Shell wrapper guards (`command_guard.py`, `safe_exec*.py`) | `SHELL` env override / exec wrapper |

All four are **regex/allowlist policy engines** that classify a proposed
action as `allow` / `block` / `approval_required` (three-state model) before
the host agent executes it. None of them sandbox or contain the underlying
tool call — they only decide whether it is allowed to run.

---

## Strengths

1. **Consistent fail-closed posture.** The OpenClaw bridge blocks if the
   Python sidecar is unreachable or returns a non-2xx status; the Hermes
   plugin blocks on any internal exception (`FAIL_CLOSED` default `1`); the
   HTTP service itself returns `block` on a 500. For a guardrail, defaulting
   to deny under uncertainty is the correct choice and it's applied uniformly.

2. **Three-state model instead of binary allow/block.** `approval_required`
   lets ambiguous or medium-risk actions (writes, unknown tools, untrusted
   reads) pause for a human rather than forcing an over-broad allowlist or
   over-broad blocklist. Pending approvals are persisted to JSONL/JSON files
   for later review.

3. **Workspace confinement uses real path resolution, not string prefixing.**
   `resolve_workspace_path()` in `tool_guard_service.py` calls `Path.resolve()`
   (which follows symlinks) and then `relative_to(WORKSPACE)`, so a symlink
   planted inside the workspace that points outside of it is still caught —
   confirmed by `test_workspace_boundary_applies_to_unknown_tools_and_symlinks`.
   This is applied generically to *any* tool schema via `extract_candidate_paths`,
   not just known file tools, so unknown/plugin tools inherit the same boundary.

4. **Destination classification beyond a plain string match.** `classify_destination()`
   parses the URL, rejects non-HTTP(S) schemes, rejects embedded credentials,
   rejects loopback/non-global IPs (via `ipaddress`), and only trusts an exact
   host or its subdomains — not a naive substring match, so
   `evil-example.com` or `example.com.evil.test` are not confused with
   `example.com` (covered by `test_destination_policy`).

5. **Command/subcommand-aware policy.** `git status` vs. `git push` vs.
   `git clean` are differentiated instead of gating on the executable name
   alone, reducing both false blocks and false allows for common dev tools.

6. **Bounded, decaying session risk trajectory.** Repeated medium/high-risk
   actions within a session accumulate a score that eventually forces
   approval or a hard block, which mitigates "boil the frog" attacks where
   each individual step looks acceptable in isolation. The score decays over
   time and sessions are capped/evicted (`SESSION_RISK_MAX_SESSIONS`), which
   avoids unbounded memory growth.

7. **Reasonable test coverage for the core service.** `test_tool_guard_service.py`
   exercises subcommand policy, path/symlink confinement, destination
   classification, and session-risk decay/escalation — this is the most
   mature and best-tested piece of the repo.

8. **Layered defense-in-depth across the shell wrappers.** The
   `shell_layer_defense` scripts progressively harden the model
   (`safe_exec.py` → `safe_exec_enhanced.py` → `safe_exec_three_state.py`),
   with the final version explicitly treating Python execution as a
   controlled operation: `-c` and `-m` are blocked outright, and only
   scripts inside an explicit `APPROVED_PYTHON_SCRIPTS` allowlist may run
   (empty by default — secure by default, opt-in per script).

---

## Weaknesses & Risks

### Cross-cutting

1. **Detection is regex/allowlist based and pattern matching is inherently
   evadable.** Every engine ultimately decides on substring/regex matches
   against the literal command text or serialized arguments
   (`DANGEROUS_COMMAND_PATTERNS`, `BLOCK_PATTERNS`, etc.). None of these can
   reliably catch obfuscated payloads: string concatenation
   (`"r"+"m -rf /"`), base64/hex-encoded payloads decoded at runtime,
   alternate binaries (`/bin/rm`, `busybox rm`, symlinked coreutils),
   environment-variable indirection (`$X /`), or Unicode homoglyphs. This is
   a fundamental limitation of the architecture, not a bug in any one file.

2. **No sandboxing/containment — the guard is purely advisory.** If a call
   is classified `allow`, it runs with the full privileges of the host
   process. There's no seccomp/namespace/chroot boundary backing any of
   these guards, so a single policy gap is a full bypass.

3. **Guard integrity assumes a trusted host boundary.** The OpenClaw bridge
   reads `TOOL_GUARD_URL` from `process.env` on every call; anything able to
   set environment variables for that process (a malicious/compromised
   plugin, misconfigured launcher) can silently repoint the guard to an
   always-allow stub. Likewise the Python sidecar binds only to
   `TOOL_GUARD_HOST=127.0.0.1` by default but has **no authentication token**
   — any local process (or remote one, if the host is mis-set to `0.0.0.0`)
   can call `/evaluate_tool_call` directly, or simply query it for
   reconnaissance on policy.

4. **Session risk trajectory is trivially resettable by the caller.**
   `session_id` is client-supplied and unauthenticated. Since risk state is
   keyed purely by that string, a caller (or a compromised tool wrapper)
   that rotates or omits `session_id` on each risky call resets the score to
   zero (`apply_session_risk` returns the decision unchanged when
   `session_id` is falsy), defeating the "boil the frog" protection that is
   advertised as a v1.1 improvement.

5. **In-memory-only state.** `SESSION_RISK` in the Python service and the
   equivalent constructs elsewhere are process-local dictionaries with no
   persistence — a service restart (e.g. via `systemctl restart`, or a crash
   recovered by `Restart=on-failure` in the provided systemd unit) silently
   wipes accumulated trajectory risk.

6. **Single-threaded HTTP server.** `tool_guard_service.py` uses
   `http.server.HTTPServer` (not `ThreadingHTTPServer`/`socketserver.ForkingMixIn`),
   so concurrent tool calls from a busy agent session are serialized; this
   is a latency/availability concern for real deployments, though not a
   security bug per se.

7. **Hardcoded, single-user paths in `shell_layer_defense`.** `safe_exec.py`,
   `safe_exec_enhanced.py`, and `safe_exec_three_state.py` all hardcode
   `Path("/home/richardsun/.openclaw/workspace/")` rather than deriving the
   workspace from an environment variable (unlike
   `before-tool-guard-service`, which correctly uses
   `TOOL_GUARD_WORKSPACE`). This is a portability defect: on any other
   machine/user the guard will either crash (path doesn't exist) or, worse,
   silently misresolve workspace confinement checks.

### Component-specific

8. **`shell_layer_defense/command_guard.py` has an outright policy bypass.**
   `evaluate()` checks `BLOCK_PATTERNS` / `SENSITIVE_READ_PATTERNS` /
   `APPROVAL_PATTERNS` against the whole command string, but falls back to
   `is_allowed_prefix()`, and `ALLOWED_PREFIXES` includes bare `"python"`,
   `"python3"`, and `"pytest"` with **no restriction on their arguments**.
   A command such as `python3 -c "import os,base64;
   os.system(base64.b64decode('...'))"` will not match any block/approval
   regex and will match the `python3` allowed-prefix, so it is **allowed to
   run unrestricted arbitrary code** — a complete guard bypass. Note this is
   fixed correctly in the more mature `safe_exec_three_state.py`, which
   treats Python as a controlled command and hard-blocks `-c`/`-m`, so the
   flaw appears to be isolated to the earlier prototype that the repo's own
   README labels "regex-first prototype."

9. **Metacharacter blocking can produce false blocks/positives, and misses
   some vectors.** `tool_guard_service.evaluate_shell_tool` rejects if any of
   `&& || ; | \` $( > >> <` appear anywhere in the raw string — including
   inside quoted arguments (e.g. `grep 'a;b' notes.txt` is blocked even
   though it's benign) — while newline (`\n`) and `\r` are not in that
   denylist and are not rejected before `shlex.split`, though since these
   guards never invoke a real shell (`subprocess` is called with
   `shell=False`/argv lists, or the decision is advisory only) this is lower
   severity but still worth closing for defense-in-depth.

10. **Substring-based sensitive-path/content detection is coarse.**
    `SENSITIVE_PATH_PATTERNS` / `SENSITIVE_PATH_FRAGMENTS` match on plain
    substrings like `"secret"`, `"token"`, `"account"` — this both
    over-blocks legitimate paths (`secretary_notes.md`, `token_bucket.py`)
    and under-blocks anything renamed to avoid the fragment. Content
    scanning in `scan_file_content()` also only reads the first
    `MAX_SCAN_BYTES` (32 KB default) of a file, so secrets placed after that
    offset in a larger file are not detected.

11. **Hermes plugin has no real approval flow.** `pre_tool_call` in Hermes
    has no native third state, so `approval` decisions are converted to a
    `block` with a message pointing at a JSON file under
    `~/.hermes/tool_guard/pending/`. There is no mechanism shown for a human
    to actually resume/approve the call — it's a dead end unless the
    operator has separate tooling to replay the action, unlike the
    `before-tool-guard-service`/`safe_exec_three_state.py` designs which at
    least provide an `--approve/--reject` CLI path.

12. **`HERMES_TOOL_GUARD_ALLOW_APPROVAL` env toggle silently downgrades
    approval-required to allow.** If left set to `1`/`true` in a production
    environment (e.g. copied from a debugging session), every
    "approval"-classified action executes without any pause or operator
    awareness beyond an audit-log line — an easy footgun since the docstring
    even calls it "not recommended for defense experiments" but does not
    warn at runtime (e.g., no startup log line announcing degraded mode).

13. **No authentication/authorization on the OpenClaw plugin install itself.**
    The README documents bypassing OpenClaw's plugin security scanner via
    `--dangerously-force-unsafe-install` as a standard step whenever the
    scanner flags the plugin for reading env vars and making local HTTP
    calls — normalizing use of a "dangerous" override flag in routine setup
    instructions is a process weakness (it trains operators to reach for the
    override rather than investigate the warning).

14. **Limited automated test coverage outside the core Python service.**
    Only `before-tool-guard-service` has a unit-test file
    (`test_tool_guard_service.py`); the OpenClaw TS bridge, the Hermes
    plugin, and all of `shell_layer_defense` have no automated tests, so
    regressions in their (more permissive) policy tables would not be
    caught by CI.

---

## Summary

The `before-tool-guard-service` Python policy engine is the strongest piece
of this repository: it uses proper path resolution (not string prefixing),
structured URL/host classification, subcommand-aware policy, and a tested,
bounded session-risk mechanism. The weakest piece is the shell-layer
prototype (`command_guard.py`), which contains a straightforward bypass via
unrestricted `python`/`python3` in its allowlist. Across all four
components, the underlying model is a **regex/allowlist advisory layer with
no execution sandboxing**, so its ceiling is bounded by what static
pattern-matching can catch — sufficiently motivated obfuscation, encoding,
or use of an unlisted binary will get past any of these guards. It is best
understood as a speed bump against unsophisticated/careless agent actions
and prompt-injection-driven mistakes, not a hard security boundary against
an adversarial agent or attacker-controlled tool arguments.
