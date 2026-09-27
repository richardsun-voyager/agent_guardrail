# Codex Agent Guardrail

This Codex plugin sends Bash, `apply_patch`, and MCP `PreToolUse` events to the
existing Python policy service before execution. It intentionally returns no hook
decision for `allow`, preserving Codex's native sandbox and approval checks.
`block` is denied. Because Codex currently does not support forcing `ask` from
`PreToolUse`, `approval_required` is denied with the approval ID and a clear
manual-review message.

## Install

Start the shared service with a workspace matching the Codex project:

```bash
export TOOL_GUARD_WORKSPACE=/absolute/path/to/project
python3 before-tool-guard-service/tool_guard_service.py
```

Add this folder to a local Codex plugin marketplace, install it, then review and
trust its hook with `/hooks`. Codex discovers `hooks/hooks.json` from the plugin.
The adapter uses `http://127.0.0.1:8765/evaluate_tool_call` by default; override
it with `TOOL_GUARD_URL`.

Run its unit tests from the repository root:

```bash
python3 -m unittest codex/test_guard_hook.py -v
```

This hook supplements rather than replaces Codex sandboxing, approvals, and OS
isolation. Hosted tools, non-matching local tools, and specialized tool paths
that do not emit `PreToolUse` are outside this adapter's coverage.
