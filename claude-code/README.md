# Claude Code Agent Guardrail

This adapter maps shell, file, web, and MCP `PreToolUse` events to the shared
Agent Guardrail service. Guard decisions become native hook outcomes:

| Guard service | Claude Code hook |
|---|---|
| `allow` | no hook decision; continue through native permissions |
| `approval_required` | `permissionDecision: "ask"` |
| `block` | `permissionDecision: "deny"` |

## Install

Start the service with the protected project as its workspace:

```bash
export TOOL_GUARD_WORKSPACE=/absolute/path/to/project
python3 before-tool-guard-service/tool_guard_service.py
```

Merge `settings.example.json` into the project's `.claude/settings.json`. If
this adapter is stored elsewhere, replace the command with its absolute path.
The endpoint defaults to `http://127.0.0.1:8765/evaluate_tool_call` and can be
overridden with `TOOL_GUARD_URL`.

Test the adapter with:

```bash
python3 -m unittest claude-code/test_guard_hook.py -v
```

The hook fails closed if input is invalid, the service cannot be reached, or
the response is not a recognized decision. Native Claude Code permissions,
sandboxing, and deny rules remain active.
