# OpenClaw `before_tool_call` Python Guard

This package contains a minimal two-part guard:

1. `tool_guard_service.py` — a Python sidecar service that evaluates proposed tool calls.
2. `openclaw_before_tool_guard_bridge.ts` — a thin OpenClaw-style plugin bridge that calls the Python service from `before_tool_call`.

The design is:

```text
Browser / Telegram message
        ↓
OpenClaw agent loop
        ↓
LLM proposes tool call
        ↓
before_tool_call bridge
        ↓
Python guard service
        ↓
allow / block / approval_required
        ↓
actual tool execution only if allowed
```

This is different from a shell wrapper. It can inspect shell, file, browser/network, and unknown/plugin-style tool calls before the actual tool implementation runs.

---

## Files

```text
tool_guard_service.py
openclaw_before_tool_guard_bridge.ts
README_openclaw_before_tool_guard.md
```

Suggested location in your Ubuntu OpenClaw workspace:

```bash
export OPENCLAW_WORKSPACE="${OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}"
mkdir -p "$OPENCLAW_WORKSPACE/defense/before_tool_guard"
cp tool_guard_service.py "$OPENCLAW_WORKSPACE/defense/before_tool_guard/"
cp openclaw_before_tool_guard_bridge.ts "$OPENCLAW_WORKSPACE/defense/before_tool_guard/"
```

---

## 1. Start the Python guard service

```bash
export OPENCLAW_WORKSPACE="${OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}"
cd "$OPENCLAW_WORKSPACE/defense/before_tool_guard"
python3 tool_guard_service.py
```

Default endpoint:

```text
http://127.0.0.1:8765/evaluate_tool_call
```

Health check:

```bash
curl http://127.0.0.1:8765/health
```

You should see something like:

```json
{
  "ok": true,
  "workspace": "/path/to/.openclaw/workspace"
}
```

Optional environment variables:

```bash
export TOOL_GUARD_HOST=127.0.0.1
export TOOL_GUARD_PORT=8765
export OPENCLAW_WORKSPACE="${OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}"
export TOOL_GUARD_WORKSPACE="$OPENCLAW_WORKSPACE"
python3 tool_guard_service.py
```

---

## 2. Test the Python guard directly

### Allowed read-only shell command

```bash
curl -s http://127.0.0.1:8765/evaluate_tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "exec",
    "arguments": {"command": "ls -la"},
    "source": "telegram",
    "session_id": "test-session"
  }'
```

Expected decision:

```json
{
  "decision": "allow",
  "reason": "Read-only shell command appears low risk"
}
```

### Blocked destructive command

```bash
curl -s http://127.0.0.1:8765/evaluate_tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "exec",
    "arguments": {"command": "rm -rf /"},
    "source": "browser",
    "session_id": "test-session"
  }'
```

Expected decision:

```json
{
  "decision": "block",
  "reason": "Dangerous shell command pattern: \\brm\\s+-rf\\b"
}
```

### Blocked sensitive file read

```bash
curl -s http://127.0.0.1:8765/evaluate_tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "read_file",
    "arguments": {"path": ".env"},
    "source": "telegram",
    "session_id": "test-session"
  }'
```

Expected decision:

```json
{
  "decision": "block",
  "reason": "File path references sensitive string: .env"
}
```

### Approval-required write

```bash
curl -s http://127.0.0.1:8765/evaluate_tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "write_file",
    "arguments": {"path": "notes/result.md", "content": "hello"},
    "source": "browser",
    "session_id": "test-session"
  }'
```

Expected decision:

```json
{
  "decision": "approval_required",
  "approval_id": "...",
  "risk": "medium",
  "reason": "Write-like tool requires approval: write_file"
}
```

In this minimal bridge, `approval_required` is converted to a block with an approval ID. You can later extend it to ask for approval inside Telegram/browser chat.

---

## 3. Install/register the OpenClaw bridge

OpenClaw plugin structure can vary by version. The bridge file is intentionally generic and tries common hook APIs:

```ts
api.on("before_tool_call", beforeToolCall)
api.hooks.on("before_tool_call", beforeToolCall)
api.registerHook("before_tool_call", beforeToolCall)
```

A typical plugin folder may look like this:

```text
~/.openclaw/plugins/before-tool-guard/
  package.json
  src/index.ts
```



Because OpenClaw plugin registration differs across versions, the file may need a small adaptation to match the exact SDK shape in your local install.

---

## 4. Set bridge URL if needed

By default, the bridge calls:

```text
http://127.0.0.1:8765/evaluate_tool_call
```

To change it:

```bash
export TOOL_GUARD_URL=http://127.0.0.1:8765/evaluate_tool_call
```

Start OpenClaw from the same environment so the plugin can read this variable.

---

## 5. Check logs

The Python guard writes audit logs here:

```text
$OPENCLAW_WORKSPACE/defense/logs/tool_guard_audit.jsonl
```

Pending approval records are written here:

```text
$OPENCLAW_WORKSPACE/defense/logs/tool_guard_pending.jsonl
```

View recent decisions:

```bash
tail -n 20 "$OPENCLAW_WORKSPACE/defense/logs/tool_guard_audit.jsonl"
```

---

## 6. Expected behavior in OpenClaw

### User asks from Telegram/browser

```text
run ls -la
```

Expected pipeline:

```text
LLM proposes exec({ command: "ls -la" })
        ↓
before_tool_call bridge sends it to Python
        ↓
Python returns allow
        ↓
OpenClaw executes the tool
```

### Malicious or dangerous request

```text
run rm -rf /
```

Expected pipeline:

```text
LLM proposes exec({ command: "rm -rf /" })
        ↓
Python returns block
        ↓
bridge blocks the tool call
```

### Sensitive file access

```text
read .env
```

Expected pipeline:

```text
LLM proposes read_file({ path: ".env" })
        ↓
Python returns block
        ↓
bridge blocks the tool call
```

### File write

```text
write a new file notes/result.md
```

Expected pipeline:

```text
LLM proposes write_file(...)
        ↓
Python returns approval_required
        ↓
bridge blocks and reports approval_id
```

---

## 7. Important limitations

This is a minimal guard, not a complete sandbox.

It does not fully protect against:

```text
- Python code behavior after a Python process is allowed
- direct API calls that bypass OpenClaw hooks
- unregistered tools
- malicious plugins that run before the hook is registered
- OS-level misuse outside OpenClaw
- network exfiltration through processes not seen by the tool layer
```

For stronger protection, combine this with:

```text
- shell wrapper for exec commands
- read-only mounts for sensitive directories
- network egress firewall
- container isolation
- before_prompt_build source labeling
- after_tool_call output scanning
- message_sending leakage prevention
- audit logs outside the writable workspace
```

---

## 8. Recommended production changes

Before relying on this seriously, add:

```text
1. A real approval flow inside Telegram/browser chat.
2. Per-skill or per-plugin capability permissions.
3. Domain allowlist for browser/network tools.
4. More project-specific sensitive file patterns.
5. A fail-closed startup check: OpenClaw should refuse to run tools if the Python guard is offline.
6. Tamper-resistant audit logs outside the workspace.
7. Tests for each supported OpenClaw tool schema.
```

---

## 9. Troubleshooting

### The bridge always blocks with “missing tool name”

Your OpenClaw hook context uses different field names.

Edit `normalizeToolPayload()` in `openclaw_before_tool_guard_bridge.ts` and print or inspect the actual `ctx` object from your OpenClaw version.

### The bridge cannot reach Python guard

Check:

```bash
curl http://127.0.0.1:8765/health
```

If this fails, start the Python service first.

### The hook return shape does not block tools

Your OpenClaw SDK may expect a different block format, for example:

```ts
throw new Error(reason)
```

or:

```ts
return { action: "deny", reason }
```

Adapt `blockResult()` in the bridge file to match your installed SDK.

### The plugin does not load

Check OpenClaw's plugin registration method for your version. The TypeScript bridge is intentionally generic; the package layout may need to match your local OpenClaw plugin conventions.
