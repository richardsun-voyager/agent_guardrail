# Before Tool Call Guard Setup

This workspace contains a two-part defense for OpenClaw tool calls:

1. A Python `before_tool_call` evaluation service that decides whether a proposed tool call should be `allow`ed, `block`ed, or marked `approval_required`.
2. An OpenClaw bridge plugin that hooks `before_tool_call`, sends the proposed tool invocation to the Python service, and enforces the returned decision before the real tool executes.

The flow is:

```text
OpenClaw agent
  -> before_tool_call hook
  -> before-tool-guard plugin
  -> Python evaluation service
  -> allow / block / approval_required
  -> actual tool execution only if allowed
```

## Workspace Layout

Relevant files in this repo:

```text
before-tool-guard-service/
  tool_guard_service.py

before-tool-guard/
  src/index.ts
  dist/index.js
  openclaw.plugin.json
  package.json
```

Use:

- `before-tool-guard-service/tool_guard_service.py` for the Python evaluator.
- `before-tool-guard/src/index.ts` for the OpenClaw bridge hook.

## 1. Create the Before Tool Call Evaluation Service

The service is a small HTTP sidecar. OpenClaw does not call it directly; the plugin does.

### What the service does

The evaluator receives a payload like:

```json
{
  "tool_name": "exec",
  "arguments": { "command": "ls -la" },
  "session_id": "session-123",
  "user_id": "user-456",
  "source": "webchat"
}
```

It returns:

```json
{
  "decision": "allow"
}
```

or:

```json
{
  "decision": "block",
  "reason": "Dangerous shell command pattern: \\brm\\s+-rf\\b"
}
```

or:

```json
{
  "decision": "approval_required",
  "approval_id": "abc123",
  "risk": "medium",
  "reason": "Write-like tool requires approval: write_file"
}
```

### Service behavior in this repo

The implementation in `before-tool-guard-service/tool_guard_service.py` currently:

- blocks obviously dangerous shell commands such as `rm`, `sudo`, `dd`, `docker`, `ssh`, and pipe-to-shell patterns
- blocks shell metacharacters such as `&&`, `||`, `;`, `|`, redirection, and command substitution
- blocks sensitive paths and strings such as `.env`, `.ssh`, `/etc/passwd`, `token`, and `password`
- blocks file paths that resolve outside the configured workspace
- allows low-risk read-only shell commands like `ls`, `pwd`, `cat`, `head`, `tail`, `grep`, `find`, and `wc`
- allows known read-only tools
- requires approval for writes, unknown tools, and high-risk network methods
- writes audit records to JSONL logs

### Run the service

From this workspace:

```bash
cd before-tool-guard-service
python3 tool_guard_service.py
```

By default it listens on:

```text
http://127.0.0.1:8765/evaluate_tool_call
```

Health check:

```bash
curl http://127.0.0.1:8765/health
```

Expected response:

```json
{
  "ok": true,
  "workspace": "/path/to/.openclaw/workspace"
}
```

### Service environment variables

The Python service supports:

```bash
export TOOL_GUARD_HOST=127.0.0.1
export TOOL_GUARD_PORT=8765
export TOOL_GUARD_WORKSPACE="$OPENCLAW_WORKSPACE"
python3 tool_guard_service.py
```

Example:

```bash
export OPENCLAW_WORKSPACE="$HOME/.openclaw/workspace"
export TOOL_GUARD_WORKSPACE="$OPENCLAW_WORKSPACE"
```

### Logs written by the service

When running with the default workspace layout, the service writes:

- `defense/logs/tool_guard_audit.jsonl`
- `defense/logs/tool_guard_pending.jsonl`

`tool_guard_audit.jsonl` stores evaluated tool calls and decisions.  
`tool_guard_pending.jsonl` stores approval requests created when the decision is `approval_required`.

## 2. Test the Evaluation Service Before Wiring It Into OpenClaw

Allow a low-risk shell command:

```bash
curl -s http://127.0.0.1:8765/evaluate_tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "exec",
    "arguments": {"command": "ls -la"},
    "source": "webchat",
    "session_id": "demo-session"
  }'
```

Block a destructive command:

```bash
curl -s http://127.0.0.1:8765/evaluate_tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "exec",
    "arguments": {"command": "rm -rf /"},
    "source": "webchat",
    "session_id": "demo-session"
  }'
```

Trigger approval for a write:

```bash
curl -s http://127.0.0.1:8765/evaluate_tool_call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "write_file",
    "arguments": {"path": "notes/output.md", "content": "hello"},
    "source": "webchat",
    "session_id": "demo-session"
  }'
```

If these three cases behave correctly, the service is ready for the bridge plugin.

## 3. Create the OpenClaw Bridge Plugin

The bridge plugin is the part OpenClaw loads. Its job is to monitor `before_tool_call`, forward the event to the Python service, and enforce the result.

### Plugin responsibilities

The bridge in `before-tool-guard/src/index.ts`:

- registers a `before_tool_call` hook with priority `100`
- extracts `toolName`, `params`, and context values such as `sessionId`, `userId`, and `channel`
- POSTs the event to the Python service
- fails closed if the guard service is unreachable
- returns one of the OpenClaw hook outcomes:
  - pass through for `allow`
  - `block: true` for `block`
  - `requireApproval` for `approval_required`

### Minimal plugin structure

```text
before-tool-guard/
  src/index.ts
  dist/index.js
  openclaw.plugin.json
  package.json
  tsconfig.json
```

### Plugin manifest

This repo already includes `before-tool-guard/openclaw.plugin.json`:

```json
{
  "id": "before-tool-guard",
  "name": "Before Tool Guard",
  "version": "0.1.0",
  "description": "Blocks or escalates risky tool calls by consulting a local Python guard service.",
  "activation": {
    "onStartup": true,
    "onCapabilities": ["hook"]
  }
}
```

### Plugin package metadata

`before-tool-guard/package.json` points OpenClaw at:

- `./src/index.ts` as the development extension entry
- `./dist/index.js` as the runtime extension entry

It also declares the compatibility target:

```json
"compat": {
  "pluginApi": ">=2026.3.24-beta.2",
  "minGatewayVersion": "2026.3.24-beta.2"
}
```

To keep the plugin portable across machines, `package.json` declares:

```json
"peerDependencies": {
  "openclaw": ">=2026.3.24-beta.2"
}
```

That means the repo does not hardcode a machine-local `file:` path for the OpenClaw SDK. Each machine must provide the `openclaw` package locally before building.

### Provide the OpenClaw SDK locally

Pick one of these setup patterns inside `before-tool-guard/`:

```bash
npm install
npm install --no-save openclaw
```

or:

```bash
npm install
npm install --no-save /path/to/openclaw
```

or:

```bash
npm install
npm link openclaw
```

Use the second option when OpenClaw is only available from a local checkout or unpacked package directory on that machine.

### Build the plugin

```bash
cd before-tool-guard
npm run build
```

That compiles `src/index.ts` into `dist/index.js`.

## 4. Register the Plugin With OpenClaw

For development, linked install is the easiest:

```bash
openclaw plugins install --link ./before-tool-guard
```

For a copied install:

```bash
openclaw plugins install ./before-tool-guard
```

If OpenClaw's security scanner flags the plugin because it reads environment variables and makes HTTP requests to the local guard service, install with:

```bash
openclaw plugins install \
  --link \
  --dangerously-force-unsafe-install \
  ./before-tool-guard
```

Then enable it in OpenClaw config:

```json
{
  "plugins": {
    "entries": {
      "before-tool-guard": {
        "enabled": true,
        "config": {}
      }
    }
  }
}
```

Or patch config from the CLI:

```bash
openclaw config patch '{"plugins":{"entries":{"before-tool-guard":{"enabled":true,"config":{}}}}}'
```

Restart the gateway:

```bash
openclaw gateway restart
```

Verify the plugin is loaded:

```bash
openclaw plugins inspect before-tool-guard --runtime --json
```

You want to see the runtime report indicate:

- `status: loaded`
- `activated: true`
- one registered `before_tool_call` hook

## 5. Point the Plugin at the Evaluation Service

The bridge defaults to:

```text
http://127.0.0.1:8765/evaluate_tool_call
```

To override it:

```bash
export TOOL_GUARD_URL=http://127.0.0.1:8765/evaluate_tool_call
```

The plugin reads `TOOL_GUARD_URL` and uses it for each `before_tool_call` evaluation.

## 6. End-to-End Verification

Once both pieces are running:

1. Start the Python service.
2. Confirm `/health` returns `ok: true`.
3. Build and register the plugin.
4. Restart the OpenClaw gateway.
5. Trigger a safe tool call and confirm it proceeds.
6. Trigger a blocked pattern like `rm -rf /` and confirm the plugin stops it before execution.
7. Trigger a write-like tool call and confirm OpenClaw surfaces approval instead of executing immediately.

If everything is wired correctly, the Python service should receive each `before_tool_call` request and append an audit entry for it.

## 7. Troubleshooting

- All tool calls are blocked: the plugin fails closed when the Python service is unreachable. Check that the service is running and that `TOOL_GUARD_URL` is correct.
- The hook does not fire: confirm the plugin is enabled and that the gateway was restarted after install.
- The plugin builds but does not load: verify the OpenClaw version satisfies the compatibility range in `package.json`.
- Approvals are generated but never acted on: the current Python service records pending approvals, but approval fulfillment workflow still needs to be implemented separately in the surrounding OpenClaw UX.
- File access is blocked unexpectedly: check the configured `TOOL_GUARD_WORKSPACE`, because the service blocks paths outside that workspace.

## Reference

If you want the split component docs as well, see:

- `before-tool-guard-service/README_openclaw_before_tool_guard.md`
- `before-tool-guard/README.md`
