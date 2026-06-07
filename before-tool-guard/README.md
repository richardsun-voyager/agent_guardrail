# Before Tool Guard

An OpenClaw plugin that intercepts every tool call and consults a local Python guard service to **allow**, **block**, or **escalate for approval** before execution proceeds.

## How It Works

1. OpenClaw triggers the `before_tool_call` hook before any tool runs
2. The plugin sends the tool name, arguments, and session context to the Python guard service
3. The guard service returns a decision:
   - **`allow`** — tool call proceeds
   - **`block`** — tool call is rejected with a reason
   - **`approval_required`** — agent run pauses, user must approve via `/approve`
4. If the guard service is unreachable, the plugin **fails closed** (blocks the call)

## Prerequisites

- **OpenClaw** v2026.3.24-beta.2 or newer
- **Python guard service** running at `http://127.0.0.1:8765/evaluate_tool_call`

The guard service must accept POST requests with this JSON body:

```json
{
  "tool_name": "exec",
  "arguments": { "command": "rm -rf /" },
  "session_id": "...",
  "user_id": "...",
  "source": "webchat"
}
```

And return:

```json
{
  "decision": "allow|block|approval_required",
  "reason": "optional explanation",
  "risk": "low|medium|high|critical",
  "approval_id": "optional id for tracking"
}
```

## Installation

### 1. Make the OpenClaw SDK available

This plugin imports `openclaw/plugin-sdk/plugin-entry`, so the `openclaw` package must be available locally before you build.

Use one of these approaches:

**Option A: install from your package registry**

```bash
cd before-tool-guard
npm install
npm install --no-save openclaw
```

**Option B: use a local OpenClaw checkout or local package directory**

```bash
cd before-tool-guard
npm install
npm install --no-save /path/to/openclaw
```

**Option C: if `openclaw` is already installed globally, link it**

```bash
cd before-tool-guard
npm install
npm link openclaw
```

The plugin's `package.json` intentionally does not pin `openclaw` to a machine-specific `file:` path. Instead it declares `openclaw` as a peer dependency:

```json
"peerDependencies": {
  "openclaw": ">=2026.3.24-beta.2"
}
```

That keeps the repo portable while still making the required SDK version explicit.

### 2. Build the plugin

```bash
npm run build
```

### 3. Install into OpenClaw

**Option A: Linked (recommended for development)**

```bash
openclaw plugins install --link ./before-tool-guard
```

Edits to source take effect on the next gateway restart. No copy is made — the gateway loads directly from this folder.

**Option B: Copied install**

```bash
openclaw plugins install ./before-tool-guard
```

This copies the plugin into `~/.openclaw/extensions/`. Source edits require reinstalling.

> **Note:** The security scanner may flag this plugin because it reads environment variables and makes network requests (to the guard service). If blocked, use `--dangerously-force-unsafe-install`:
>
> ```bash
> openclaw plugins install --link --dangerously-force-unsafe-install ./before-tool-guard
> ```

### 4. Enable in config

Add the plugin to your OpenClaw config (`~/.openclaw/openclaw.json`):

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

Or patch it via the gateway tool / CLI:

```bash
openclaw config patch '{"plugins":{"entries":{"before-tool-guard":{"enabled":true,"config":{}}}}}'
```

### 5. Restart the gateway

```bash
openclaw gateway restart
```

### 6. Verify

```bash
openclaw plugins inspect before-tool-guard --runtime --json
```

You should see:
- `"status": "loaded"`
- `"activated": true`
- `"hookCount": 1`
- `"typedHooks": [{ "name": "before_tool_call", "priority": 100 }]`

## Configuration

### Guard service URL

Default: `http://127.0.0.1:8765/evaluate_tool_call`

Override with the `TOOL_GUARD_URL` environment variable:

```bash
export TOOL_GUARD_URL="http://guard-host:9999/evaluate_tool_call"
```

### Hook priority

The hook runs at **priority 100** (higher runs first). Edit `src/index.ts` to change:

```typescript
api.on("before_tool_call", async (event) => { ... }, { priority: 100 });
```

### Hook timeout

Set a per-plugin timeout in config to prevent a slow guard from stalling the agent:

```json
{
  "plugins": {
    "entries": {
      "before-tool-guard": {
        "enabled": true,
        "hooks": {
          "timeoutMs": 30000,
          "timeouts": {
            "before_tool_call": 10000
          }
        }
      }
    }
  }
}
```

### Conversation access

If you want the hook to receive full conversation context (not just tool metadata), enable:

```json
{
  "plugins": {
    "entries": {
      "before-tool-guard": {
        "enabled": true,
        "hooks": {
          "allowConversationAccess": true
        }
      }
    }
  }
}
```

## Adding After-Call Logging

To audit tool results after execution, add an `after_tool_call` observation hook in `src/index.ts`:

```typescript
api.on("after_tool_call", async (event) => {
  // event.toolName, event.params, event.result, event.error, event.durationMs
  // Send to your guard service or log to file
}, { priority: 50 });
```

This hook is observation-only — it cannot modify or block results, but it provides a full audit trail.

## Uninstalling

```bash
openclaw plugins uninstall before-tool-guard
openclaw gateway restart
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Plugin not loaded after install | Gateway not restarted | `openclaw gateway restart` |
| All tool calls blocked | Guard service not running | Start the Python guard service |
| All tool calls blocked, "unreachable" | Wrong URL or firewall | Check `TOOL_GUARD_URL`, verify `curl http://127.0.0.1:8765/evaluate_tool_call` |
| Install blocked by security scan | Env var + fetch pattern flagged | Use `--dangerously-force-unsafe-install` |
| Hook not firing | Plugin not enabled | Check `plugins.entries.before-tool-guard.enabled` is `true` |
| `npm run build` cannot resolve `openclaw/plugin-sdk/...` | OpenClaw SDK package is not installed locally | Run `npm install --no-save openclaw`, `npm install --no-save /path/to/openclaw`, or `npm link openclaw` |

## File Structure

```
before-tool-guard/
├── src/index.ts           # Plugin source (SDK-based)
├── dist/index.js          # Built JS (gateway loads this)
├── openclaw.plugin.json   # Plugin manifest
├── package.json           # npm metadata + OpenClaw extension config
├── tsconfig.json          # TypeScript config
└── README.md              # This file
```
