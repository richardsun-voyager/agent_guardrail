# Agent Guardrail Integration Analysis

## Overview

The `agent_guardrail` pattern can be extended to **Codex, Claude Code, and OpenCode** by intercepting structured tool calls before execution, normalizing them into a common action schema, and passing them through a policy engine that returns:

- `ALLOW`
- `ASK` / `APPROVAL_REQUIRED`
- `DENY` / `BLOCK`

The important design principle is to inspect the **structured tool invocation**, not scrape shell commands or textual model output.

Reference project:

https://github.com/richardsun-voyager/agent_guardrail

---

## Runtime Comparison

| Runtime | Pre-tool hook | Tool name available | Tool arguments available | Can block before execution? | Guardrail fit |
|---|---|---:|---:|---:|---|
| Claude Code | `PreToolUse` | Yes | Yes (`tool_input`) | Yes | Excellent |
| OpenCode | `tool.execute.before` | Yes | Yes (`event.input`) | Yes | Excellent |
| Codex | `PreToolUse` for supported local tools | Yes | Yes (`tool_input`) | Yes; can deny, but cannot currently force `ask` | Good |

---

# 1. Claude Code

Claude Code exposes a native **`PreToolUse`** hook. This is the natural interception point for a security or policy layer because it executes before the proposed tool action runs.

A tool event is conceptually similar to:

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf ./build"
  },
  "session_id": "...",
  "cwd": "/repo"
}
```

A guardrail adapter can normalize that event:

```python
def claude_code_guard(event):
    action = {
        "source": "claude-code",
        "tool": event["tool_name"],
        "arguments": event["tool_input"],
        "cwd": event.get("cwd"),
    }

    verdict = guardrail.evaluate(action)

    if verdict == "deny":
        return deny()

    if verdict == "ask":
        return require_approval()

    return allow()
```

Typical Claude Code tools that can be inspected include:

- `Bash`
- `Read`
- `Write`
- `Edit`
- `WebFetch`
- MCP tools
- Other built-in or connected tools

### Flow

```text
Claude
   |
   | proposes tool call
   v
PreToolUse
   |
   +-- tool_name
   +-- tool_input
   +-- cwd
   +-- session metadata
   |
   v
agent_guardrail
   |
   +-- ALLOW
   +-- ASK
   +-- DENY
   |
   v
Claude Code permission system
   |
   v
Execution
```

Claude Code also exposes SDK-level permission handling such as `canUseTool`, but for a portable agent firewall design, `PreToolUse` is the cleaner abstraction because it directly represents the pre-execution tool boundary.

References:

- https://code.claude.com/docs/
- https://code.claude.com/docs/en/hooks

---

# 2. OpenCode

OpenCode exposes a highly suitable pre-execution hook:

```typescript
tool.execute.before
```

The hook provides the structured tool name and input.

Conceptually:

```typescript
await ctx.tool.hook("execute.before", async (event) => {
  const decision = await guardrail.evaluate({
    source: "opencode",
    tool: event.tool,
    arguments: event.input,
  })

  if (decision.effect === "deny") {
    throw new Error(decision.reason)
  }
})
```

This is preferable to parsing terminal output because `event.tool` and `event.input` already represent the proposed action structurally.

OpenCode documentation also demonstrates security-style interception, for example preventing reads of sensitive files:

```typescript
await ctx.tool.hook("execute.before", (event) => {
  const input = event.input as { filePath?: string }

  if (
    event.tool === "read" &&
    input.filePath?.includes(".env")
  ) {
    throw new Error("Do not read .env files")
  }
})
```

## OpenCode Permission Layer

OpenCode also exposes a permission evaluation layer that maps especially well to a three-state policy engine:

```typescript
await ctx.permission.hook("evaluate", async (event) => {
    event.action
    event.resources
    event.metadata

    event.effect = "allow" | "ask" | "deny"
})
```

This gives two useful interception layers.

### Raw tool interception

```text
tool.execute.before
        |
        +-- event.tool
        +-- event.input
        |
        v
agent_guardrail
        |
        +-- allow
        +-- block
```

### Permission-policy interception

```text
Tool call
   |
   v
OpenCode permission system
   |
   v
permission.evaluate
   |
   +-- action
   +-- resources
   +-- metadata
   |
   v
agent_guardrail
   |
   +-- allow
   +-- ask
   +-- deny
```

For a general-purpose guardrail, using the tool hook for action inspection and the permission hook for approval semantics is a strong design.

References:

- https://opencode.ai/docs/
- https://opencode.ai/docs/plugins/

---

# 3. Codex

Codex now exposes a `PreToolUse` lifecycle hook for supported local tools. It
provides the canonical tool name and structured `tool_input` before execution.

The recommended conceptual flow is:

```text
Codex
   |
   | proposes structured action
   v
Tool / lifecycle interception
   |
   +-- tool name
   +-- arguments
   +-- cwd / repository
   +-- contextual metadata
   |
   v
agent_guardrail
   |
   +-- ALLOW
   +-- APPROVAL_REQUIRED
   +-- BLOCK
   |
   v
Sandbox / approval / execution layer
```

The current native hook can allow or deny a tool call, but `ask` is parsed and
not supported by `PreToolUse`. A fail-closed adapter should therefore map the
guard's `approval_required` result to a denial with an approval ID and manual
review instructions. A custom harness can instead implement a true approval UI.

Example:

```python
tool_call = extract_tool_call(response)

verdict = guardrail.evaluate(
    tool=tool_call.name,
    arguments=tool_call.arguments,
    user_request=current_user_request,
)

match verdict:
    case "allow":
        result = execute(tool_call)

    case "approval_required":
        return deny_with_manual_approval_instructions(tool_call)

    case "block":
        return reject_tool_call(tool_call)
```

The critical point is to inspect structured fields such as:

```json
{
  "tool": "shell",
  "args": {
    "command": "rm -rf ..."
  }
}
```

rather than scanning assistant text for dangerous-looking shell commands.

References:

- https://developers.openai.com/
- https://openai.com/index/running-codex-safely/

---

# Recommended Cross-Runtime Architecture

The guardrail service should be independent of any one agent runtime.

```text
                   +------------------------+
                   |     agent_guardrail    |
                   |                        |
                   | Normalized Action      |
                   | + Context              |
                   |          |             |
                   |          v             |
                   | ALLOW / ASK / DENY     |
                   +-----------^------------+
                               |
          +--------------------+--------------------+
          |                    |                    |
    Claude Code            OpenCode              Codex
          |                    |                    |
     PreToolUse       tool.execute.before      tool hook
          |                    |                    |
          +--------- adapters / normalizers -------+
```

The runtime-specific components should remain thin adapters.

Suggested repository structure:

```text
agent_guardrail/
├── guard-service/
│   ├── evaluator.py
│   ├── policies.py
│   └── normalization.py
│
├── adapters/
│   ├── openclaw/
│   ├── hermes/
│   ├── claude-code/
│   ├── opencode/
│   └── codex/
│
└── policies/
    ├── filesystem.yaml
    ├── shell.yaml
    ├── network.yaml
    ├── secrets.yaml
    └── mcp.yaml
```

---

# Normalized Action Schema

A common schema avoids coupling policies to the underlying agent runtime.

Example TypeScript representation:

```typescript
interface GuardrailAction {
  runtime:
    | "claude-code"
    | "opencode"
    | "codex"
    | "openclaw"
    | "hermes"

  tool: string

  input: unknown

  category:
    | "shell"
    | "filesystem-read"
    | "filesystem-write"
    | "network"
    | "mcp"
    | "other"

  context: {
    cwd?: string
    sessionId?: string
    toolCallId?: string
    repository?: string
  }
}
```

A more semantic shell action might normalize to:

```json
{
  "kind": "shell",
  "action": "rm",
  "args": ["-rf", "/tmp/foo"],
  "cwd": "/repo",
  "network": false,
  "writes_files": true
}
```

The policy engine should therefore operate on:

```text
evaluate(Action, Context) -> Decision
```

where:

```python
class Decision(Enum):
    ALLOW = "allow"
    APPROVAL = "approval_required"
    BLOCK = "block"
```

---

# Why Structured Tool Calls Matter

Avoid this:

```text
assistant output
     |
regex for "rm -rf"
     |
policy
```

This approach is fragile because:

- commands may be escaped or encoded
- shell actions may be nested
- non-shell tools can still perform destructive actions
- MCP tools may modify remote systems
- the model may describe a command without executing it
- execution APIs already expose richer structured metadata

Prefer:

```text
structured tool call
     |
runtime adapter
     |
normalized Action
     |
policy engine
     |
ALLOW / ASK / DENY
```

---

# Suggested Policy Categories

A reusable agent firewall should classify actions semantically rather than only matching tool names.

Useful categories include:

## Filesystem

- reads outside repository root
- writes outside repository root
- deletion
- recursive deletion
- overwriting configuration files
- reading secret files
- modifying SSH or credential stores

## Shell

- destructive commands
- privilege escalation
- process termination
- persistence mechanisms
- package installation
- arbitrary interpreter execution

## Network

- outbound requests
- unknown destinations
- uploading repository contents
- downloading and executing binaries

## Secrets

- `.env`
- SSH private keys
- cloud credentials
- API keys
- browser credential stores

## MCP / Remote Tools

- sending email
- creating cloud resources
- modifying tickets or documents
- database writes
- GitHub pushes
- destructive SaaS operations

---

# Decision Model

A useful guardrail should not be limited to allow/block.

Three-state decisions are more practical:

```text
ALLOW
  Safe enough to execute automatically.

ASK
  Potentially sensitive but legitimate.
  Require explicit user approval.

DENY
  Violates policy regardless of model intent.
```

Example:

```text
git status
    -> ALLOW

git push
    -> ASK

rm -rf /
    -> DENY
```

This is especially compatible with OpenCode's `allow | ask | deny` permission model and Claude Code's permission workflow.

---

# Recommended Design Principle

Treat native runtime protections as separate security layers.

The external guardrail should supplement, not replace:

- filesystem sandboxing
- network isolation
- native permissions
- OS-level controls
- containerization
- user approval prompts
- credential scoping

The resulting defense-in-depth model becomes:

```text
Model
  |
  v
Structured tool call
  |
  v
agent_guardrail
  |
  +-- deny
  |
  +-- approval required
  |
  v
Native agent permissions
  |
  v
Sandbox
  |
  v
OS / container / network controls
  |
  v
Execution
```

---

# Conclusion

Claude Code and OpenCode are both strong targets for `agent_guardrail`.

**Claude Code**

- Native `PreToolUse` hook
- Structured `tool_name`
- Structured `tool_input`
- Can block before execution
- Good fit for a runtime adapter

**OpenCode**

- Native `tool.execute.before` hook
- Structured tool and argument access
- Can block before execution
- Additional `permission.evaluate` layer
- Native `allow | ask | deny` semantics are especially well aligned with a guardrail engine

**Codex**

- Native `PreToolUse` covers Bash, `apply_patch`, MCP calls, and most local function tools
- Native hooks can block before execution but cannot currently force an approval prompt
- A custom harness can preserve a true three-state approval workflow

The most scalable direction is therefore to turn `agent_guardrail` into a runtime-independent **agent firewall**, with small adapters for each coding agent and a shared normalized policy engine.
