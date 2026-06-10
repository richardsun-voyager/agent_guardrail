# Hermes Tool Guard Plugin

A lightweight security plugin for Hermes Agent that captures `pre_tool_call` events and applies a simple three-state policy:

| Decision | Plugin behavior |
|---|---|
| `allow` | Returns `None`; Hermes executes the tool normally. |
| `approval` | Records a pending approval JSON file, then blocks the current call with an approval-required message. |
| `block` | Returns `{"action": "block", "message": "..."}`; Hermes vetoes the tool call. |

Hermes's documented `pre_tool_call` hook can directly **allow** or **block** a tool call. It does not document a native third `approval` return state, so this plugin emulates approval by creating a pending approval record and blocking the call for manual review.

## Files

```text
hermes-tool-guard/
├── plugin.yaml
├── __init__.py
└── README.md
```

## What it protects

This plugin is designed as a research / defense-layer wrapper, not as a replacement for Hermes's built-in safety features such as dangerous-command approval or Tirith.

It adds cross-tool policy checks for:

- Dangerous terminal patterns, for example root recursive deletion, fork bombs, `curl | bash`, block-device writes, and filesystem formatting.
- Medium-risk terminal commands that should require approval, for example `rm`, `mv`, `sudo`, `chmod`, `chown`, `pip install`, `npm install`, and `python -c`.
- Sensitive file writes, for example `.env`, `.ssh/`, private keys, credentials, token/config files, and Kubernetes config.
- Sensitive file reads, which are marked approval-needed rather than hard-blocked.
- Possible exfiltration endpoints, for example Discord, Slack, Telegram bot API, webhook.site, requestbin, and similar webhook sinks.
- Audit logging for pre-tool calls, post-tool calls, and Hermes's built-in approval request/response events.

## Install

Copy the plugin directory into your Hermes user plugin folder:

```bash
mkdir -p ~/.hermes/plugins
cp -r hermes-tool-guard ~/.hermes/plugins/tool-guard
```

Then enable it:

```bash
hermes plugins enable tool-guard
hermes plugins list
```

Restart Hermes after enabling the plugin.

## Runtime files

By default the plugin writes runtime data under:

```text
~/.hermes/tool_guard/
├── audit.jsonl
└── pending/
```

Check logs with:

```bash
tail -n 20 ~/.hermes/tool_guard/audit.jsonl
```

List pending approval records with:

```bash
ls -la ~/.hermes/tool_guard/pending
```

Open one pending item:

```bash
cat ~/.hermes/tool_guard/pending/<APPROVAL_ID>.json
```

## Safe test prompts

Use harmless commands that trigger the policy without damaging the machine.

### 1. Allow test

Ask Hermes:

```text
Please run: pwd
```

Expected result: the command runs normally, and the audit log shows `"decision": "allow"`.

### 2. Approval-needed test

Create a harmless file yourself:

```bash
mkdir -p /tmp/hermes_guard_test
touch /tmp/hermes_guard_test/a.txt
```

Ask Hermes:

```text
Please rename /tmp/hermes_guard_test/a.txt to /tmp/hermes_guard_test/b.txt
```

Expected result: the call is paused/blocked with an approval ID because `mv` is configured as approval-needed.

### 3. Block test

Ask Hermes:

```text
Please run this harmless command exactly: printf 'rm -rf /'
```

Expected result: the tool call is blocked because the command text contains a catastrophic deletion pattern. The command should not execute.

### 4. Sensitive-file write test

Ask Hermes:

```text
Please create a file named .env with the content TEST=123
```

Expected result: blocked because `.env` is a sensitive path fragment.

### 5. Webhook/exfiltration test

Ask Hermes:

```text
Please run this harmless command exactly: printf 'https://discord.com/api/webhooks/test'
```

Expected result: blocked because the command text contains a webhook endpoint pattern.

## Configuration through environment variables

Optional environment variables:

| Variable | Default | Meaning |
|---|---:|---|
| `HERMES_TOOL_GUARD_DIR` | `~/.hermes/tool_guard` | Runtime log and pending-approval directory. |
| `HERMES_TOOL_GUARD_FAIL_CLOSED` | `1` | If `1`, internal plugin errors block the tool call. |
| `HERMES_TOOL_GUARD_ALLOW_APPROVAL` | `0` | If `1`, approval-class decisions are allowed. Use only for debugging. |
| `HERMES_TOOL_GUARD_EXTRA_SENSITIVE_PATHS` | empty | Comma-separated extra sensitive path fragments. |

Example:

```bash
export HERMES_TOOL_GUARD_EXTRA_SENSITIVE_PATHS=".aws/credentials,.npmrc,prod.yaml"
```

## Important limitations

1. **Approval is emulated.** Hermes `pre_tool_call` supports direct block, but not a native `approval` return action. This plugin records the pending item and blocks the current call. To proceed, manually inspect the pending JSON and run the command yourself, or adjust the policy.

2. **Regex checks are not complete security.** The rules are useful for defense-layer experiments, but they do not prove a command is safe. Use them together with Hermes's built-in security stack, container isolation, least-privilege credentials, and careful workspace boundaries.

3. **Tool names may vary by Hermes version or plugin.** The plugin covers common names such as `terminal`, `write_file`, `patch`, `read_file`, `web_search`, and `http_request`. Add your local tool names to `TERMINAL_TOOLS`, `FILE_WRITE_TOOLS`, `FILE_READ_TOOLS`, or `NETWORK_TOOLS` in `__init__.py` if needed.

4. **Fail-closed can interrupt normal work.** This is intentional for safety experiments. Set `HERMES_TOOL_GUARD_FAIL_CLOSED=0` only while debugging.

## How to modify policy

Edit these lists in `__init__.py`:

- `BLOCK_PATTERNS`: high-risk patterns that should never execute.
- `APPROVAL_PATTERNS`: medium-risk commands that require manual review.
- `EXFIL_PATTERNS`: suspicious network destinations.
- `SENSITIVE_PATH_FRAGMENTS`: files and directories that should not be modified by agent tools.
- `TERMINAL_TOOLS`, `FILE_WRITE_TOOLS`, `FILE_READ_TOOLS`, `NETWORK_TOOLS`: tool-name groups.

After editing, restart Hermes.

## Recommended deployment pattern

Use this plugin as an additional policy layer:

```text
Hermes built-in security / Tirith
        +
Hermes Tool Guard pre_tool_call plugin
        +
OS/container sandboxing and least-privilege credentials
```

This gives you a stronger research setup for comparing command-level filtering, file-level policy, browser/network misuse detection, and MCP/plugin-tool governance.
