# Agent Guardrail

A defense layer for agent tool calls, with separate integrations for
**OpenClaw** and **Hermes Agent**.

This repository currently contains:

``` text
agent_guardrail/
├── before-tool-guard-service/   # Python policy service used by OpenClaw
├── before-tool-guard/           # OpenClaw before_tool_call bridge plugin
├── hermes-tool-guard/           # Native Hermes pre_tool_call plugin
└── shell_layer_defense/
```

## v1.1 policy controls

The Python guard adds four architecture-preserving controls:

- command/subcommand policy, so approval is based on the actual operation
  (`git status` versus `git push`) rather than only the executable name;
- a workspace boundary invariant across known and unknown tool schemas, with
  canonical path and symlink resolution;
- outbound destination classification, including an HTTPS hostname allowlist,
  known exfiltration endpoints, URL credentials, localhost, and non-global IPs;
- a bounded per-session risk score that escalates repeated risky actions and
  decays over time.

Hard policy blocks remain blocks regardless of the session score. Calls without
a session ID are evaluated normally but do not share trajectory state.

Configure trusted outbound hosts and trajectory thresholds before starting the
sidecar:

``` bash
export TOOL_GUARD_TRUSTED_DESTINATIONS="api.example.com,docs.example.com"
export TOOL_GUARD_SESSION_APPROVAL_THRESHOLD=4
export TOOL_GUARD_SESSION_BLOCK_THRESHOLD=8
export TOOL_GUARD_SESSION_RISK_DECAY_SECONDS=300
export TOOL_GUARD_SESSION_RISK_TTL_SECONDS=1800
export TOOL_GUARD_SESSION_RISK_MAX_SESSIONS=10000
```

Only HTTPS requests to an exact allowlisted hostname or its subdomains are
automatically allowed. Read requests to other public destinations require
approval; unsafe destinations and known exfiltration endpoints are blocked.

Run the policy regression tests with:

``` bash
python3 -m unittest discover -s before-tool-guard-service -p 'test_*.py' -v
```

> **Important:** OpenClaw and Hermes use different installation models.\
> On OpenClaw, the guard consists of a Python sidecar service **plus**
> an OpenClaw plugin.\
> On Hermes, the guard is installed directly as a Hermes plugin and does
> **not** require the OpenClaw Python sidecar.

------------------------------------------------------------------------

# Installation A --- OpenClaw on Ubuntu

## Architecture

On an OpenClaw machine, tool calls flow through:

``` text
OpenClaw agent
    ↓
before_tool_call hook
    ↓
before-tool-guard plugin
    ↓ HTTP on localhost
Python guard service
    ↓
allow / block / approval_required
    ↓
tool executes only when permitted
```

The OpenClaw plugin fails closed if it cannot reach the guard service,
so the recommended Ubuntu installation runs the Python service under
**systemd** rather than starting it manually in a terminal.

## 1. Prerequisites

Verify the basic tools:

``` bash
python3 --version
node --version
npm --version
openclaw --version
git --version
```

The OpenClaw plugin currently targets OpenClaw/plugin API version
`>=2026.3.24-beta.2`.

If Git is missing:

``` bash
sudo apt update
sudo apt install -y git
```

## 2. Clone Agent Guardrail

A convenient location is `/opt/agent_guardrail`:

``` bash
cd /opt
sudo git clone https://github.com/richardsun-voyager/agent_guardrail.git
sudo chown -R "$USER":"$USER" /opt/agent_guardrail
cd /opt/agent_guardrail
```

Alternatively, clone it under your home directory. If you do, substitute
that path in the commands below.

## 3. Test the Python guard service

Set the OpenClaw workspace:

``` bash
export TOOL_GUARD_HOST=127.0.0.1
export TOOL_GUARD_PORT=8765
export TOOL_GUARD_WORKSPACE="$HOME/.openclaw/workspace"
```

Start the service manually for the first test:

``` bash
python3 /opt/agent_guardrail/before-tool-guard-service/tool_guard_service.py
```

In another terminal:

``` bash
curl http://127.0.0.1:8765/health
```

A successful response should look similar to:

``` json
{
  "ok": true,
  "workspace": "/home/USER/.openclaw/workspace"
}
```

Stop the manually started service with `Ctrl+C` after the test.

## 4. Install the guard service as a systemd service

Running:

``` bash
cd before-tool-guard-service
python3 tool_guard_service.py
```

is useful for development, but it is not the recommended permanent
setup. Use systemd so the guard starts automatically and restarts if it
crashes.

First determine your username and home directory:

``` bash
whoami
echo "$HOME"
which python3
```

Create the service:

``` bash
sudo nano /etc/systemd/system/openclaw-tool-guard.service
```

Paste the following and replace `YOUR_USER` and `/home/YOUR_USER` where
necessary:

``` ini
[Unit]
Description=OpenClaw Tool Guard Service
After=network.target

[Service]
Type=simple
User=YOUR_USER
WorkingDirectory=/opt/agent_guardrail/before-tool-guard-service
ExecStart=/usr/bin/python3 /opt/agent_guardrail/before-tool-guard-service/tool_guard_service.py

Environment=TOOL_GUARD_HOST=127.0.0.1
Environment=TOOL_GUARD_PORT=8765
Environment=TOOL_GUARD_WORKSPACE=/home/YOUR_USER/.openclaw/workspace

Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Enable and start it:

``` bash
sudo systemctl daemon-reload
sudo systemctl enable --now openclaw-tool-guard
```

Check status:

``` bash
systemctl status openclaw-tool-guard --no-pager
```

Check the health endpoint:

``` bash
curl http://127.0.0.1:8765/health
```

View logs:

``` bash
journalctl -u openclaw-tool-guard -f
```

From this point onward, **you do not need to manually run
`python3 tool_guard_service.py` after reboot**.

Useful service commands:

``` bash
sudo systemctl restart openclaw-tool-guard
sudo systemctl stop openclaw-tool-guard
sudo systemctl start openclaw-tool-guard
```

## 5. Build the OpenClaw bridge plugin

Go to the plugin:

``` bash
cd /opt/agent_guardrail/before-tool-guard
```

Install its dependencies:

``` bash
npm install
```

The plugin expects the OpenClaw package to be available locally. If
OpenClaw is available through npm on your machine:

``` bash
npm install --no-save openclaw
```

If instead you have a local OpenClaw checkout/package:

``` bash
npm install --no-save /path/to/openclaw
```

Then build:

``` bash
npm run build
```

The compiled runtime entry should be created under `dist/`.

## 6. Install the plugin into OpenClaw

From the repository root:

``` bash
cd /opt/agent_guardrail
openclaw plugins install --link ./before-tool-guard
```

If OpenClaw's plugin security scanner rejects the plugin because it
reads environment variables and connects to the local guard service, the
repository documents this explicit override:

``` bash
openclaw plugins install \
  --link \
  --dangerously-force-unsafe-install \
  ./before-tool-guard
```

Only use the override after reviewing the plugin source.

Enable the plugin:

``` bash
openclaw config patch '{"plugins":{"entries":{"before-tool-guard":{"enabled":true,"config":{}}}}}'
```

Restart OpenClaw:

``` bash
openclaw gateway restart
```

Verify that the plugin loaded:

``` bash
openclaw plugins inspect before-tool-guard --runtime --json
```

Look for a loaded/activated plugin and a registered `before_tool_call`
hook.

## 7. Verify the guard end to end

First verify the sidecar:

``` bash
curl http://127.0.0.1:8765/health
```

Then verify OpenClaw:

``` bash
openclaw plugins inspect before-tool-guard --runtime --json
```

The plugin defaults to this local evaluator endpoint:

``` text
http://127.0.0.1:8765/evaluate_tool_call
```

The Python service writes audit and pending-approval records under the
configured OpenClaw workspace, including:

``` text
defense/logs/tool_guard_audit.jsonl
defense/logs/tool_guard_pending.jsonl
```

You can inspect recent audit entries with:

``` bash
tail -n 20 "$HOME/.openclaw/workspace/defense/logs/tool_guard_audit.jsonl"
```

## 8. Updating the OpenClaw installation

``` bash
cd /opt/agent_guardrail
git pull

cd before-tool-guard
npm install
npm run build

sudo systemctl restart openclaw-tool-guard
openclaw gateway restart
```

## OpenClaw troubleshooting

### All tool calls are blocked

The plugin intentionally fails closed if the Python guard cannot be
reached.

Check:

``` bash
systemctl status openclaw-tool-guard --no-pager
curl http://127.0.0.1:8765/health
journalctl -u openclaw-tool-guard -n 100 --no-pager
```

### Plugin is installed but the hook does not run

Check:

``` bash
openclaw plugins inspect before-tool-guard --runtime --json
```

Then restart:

``` bash
openclaw gateway restart
```

### File operations are unexpectedly blocked

Check the workspace configured in:

``` text
TOOL_GUARD_WORKSPACE
```

The service blocks paths that resolve outside its configured workspace.

------------------------------------------------------------------------

# Installation B --- Hermes Machine

## Architecture

Hermes uses a simpler installation:

``` text
Hermes Agent
    ↓
pre_tool_call
    ↓
Hermes Tool Guard plugin
    ↓
allow / approval-like block / block
    ↓
tool execution
```

The Hermes plugin runs inside Hermes's plugin system. You **do not need
to run**:

``` bash
python3 before-tool-guard-service/tool_guard_service.py
```

for the Hermes integration.

Hermes's documented `pre_tool_call` hook directly supports allowing or
blocking calls. The guard therefore emulates an approval state by
recording a pending approval and blocking the current invocation for
manual review.

## 1. Prerequisites

Verify Hermes and Git:

``` bash
hermes --version
git --version
```

If Git is missing on Ubuntu:

``` bash
sudo apt update
sudo apt install -y git
```

## 2. Clone Agent Guardrail

For a user-level Hermes installation:

``` bash
cd ~
git clone https://github.com/richardsun-voyager/agent_guardrail.git
cd agent_guardrail
```

If the repository is already present, simply enter it:

``` bash
cd ~/agent_guardrail
```

## 3. Install the Hermes plugin

Create the Hermes plugin directory:

``` bash
mkdir -p ~/.hermes/plugins
```

Copy the plugin:

``` bash
rm -rf ~/.hermes/plugins/tool-guard
cp -r ~/agent_guardrail/hermes-tool-guard ~/.hermes/plugins/tool-guard
```

The installed directory should contain:

``` text
~/.hermes/plugins/tool-guard/
├── plugin.yaml
├── __init__.py
└── README.md
```

## 4. Enable the plugin

``` bash
hermes plugins enable tool-guard
hermes plugins list
```

Restart Hermes after enabling the plugin.

There is no separate systemd service required for the Hermes guard
itself.

## 5. Verify runtime logging

By default, runtime data is stored under:

``` text
~/.hermes/tool_guard/
├── audit.jsonl
└── pending/
```

Check recent audit events:

``` bash
tail -n 20 ~/.hermes/tool_guard/audit.jsonl
```

List pending approval records:

``` bash
ls -la ~/.hermes/tool_guard/pending
```

Inspect a pending request:

``` bash
cat ~/.hermes/tool_guard/pending/<APPROVAL_ID>.json
```

## 6. Safe verification tests

Use harmless tests rather than destructive commands.

### Allow test

Ask Hermes to run:

``` text
pwd
```

Expected: the command executes and the audit log records an `allow`
decision.

### Approval-policy test

Prepare a harmless file yourself:

``` bash
mkdir -p /tmp/hermes_guard_test
touch /tmp/hermes_guard_test/a.txt
```

Then ask Hermes to rename it:

``` text
Rename /tmp/hermes_guard_test/a.txt to /tmp/hermes_guard_test/b.txt
```

`mv` is currently treated as approval-needed by the plugin.

### Block-pattern test

Ask Hermes to print dangerous-looking text rather than execute it:

``` text
Run this command exactly: printf 'rm -rf /'
```

Expected: the guard detects the catastrophic deletion pattern in the
proposed tool call and blocks it. The destructive command itself is
never executed.

## 7. Optional Hermes configuration

The plugin supports these environment variables:

``` text
HERMES_TOOL_GUARD_DIR
HERMES_TOOL_GUARD_FAIL_CLOSED
HERMES_TOOL_GUARD_ALLOW_APPROVAL
HERMES_TOOL_GUARD_EXTRA_SENSITIVE_PATHS
```

Defaults include:

``` text
HERMES_TOOL_GUARD_DIR=~/.hermes/tool_guard
HERMES_TOOL_GUARD_FAIL_CLOSED=1
HERMES_TOOL_GUARD_ALLOW_APPROVAL=0
```

For example, to add sensitive paths:

``` bash
export HERMES_TOOL_GUARD_EXTRA_SENSITIVE_PATHS=".aws/credentials,.npmrc,prod.yaml"
```

Restart Hermes after changing the environment used by the Hermes
process.

`HERMES_TOOL_GUARD_FAIL_CLOSED=1` is recommended for normal guard
operation. Setting it to `0` can allow calls through when the guard
itself encounters an internal error, so use that mode only for
debugging.

## 8. Updating the Hermes installation

Pull the latest repository:

``` bash
cd ~/agent_guardrail
git pull
```

Replace the installed plugin:

``` bash
rm -rf ~/.hermes/plugins/tool-guard
cp -r ~/agent_guardrail/hermes-tool-guard ~/.hermes/plugins/tool-guard
```

Then restart Hermes.

## Hermes troubleshooting

### Plugin does not appear

Check:

``` bash
hermes plugins list
ls -la ~/.hermes/plugins/tool-guard
```

Make sure `plugin.yaml` and `__init__.py` are directly inside
`~/.hermes/plugins/tool-guard/`, rather than accidentally creating an
extra nested directory.

### Approval requests do not resume automatically

This is currently expected. Hermes's `pre_tool_call` interface does not
provide the same native three-state approval return used by the OpenClaw
integration. The Hermes plugin records a pending request and blocks that
invocation for manual review.

### Normal calls are blocked after a plugin error

The plugin defaults to fail-closed behavior. Inspect:

``` bash
tail -n 100 ~/.hermes/tool_guard/audit.jsonl
```

Use `HERMES_TOOL_GUARD_FAIL_CLOSED=0` only temporarily while diagnosing
the problem.

------------------------------------------------------------------------

# OpenClaw vs. Hermes

  -------------------------------------------------------------------------
                          OpenClaw                Hermes
  ----------------------- ----------------------- -------------------------
  Integration             `before_tool_call`      Native `pre_tool_call`
                          bridge plugin           plugin

  Python sidecar          **Required**            **Not required**

  Recommended startup     systemd                 Hermes plugin lifecycle

  Default runtime         `127.0.0.1:8765`        N/A
  endpoint                                        

  Approval behavior       `approval_required`     Pending record + current
                          passed to OpenClaw      call blocked

  Audit location          OpenClaw workspace      `~/.hermes/tool_guard/`
                          `defense/logs/`         
  -------------------------------------------------------------------------

# Security notes

Agent Guardrail is intended as an additional defense layer, not a
complete sandbox.

For stronger isolation, combine it with:

-   least-privilege OS users and credentials;
-   strict workspace boundaries;
-   container or VM isolation where appropriate;
-   the agent platform's built-in security controls;
-   restricted network access for agents that do not require arbitrary
    outbound traffic;
-   regular review of audit logs and guard policy.

The policy is intentionally conservative. Review the source and adapt
the rules to your environment before relying on it in production.
