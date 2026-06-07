# Deploying This Wrapper Layer in AI Agents such as OpenClaw

This repo contains a guarded shell wrapper you can place in front of an AI agent's command executor so the agent cannot freely run arbitrary shell commands.

For OpenClaw, the intended flow is:

1. OpenClaw tries to run a shell command.
2. A wrapper shell script forwards that command to `safe_exec_three_state.py`.
3. The policy engine returns one of three outcomes:
   - `allowed`: run immediately
   - `blocked`: deny the command
   - `needs_user_approval`: record the request and wait for a human
4. Every decision is logged for auditability.

## Files

- `safe_exec_three_state.py`: recommended production wrapper for agent use. Supports direct allow, hard block, and pending human approval.
- `openclaw-guarded-shell-0`: tiny shell adapter that accepts `-c` or `-lc` and forwards the command into the Python guard.
- `safe_exec_enhanced.py`: earlier guarded executor variant with a simpler allow/block model.
- `safe_exec.py`: minimal allowlist-based version.
- `command_guard.py`: regex-first prototype that returns allow, block, or approval-required decisions.
- `logs/defense_audit.jsonl`: append-only audit log.
- `logs/pending_approvals.jsonl`: append-only approval queue and approval status updates.

## Recommended OpenClaw deployment

### 1. Copy the repo into the OpenClaw workspace

The current scripts assume this layout:

```text
/home/richardsun/.openclaw/workspace/
└── defense/
    ├── safe_exec_three_state.py
    ├── openclaw-guarded-shell-0
    └── logs/
```

If you want a different location, update the hard-coded paths near the top of `safe_exec_three_state.py` and in the shell wrapper.

### 2. Install the shell wrapper

Create an executable wrapper where OpenClaw can use it as its shell:

```bash
sudo cp /home/richardsun/.openclaw/workspace/defense/openclaw-guarded-shell-0 /usr/local/bin/openclaw-guarded-shell
sudo chmod +x /usr/local/bin/openclaw-guarded-shell
sudo chmod +x /home/richardsun/.openclaw/workspace/defense/safe_exec_three_state.py
```

The wrapper should execute the three-state guard, for example:

```bash
#!/usr/bin/env bash

if [[ "$1" == "-lc" || "$1" == "-c" ]]; then
    shift
fi

CMD="$*"

exec /home/richardsun/.openclaw/workspace/defense/safe_exec_three_state.py "$CMD"
```

### 3. Point OpenClaw at the guarded shell

Start OpenClaw with the guarded shell in `SHELL`:

```bash
export SHELL=/usr/local/bin/openclaw-guarded-shell
openclaw gateway --port 18789
```

If your OpenClaw deployment uses another way to define the shell executable, set that field to `/usr/local/bin/openclaw-guarded-shell` instead.

## How the wrapper behaves

`safe_exec_three_state.py` parses the incoming command with `shlex`, rejects shell metacharacters such as pipes and redirections, and then validates the command against a narrow policy.

### Directly allowed examples

These are intended to be low-risk read-only commands:

```bash
ls -la
pwd
grep TODO project/notes.txt
find src -name "*.py"
git status
git log --oneline
```

### Approval-required examples

These are not executed immediately. They are written to `logs/pending_approvals.jsonl` and the script exits with code `2`.

```bash
sed 's/foo/bar/' notes.txt
awk '{print $1}' data.txt
git diff
git show HEAD~1
pytest tests/test_wrapper.py
mv draft.txt archive/draft.txt
rename old new report_old.txt
python3 defense/approved_scripts/summarize_pdf.py paper.pdf
```

### Hard-blocked examples

These are denied outright:

```bash
python3 -c "import os; os.remove('x')"
python3 -m pip install requests
pip install openai
git pull
git push
rm -rf logs
cat ~/.ssh/id_rsa
grep password .env
```

## Approval workflow

When a command requires approval, the guard prints a JSON payload like this:

```json
{
  "decision": "needs_user_approval",
  "approval_id": "abc123def4567890",
  "risk": "medium",
  "reason": "pytest executes Python test code and requires user confirmation",
  "command": "pytest tests/test_wrapper.py"
}
```

Approve and run it:

```bash
python3 /home/richardsun/.openclaw/workspace/defense/safe_exec_three_state.py --approve abc123def4567890
```

Reject it:

```bash
python3 /home/richardsun/.openclaw/workspace/defense/safe_exec_three_state.py --reject abc123def4567890
```

The approval log is append-only, so you keep a record of:

- the original request
- whether it was approved or rejected
- the final command execution result if approved

## Policy summary

The current three-state wrapper is opinionated:

- It only permits commands on an allowlist.
- It blocks shell chaining and redirection tokens such as `&&`, `||`, `;`, `|`, `` ` ``, `$(`, `>`, and `<`.
- It blocks sensitive paths and strings such as `.ssh`, `.env`, `/etc/shadow`, `/root`, `token`, and `password`.
- It keeps execution inside the configured workspace.
- It treats Python, `pytest`, `pip`, `git`, `mv`, and `rename` as controlled commands with special validation.
- It only allows Python scripts from an explicitly approved directory and explicit approved-script set.

## Important setup note for Python scripts

Out of the box, `safe_exec_three_state.py` sets:

```python
APPROVED_PYTHON_SCRIPTS = set()
```

That means agent-launched Python scripts are blocked until you explicitly approve them in code. To allow one, place it under `approved_scripts/` and add its resolved path to `APPROVED_PYTHON_SCRIPTS`.

## Operational logs

Watch the audit trail:

```bash
tail -f /home/richardsun/.openclaw/workspace/defense/logs/defense_audit.jsonl
```

Inspect pending approvals:

```bash
tail -f /home/richardsun/.openclaw/workspace/defense/logs/pending_approvals.jsonl
```

## Adapting this to other AI agents

This pattern works for any agent framework that lets you replace the shell or command runner.

Use the same design:

1. Put a very small wrapper in front of the agent's shell execution.
2. Forward the raw command string into `safe_exec_three_state.py`.
3. Treat exit code `0` as executed, `1` as blocked, and `2` as waiting for human approval.
4. Surface the JSON response back to the operator or orchestration layer.

For agents other than OpenClaw, the only part that usually changes is how you register the wrapper shell.

## Suggested next improvements

- Move hard-coded paths into environment variables such as `OPENCLAW_WORKSPACE` and `DEFENSE_DIR`.
- Add a small approval UI or CLI helper that lists pending requests by `approval_id`.
- Add tests that cover allowed, blocked, and approval-required commands.
- Rename `openclaw-guarded-shell-0` to `openclaw-guarded-shell` in the repo to match the installed binary name.
