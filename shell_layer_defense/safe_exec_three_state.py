#!/usr/bin/env python3
"""
safe_exec.py — guarded command executor with three decisions:

  1. allowed
  2. blocked
  3. needs_user_approval

This version is designed for OpenClaw-style agents.

Core idea:
  - Low-risk read-only commands can run directly.
  - High-risk commands are blocked.
  - Medium-risk commands are not run immediately. They are written to a
    pending-approval file. A human can then approve them by approval id.
  - File-moving / renaming operations such as mv and rename require approval.

Usage examples:

  Normal guarded execution:
    python3 safe_exec.py "ls -la"

  Medium-risk command:
    python3 safe_exec.py "python3 defense/approved_scripts/summarize_pdf.py paper.pdf"
    # If classified as needs_user_approval, it will NOT run yet.

  Approve and run a pending command:
    python3 safe_exec.py --approve APPROVAL_ID

  Reject a pending command:
    python3 safe_exec.py --reject APPROVAL_ID

Recommended wrapper:
  exec /usr/bin/python3 /home/richardsun/.openclaw/workspace/defense/safe_exec.py "$COMMAND"
"""

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

WORKSPACE = Path("/home/richardsun/.openclaw/workspace/").resolve()
DEFENSE_DIR = (WORKSPACE / "defense").resolve()
LOG_PATH = DEFENSE_DIR / "logs" / "defense_audit.jsonl"
PENDING_APPROVALS_PATH = DEFENSE_DIR / "logs" / "pending_approvals.jsonl"

APPROVED_SCRIPT_DIR = (DEFENSE_DIR / "approved_scripts").resolve()
APPROVED_TEST_DIR = (WORKSPACE / "tests").resolve()

# Add trusted scripts here, one by one.
# Example:
# APPROVED_PYTHON_SCRIPTS = {
#     str((APPROVED_SCRIPT_DIR / "summarize_pdf.py").resolve()),
# }
APPROVED_PYTHON_SCRIPTS = set()


# ---------------------------------------------------------------------
# Policy groups
# ---------------------------------------------------------------------

# Usually safe enough to run directly after path checks.
READ_ONLY_COMMANDS = {
    "ls",
    "pwd",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "wc",
}

# These can be read-only, but have options that may write or execute.
CAREFUL_READ_COMMANDS = {
    "sed",
    "awk",
}

# These are not allowed directly. They either require narrow validation
# or user approval.
CONTROLLED_COMMANDS = {
    "python",
    "python3",
    "pytest",
    "pip",
    "git",
    "mv",
    "rename",
}

# Hard-block shell/system operations.
DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\brm\b",
    r"\bsudo\b",
    r"\bsu\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bcurl\b.*\|\s*(sh|bash|python|python3)",
    r"\bwget\b.*\|\s*(sh|bash|python|python3)",
    r"\bnc\b",
    r"\bnetcat\b",
    r"\bssh\b",
    r"\bscp\b",
    r"\brsync\b",
    r"\bmkfs\b",
    r"\bdd\b",
    r"\bmount\b",
    r"\bumount\b",
    r"\bkill\b",
    r"\bpkill\b",
    r"\bcrontab\b",
    r"\bsystemctl\b",
    r"\bservice\b",
    r"\bdocker\b",
]

# Hard-block sensitive data / system paths.
FORBIDDEN_STRINGS = [
    ".ssh",
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credential",
    "secret",
    "token",
    "apikey",
    "api_key",
    "password",
    "/etc/passwd",
    "/etc/shadow",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/var/run/docker.sock",
]

FORBIDDEN_SHELL_TOKENS = [
    "&&",
    "||",
    ";",
    "|",
    "`",
    "$(",
    ">",
    ">>",
    "<",
]

# Dangerous Python-specific bypass indicators.
PYTHON_DANGEROUS_TOKENS = [
    "os.remove",
    "os.unlink",
    "pathlib.path.unlink",
    ".unlink(",
    "shutil.rmtree",
    "shutil.move",
    "subprocess",
    "os.system",
    "popen",
    "socket",
    "requests",
    "urllib",
    "http.client",
    "ftplib",
    "paramiko",
    "eval(",
    "exec(",
    "compile(",
    "__import__",
    "open('/etc",
    'open("/etc',
    "open('/root",
    'open("/root',
]


# ---------------------------------------------------------------------
# Decision helpers
# ---------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_record(record: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def print_json(obj: dict) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def block(reason: str, command: str) -> None:
    record = {
        "timestamp": now_iso(),
        "decision": "blocked",
        "reason": reason,
        "command": command,
    }
    log_record(record)
    print_json(record)
    sys.exit(1)


def allow_log(command: str, result: subprocess.CompletedProcess, approved_by: Optional[str] = None) -> None:
    record = {
        "timestamp": now_iso(),
        "decision": "allowed",
        "command": command,
        "returncode": result.returncode,
    }
    if approved_by:
        record["approved_by"] = approved_by
    log_record(record)


def approval_id_for(command: str) -> str:
    material = f"{now_iso()}::{command}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:16]


def request_user_approval(reason: str, command: str, risk: str = "medium") -> None:
    """
    Write a pending approval record and exit without executing the command.
    """
    approval_id = approval_id_for(command)
    record = {
        "timestamp": now_iso(),
        "decision": "needs_user_approval",
        "approval_id": approval_id,
        "risk": risk,
        "reason": reason,
        "command": command,
        "status": "pending",
    }

    PENDING_APPROVALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PENDING_APPROVALS_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    log_record(record)

    print_json({
        "decision": "needs_user_approval",
        "approval_id": approval_id,
        "risk": risk,
        "reason": reason,
        "command": command,
        "next_steps": {
            "approve_and_run": f"python3 {Path(__file__).resolve()} --approve {approval_id}",
            "reject": f"python3 {Path(__file__).resolve()} --reject {approval_id}",
        },
    })
    # Use code 2 for "not run, awaiting user approval".
    sys.exit(2)


# ---------------------------------------------------------------------
# Pending approval storage
# ---------------------------------------------------------------------

def load_pending_records() -> List[dict]:
    if not PENDING_APPROVALS_PATH.exists():
        return []

    records = []
    with PENDING_APPROVALS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def append_pending_record(record: dict) -> None:
    PENDING_APPROVALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PENDING_APPROVALS_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def find_latest_pending(approval_id: str) -> Optional[dict]:
    matches = [
        r for r in load_pending_records()
        if r.get("approval_id") == approval_id
    ]
    if not matches:
        return None

    latest = matches[-1]
    if latest.get("status") != "pending":
        return None

    return latest


def mark_approval(approval_id: str, status: str) -> None:
    record = {
        "timestamp": now_iso(),
        "decision": "approval_update",
        "approval_id": approval_id,
        "status": status,
    }
    append_pending_record(record)
    log_record(record)


# ---------------------------------------------------------------------
# Path and pattern helpers
# ---------------------------------------------------------------------

def is_inside(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def reject_global_patterns(command: str) -> None:
    lowered = command.lower()

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, lowered):
            block(f"Dangerous shell pattern: {pattern}", command)

    for item in FORBIDDEN_STRINGS:
        if item.lower() in lowered:
            block(f"Forbidden sensitive string: {item}", command)

    for token in FORBIDDEN_SHELL_TOKENS:
        if token in command:
            block(f"Forbidden shell token: {token}", command)


def reject_path_outside_workspace(path_text: str, command: str) -> None:
    if not path_text or path_text.startswith("-"):
        return

    p = Path(path_text)
    resolved = p.resolve() if p.is_absolute() else (WORKSPACE / p).resolve()

    if not is_inside(resolved, WORKSPACE):
        block(f"Path outside workspace: {resolved}", command)


def reject_sensitive_path(path_text: str, command: str) -> None:
    lowered = path_text.lower()
    for item in FORBIDDEN_STRINGS:
        if item.lower() in lowered:
            block(f"Forbidden sensitive path/string: {item}", command)


def reject_python_bypass_tokens(parts: List[str], command: str) -> None:
    joined = " ".join(parts).lower()
    for token in PYTHON_DANGEROUS_TOKENS:
        if token.lower() in joined:
            block(f"Dangerous Python-related token: {token}", command)


def ensure_cwd_inside_workspace(command: str) -> None:
    cwd = Path.cwd().resolve()
    if not is_inside(cwd, WORKSPACE):
        block(f"Current directory outside workspace: {cwd}", command)


# ---------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------

def validate_command(parts: List[str], command: str, approval_mode: bool = False) -> Tuple[str, Optional[str]]:
    """
    Return:
      ("allow", None)
      ("ask", reason)

    Hard blocks call block(...) directly.

    approval_mode=True means we are running a command that the user already
    approved. Even then, hard-block rules are still enforced.
    """
    executable = os.path.basename(parts[0])

    if executable in READ_ONLY_COMMANDS:
        validate_read_only(executable, parts, command)
        return "allow", None

    if executable in CAREFUL_READ_COMMANDS:
        validate_careful_read(executable, parts, command)
        # sed/awk are powerful; ask on first run, allow after approval.
        if approval_mode:
            return "allow", None
        return "ask", f"{executable} can transform text and may behave unexpectedly"

    if executable in CONTROLLED_COMMANDS:
        return validate_controlled(executable, parts, command, approval_mode=approval_mode)

    block(f"Command not allowlisted: {executable}", command)


def validate_read_only(executable: str, parts: List[str], command: str) -> None:
    if executable == "pwd":
        if len(parts) > 1:
            block("pwd with arguments is not approved", command)
        return

    risky_flags = {
        "-i", "--in-place",
        "-exec", "-execdir",
        "-delete",
        "--files0-from",
    }

    for p in parts[1:]:
        if p in risky_flags:
            block(f"Risky flag for read-only command: {p}", command)

    if executable == "find":
        validate_find(parts, command)
        return

    if executable == "grep":
        validate_grep(parts, command)
        return

    for p in parts[1:]:
        if p.startswith("-"):
            continue
        reject_sensitive_path(p, command)
        reject_path_outside_workspace(p, command)


def validate_careful_read(executable: str, parts: List[str], command: str) -> None:
    # Never allow in-place edits.
    for p in parts[1:]:
        if p in {"-i", "--in-place"}:
            block(f"{executable} in-place edit is blocked: {p}", command)

    # Treat likely file arguments conservatively.
    non_options = [p for p in parts[1:] if not p.startswith("-")]
    if len(non_options) >= 2:
        for p in non_options[1:]:
            reject_sensitive_path(p, command)
            if "/" in p or "." in Path(p).name:
                reject_path_outside_workspace(p, command)


def validate_find(parts: List[str], command: str) -> None:
    if len(parts) == 1:
        return

    root_seen = False
    for p in parts[1:]:
        if p.startswith("-"):
            continue
        if not root_seen:
            reject_sensitive_path(p, command)
            reject_path_outside_workspace(p, command)
            root_seen = True


def validate_grep(parts: List[str], command: str) -> None:
    non_options = [p for p in parts[1:] if not p.startswith("-")]
    # First non-option is usually pattern; later non-options are file paths.
    for p in non_options[1:]:
        reject_sensitive_path(p, command)
        reject_path_outside_workspace(p, command)


def validate_controlled(
    executable: str,
    parts: List[str],
    command: str,
    approval_mode: bool = False,
) -> Tuple[str, Optional[str]]:
    if executable in {"python", "python3"}:
        return validate_python(parts, command, approval_mode=approval_mode)
    if executable == "pip":
        return validate_pip(parts, command, approval_mode=approval_mode)
    if executable == "pytest":
        return validate_pytest(parts, command, approval_mode=approval_mode)
    if executable == "git":
        return validate_git(parts, command, approval_mode=approval_mode)
    if executable in {"mv", "rename"}:
        return validate_move_or_rename(executable, parts, command, approval_mode=approval_mode)

    block(f"Controlled command has no validator: {executable}", command)


def validate_python(parts: List[str], command: str, approval_mode: bool = False) -> Tuple[str, Optional[str]]:
    reject_python_bypass_tokens(parts, command)

    if parts in [["python", "--version"], ["python", "-V"], ["python3", "--version"], ["python3", "-V"]]:
        return "allow", None

    if "-c" in parts:
        block("Python inline execution is blocked: -c", command)

    if "-m" in parts:
        block("Python module execution is blocked: -m", command)

    script_index = None
    for i, p in enumerate(parts[1:], start=1):
        if p.endswith(".py"):
            script_index = i
            break

    if script_index is None:
        block("Python command has no approved script", command)

    script_path = Path(parts[script_index])
    script = script_path.resolve() if script_path.is_absolute() else (WORKSPACE / script_path).resolve()

    if not is_inside(script, APPROVED_SCRIPT_DIR):
        block(f"Python script outside approved script directory: {script}", command)

    if str(script) not in APPROVED_PYTHON_SCRIPTS:
        block(f"Python script not explicitly approved: {script}", command)

    for arg in parts[script_index + 1:]:
        if arg.startswith("-"):
            continue
        reject_sensitive_path(arg, command)
        if "/" in arg or "." in Path(arg).name:
            reject_path_outside_workspace(arg, command)

    # Even approved scripts may read/process files, so ask unless already approved.
    if approval_mode:
        return "allow", None

    return "ask", f"Approved Python script requires user confirmation before execution: {script}"


def validate_pip(parts: List[str], command: str, approval_mode: bool = False) -> Tuple[str, Optional[str]]:
    passive = {"--version", "-V", "list", "show", "freeze"}

    if len(parts) >= 2 and parts[1] in passive:
        for p in parts[2:]:
            reject_sensitive_path(p, command)
        return "allow", None

    # Installation or download remains hard-blocked, not approval-based.
    block("pip command not approved. install/uninstall/download are blocked.", command)


def validate_pytest(parts: List[str], command: str, approval_mode: bool = False) -> Tuple[str, Optional[str]]:
    if len(parts) < 2:
        block("pytest requires an approved test path", command)

    for p in parts[1:]:
        if p.startswith("-"):
            if p.startswith("--pyargs") or p.startswith("-p"):
                block(f"pytest option not approved: {p}", command)
            continue

        target = (WORKSPACE / p).resolve()
        if not is_inside(target, APPROVED_TEST_DIR):
            block(f"pytest target outside approved tests directory: {target}", command)

    if approval_mode:
        return "allow", None

    return "ask", "pytest executes Python test code and requires user confirmation"


def validate_git(parts: List[str], command: str, approval_mode: bool = False) -> Tuple[str, Optional[str]]:
    if len(parts) < 2:
        block("git command requires subcommand", command)

    sub = parts[1]

    # Safe-ish commands allowed directly.
    direct_allow = {"status", "log", "branch", "rev-parse"}

    # May expose lots of content; require user approval.
    approval_required = {"diff", "show"}

    hard_block = {
        "clone", "pull", "push", "fetch", "checkout", "reset", "clean",
        "submodule", "merge", "rebase", "apply", "am", "bisect", "remote",
    }

    if sub in hard_block:
        block(f"git subcommand blocked: {sub}", command)

    joined = " ".join(parts[1:]).lower()
    for token in ["credential", "--exec-path", "-c"]:
        if token in joined:
            block(f"git token not approved: {token}", command)

    if sub in direct_allow:
        return "allow", None

    if sub in approval_required:
        if approval_mode:
            return "allow", None
        return "ask", f"git {sub} may reveal or process substantial file contents"

    block(f"git subcommand not approved: {sub}", command)


def validate_move_or_rename(
    executable: str,
    parts: List[str],
    command: str,
    approval_mode: bool = False,
) -> Tuple[str, Optional[str]]:
    """
    mv / rename are medium-risk operations:
      - They can overwrite files.
      - They can hide files by moving them.
      - They can move files out of expected locations.

    Policy:
      - Source and destination must stay inside WORKSPACE.
      - Sensitive paths are blocked.
      - Dangerous flags are blocked.
      - Operation requires user approval before execution.
    """

    if executable == "mv":
        validate_mv(parts, command)
        if approval_mode:
            return "allow", None
        return "ask", "mv can rename, relocate, or overwrite files and requires user confirmation"

    if executable == "rename":
        validate_rename(parts, command)
        if approval_mode:
            return "allow", None
        return "ask", "rename can modify many filenames and requires user confirmation"

    block(f"Unsupported move/rename executable: {executable}", command)


def validate_mv(parts: List[str], command: str) -> None:
    if len(parts) < 3:
        block("mv requires at least source and destination", command)

    blocked_flags = {
        "-f",
        "--force",
        "--backup",
        "-b",
        "-T",
        "--target-directory",
        "-t",
        "--no-target-directory",
    }

    allowed_flags = {
        "-n",
        "--no-clobber",
        "-v",
        "--verbose",
    }

    path_args = []
    for p in parts[1:]:
        if p.startswith("-"):
            if p in blocked_flags:
                block(f"mv flag not approved: {p}", command)
            if p not in allowed_flags:
                block(f"mv option not approved: {p}", command)
            continue
        path_args.append(p)

    if len(path_args) < 2:
        block("mv requires source and destination paths", command)

    # Validate every source and destination path.
    for p in path_args:
        reject_sensitive_path(p, command)
        reject_path_outside_workspace(p, command)

    # Avoid accidental multi-file moves unless user approves via a clear directory target.
    # This is still approval-gated, but we keep the command shape explicit.
    if len(path_args) > 2:
        dest = Path(path_args[-1])
        dest_resolved = dest.resolve() if dest.is_absolute() else (WORKSPACE / dest).resolve()
        if not dest_resolved.exists() or not dest_resolved.is_dir():
            block("mv with multiple sources requires an existing directory destination", command)


def validate_rename(parts: List[str], command: str) -> None:
    """
    Supports common Linux rename styles conservatively, but always approval-gated.

    Examples vary by distro:
      rename 's/old/new/' *.txt
      rename old new file1 file2

    Because rename can affect many files, reject broad path escape and sensitive strings,
    but do not try to fully interpret the rename expression.
    """

    if len(parts) < 4:
        block("rename requires an expression/pattern and at least one target", command)

    blocked_flags = {
        "-f",
        "--force",
    }

    allowed_flags = {
        "-n",
        "--no-act",
        "-v",
        "--verbose",
    }

    non_option_args = []
    for p in parts[1:]:
        if p.startswith("-"):
            if p in blocked_flags:
                block(f"rename flag not approved: {p}", command)
            if p not in allowed_flags:
                block(f"rename option not approved: {p}", command)
            continue
        non_option_args.append(p)

    # Check all args for sensitive references.
    for p in non_option_args:
        reject_sensitive_path(p, command)

    # Only target file/path arguments should be workspace-checked.
    # In common forms, the first one or two non-option args are expressions,
    # and the remaining args are paths.
    likely_targets = non_option_args[2:] if len(non_option_args) >= 3 else non_option_args[1:]

    for p in likely_targets:
        # Shell glob expansion will already have happened before safe_exec receives
        # the command only if an outer shell expands it. In this guarded executor,
        # shell=False prevents expansion. So block raw globs to avoid surprises.
        if any(ch in p for ch in ["*", "?", "["]):
            block(f"rename glob pattern is not approved in guarded mode: {p}", command)
        reject_path_outside_workspace(p, command)


# ---------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------

def parse_command(command: str) -> List[str]:
    if not command:
        block("Empty command", command)

    if len(command) > 4000:
        block("Command too long", command)

    reject_global_patterns(command)

    try:
        parts = shlex.split(command)
    except Exception as e:
        block(f"Command parse error: {e}", command)

    if not parts:
        block("Empty command", command)

    ensure_cwd_inside_workspace(command)
    return parts


def run_command(command: str, approved_by: Optional[str] = None) -> int:
    parts = parse_command(command)

    decision, reason = validate_command(
        parts,
        command,
        approval_mode=approved_by is not None,
    )

    if decision == "ask":
        request_user_approval(reason or "User approval required", command, risk="medium")

    result = subprocess.run(
        parts,
        cwd=str(WORKSPACE),
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )

    allow_log(command, result, approved_by=approved_by)

    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")

    return result.returncode


def approve_and_run(approval_id: str) -> None:
    pending = find_latest_pending(approval_id)
    if pending is None:
        print_json({
            "decision": "blocked",
            "reason": f"No pending approval found for id: {approval_id}",
        })
        sys.exit(1)

    command = pending.get("command", "")
    mark_approval(approval_id, "approved")
    rc = run_command(command, approved_by=approval_id)
    sys.exit(rc)


def reject_pending(approval_id: str) -> None:
    pending = find_latest_pending(approval_id)
    if pending is None:
        print_json({
            "decision": "blocked",
            "reason": f"No pending approval found for id: {approval_id}",
        })
        sys.exit(1)

    mark_approval(approval_id, "rejected")
    print_json({
        "decision": "rejected",
        "approval_id": approval_id,
        "command": pending.get("command", ""),
    })
    sys.exit(0)


def main() -> None:
    if len(sys.argv) >= 3 and sys.argv[1] == "--approve":
        approve_and_run(sys.argv[2])

    if len(sys.argv) >= 3 and sys.argv[1] == "--reject":
        reject_pending(sys.argv[2])

    if len(sys.argv) < 2:
        block("No command provided", "")

    command = " ".join(sys.argv[1:]).strip()
    rc = run_command(command)
    sys.exit(rc)


if __name__ == "__main__":
    main()
