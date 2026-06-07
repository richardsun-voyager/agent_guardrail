#!/usr/bin/env python3
"""
safe_exec.py — guarded command executor for OpenClaw-style agents.

Purpose:
  - Allow only a small set of low-risk commands.
  - Treat Python, pip, pytest, and git as controlled commands with separate policies.
  - Prevent common bypasses such as:
      python3 -c "import os; os.remove(...)"
      python3 -m pip install ...
      pip install ...
      git clone / pull / push / reset / clean
  - Keep all execution inside WORKSPACE.
  - Log both allowed and blocked actions.

Recommended wrapper:
  exec /usr/bin/python3 /home/richardsun/.openclaw/workspace/defense/safe_exec.py "$COMMAND"
"""

import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

WORKSPACE = Path("/home/richardsun/.openclaw/workspace/").resolve()
DEFENSE_DIR = (WORKSPACE / "defense").resolve()
LOG_PATH = DEFENSE_DIR / "logs" / "defense_audit.jsonl"

APPROVED_SCRIPT_DIR = (DEFENSE_DIR / "approved_scripts").resolve()
APPROVED_TEST_DIR = (WORKSPACE / "tests").resolve()

# Add trusted scripts here, one by one.
# Example:
# APPROVED_PYTHON_SCRIPTS = {
#     str((APPROVED_SCRIPT_DIR / "summarize_pdf.py").resolve()),
# }
APPROVED_PYTHON_SCRIPTS = set()


# ---------------------------------------------------------------------
# General policy
# ---------------------------------------------------------------------

READ_ONLY_COMMANDS = {
    "ls",
    "pwd",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "wc",
    "sed",
    "awk",
}

CONTROLLED_COMMANDS = {
    "python",
    "python3",
    "pytest",
    "pip",
    "git",
}

# Strongly dangerous shell-level patterns.
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

# Sensitive strings should not appear anywhere in the command.
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

# Shell features we do not want the agent to use in a guarded executor.
# Since subprocess.run(..., shell=False) is used, these are not interpreted
# by the shell here, but blocking them reduces confusion and prompt-injection
# tricks.
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

# Python bypass indicators.
PYTHON_DANGEROUS_TOKENS = [
    "os.remove",
    "os.unlink",
    "pathlib.path.unlink",
    ".unlink(",
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "subprocess",
    "os.system",
    "popen",
    "socket",
    "requests",
    "urllib",
    "http.client",
    "ftplib",
    "paramiko",
    "importlib",
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
# Logging and decisions
# ---------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_record(record: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def block(reason: str, command: str) -> None:
    record = {
        "timestamp": now_iso(),
        "decision": "blocked",
        "reason": reason,
        "command": command,
    }
    log_record(record)
    print(json.dumps(record, indent=2, ensure_ascii=False))
    # Use 1 instead of 126. 126 means "command found but not executable",
    # which may cause some tools to retry with another executor.
    sys.exit(1)


def allow(command: str, result: subprocess.CompletedProcess) -> None:
    record = {
        "timestamp": now_iso(),
        "decision": "allowed",
        "command": command,
        "returncode": result.returncode,
    }
    log_record(record)


# ---------------------------------------------------------------------
# Helpers
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
    # Ignore obvious non-path values.
    if not path_text:
        return

    # Flags are handled by command-specific validators.
    if path_text.startswith("-"):
        return

    # Some grep/sed/awk arguments are patterns, not paths. Command-specific
    # validators avoid calling this on those where possible.
    p = Path(path_text)

    if p.is_absolute():
        resolved = p.resolve()
    else:
        resolved = (WORKSPACE / p).resolve()

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
# Read-only command validators
# ---------------------------------------------------------------------

def validate_read_only(executable: str, parts: List[str], command: str) -> None:
    """
    Basic read-only policy.

    This does not mean the Unix command is mathematically incapable of writes
    in every mode; it means we restrict common dangerous flags and paths.
    """

    # pwd has no useful path arguments.
    if executable == "pwd":
        if len(parts) > 1:
            block("pwd with arguments is not approved", command)
        return

    # Block common output/write/edit flags.
    risky_flags = {
        "-i", "--in-place",        # sed -i
        "-exec", "-execdir",       # find -exec
        "-delete",                # find -delete
        "-f", "--files0-from",     # can cause confusing behavior in some tools
    }

    for p in parts[1:]:
        if p in risky_flags:
            block(f"Risky flag for read-only command: {p}", command)

    if executable == "find":
        validate_find(parts, command)
        return

    if executable in {"sed", "awk"}:
        validate_sed_awk(parts, command)
        return

    if executable == "grep":
        validate_grep(parts, command)
        return

    # For cat/head/tail/wc/ls, treat non-option arguments as paths.
    for p in parts[1:]:
        if p.startswith("-"):
            continue
        reject_sensitive_path(p, command)
        reject_path_outside_workspace(p, command)


def validate_find(parts: List[str], command: str) -> None:
    # Allow simple find rooted inside workspace. Block action flags above.
    if len(parts) == 1:
        return

    # First non-option token is usually the search root.
    root_seen = False
    for p in parts[1:]:
        if p.startswith("-"):
            continue
        if not root_seen:
            reject_sensitive_path(p, command)
            reject_path_outside_workspace(p, command)
            root_seen = True
        # Later tokens may be patterns, names, etc.; do not treat all as paths.


def validate_grep(parts: List[str], command: str) -> None:
    # Conservative grep:
    #   grep PATTERN FILE
    #   grep -R PATTERN DIR
    # Do not allow output redirection globally.
    non_options = [p for p in parts[1:] if not p.startswith("-")]

    # First non-option is usually the pattern. Remaining non-options are paths.
    for p in non_options[1:]:
        reject_sensitive_path(p, command)
        reject_path_outside_workspace(p, command)


def validate_sed_awk(parts: List[str], command: str) -> None:
    # Block in-place already. Treat last non-option as path if there is one.
    non_options = [p for p in parts[1:] if not p.startswith("-")]
    if len(non_options) >= 2:
        for p in non_options[1:]:
            reject_sensitive_path(p, command)
            reject_path_outside_workspace(p, command)


# ---------------------------------------------------------------------
# Controlled command validators
# ---------------------------------------------------------------------

def validate_controlled(executable: str, parts: List[str], command: str) -> None:
    if executable in {"python", "python3"}:
        validate_python(parts, command)
    elif executable == "pip":
        validate_pip(parts, command)
    elif executable == "pytest":
        validate_pytest(parts, command)
    elif executable == "git":
        validate_git(parts, command)
    else:
        block(f"Controlled command has no validator: {executable}", command)


def validate_python(parts: List[str], command: str) -> None:
    """
    Python is not generally allowed. It is only allowed for:
      - version checks
      - explicitly approved scripts under defense/approved_scripts/

    Block:
      - python -c ...
      - python -m ...
      - arbitrary .py scripts
    """

    reject_python_bypass_tokens(parts, command)

    if parts in [["python", "--version"], ["python", "-V"], ["python3", "--version"], ["python3", "-V"]]:
        return

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

    script_text = parts[script_index]
    script_path = Path(script_text)
    if script_path.is_absolute():
        script = script_path.resolve()
    else:
        script = (WORKSPACE / script_path).resolve()

    if not is_inside(script, APPROVED_SCRIPT_DIR):
        block(f"Python script outside approved script directory: {script}", command)

    if str(script) not in APPROVED_PYTHON_SCRIPTS:
        block(f"Python script not explicitly approved: {script}", command)

    # Validate all path-like arguments after the script.
    for arg in parts[script_index + 1:]:
        if arg.startswith("-"):
            continue
        reject_sensitive_path(arg, command)
        # Only enforce workspace for arguments that look path-like.
        if "/" in arg or "." in Path(arg).name:
            reject_path_outside_workspace(arg, command)


def validate_pip(parts: List[str], command: str) -> None:
    """
    pip is dangerous because install operations can download and execute code.
    Allow only passive inspection.
    """
    allowed = {
        "--version",
        "-V",
        "list",
        "show",
        "freeze",
    }

    if len(parts) >= 2 and parts[1] in allowed:
        # pip show PACKAGE is okay as package names, but still reject sensitive strings.
        for p in parts[2:]:
            reject_sensitive_path(p, command)
        return

    block("pip command not approved. Install/uninstall/download are blocked.", command)


def validate_pytest(parts: List[str], command: str) -> None:
    """
    pytest can execute arbitrary Python test code. Only allow tests under WORKSPACE/tests.
    """
    if len(parts) < 2:
        block("pytest requires an approved test path", command)

    for p in parts[1:]:
        if p.startswith("-"):
            # Block plugin loading and arbitrary Python execution-ish options.
            if p.startswith("--pyargs") or p.startswith("-p"):
                block(f"pytest option not approved: {p}", command)
            continue

        target = (WORKSPACE / p).resolve()
        if not is_inside(target, APPROVED_TEST_DIR):
            block(f"pytest target outside approved tests directory: {target}", command)


def validate_git(parts: List[str], command: str) -> None:
    """
    Git can access network, overwrite files, and run hooks. Allow read-only inspection only.
    """
    if len(parts) < 2:
        block("git command requires subcommand", command)

    sub = parts[1]

    allowed_subcommands = {
        "status",
        "log",
        "diff",
        "show",
        "branch",
        "rev-parse",
    }

    if sub not in allowed_subcommands:
        block(f"git subcommand not approved: {sub}", command)

    # Block options that can invoke external tools or write.
    blocked_git_tokens = [
        "--output",
        "--exec-path",
        "-c",
        "credential",
        "remote",
        "push",
        "pull",
        "fetch",
        "clone",
        "checkout",
        "reset",
        "clean",
        "submodule",
    ]
    joined = " ".join(parts[1:]).lower()
    for token in blocked_git_tokens:
        if token in joined:
            block(f"git token not approved: {token}", command)


# ---------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        block("No command provided", "")

    command = " ".join(sys.argv[1:]).strip()

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

    executable = os.path.basename(parts[0])

    ensure_cwd_inside_workspace(command)

    if executable in READ_ONLY_COMMANDS:
        validate_read_only(executable, parts, command)
    elif executable in CONTROLLED_COMMANDS:
        validate_controlled(executable, parts, command)
    else:
        block(f"Command not allowlisted: {executable}", command)

    result = subprocess.run(
        parts,
        cwd=str(WORKSPACE),
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )

    allow(command, result)

    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
