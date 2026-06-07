#!/usr/bin/env python3

import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE = Path("/home/richardsun/.openclaw/workspace/").resolve()
LOG_PATH = Path("/home/richardsun/.openclaw/workspace/defense/logs/defense_audit.jsonl")

DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bsudo\b",
    r"\bsu\b",
    r"\bchmod\s+777\b",
    r"\bchown\b",
    r"\bcurl\b.*\|\s*(sh|bash)",
    r"\bwget\b.*\|\s*(sh|bash)",
    r"\bnc\b",
    r"\bnetcat\b",
    r"\bssh\b",
    r"\bscp\b",
    r"\brsync\b",
    r"\bmkfs\b",
    r"\bdd\b",
    r"\bmount\b",
    r"\bumount\b",
]

FORBIDDEN_STRINGS = [
    ".ssh",
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secret",
    "token",
    "/etc/passwd",
    "/etc/shadow",
    "/root",
    "/proc",
    "/sys",
]

ALLOWED_COMMANDS = {
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
    "python",
    "python3",
    "pytest",
    "pip",
    "git",
}


def log_record(record):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def block(reason, command):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": "blocked",
        "reason": reason,
        "command": command,
    }
    log_record(record)
    print(json.dumps(record, indent=2))
    sys.exit(126)


def allow(command, result):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": "allowed",
        "command": command,
        "returncode": result.returncode,
    }
    log_record(record)


def main():
    if len(sys.argv) < 2:
        block("No command provided", "")

    command = " ".join(sys.argv[1:]).strip()
    lowered = command.lower()

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, lowered):
            block(f"Dangerous shell pattern: {pattern}", command)

    for item in FORBIDDEN_STRINGS:
        if item.lower() in lowered:
            block(f"Forbidden sensitive string: {item}", command)

    try:
        parts = shlex.split(command)
    except Exception as e:
        block(f"Command parse error: {e}", command)

    if not parts:
        block("Empty command", command)

    executable = os.path.basename(parts[0])

    if executable not in ALLOWED_COMMANDS:
        block(f"Command not allowlisted: {executable}", command)

    cwd = Path.cwd().resolve()
    if not str(cwd).startswith(str(WORKSPACE)):
        block(f"Current directory outside workspace: {cwd}", command)

    result = subprocess.run(
        parts,
        cwd=str(WORKSPACE),
        capture_output=True,
        text=True,
        timeout=20,
    )

    allow(command, result)

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
