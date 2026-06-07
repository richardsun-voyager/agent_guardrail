#!/usr/bin/env python3

import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path


AUDIT_LOG = Path.home() / "defense/logs/audit.log"

BLOCK_PATTERNS = [
    r"\brm\s+-rf\s+/",
    r"\brm\s+-rf\s+\$HOME",
    r"\bdd\s+if=",
    r"\bmkfs\b",
    r":\(\)\s*{\s*:\|:&\s*};:",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r"\biptables\b",
    r"\bufw\s+disable\b",
    r"\bsudo\b",
    r"\bsu\s",
    r"\bchmod\s+777\b",
    r"\bchown\s+-R\b",
    r"\bcurl\b.*\|\s*(sh|bash)",
    r"\bwget\b.*\|\s*(sh|bash)",
    r"\bnc\s+.*-e\b",
    r"\bbash\s+-i\b",
    r"/dev/tcp/",
]

SENSITIVE_READ_PATTERNS = [
    r"\bcat\s+.*\.env\b",
    r"\bcat\s+.*id_rsa\b",
    r"\bcat\s+.*id_ed25519\b",
    r"\bcat\s+.*credentials\b",
    r"\bcat\s+.*token\b",
    r"\bcat\s+.*secret\b",
    r"\bprintenv\b",
    r"\benv\b",
    r"\bgrep\b.*(password|token|secret|api[_-]?key)",
]

APPROVAL_PATTERNS = [
    r"\brm\s+",
    r"\bmv\s+",
    r"\bcp\s+.*\s+/",
    r"\bpip\s+install\b",
    r"\bnpm\s+install\b",
    r"\bapt\s+install\b",
    r"\bapt-get\s+install\b",
    r"\bgit\s+push\b",
    r"\bgit\s+commit\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bssh\b",
    r"\bscp\b",
    r"\brsync\b",
    r"\bcurl\b",
    r"\bwget\b",
]

ALLOWED_PREFIXES = [
    "ls",
    "pwd",
    "whoami",
    "date",
    "echo",
    "find",
    "grep",
    "sed",
    "awk",
    "head",
    "tail",
    "cat",
    "python",
    "python3",
    "pytest",
    "pip show",
    "pip list",
    "git status",
    "git diff",
    "git log",
]


def log_event(event: dict):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    event["time"] = datetime.utcnow().isoformat() + "Z"
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def normalize(command: str) -> str:
    return " ".join(command.strip().split())


def first_token(command: str) -> str:
    try:
        parts = shlex.split(command)
        return parts[0] if parts else ""
    except Exception:
        return command.strip().split()[0] if command.strip() else ""


def matches_any(command: str, patterns: list[str]) -> list[str]:
    hits = []
    for pattern in patterns:
        if re.search(pattern, command, flags=re.IGNORECASE):
            hits.append(pattern)
    return hits


def is_allowed_prefix(command: str) -> bool:
    c = command.strip()
    return any(c == p or c.startswith(p + " ") for p in ALLOWED_PREFIXES)


def evaluate(command: str) -> dict:
    command = normalize(command)

    block_hits = matches_any(command, BLOCK_PATTERNS)
    if block_hits:
        return {
            "decision": "BLOCK",
            "reason": "Dangerous command pattern",
            "matches": block_hits,
        }

    sensitive_hits = matches_any(command, SENSITIVE_READ_PATTERNS)
    if sensitive_hits:
        return {
            "decision": "BLOCK",
            "reason": "Sensitive credential or environment access",
            "matches": sensitive_hits,
        }

    approval_hits = matches_any(command, APPROVAL_PATTERNS)
    if approval_hits:
        return {
            "decision": "REQUIRE_APPROVAL",
            "reason": "Command has side effects or network/file risk",
            "matches": approval_hits,
        }

    if is_allowed_prefix(command):
        return {
            "decision": "ALLOW",
            "reason": "Allowed low-risk command",
            "matches": [],
        }

    return {
        "decision": "REQUIRE_APPROVAL",
        "reason": "Unknown command not on allowlist",
        "matches": [],
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: command_guard.py '<command>'", file=sys.stderr)
        sys.exit(2)

    command = sys.argv[1]
    verdict = evaluate(command)

    log_event({
        "command": command,
        "verdict": verdict,
        "cwd": os.getcwd(),
        "openclaw_shell": os.environ.get("OPENCLAW_SHELL"),
        "user": os.environ.get("USER"),
    })

    if verdict["decision"] == "BLOCK":
        print("[GUARD BLOCKED]", verdict["reason"], file=sys.stderr)
        print("Matches:", verdict["matches"], file=sys.stderr)
        sys.exit(126)

    if verdict["decision"] == "REQUIRE_APPROVAL":
        print("[GUARD APPROVAL REQUIRED]", verdict["reason"], file=sys.stderr)
        print("Command:", command, file=sys.stderr)
        print("Matches:", verdict["matches"], file=sys.stderr)
        sys.exit(125)

    result = subprocess.run(
        ["/bin/bash", "-lc", command],
        text=True,
    )

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()