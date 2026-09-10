#!/usr/bin/env python3
"""
tool_guard_service.py

Python sidecar guard for OpenClaw-style before_tool_call protection.

It evaluates proposed tool calls before execution and returns one of:
  - allow
  - block
  - approval_required

Run:
  python3 tool_guard_service.py

Default endpoint:
  POST http://127.0.0.1:8765/evaluate_tool_call

Environment variables:
  TOOL_GUARD_HOST                         default: 127.0.0.1
  TOOL_GUARD_PORT                         default: 8765
  TOOL_GUARD_WORKSPACE                    default: ~/.openclaw/workspace
  TOOL_GUARD_TRUSTED_DESTINATIONS         comma-separated host allowlist
  TOOL_GUARD_SESSION_APPROVAL_THRESHOLD   default: 4
  TOOL_GUARD_SESSION_BLOCK_THRESHOLD      default: 8
  TOOL_GUARD_SESSION_RISK_DECAY_SECONDS   default: 300
  TOOL_GUARD_SESSION_RISK_TTL_SECONDS     default: 1800
  TOOL_GUARD_SESSION_RISK_MAX_SESSIONS    default: 10000
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

WORKSPACE = Path(
    os.environ.get(
        "TOOL_GUARD_WORKSPACE", str(Path.home() / ".openclaw" / "workspace")
    )
).resolve()

DEFENSE_DIR = WORKSPACE / "defense"
LOG_PATH = DEFENSE_DIR / "logs" / "tool_guard_audit.jsonl"
PENDING_APPROVAL_PATH = DEFENSE_DIR / "logs" / "tool_guard_pending.jsonl"

SENSITIVE_PATH_PATTERNS = [
    ".env",
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credential",
    "secret",
    "secrets",
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
]

HIGH_SENSITIVITY_PATH_HINTS = [
    "contact",
    "contacts",
    "beneficiar",
    "payroll",
    "treasury",
    "wallet",
    "routing",
    "account",
    "email-archive",
    "inbox",
    "slack-exports",
    "credential",
    "secret",
]

MEDIUM_SENSITIVITY_PATH_HINTS = [
    "incident",
    "audit",
    "notes",
    "finance",
    "settlement",
]

CONTENT_BLOCK_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("api_token", re.compile(r"\b(?:api[_-]?key|token|password|secret)\b\s*[:=]\s*[^\s,;]+", re.IGNORECASE)),
    ("wire_auth_token", re.compile(r"WIRE-AUTH-[A-Z0-9-]+", re.IGNORECASE)),
    ("swift_auth_token", re.compile(r"SWIFT-MT103-AUTH-[A-Z0-9-]+", re.IGNORECASE)),
    ("ach_auth_token", re.compile(r"ACH-BATCH-AUTH-[A-Z0-9-]+", re.IGNORECASE)),
    ("treasury_key", re.compile(r"TRSRY-KEY-[A-Z0-9-]+", re.IGNORECASE)),
]

CONTENT_APPROVAL_PATTERNS = [
    ("phone_number", re.compile(r"\+?\d[\d\-\s()]{7,}\d")),
    ("email_address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("crypto_wallet", re.compile(r"\bbc1[ac-hj-np-z02-9]{20,}\b", re.IGNORECASE)),
    ("bank_routing_or_account", re.compile(r"\b\d{9,12}\b")),
]

MAX_SCAN_BYTES = int(os.environ.get("TOOL_GUARD_MAX_SCAN_BYTES", "32768"))

TRUSTED_DESTINATIONS = {
    host.strip().lower().rstrip(".")
    for host in os.environ.get("TOOL_GUARD_TRUSTED_DESTINATIONS", "").split(",")
    if host.strip()
}

SESSION_RISK_APPROVAL_THRESHOLD = max(
    1, int(os.environ.get("TOOL_GUARD_SESSION_APPROVAL_THRESHOLD", "4"))
)
SESSION_RISK_BLOCK_THRESHOLD = max(
    SESSION_RISK_APPROVAL_THRESHOLD + 1,
    int(os.environ.get("TOOL_GUARD_SESSION_BLOCK_THRESHOLD", "8")),
)
SESSION_RISK_DECAY_SECONDS = max(
    1, int(os.environ.get("TOOL_GUARD_SESSION_RISK_DECAY_SECONDS", "300"))
)
SESSION_RISK_TTL_SECONDS = max(
    SESSION_RISK_DECAY_SECONDS,
    int(os.environ.get("TOOL_GUARD_SESSION_RISK_TTL_SECONDS", "1800")),
)
SESSION_RISK_MAX_SESSIONS = max(
    1, int(os.environ.get("TOOL_GUARD_SESSION_RISK_MAX_SESSIONS", "10000"))
)

DANGEROUS_COMMAND_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\brm\b",
    r"\bsudo\b",
    r"\bsu\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bmkfs\b",
    r"\bdd\b",
    r"\bmount\b",
    r"\bumount\b",
    r"\bkill\b",
    r"\bpkill\b",
    r"\bsystemctl\b",
    r"\bservice\b",
    r"\bdocker\b",
    r"\bcurl\b.*\|\s*(sh|bash|python|python3)",
    r"\bwget\b.*\|\s*(sh|bash|python|python3)",
    r"\bnc\b",
    r"\bnetcat\b",
    r"\bssh\b",
    r"\bscp\b",
    r"\brsync\b",
]

EXFIL_DOMAINS = [
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org/bot",
    "hooks.slack.com",
    "webhook.site",
    "requestbin",
    "ngrok",
    "pastebin.com",
]

READ_ONLY_TOOLS = {
    "read",
    "read_file",
    "list",
    "ls",
    "grep",
    "search",
    "web_search",
}

WRITE_TOOLS = {
    "write",
    "write_file",
    "edit",
    "apply_patch",
    "delete_file",
    "move_file",
    "rename_file",
}

NETWORK_TOOLS = {
    "web_fetch",
    "browser",
    "http_request",
    "fetch",
    "download",
}

SHELL_TOOLS = {
    "exec",
    "shell",
    "run_command",
    "bash",
}

LOW_RISK_SHELL_COMMANDS = {
    "date",
    "echo",
    "ls",
    "pwd",
    "uname",
    "whoami",
}

READ_ONLY_SHELL_COMMANDS = {
    "cat",
    "find",
    "grep",
    "head",
    "tail",
    "wc",
}

COMMAND_SUBCOMMAND_POLICY = {
    "git": {
        "allow": {"status", "diff", "log", "show", "rev-parse"},
        "block": {"clean"},
    },
    "npm": {"allow": {"view", "search"}, "block": set()},
    "pip": {"allow": {"show", "list", "freeze", "check"}, "block": set()},
    "pip3": {"allow": {"show", "list", "freeze", "check"}, "block": set()},
}

PATH_OPERAND_COMMANDS = READ_ONLY_SHELL_COMMANDS | {"ls", "mkdir"}
URL_KEYS = {
    "url",
    "uri",
    "endpoint",
    "base_url",
    "destination",
    "destination_url",
    "webhook_url",
    "callback_url",
    "host",
}

# Process-local trajectory state. Scores are bounded, decay, and eventually expire.
SESSION_RISK: Dict[str, Dict[str, float]] = {}


# ---------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------

def now_ts() -> float:
    return time.time()


def write_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def audit(record: Dict[str, Any]) -> None:
    write_jsonl(LOG_PATH, {"timestamp": now_ts(), **record})


# ---------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------

def contains_sensitive_text(value: str) -> Optional[str]:
    lowered = value.lower()
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.lower() in lowered:
            return pattern
    return None


def resolve_workspace_path(path_text: str) -> Optional[Path]:
    try:
        p = Path(path_text)
        resolved = p.resolve() if p.is_absolute() else (WORKSPACE / p).resolve()
        resolved.relative_to(WORKSPACE)
        return resolved
    except Exception:
        return None


def is_inside_workspace(path_text: str) -> bool:
    return resolve_workspace_path(path_text) is not None


def classify_path_sensitivity(path: Path) -> Optional[str]:
    lowered = path.as_posix().lower()
    for hint in HIGH_SENSITIVITY_PATH_HINTS:
        if hint in lowered:
            return "high"
    for hint in MEDIUM_SENSITIVITY_PATH_HINTS:
        if hint in lowered:
            return "medium"
    return None


def scan_file_content(path: Path) -> Optional[Dict[str, str]]:
    if not path.exists() or not path.is_file():
        return None

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            sample = f.read(MAX_SCAN_BYTES)
    except OSError:
        return None

    for label, pattern in CONTENT_BLOCK_PATTERNS:
        if pattern.search(sample):
            return {"severity": "block", "label": label}

    for label, pattern in CONTENT_APPROVAL_PATTERNS:
        if pattern.search(sample):
            return {"severity": "approval", "label": label}

    return None


def shell_paths_are_inside_workspace(parts: list[str]) -> bool:
    for part in parts:
        if part.startswith("-"):
            continue
        if resolve_workspace_path(part) is None:
            return False
    return True


def shell_path_operands(parts: list[str]) -> list[str]:
    """Return path operands for commands whose positional arguments are paths."""
    operands: list[str] = []
    skip_next = False
    for part in parts:
        if skip_next:
            skip_next = False
            continue
        if part in {"-C", "--directory", "--exclude", "-e"}:
            skip_next = True
            continue
        if not part.startswith("-"):
            operands.append(part)
    return operands


def option_paths(parts: list[str], option_names: set[str]) -> list[str]:
    """Extract path values from `--option value` and `--option=value`."""
    paths: list[str] = []
    for index, part in enumerate(parts):
        if part in option_names and index + 1 < len(parts):
            paths.append(parts[index + 1])
            continue
        for name in option_names:
            prefix = f"{name}="
            if part.startswith(prefix):
                paths.append(part[len(prefix):])
            elif len(name) == 2 and part.startswith(name) and part != name:
                paths.append(part[len(name):])
    return paths


def extract_candidate_paths(args: Dict[str, Any]) -> list[str]:
    """
    Extract likely file paths from arbitrary tool arguments.
    Different tools use different schemas, so this is intentionally generic.
    """
    path_keys = {
        "path",
        "file",
        "filepath",
        "file_path",
        "filename",
        "target",
        "source",
        "destination",
        "src",
        "dst",
        "cwd",
        "workdir",
        "working_directory",
        "directory",
        "root",
        "output_path",
    }

    paths: list[str] = []

    def walk(obj: Any, key_hint: Optional[str] = None) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in path_keys:
                    walk(v, key_hint=k.lower())
                else:
                    walk(v, key_hint=None)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, key_hint=key_hint)
        elif isinstance(obj, str):
            if key_hint in path_keys and not looks_like_url(obj):
                paths.append(obj)

    walk(args)
    return paths


def looks_like_url(value: str) -> bool:
    try:
        return urlparse(value).scheme.lower() in {"http", "https"}
    except ValueError:
        return False


def extract_destinations(args: Dict[str, Any]) -> list[str]:
    destinations: list[str] = []

    def walk(obj: Any, key_hint: Optional[str] = None) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                walk(value, key.lower())
        elif isinstance(obj, list):
            for item in obj:
                walk(item, key_hint)
        elif isinstance(obj, str) and (key_hint in URL_KEYS or looks_like_url(obj)):
            destinations.append(obj)

    walk(args)
    return destinations


def classify_destination(destination: str) -> tuple[str, str]:
    """Classify a destination as trusted, untrusted, or blocked."""
    try:
        value = destination if "://" in destination else f"https://{destination}"
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return "blocked", "Malformed network destination"

    if scheme not in {"http", "https"} or not hostname:
        return "blocked", "Only explicit HTTP(S) destinations are permitted"
    if parsed.username or parsed.password:
        return "blocked", "Credentials embedded in destination URL"
    if any(domain in destination.lower() for domain in EXFIL_DOMAINS):
        return "blocked", "Known exfiltration/webhook destination"
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return "blocked", "Loopback destination is not trusted"

    try:
        address = ipaddress.ip_address(hostname)
        if not address.is_global:
            return "blocked", "Private or non-global IP destination"
    except ValueError:
        pass

    try:
        port = parsed.port
    except ValueError:
        return "blocked", "Malformed network destination port"

    trusted = any(
        hostname == domain or hostname.endswith(f".{domain}")
        for domain in TRUSTED_DESTINATIONS
    )
    if trusted and scheme == "https" and port in {None, 443}:
        return "trusted", "Destination is allowlisted"
    if trusted:
        return "untrusted", "Allowlisted host uses an untrusted scheme or port"
    return "untrusted", "Destination is not allowlisted"


def serialize_args(args: Dict[str, Any]) -> str:
    try:
        return json.dumps(args, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(args)


# ---------------------------------------------------------------------
# Decision helpers
# ---------------------------------------------------------------------

def allow(reason: str) -> Dict[str, Any]:
    return {"decision": "allow", "reason": reason}


def block(reason: str) -> Dict[str, Any]:
    return {"decision": "block", "reason": reason}


def require_approval(reason: str, risk: str = "medium") -> Dict[str, Any]:
    approval_id = uuid.uuid4().hex[:16]
    return {
        "decision": "approval_required",
        "approval_id": approval_id,
        "risk": risk,
        "reason": reason,
    }


def apply_session_risk(
    decision: Dict[str, Any], session_id: Any
) -> Dict[str, Any]:
    """Accumulate bounded risk and escalate otherwise-permitted trajectories."""
    if not session_id:
        return decision

    key = str(session_id)
    now = now_ts()
    if key not in SESSION_RISK and len(SESSION_RISK) >= SESSION_RISK_MAX_SESSIONS:
        expired = [
            session
            for session, item in SESSION_RISK.items()
            if now - item["updated"] >= SESSION_RISK_TTL_SECONDS
        ]
        for session in expired:
            SESSION_RISK.pop(session, None)
        if len(SESSION_RISK) >= SESSION_RISK_MAX_SESSIONS:
            oldest = min(
                SESSION_RISK,
                key=lambda session: SESSION_RISK[session]["updated"],
            )
            SESSION_RISK.pop(oldest)

    state = SESSION_RISK.get(key, {"score": 0.0, "updated": now})
    elapsed = max(0.0, now - state["updated"])
    if elapsed >= SESSION_RISK_TTL_SECONDS:
        score = 0
    else:
        score = max(
            0,
            int(state["score"]) - int(elapsed // SESSION_RISK_DECAY_SECONDS),
        )

    risk = str(decision.get("risk", "low"))
    increment = {"low": 0, "medium": 2, "high": 3}.get(risk, 1)
    if decision["decision"] == "block":
        increment = max(increment, 4)
    score = min(SESSION_RISK_BLOCK_THRESHOLD, score + increment)
    SESSION_RISK[key] = {"score": float(score), "updated": now}

    if decision["decision"] != "block" and score >= SESSION_RISK_BLOCK_THRESHOLD:
        decision = block("Session risk threshold exceeded")
    elif decision["decision"] == "allow" and score >= SESSION_RISK_APPROVAL_THRESHOLD:
        decision = require_approval(
            "Accumulated session risk requires approval", risk="high"
        )

    decision["session_risk_score"] = score
    return decision


# ---------------------------------------------------------------------
# Tool-specific evaluators
# ---------------------------------------------------------------------

def evaluate_shell_tool(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    command = str(args.get("command") or args.get("cmd") or args.get("input") or "")

    if not command.strip():
        return block("Shell tool call has no command")

    sensitive = contains_sensitive_text(command)
    if sensitive:
        return block(f"Shell command references sensitive string: {sensitive}")

    lowered = command.lower()
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, lowered):
            return block(f"Dangerous shell command pattern: {pattern}")

    for token in ["&&", "||", ";", "|", "`", "$(", ">", ">>", "<"]:
        if token in command:
            return block(f"Forbidden shell metacharacter: {token}")

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return block(f"Invalid shell command syntax: {exc}")

    if not parts:
        return block("Shell tool call has no command")

    first_word = parts[0]
    command_args = parts[1:]

    option_assigned_paths = [
        part.split("=", 1)[1]
        for part in command_args
        if part.startswith("-")
        and "=" in part
        and part.split("=", 1)[1].startswith(("/", "./", "../", "~"))
    ]
    if not shell_paths_are_inside_workspace(option_assigned_paths):
        return block(f"{first_word} option path outside workspace")

    if first_word in PATH_OPERAND_COMMANDS:
        operands = shell_path_operands(command_args)
        if operands and not shell_paths_are_inside_workspace(operands):
            return block(f"{first_word} path outside workspace")

    if first_word in LOW_RISK_SHELL_COMMANDS:
        return allow("Read-only shell command appears low risk")

    if first_word in READ_ONLY_SHELL_COMMANDS:
        return allow("Read-only shell command appears low risk")

    if first_word == "mkdir":
        if not command_args:
            return block("mkdir requires at least one path")
        if shell_paths_are_inside_workspace(command_args):
            return allow("mkdir creates directories inside workspace")
        return block("mkdir path outside workspace")

    if first_word in {"curl", "wget"}:
        output_paths = option_paths(command_args, {"-o", "-O", "--output"})
        if not shell_paths_are_inside_workspace(output_paths):
            return block(f"{first_word} output path outside workspace")
        destinations = [part for part in command_args if looks_like_url(part)]
        method = "GET"
        if first_word == "curl":
            for index, part in enumerate(command_args):
                if part in {"-X", "--request"} and index + 1 < len(command_args):
                    method = command_args[index + 1].upper()
                elif part.startswith("--request="):
                    method = part.split("=", 1)[1].upper()
                elif part.startswith("-X") and part != "-X":
                    method = part[2:].upper()
                elif part in {"-d", "--data", "--data-raw", "--data-binary"}:
                    method = "POST"
                elif part.startswith(("-d", "--data=")):
                    method = "POST"
        network_decision = evaluate_network_tool(
            first_word, {"url": destinations, "method": method}
        )
        if network_decision["decision"] != "allow":
            return network_decision
        return require_approval(
            f"Shell network command requires approval: {first_word}", risk="medium"
        )

    policy = COMMAND_SUBCOMMAND_POLICY.get(first_word)
    if policy is not None:
        if first_word == "git":
            if "--no-index" in command_args:
                return block("git --no-index can access paths outside the repository")
            configured_paths = option_paths(
                command_args, {"-C", "--git-dir", "--work-tree", "--output"}
            )
            if not shell_paths_are_inside_workspace(configured_paths):
                return block("git path option outside workspace")
            if option_paths(command_args, {"--output"}):
                return require_approval(
                    "git output file requires approval", risk="medium"
                )
            explicit_paths = [
                part
                for part in command_args
                if part.startswith(("/", "./", "../", "~"))
            ]
            if not shell_paths_are_inside_workspace(explicit_paths):
                return block("git path operand outside workspace")
        subcommand = next(
            (
                part
                for index, part in enumerate(command_args)
                if not part.startswith("-")
                and (
                    index == 0
                    or command_args[index - 1]
                    not in {"-C", "--git-dir", "--work-tree"}
                )
            ),
            "",
        )
        if not subcommand:
            return require_approval(
                f"{first_word} command has no recognized subcommand"
            )
        if subcommand in policy["block"]:
            return block(f"Blocked command policy: {first_word} {subcommand}")
        if subcommand in policy["allow"]:
            return allow(f"Allowed command policy: {first_word} {subcommand}")
        return require_approval(
            f"Command policy requires approval: {first_word} {subcommand}",
            risk="medium",
        )

    if first_word in {"python", "python3", "node"}:
        return require_approval(
            f"Interpreter execution requires human approval: {first_word}",
            risk="high",
        )

    return require_approval(
        f"Shell command requires human approval: {first_word}",
        risk="medium",
    )


def evaluate_file_tool(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    paths = extract_candidate_paths(args)
    resolved_paths: list[Path] = []

    if not paths:
        return block(f"File tool call has no path: {tool_name}")

    for path in paths:
        sensitive = contains_sensitive_text(path)
        if sensitive:
            return block(f"File path references sensitive string: {sensitive}")

        resolved = resolve_workspace_path(path)
        if resolved is None:
            return block(f"File path outside workspace: {path}")
        resolved_paths.append(resolved)

    normalized = tool_name.lower()

    if normalized in {"read", "read_file"}:
        for original_path, resolved_path in zip(paths, resolved_paths):
            sensitivity = classify_path_sensitivity(resolved_path)
            content_hit = scan_file_content(resolved_path)

            if content_hit and content_hit["severity"] == "block":
                return block(
                    f"Read blocked: {original_path} matched sensitive content pattern {content_hit['label']}"
                )

            if sensitivity == "high":
                reason = f"High-sensitivity workspace file read: {original_path}"
                if content_hit:
                    reason += f" (matched {content_hit['label']})"
                return require_approval(reason, risk="high")

            if content_hit and content_hit["severity"] == "approval":
                return require_approval(
                    f"Read may expose sensitive content ({content_hit['label']}): {original_path}",
                    risk="high" if sensitivity == "medium" else "medium",
                )

            if sensitivity == "medium":
                return require_approval(
                    f"Medium-sensitivity workspace file read: {original_path}",
                    risk="medium",
                )

        return allow("Read tool call is inside workspace, low-sensitivity, and content scan is clean")

    if normalized in WRITE_TOOLS:
        return require_approval(
            f"Write-like tool requires approval: {tool_name}",
            risk="medium",
        )

    return require_approval(
        f"Unknown file-related tool requires approval: {tool_name}",
        risk="medium",
    )


def evaluate_network_tool(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    serialized = serialize_args(args).lower()

    sensitive = contains_sensitive_text(serialized)
    if sensitive:
        return block(f"Network request appears to include sensitive string: {sensitive}")

    destinations = extract_destinations(args)
    if not destinations:
        return block("Network tool call has no explicit destination")

    untrusted = False
    for destination in destinations:
        trust, reason = classify_destination(destination)
        if trust == "blocked":
            return block(f"Blocked network destination: {reason}: {destination}")
        if trust == "untrusted":
            untrusted = True

    method = str(args.get("method", "GET")).upper()

    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return require_approval(
            f"Network method {method} can send or modify data",
            risk="high",
        )

    if untrusted:
        return require_approval(
            "Read request to an untrusted destination", risk="medium"
        )

    return allow("Read request targets a trusted destination")


def evaluate_unknown_tool(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    serialized = serialize_args(args)

    sensitive = contains_sensitive_text(serialized)
    if sensitive:
        return block(f"Unknown tool call references sensitive string: {sensitive}")

    return require_approval(
        f"Unknown tool requires approval: {tool_name}",
        risk="medium",
    )


# ---------------------------------------------------------------------
# Main policy evaluator
# ---------------------------------------------------------------------

def evaluate_tool_call(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Expected payload shape:

    {
      "tool_name": "exec",
      "arguments": {"command": "ls -la"},
      "session_id": "...",
      "user_id": "...",
      "source": "telegram|browser|agent|skill",
      "skill_id": "optional"
    }
    """
    tool_name = str(payload.get("tool_name") or payload.get("name") or "").strip()
    args = payload.get("arguments") or payload.get("args") or {}

    if not isinstance(args, dict):
        return block("Tool arguments must be a JSON object")

    if not tool_name:
        return block("Missing tool_name")

    normalized = tool_name.lower()

    # Enforce the workspace invariant for every tool schema, including plugins
    # and network tools that also carry local source or destination paths.
    decision: Optional[Dict[str, Any]] = None
    for candidate in extract_candidate_paths(args):
        sensitive = contains_sensitive_text(candidate)
        if sensitive:
            decision = block(f"Tool path references sensitive string: {sensitive}")
            break
        if not is_inside_workspace(candidate):
            decision = block(f"Tool path outside workspace: {candidate}")
            break

    if decision is not None:
        pass
    elif normalized in SHELL_TOOLS:
        decision = evaluate_shell_tool(normalized, args)
    elif normalized in WRITE_TOOLS or normalized in {"read", "read_file"}:
        decision = evaluate_file_tool(normalized, args)
    elif normalized in NETWORK_TOOLS:
        decision = evaluate_network_tool(normalized, args)
    elif normalized in READ_ONLY_TOOLS:
        decision = allow("Known read-only tool")
    else:
        decision = evaluate_unknown_tool(normalized, args)

    decision = apply_session_risk(decision, payload.get("session_id"))

    if decision["decision"] == "approval_required":
        write_jsonl(PENDING_APPROVAL_PATH, {
            "approval_id": decision["approval_id"],
            "status": "pending",
            "risk": decision["risk"],
            "reason": decision["reason"],
            "timestamp": now_ts(),
            "session_id": payload.get("session_id"),
        })

    audit({
        "event": "before_tool_call_evaluation",
        "tool_name": tool_name,
        "arguments": args,
        "source": payload.get("source"),
        "session_id": payload.get("session_id"),
        "user_id": payload.get("user_id"),
        "skill_id": payload.get("skill_id"),
        "decision": decision,
    })

    return decision


# ---------------------------------------------------------------------
# Minimal HTTP server
# ---------------------------------------------------------------------

class GuardHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, obj: Dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep stdout clean. Audit logs are written to JSONL.
        return

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"ok": True, "workspace": str(WORKSPACE)})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/evaluate_tool_call":
            self._send_json(404, {"error": "not_found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"decision": "block", "reason": f"Invalid JSON: {e}"})
            return

        try:
            decision = evaluate_tool_call(payload)
            self._send_json(200, decision)
        except Exception as e:
            # Fail closed.
            self._send_json(500, {
                "decision": "block",
                "reason": f"Guard internal error: {e}",
            })


def main() -> None:
    host = os.environ.get("TOOL_GUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("TOOL_GUARD_PORT", "8765"))
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    server = HTTPServer((host, port), GuardHandler)
    print(f"Tool guard service listening on http://{host}:{port}")
    print(f"Workspace: {WORKSPACE}")
    server.serve_forever()


if __name__ == "__main__":
    main()
