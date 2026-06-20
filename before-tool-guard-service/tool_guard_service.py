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
  TOOL_GUARD_HOST       default: 127.0.0.1
  TOOL_GUARD_PORT       default: 8765
  TOOL_GUARD_WORKSPACE  default: /home/richardsun/.openclaw/workspace
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

WORKSPACE = Path(
    os.environ.get("TOOL_GUARD_WORKSPACE", "/home/richardsun/.openclaw/workspace")
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
            if key_hint in path_keys:
                paths.append(obj)

    walk(args)
    return paths


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
    record = {
        "approval_id": approval_id,
        "status": "pending",
        "risk": risk,
        "reason": reason,
        "timestamp": now_ts(),
    }
    write_jsonl(PENDING_APPROVAL_PATH, record)
    return {
        "decision": "approval_required",
        "approval_id": approval_id,
        "risk": risk,
        "reason": reason,
    }


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

    first_word = command.strip().split()[0]
    if first_word in {"ls", "pwd", "cat", "head", "tail", "grep", "find", "wc"}:
        return allow("Read-only shell command appears low risk")

    return require_approval(
        f"Shell command requires human approval: {first_word}",
        risk="medium",
    )


def evaluate_file_tool(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    paths = extract_candidate_paths(args)
    resolved_paths: list[Path] = []

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

    for domain in EXFIL_DOMAINS:
        if domain.lower() in serialized:
            return block(f"Known exfiltration/webhook destination: {domain}")

    method = str(args.get("method", "GET")).upper()

    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return require_approval(
            f"Network method {method} can send or modify data",
            risk="high",
        )

    return allow("Network request appears read-only")


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

    if normalized in SHELL_TOOLS:
        decision = evaluate_shell_tool(normalized, args)
    elif normalized in WRITE_TOOLS or normalized in {"read", "read_file"}:
        decision = evaluate_file_tool(normalized, args)
    elif normalized in NETWORK_TOOLS:
        decision = evaluate_network_tool(normalized, args)
    elif normalized in READ_ONLY_TOOLS:
        decision = allow("Known read-only tool")
    else:
        decision = evaluate_unknown_tool(normalized, args)

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
