"""
Hermes Agent Tool Guard Plugin
==============================

A lightweight, fail-closed pre-tool-call security plugin for Hermes Agent.

Policy model:
- allow: return None so Hermes executes the tool normally.
- block: return {"action": "block", "message": "..."} so Hermes vetoes the tool.
- approval: Hermes pre_tool_call has no native third state, so this plugin records a
  pending approval item and blocks the current call with an approval message.

Install by copying this directory to:
    ~/.hermes/plugins/tool-guard/

Then enable with:
    hermes plugins enable tool-guard

Audit logs:
    ~/.hermes/tool_guard/audit.jsonl
Pending approvals:
    ~/.hermes/tool_guard/pending/*.json
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping


PLUGIN_NAME = "tool-guard"
BASE_DIR = Path(os.environ.get("HERMES_TOOL_GUARD_DIR", str(Path.home() / ".hermes" / "tool_guard"))).expanduser()
AUDIT_LOG = BASE_DIR / "audit.jsonl"
PENDING_DIR = BASE_DIR / "pending"

# Set this to "0" if you want internal errors to allow instead of block.
# Security recommendation: keep fail-closed enabled.
FAIL_CLOSED = os.environ.get("HERMES_TOOL_GUARD_FAIL_CLOSED", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}

# Optional: comma-separated additional path fragments to block for file tools.
EXTRA_SENSITIVE_PATHS = [
    item.strip()
    for item in os.environ.get("HERMES_TOOL_GUARD_EXTRA_SENSITIVE_PATHS", "").split(",")
    if item.strip()
]

# Optional: if set to "1", medium-risk policy decisions are allowed rather than paused.
# Useful while debugging the plugin; not recommended for defense experiments.
ALLOW_APPROVAL_CLASS = os.environ.get("HERMES_TOOL_GUARD_ALLOW_APPROVAL", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


TERMINAL_TOOLS = {
    "terminal",
    "shell",
    "bash",
    "sh",
    "run_command",
    "exec",
    "execute_command",
}

FILE_WRITE_TOOLS = {
    "write_file",
    "edit_file",
    "file_edit",
    "patch",
    "apply_patch",
    "replace_file",
    "create_file",
}

FILE_READ_TOOLS = {
    "read_file",
    "open_file",
    "cat_file",
}

NETWORK_TOOLS = {
    "web_search",
    "web_extract",
    "browser_navigate",
    "browser_click",
    "http_request",
    "fetch",
    "download",
}

# These are deliberately conservative catastrophic patterns.
BLOCK_PATTERNS = [
    ("root_rm_rf", r"(?<![\w-])rm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)[^\n;|&]*\s+(?:/|~|\$HOME)(?:\s|$)"),
    ("fork_bomb", r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:"),
    ("pipe_to_shell", r"\b(?:curl|wget)\b[^\n;]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|fish)\b"),
    ("block_device_write", r"\bdd\b[^\n;]*(?:of=\s*)/dev/(?:sd[a-z]|nvme\d+n\d+|mmcblk\d+|disk)"),
    ("make_filesystem", r"\bmkfs(?:\.[a-z0-9]+)?\b"),
    ("disk_wipe", r"\b(?:wipefs|shred)\b[^\n;]*(?:/dev/|/\s*$)"),
    ("recursive_world_writable_root", r"\bchmod\s+-R\s+777\s+(?:/|~|\$HOME)(?:\s|$)"),
    ("overwrite_sensitive_unix", r">\s*/etc/(?:passwd|shadow|sudoers)\b"),
]

# Medium-risk patterns. The plugin records a pending approval item and blocks.
APPROVAL_PATTERNS = [
    ("rm", r"(?<![\w-])rm\b"),
    ("mv", r"(?<![\w-])mv\b"),
    ("sudo", r"(?<![\w-])sudo\b"),
    ("chmod", r"(?<![\w-])chmod\b"),
    ("chown", r"(?<![\w-])chown\b"),
    ("pip_install", r"\bpip(?:3)?\s+install\b"),
    ("npm_install", r"\bnpm\s+(?:install|i)\b"),
    ("python_dash_c", r"\bpython(?:3)?\b[^\n;]*\s-c\s+"),
    ("bash_dash_c", r"\b(?:bash|sh|zsh)\b\s+-c\s+"),
    ("git_config", r"\bgit\s+config\b"),
    ("systemctl", r"\bsystemctl\b"),
    ("service", r"\bservice\b"),
]

# Exfiltration endpoints and suspicious webhook patterns.
EXFIL_PATTERNS = [
    ("discord_webhook", r"discord(?:app)?\.com/api/webhooks"),
    ("slack_webhook", r"hooks\.slack\.com/services"),
    ("telegram_bot_api", r"api\.telegram\.org/bot"),
    ("pastebin_api", r"pastebin\.com/api"),
    ("requestbin", r"(?:requestbin|webhook\.site|pipedream\.net)"),
]

SENSITIVE_PATH_FRAGMENTS = [
    ".env",
    ".env.local",
    ".envrc",
    ".ssh/",
    "/.ssh/",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
    "authorized_keys",
    "credentials",
    "credential",
    "secrets",
    "secret",
    "token",
    "api_key",
    "apikey",
    "service-account",
    "service_account",
    "kubeconfig",
    ".kube/config",
    "cli-config.yaml",
    "config.yaml",
] + EXTRA_SENSITIVE_PATHS

SECRET_LIKE_OUTPUT_PATTERNS = [
    ("openai_key", r"sk-[A-Za-z0-9_\-]{20,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("generic_token", r"(?i)(api[_-]?key|access[_-]?token|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{16,}"),
]


def _ensure_dirs() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    PENDING_DIR.mkdir(parents=True, exist_ok=True)


def _json_default(obj: Any) -> str:
    try:
        return str(obj)
    except Exception:
        return "<unserializable>"


def _safe_json_dumps(obj: Any, *, indent: int | None = None) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=_json_default, indent=indent)


def _now() -> float:
    return time.time()


def _log(event: Mapping[str, Any]) -> None:
    _ensure_dirs()
    record = dict(event)
    record.setdefault("plugin", PLUGIN_NAME)
    record.setdefault("ts", _now())
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(_safe_json_dumps(record) + "\n")


def _normalise_tool_name(tool_name: Any) -> str:
    return str(tool_name or "").strip()


def _args_text(args: Any) -> str:
    if isinstance(args, str):
        return args
    try:
        return _safe_json_dumps(args)
    except Exception:
        return str(args)


def _get_nested(mapping: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _command_from_args(args: Any) -> str:
    if isinstance(args, str):
        return args
    if not isinstance(args, Mapping):
        return ""

    direct = _get_nested(
        args,
        [
            "command",
            "cmd",
            "shell_command",
            "input",
            "code",
            "script",
            "query",
        ],
    )
    if direct is not None:
        return str(direct)

    # Some wrappers use {"argv": ["ls", "-la"]}.
    argv = args.get("argv")
    if isinstance(argv, list):
        return " ".join(str(x) for x in argv)

    return ""


def _extract_paths(args: Any) -> list[str]:
    if not isinstance(args, Mapping):
        return []

    paths: list[str] = []
    path_keys = {
        "path",
        "file_path",
        "filepath",
        "filename",
        "target_path",
        "source_path",
        "destination_path",
        "dest_path",
        "new_path",
        "old_path",
    }

    def walk(obj: Any) -> None:
        if isinstance(obj, Mapping):
            for key, value in obj.items():
                if str(key) in path_keys and value is not None:
                    paths.append(str(value))
                else:
                    walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(args)
    return paths


def _match_any(patterns: Iterable[tuple[str, str]], text: str) -> tuple[str, str] | None:
    for name, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            return name, pattern
    return None


def _path_is_sensitive(path: str) -> str | None:
    lowered = path.replace("\\", "/").lower()
    for fragment in SENSITIVE_PATH_FRAGMENTS:
        frag = fragment.replace("\\", "/").lower()
        if frag and frag in lowered:
            return fragment
    return None


def _text_mentions_sensitive_path(text: str) -> str | None:
    lowered = text.replace("\\", "/").lower()
    for fragment in SENSITIVE_PATH_FRAGMENTS:
        frag = fragment.replace("\\", "/").lower()
        if frag and frag in lowered:
            return fragment
    return None


def _record_pending_approval(tool_name: str, args: Any, task_id: str, reason: str, match_name: str | None = None) -> str:
    _ensure_dirs()
    approval_id = str(uuid.uuid4())[:8]
    pending = {
        "approval_id": approval_id,
        "tool_name": tool_name,
        "args": args,
        "task_id": task_id,
        "reason": reason,
        "match_name": match_name,
        "created_at": _now(),
        "status": "pending",
        "note": (
            "Hermes pre_tool_call has no native approval return state. "
            "This record is for manual review; rerun the requested action manually or adjust policy if approved."
        ),
    }
    pending_path = PENDING_DIR / f"{approval_id}.json"
    pending_path.write_text(_safe_json_dumps(pending, indent=2), encoding="utf-8")
    return approval_id


def _decision(tool_name: str, args: Any) -> tuple[str, str, str | None]:
    """Return (decision, reason, match_name). decision is allow | approval | block."""
    tool = _normalise_tool_name(tool_name)
    tool_lower = tool.lower()
    text = _args_text(args)
    command = _command_from_args(args)
    paths = _extract_paths(args)

    # Universal exfil checks across every tool type.
    hit = _match_any(EXFIL_PATTERNS, text)
    if hit:
        name, pattern = hit
        return "block", f"Possible exfiltration endpoint matched: {name}", name

    # File write policy: block writes to secrets/configs.
    if tool_lower in FILE_WRITE_TOOLS:
        for path in paths:
            fragment = _path_is_sensitive(path)
            if fragment:
                return "block", f"Attempt to modify sensitive path fragment: {fragment}", fragment
        fragment = _text_mentions_sensitive_path(text)
        if fragment:
            return "block", f"Attempt to modify sensitive path fragment: {fragment}", fragment

    # File read policy: require approval for secret/config reads, rather than hard-block.
    if tool_lower in FILE_READ_TOOLS:
        for path in paths:
            fragment = _path_is_sensitive(path)
            if fragment:
                return "approval", f"Read of sensitive path fragment requires approval: {fragment}", fragment

    # Terminal/shell command policy.
    if tool_lower in TERMINAL_TOOLS or command:
        scan_target = command or text

        hit = _match_any(BLOCK_PATTERNS, scan_target)
        if hit:
            name, pattern = hit
            return "block", f"Dangerous shell pattern matched: {name}", name

        # Shell commands that mention sensitive paths usually need approval.
        fragment = _text_mentions_sensitive_path(scan_target)
        if fragment:
            return "approval", f"Command references sensitive path fragment: {fragment}", fragment

        hit = _match_any(APPROVAL_PATTERNS, scan_target)
        if hit:
            name, pattern = hit
            return "approval", f"Command requires approval: {name}", name

    # Browser/network policy.
    if tool_lower in NETWORK_TOOLS:
        hit = _match_any(EXFIL_PATTERNS, text)
        if hit:
            name, pattern = hit
            return "block", f"Suspicious network destination matched: {name}", name

    return "allow", "No policy violation", None


def before_tool_call(tool_name: str, args: dict | None = None, task_id: str = "", **kwargs: Any):
    """Hermes pre_tool_call hook: allow by returning None; veto by returning action=block."""
    tool = _normalise_tool_name(tool_name)
    actual_args: Any = args if args is not None else kwargs.get("tool_input", {})

    try:
        decision, reason, match_name = _decision(tool, actual_args)

        if decision == "approval" and ALLOW_APPROVAL_CLASS:
            _log(
                {
                    "hook": "pre_tool_call",
                    "tool_name": tool,
                    "args": actual_args,
                    "task_id": task_id,
                    "decision": "allow",
                    "original_decision": "approval",
                    "reason": reason,
                    "match_name": match_name,
                }
            )
            return None

        _log(
            {
                "hook": "pre_tool_call",
                "tool_name": tool,
                "args": actual_args,
                "task_id": task_id,
                "decision": decision,
                "reason": reason,
                "match_name": match_name,
            }
        )

        if decision == "allow":
            return None

        if decision == "block":
            return {"action": "block", "message": f"Blocked by {PLUGIN_NAME}: {reason}"}

        if decision == "approval":
            approval_id = _record_pending_approval(tool, actual_args, task_id, reason, match_name)
            return {
                "action": "block",
                "message": (
                    f"Tool call paused by {PLUGIN_NAME}; approval required.\n"
                    f"Approval ID: {approval_id}\n"
                    f"Reason: {reason}\n"
                    f"Review pending approval at: {PENDING_DIR / (approval_id + '.json')}"
                ),
            }

        return None

    except Exception as exc:  # fail closed for a security plugin
        _log(
            {
                "hook": "pre_tool_call",
                "tool_name": tool,
                "args": actual_args,
                "task_id": task_id,
                "decision": "block" if FAIL_CLOSED else "allow",
                "reason": f"internal error: {exc!r}",
            }
        )
        if FAIL_CLOSED:
            return {
                "action": "block",
                "message": f"Blocked by {PLUGIN_NAME}: internal guard error; failing closed: {exc}",
            }
        return None


def post_tool_call(
    tool_name: str,
    args: dict | None = None,
    result: str | None = None,
    task_id: str = "",
    duration_ms: int | None = None,
    **kwargs: Any,
):
    """Observer hook for audit logging after a tool call."""
    try:
        _log(
            {
                "hook": "post_tool_call",
                "tool_name": _normalise_tool_name(tool_name),
                "args": args,
                "task_id": task_id,
                "duration_ms": duration_ms,
                "result_preview": str(result or "")[:1000],
            }
        )
    except Exception:
        # Observer hook: never raise.
        return None
    return None


def pre_approval_request(
    command: str = "",
    description: str = "",
    pattern_key: str = "",
    pattern_keys: list[str] | None = None,
    session_key: str = "",
    surface: str = "",
    **kwargs: Any,
):
    """Observer hook for Hermes's built-in approval system."""
    try:
        _log(
            {
                "hook": "pre_approval_request",
                "command": command,
                "description": description,
                "pattern_key": pattern_key,
                "pattern_keys": pattern_keys or [],
                "session_key": session_key,
                "surface": surface,
            }
        )
    except Exception:
        return None
    return None


def post_approval_response(
    command: str = "",
    choice: str = "",
    description: str = "",
    pattern_key: str = "",
    pattern_keys: list[str] | None = None,
    session_key: str = "",
    surface: str = "",
    **kwargs: Any,
):
    """Observer hook for Hermes's built-in approval result."""
    try:
        _log(
            {
                "hook": "post_approval_response",
                "command": command,
                "choice": choice,
                "description": description,
                "pattern_key": pattern_key,
                "pattern_keys": pattern_keys or [],
                "session_key": session_key,
                "surface": surface,
            }
        )
    except Exception:
        return None
    return None


def register(ctx: Any) -> None:
    """Hermes plugin entry point."""
    _ensure_dirs()
    ctx.register_hook("pre_tool_call", before_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("pre_approval_request", pre_approval_request)
    ctx.register_hook("post_approval_response", post_approval_response)
