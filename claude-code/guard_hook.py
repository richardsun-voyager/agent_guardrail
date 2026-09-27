#!/usr/bin/env python3
"""Claude Code PreToolUse adapter for the Agent Guardrail sidecar."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


GUARD_URL = os.environ.get(
    "TOOL_GUARD_URL", "http://127.0.0.1:8765/evaluate_tool_call"
)
TIMEOUT = float(os.environ.get("TOOL_GUARD_TIMEOUT_SECONDS", "5"))
TOOL_NAMES = {
    "Bash": "exec",
    "Read": "read_file",
    "Write": "write_file",
    "Edit": "edit",
    "Glob": "search",
    "Grep": "grep",
    "WebFetch": "web_fetch",
    "WebSearch": "web_search",
}


def patch_paths(command: Any) -> list[str]:
    if not isinstance(command, str):
        return []
    prefixes = ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: ")
    return [
        line[len(prefix):].strip()
        for line in command.splitlines()
        for prefix in prefixes
        if line.startswith(prefix) and line[len(prefix):].strip()
    ]


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(event.get("tool_name") or "")
    raw_input = event.get("tool_input", {})
    arguments = dict(raw_input) if isinstance(raw_input, dict) else {"input": raw_input}
    if tool_name == "apply_patch" and "path" not in arguments:
        paths = patch_paths(arguments.get("command") or arguments.get("patchText"))
        if paths:
            arguments["path"] = paths
    if event.get("cwd") and "cwd" not in arguments:
        arguments["cwd"] = event["cwd"]
    return {
        "tool_name": TOOL_NAMES.get(tool_name, tool_name),
        "arguments": arguments,
        "session_id": event.get("session_id"),
        "source": "claude-code",
        "tool_call_id": event.get("tool_use_id"),
    }


def call_guard(payload: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        GUARD_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            result = json.load(response)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"guard service unavailable: {exc}") from exc
    if not isinstance(result, dict) or result.get("decision") not in {
        "allow",
        "approval_required",
        "block",
    }:
        raise RuntimeError("guard service returned an invalid decision")
    return result


def hook_output(decision: dict[str, Any]) -> dict[str, Any] | None:
    effect = decision.get("decision")
    if effect == "allow":
        # Staying silent keeps Claude Code's normal permission flow intact.
        return None
    permission = "ask" if effect == "approval_required" else "deny"
    reason = str(decision.get("reason") or "Blocked by Agent Guardrail")
    if effect == "approval_required" and decision.get("approval_id"):
        reason = f"{reason} (approval ID: {decision['approval_id']})"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }


def evaluate_event(
    event: dict[str, Any],
    evaluator: Callable[[dict[str, Any]], dict[str, Any]] = call_guard,
) -> dict[str, Any] | None:
    return hook_output(evaluator(normalize_event(event)))


def main() -> int:
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook input must be a JSON object")
        output = evaluate_event(event)
    except Exception as exc:
        output = hook_output({"decision": "block", "reason": str(exc)})
    if output is not None:
        json.dump(output, sys.stdout)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
