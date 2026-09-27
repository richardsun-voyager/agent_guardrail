#!/usr/bin/env python3
"""Codex PreToolUse adapter for the Agent Guardrail sidecar."""

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
    "apply_patch": "apply_patch",
    "Edit": "edit",
    "Write": "write_file",
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
        paths = patch_paths(arguments.get("command"))
        if paths:
            arguments["path"] = paths
    if event.get("cwd") and "cwd" not in arguments:
        arguments["cwd"] = event["cwd"]
    return {
        "tool_name": TOOL_NAMES.get(tool_name, tool_name),
        "arguments": arguments,
        "session_id": event.get("session_id"),
        "source": "codex",
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
        # No decision preserves Codex's normal sandbox and approval checks.
        return None
    reason = str(decision.get("reason") or "Blocked by Agent Guardrail")
    if effect == "approval_required":
        approval_id = decision.get("approval_id", "none")
        reason = (
            f"Agent Guardrail requires approval ({approval_id}): {reason}. "
            "Codex PreToolUse cannot force an approval prompt; review and perform "
            "the action manually or change policy."
        )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
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
