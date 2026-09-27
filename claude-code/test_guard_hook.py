import importlib.util
import unittest
from pathlib import Path


PATH = Path(__file__).with_name("guard_hook.py")
SPEC = importlib.util.spec_from_file_location("claude_guard_hook", PATH)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(guard)


class ClaudeGuardHookTests(unittest.TestCase):
    def test_runtime_tool_names_are_normalized(self):
        payload = guard.normalize_event(
            {"tool_name": "WebFetch", "tool_input": {"url": "https://example.com"}}
        )
        self.assertEqual(payload["tool_name"], "web_fetch")
        self.assertEqual(payload["source"], "claude-code")

    def test_three_states(self):
        self.assertIsNone(guard.hook_output({"decision": "allow"}))
        ask = guard.hook_output(
            {"decision": "approval_required", "reason": "review", "approval_id": "a1"}
        )
        deny = guard.hook_output({"decision": "block", "reason": "unsafe"})
        self.assertEqual(ask["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertEqual(deny["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_guard_error_is_fail_closed_in_main_mapping(self):
        deny = guard.hook_output({"decision": "block", "reason": "unreachable"})
        self.assertIn("unreachable", deny["hookSpecificOutput"]["permissionDecisionReason"])


if __name__ == "__main__":
    unittest.main()
