import importlib.util
import unittest
from pathlib import Path


PATH = Path(__file__).parent / "hooks" / "guard_hook.py"
SPEC = importlib.util.spec_from_file_location("codex_guard_hook", PATH)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(guard)


class CodexGuardHookTests(unittest.TestCase):
    def test_normalizes_bash_and_context(self):
        payload = guard.normalize_event(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "session_id": "s1",
                "tool_use_id": "t1",
                "cwd": "/repo",
            }
        )
        self.assertEqual(payload["tool_name"], "exec")
        self.assertEqual(payload["arguments"]["cwd"], "/repo")
        self.assertEqual(payload["source"], "codex")

    def test_allow_defers_to_native_permissions(self):
        result = guard.evaluate_event(
            {"tool_name": "Bash", "tool_input": {"command": "pwd"}},
            lambda _: {"decision": "allow"},
        )
        self.assertIsNone(result)

    def test_extracts_apply_patch_paths_for_policy_service(self):
        payload = guard.normalize_event(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "command": "*** Begin Patch\n*** Update File: src/app.py\n*** End Patch"
                },
            }
        )
        self.assertEqual(payload["arguments"]["path"], ["src/app.py"])

    def test_block_and_approval_fail_closed(self):
        blocked = guard.hook_output({"decision": "block", "reason": "unsafe"})
        approval = guard.hook_output(
            {
                "decision": "approval_required",
                "reason": "review",
                "approval_id": "abc",
            }
        )
        self.assertEqual(
            blocked["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertIn("abc", approval["hookSpecificOutput"]["permissionDecisionReason"])


if __name__ == "__main__":
    unittest.main()
