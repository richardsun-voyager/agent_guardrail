import importlib.util
import tempfile
import time
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("tool_guard_service.py")
SPEC = importlib.util.spec_from_file_location("tool_guard_service", MODULE_PATH)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(guard)


class ToolGuardV11Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        guard.WORKSPACE = Path(self.temp_dir.name).resolve()
        guard.DEFENSE_DIR = guard.WORKSPACE / "defense"
        guard.LOG_PATH = guard.DEFENSE_DIR / "logs" / "audit.jsonl"
        guard.PENDING_APPROVAL_PATH = guard.DEFENSE_DIR / "logs" / "pending.jsonl"
        guard.TRUSTED_DESTINATIONS.clear()
        guard.SESSION_RISK.clear()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_command_and_subcommand_policy(self):
        self.assertEqual(
            guard.evaluate_shell_tool("exec", {"command": "git status"})["decision"],
            "allow",
        )
        self.assertEqual(
            guard.evaluate_shell_tool("exec", {"command": "git push origin main"})[
                "decision"
            ],
            "approval_required",
        )
        self.assertEqual(
            guard.evaluate_shell_tool("exec", {"command": "git clean -fd"})[
                "decision"
            ],
            "block",
        )
        interpreter = guard.evaluate_shell_tool(
            "exec", {"command": "python3 -c 'print(1)'"}
        )
        self.assertEqual(interpreter["decision"], "approval_required")
        self.assertEqual(interpreter["risk"], "high")

    def test_shell_paths_and_git_directory_are_confined(self):
        self.assertEqual(
            guard.evaluate_shell_tool("exec", {"command": "ls /etc"})["decision"],
            "block",
        )
        self.assertEqual(
            guard.evaluate_shell_tool("exec", {"command": "git -C /tmp status"})[
                "decision"
            ],
            "block",
        )
        self.assertEqual(
            guard.evaluate_shell_tool(
                "exec", {"command": "git --git-dir=/tmp/repo status"}
            )["decision"],
            "block",
        )
        self.assertEqual(
            guard.evaluate_shell_tool(
                "exec", {"command": "git diff --no-index inside.txt /etc/passwd"}
            )["decision"],
            "block",
        )
        self.assertEqual(
            guard.evaluate_shell_tool(
                "exec", {"command": "wc --files0-from=/etc/passwd"}
            )["decision"],
            "block",
        )
        self.assertEqual(
            guard.evaluate_shell_tool(
                "exec", {"command": "git log --output=history.txt"}
            )["decision"],
            "approval_required",
        )

    def test_shell_network_commands_use_destination_policy(self):
        guard.TRUSTED_DESTINATIONS.add("example.com")
        trusted = guard.evaluate_shell_tool(
            "exec", {"command": "curl https://example.com/data"}
        )
        private = guard.evaluate_shell_tool(
            "exec", {"command": "curl http://127.0.0.1/admin"}
        )
        outside_output = guard.evaluate_shell_tool(
            "exec", {"command": "wget -O/tmp/result https://example.com/data"}
        )
        post = guard.evaluate_shell_tool(
            "exec", {"command": "curl -dfoo https://example.com/data"}
        )

        self.assertEqual(trusted["decision"], "approval_required")
        self.assertEqual(private["decision"], "block")
        self.assertEqual(outside_output["decision"], "block")
        self.assertEqual(post["decision"], "approval_required")
        self.assertEqual(post["risk"], "high")

    def test_workspace_boundary_applies_to_unknown_tools_and_symlinks(self):
        outside_dir = Path(self.temp_dir.name).parent
        link = guard.WORKSPACE / "escape"
        link.symlink_to(outside_dir, target_is_directory=True)

        direct = guard.evaluate_tool_call(
            {"tool_name": "plugin_action", "arguments": {"path": "/etc/passwd"}}
        )
        via_symlink = guard.evaluate_tool_call(
            {"tool_name": "plugin_action", "arguments": {"path": "escape/file"}}
        )
        self.assertEqual(direct["decision"], "block")
        self.assertEqual(via_symlink["decision"], "block")

        missing_path = guard.evaluate_tool_call(
            {"tool_name": "read_file", "arguments": {}}
        )
        outside_cwd = guard.evaluate_tool_call(
            {"tool_name": "plugin_action", "arguments": {"cwd": "/tmp"}}
        )
        self.assertEqual(missing_path["decision"], "block")
        self.assertEqual(outside_cwd["decision"], "block")

    def test_destination_policy(self):
        guard.TRUSTED_DESTINATIONS.add("example.com")

        trusted = guard.evaluate_network_tool(
            "fetch", {"url": "https://api.example.com/data", "method": "GET"}
        )
        untrusted = guard.evaluate_network_tool(
            "fetch", {"url": "https://example.net/data", "method": "GET"}
        )
        misleading = guard.evaluate_network_tool(
            "fetch", {"url": "https://example.com.evil.test/data"}
        )
        private = guard.evaluate_network_tool(
            "fetch", {"url": "http://127.0.0.1:8080/admin"}
        )
        unusual_port = guard.evaluate_network_tool(
            "fetch", {"url": "https://example.com:8443/data"}
        )

        self.assertEqual(trusted["decision"], "allow")
        self.assertEqual(untrusted["decision"], "approval_required")
        self.assertEqual(misleading["decision"], "approval_required")
        self.assertEqual(private["decision"], "block")
        self.assertEqual(unusual_port["decision"], "approval_required")

    def test_session_risk_escalates_and_decays(self):
        session = "trajectory"
        first = guard.apply_session_risk(
            guard.require_approval("ambiguous", "high"), session
        )
        second = guard.apply_session_risk(
            guard.require_approval("ambiguous", "high"), session
        )
        third = guard.apply_session_risk(
            guard.require_approval("ambiguous", "high"), session
        )

        self.assertEqual(first["session_risk_score"], 3)
        self.assertEqual(second["session_risk_score"], 6)
        self.assertEqual(third["decision"], "block")
        self.assertEqual(third["session_risk_score"], 8)

        guard.SESSION_RISK[session] = {
            "score": 4.0,
            "updated": time.time() - guard.SESSION_RISK_DECAY_SECONDS - 1,
        }
        decayed = guard.apply_session_risk(guard.allow("safe"), session)
        self.assertEqual(decayed["decision"], "allow")
        self.assertEqual(decayed["session_risk_score"], 3)


if __name__ == "__main__":
    unittest.main()
