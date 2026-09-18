from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fh_tool_cli import cli

FAKE_PROBE = {
    "ip": "192.0.2.1",
    "mac": "D8:F5:07:36:BC:10",
    "fh_port": 8080,
    "fh_port_source": "default",
    "fh_tool_probe": {
        "func": "GetDevInfo",
        "ok": True,
        "response": {"result": 0, "password": "should-be-redacted"},
    },
}


def _args(**overrides) -> SimpleNamespace:
    values: dict = {"ports": None, "json": False, "output": None}
    values.update(overrides)
    return SimpleNamespace(**values)


class AdaptPromptTests(unittest.TestCase):
    def test_prompt_contains_context_guide_and_redlines(self) -> None:
        with patch.object(cli, "command_probe", return_value=dict(FAKE_PROBE)):
            prompt = cli.command_adapt_prompt(_args())

        self.assertIsInstance(prompt, str)
        self.assertIn("ADAPT.md", prompt)
        self.assertIn("192.0.2.1", prompt)
        self.assertIn("D8:F5:07:36:BC:10", prompt)
        self.assertIn("8080", prompt)
        self.assertIn("严禁批量爆破", prompt)

    def test_dev_info_sensitive_keys_are_redacted(self) -> None:
        with patch.object(cli, "command_probe", return_value=dict(FAKE_PROBE)):
            prompt = cli.command_adapt_prompt(_args())

        self.assertIn("[REDACTED]", prompt)
        self.assertNotIn("should-be-redacted", prompt)

    def test_probe_failure_still_renders_prompt(self) -> None:
        with patch.object(cli, "command_probe", side_effect=cli.FHToolError("unreachable")):
            prompt = cli.command_adapt_prompt(_args())

        self.assertIn("unreachable", prompt)
        self.assertIn("ADAPT.md", prompt)

    def test_json_mode_returns_structured_result(self) -> None:
        with patch.object(cli, "command_probe", return_value=dict(FAKE_PROBE)):
            result = cli.command_adapt_prompt(_args(json=True))

        self.assertIsInstance(result, dict)
        self.assertEqual(result["context"]["ip"], "192.0.2.1")
        self.assertEqual(result["context"]["fh_port"], 8080)
        self.assertIn("ADAPT.md", result["prompt"])

    def test_output_writes_prompt_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "adapt-prompt.md"
            with patch.object(cli, "command_probe", return_value=dict(FAKE_PROBE)):
                message = cli.command_adapt_prompt(_args(output=str(target)))

            self.assertIn("已写入", message)
            self.assertTrue(target.exists())
            self.assertIn("ADAPT.md", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
