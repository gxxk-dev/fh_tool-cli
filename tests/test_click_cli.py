from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fh_tool_cli import cli


class ClickCliTests(unittest.TestCase):
    def test_main_uses_click_entrypoint_and_emits_json(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main(["--verbose", "config", "show", "--json"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertIn("path", payload)
        self.assertIsInstance(payload["config"], dict)

    def test_click_parameter_errors_use_cli_error_channel(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main(
                [
                    "web",
                    "port-mapping",
                    "set",
                    "--external-port",
                    "not-a-port",
                    "--ip",
                    "127.0.0.1",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("错误:", stderr.getvalue())
        self.assertIn("port 必须是整数", stderr.getvalue())

    def test_click_help_is_available(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main(["--help"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("Usage: fh-tool", stdout.getvalue())
        self.assertIn("--log-file", stdout.getvalue())

    def test_no_args_shows_help_without_error(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main([])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("Usage: fh-tool", stdout.getvalue())

    def test_log_file_uses_structured_json_without_polluting_stdout(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "fh-tool.log"

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = cli.main(["-vv", "--log-file", str(log_file), "config", "show", "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertIn("config", payload)
            lines = log_file.read_text(encoding="utf-8").splitlines()
            self.assertTrue(lines)
            first = json.loads(lines[0])
            self.assertIn("timestamp", first)
            self.assertIn("event", first)
            self.assertEqual(first["logger"], "fh_tool_cli")


if __name__ == "__main__":
    unittest.main()
