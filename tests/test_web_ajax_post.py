from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fh_tool_cli.cli import parse_args
from fh_tool_cli.errors import CliError


class RecordingWebClient:
    def __init__(self, sessionid: str | None = None) -> None:
        self.sessionid = sessionid
        self.calls: list[tuple[str, object]] = []

    def login(self, username: str, password: str, *, port: str) -> dict[str, object]:
        self.calls.append(("login", (username, password, port)))
        self.sessionid = "sid-after-login"
        return {
            "ok": True,
            "username": username,
            "login_result": 0,
            "sessionid_present": True,
        }

    def raw_post(self, method: str, payload: dict[str, object], *, dry_run: bool) -> dict[str, object]:
        self.calls.append(("raw_post", (method, payload, dry_run)))
        return {
            "method": method,
            "request": payload,
            "status": "dry-run" if dry_run else "executed",
            "sessionid_present": bool(self.sessionid),
        }


class WebAjaxPostCliTests(unittest.TestCase):
    def test_web_ajax_post_defaults_to_dry_run(self) -> None:
        client = RecordingWebClient()
        args = parse_args(
            [
                "web",
                "ajax",
                "post",
                "set_fake",
                "--param",
                "Enable=1",
                "--ip",
                "192.168.1.1",
            ]
        )

        with patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client):
            result = args.handler(args)

        self.assertEqual(result["status"], "dry-run")
        self.assertEqual(result["request"], {"Enable": "1"})
        self.assertIn("--confirm", result["hint"])
        self.assertEqual(client.calls, [("raw_post", ("set_fake", {"Enable": "1"}, True))])

    def test_web_ajax_post_confirm_executes(self) -> None:
        client = RecordingWebClient()
        args = parse_args(
            [
                "web",
                "ajax",
                "post",
                "set_fake",
                "--param",
                "Enable=1",
                "--confirm",
                "--ip",
                "192.168.1.1",
            ]
        )

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch("fh_tool_cli.commands.web._web_password_from_args", return_value=("auto-secret", "cfg", [])),
        ):
            result = args.handler(args)

        self.assertEqual(result["status"], "executed")
        self.assertEqual(
            client.calls,
            [
                ("login", ("useradmin", "auto-secret", "0")),
                ("raw_post", ("set_fake", {"Enable": "1"}, False)),
            ],
        )
        self.assertEqual(result["login"]["password_source"], "cfg")
        self.assertTrue(result["login"]["ok"])
        self.assertNotIn("auto-secret", str(result))

    def test_web_ajax_post_confirm_with_sessionid_skips_auto_login(self) -> None:
        client = RecordingWebClient(sessionid="sid-explicit")
        args = parse_args(
            [
                "web",
                "ajax",
                "post",
                "set_fake",
                "--param",
                "Enable=1",
                "--confirm",
                "--sessionid",
                "sid-explicit",
                "--ip",
                "192.168.1.1",
            ]
        )

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch("fh_tool_cli.commands.web._web_password_from_args", side_effect=AssertionError("password used")),
        ):
            result = args.handler(args)

        self.assertEqual(client.calls, [("raw_post", ("set_fake", {"Enable": "1"}, False))])
        self.assertFalse(result["login"]["attempted"])
        self.assertEqual(result["login"]["password_source"], "sessionid")

    def test_web_ajax_replay_confirm_logs_in_before_post(self) -> None:
        client = RecordingWebClient()
        with tempfile.TemporaryDirectory() as tmpdir:
            catalog_path = Path(tmpdir) / "catalog.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "methods": [
                            {
                                "method": "set_fake",
                                "kind": "write",
                                "http_methods": ["POST"],
                                "params": [],
                                "verify_candidates": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            args = parse_args(
                [
                    "web",
                    "ajax",
                    "replay",
                    "--catalog",
                    str(catalog_path),
                    "--method",
                    "set_fake",
                    "--param",
                    "Enable=1",
                    "--confirm",
                    "--ip",
                    "192.168.1.1",
                ]
            )

            with (
                patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
                patch("fh_tool_cli.commands.web._web_password_from_args", return_value=("auto-secret", "cfg", [])),
            ):
                result = args.handler(args)

        self.assertEqual(
            client.calls,
            [
                ("login", ("useradmin", "auto-secret", "0")),
                ("raw_post", ("set_fake", {"Enable": "1"}, False)),
            ],
        )
        self.assertEqual(result["status"], "executed")
        self.assertEqual(result["login"]["password_source"], "cfg")

    def test_web_ajax_post_old_execute_flags_are_deprecated(self) -> None:
        args = parse_args(
            [
                "web",
                "ajax",
                "post",
                "set_fake",
                "--param",
                "Enable=1",
                "--execute",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "已弃用"):
            args.handler(args)

    def test_web_ajax_post_refuses_empty_payload_without_explicit_flag(self) -> None:
        args = parse_args(
            [
                "web",
                "ajax",
                "post",
                "set_fake",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--allow-empty-payload"):
            args.handler(args)

    def test_web_ajax_post_json_and_param_merge_with_param_override(self) -> None:
        client = RecordingWebClient()
        args = parse_args(
            [
                "web",
                "ajax",
                "post",
                "set_fake",
                "--json-payload",
                '{"Enable":"0","Mode":"auto"}',
                "--param",
                "Enable=1",
                "--ip",
                "192.168.1.1",
            ]
        )

        with patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client):
            result = args.handler(args)

        self.assertEqual(result["request"], {"Enable": "1", "Mode": "auto"})


if __name__ == "__main__":
    unittest.main()
