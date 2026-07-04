from __future__ import annotations

import unittest
from unittest.mock import patch

from fh_tool_cli.cli import parse_args
from fh_tool_cli.errors import CliError


class RecordingWebClient:
    def __init__(self) -> None:
        self.sessionid = "sid"
        self.calls: list[tuple[str, object]] = []

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

        with patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client):
            result = args.handler(args)

        self.assertEqual(result["status"], "executed")
        self.assertEqual(client.calls, [("raw_post", ("set_fake", {"Enable": "1"}, False))])

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
