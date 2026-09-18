from __future__ import annotations

import argparse
import unittest
from unittest.mock import patch

from fh_tool_cli.cli import _password_from_args, _telnet_credentials_from_args, parse_args
from fh_tool_cli.errors import CliError


def _derive_args(*extra: str) -> argparse.Namespace:
    return parse_args(
        [
            "credentials",
            "derive",
            "--ip",
            "192.0.2.1",
            "--mac",
            "D8F50736BC10",
            *extra,
        ]
    )


class PasswordStdinFromArgsTests(unittest.TestCase):
    """覆盖 _password_from_args 的 stdin 分支。

    回归背景：0.2.8 首包漏 import read_stdin_secret，
    `--password-stdin` 在 TelnetShell 连接设备前直接 NameError。
    patch cli 命名空间可锁住该 import 回归。
    """

    def test_telnet_password_stdin_reads_via_read_stdin_secret(self) -> None:
        args = parse_args(
            [
                "account",
                "show",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
                "--telnet-password-stdin",
            ]
        )

        with patch("fh_tool_cli.cli.read_stdin_secret", return_value="telnet-secret") as reader:
            self.assertEqual(_password_from_args(args), "telnet-secret")

        reader.assert_called_once()
        self.assertIn("--telnet-password-stdin", reader.call_args.args[0])

    def test_telnet_password_conflicts_with_stdin_flag(self) -> None:
        args = parse_args(
            [
                "account",
                "show",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
                "--telnet-password",
                "explicit-secret",
                "--telnet-password-stdin",
            ]
        )

        with self.assertRaises(CliError):
            _password_from_args(args)

    def test_password_stdin_reads_via_read_stdin_secret(self) -> None:
        args = _derive_args("--password-stdin")

        with patch("fh_tool_cli.cli.read_stdin_secret", return_value="secret-line") as reader:
            self.assertEqual(_password_from_args(args), "secret-line")

        reader.assert_called_once()
        self.assertIn("--password-stdin", reader.call_args.args[0])

    def test_explicit_password_conflicts_with_stdin_flag(self) -> None:
        args = _derive_args("--password", "explicit-secret", "--password-stdin")

        with self.assertRaises(CliError):
            _password_from_args(args)

    def test_no_password_flags_returns_none(self) -> None:
        self.assertIsNone(_password_from_args(_derive_args()))

    def test_stdin_flag_flows_into_telnet_credentials(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
                "--password-stdin",
            ]
        )

        with patch("fh_tool_cli.cli.read_stdin_secret", return_value="stdin-secret"):
            credentials = _telnet_credentials_from_args(args)

        self.assertEqual(credentials.password, "stdin-secret")


if __name__ == "__main__":
    unittest.main()
