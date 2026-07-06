from __future__ import annotations

import argparse
import unittest
from unittest.mock import patch

from fh_tool_cli.account import (
    SU_RUNTIME_PASSWORD_FILE,
    TELNET_PASSWORD_PATH,
    WEB_ADMIN_PASSWORD_PATH,
    account_show,
    read_secret_from_args,
    set_su_runtime_password,
    set_telnet_password,
)
from fh_tool_cli.backends.cfg_cmd import CfgCmdBackend
from fh_tool_cli.cli import parse_args
from fh_tool_cli.errors import CliError

HG5143F_DERIVED_SU_PASSWORD = "Fh@36BC10"
HG5143F_DERIVED_SU_MD5_CRYPT = "$1$$c29kb1Alc4Ic54TuMH2iv."


class AccountTests(unittest.TestCase):
    def test_read_secret_requires_exactly_one_mode(self) -> None:
        with self.assertRaises(CliError):
            read_secret_from_args(
                argparse.Namespace(password=None, password_stdin=False, generate=False)
            )
        with self.assertRaises(CliError):
            read_secret_from_args(
                argparse.Namespace(password="x", password_stdin=False, generate=True)
            )

        secret = read_secret_from_args(
            argparse.Namespace(password="target-secret", password_stdin=False, generate=False)
        )
        self.assertEqual(secret.password, "target-secret")
        self.assertFalse(secret.generated)

    def test_account_show_redacts_sensitive_values(self) -> None:
        values = {
            WEB_ADMIN_PASSWORD_PATH: "web-secret",
            TELNET_PASSWORD_PATH: "telnet-secret",
            "InternetGatewayDevice.DeviceInfo.X_CT-COM_ServiceManage.TelnetUserName": "admin",
        }

        backend = CfgCmdBackend(lambda command: f"{command.split()[-1]}={values[command.split()[-1]]}")
        result = account_show(backend)

        self.assertEqual(result["accounts"]["web_admin_password"]["value"], "[REDACTED]")
        self.assertEqual(result["accounts"]["telnet_password"]["value"], "[REDACTED]")
        self.assertEqual(result["accounts"]["telnet_username"]["value"], "admin")

    def test_set_telnet_password_redacts_result(self) -> None:
        values = {TELNET_PASSWORD_PATH: "old"}

        def runner(command: str) -> str:
            if command.startswith("cfg_cmd set "):
                values[TELNET_PASSWORD_PATH] = "new-secret"
                return "ok"
            if command.startswith("cfg_cmd get "):
                return f"{TELNET_PASSWORD_PATH}={values[TELNET_PASSWORD_PATH]}"
            raise AssertionError(command)

        result = set_telnet_password(CfgCmdBackend(runner), "new-secret")

        self.assertTrue(result["verified"])
        self.assertEqual(result["value"], "[REDACTED]")
        self.assertEqual(result["observed"], "[REDACTED]")

    def test_set_su_runtime_password_writes_md5_crypt_passwd_line(self) -> None:
        calls: list[str] = []
        result = set_su_runtime_password(calls.append, HG5143F_DERIVED_SU_PASSWORD)

        self.assertEqual(result["value"], "[REDACTED]")
        self.assertEqual(result["path"], SU_RUNTIME_PASSWORD_FILE)
        self.assertFalse(result["persistent"])
        self.assertEqual(
            calls,
            [
                "printf '%s\\n' "
                "'root:$1$$c29kb1Alc4Ic54TuMH2iv.:0:0:Telnet user:/:/bin/ash' "
                "> /var/telsu"
            ],
        )
        self.assertNotIn(HG5143F_DERIVED_SU_PASSWORD, calls[0])

    def test_set_su_runtime_password_uses_derived_default(self) -> None:
        calls: list[str] = []
        args = parse_args(
            [
                "account",
                "set-su-runtime-password",
                "--ip",
                "192.168.1.1",
                "--mac",
                "D8F50736BC10",
                "--confirm",
            ]
        )

        class FakeShell:
            def run(self, command: str) -> str:
                calls.append(command)
                return "ok"

        with patch("fh_tool_cli.cli._telnet_shell_from_args", return_value=FakeShell()):
            result = args.handler(args)

        self.assertEqual(result["password_source"], "derived-hg5143f-su")
        self.assertEqual(result["value"], "[REDACTED]")
        self.assertIn(HG5143F_DERIVED_SU_MD5_CRYPT, calls[0])
        self.assertNotIn(HG5143F_DERIVED_SU_PASSWORD, calls[0])

    def test_set_su_runtime_password_dry_run_mentions_derived_default(self) -> None:
        args = parse_args(
            [
                "account",
                "set-su-runtime-password",
                "--ip",
                "192.168.1.1",
                "--mac",
                "D8F50736BC10",
            ]
        )

        result = args.handler(args)

        self.assertEqual(result["target"]["input_mode"], "derived-hg5143f-su-on-confirm")
        self.assertFalse(result["executed"])


if __name__ == "__main__":
    unittest.main()
