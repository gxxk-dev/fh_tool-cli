from __future__ import annotations

import argparse
import unittest

from fh_tool_cli.account import (
    TELNET_PASSWORD_PATH,
    WEB_ADMIN_PASSWORD_PATH,
    account_show,
    read_secret_from_args,
    set_su_runtime_password,
    set_telnet_password,
)
from fh_tool_cli.backends.cfg_cmd import CfgCmdBackend
from fh_tool_cli.errors import CliError


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

    def test_set_su_runtime_password_does_not_return_plaintext(self) -> None:
        calls: list[str] = []
        result = set_su_runtime_password(calls.append, "runtime-secret")

        self.assertEqual(result["value"], "[REDACTED]")
        self.assertFalse(result["persistent"])
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
