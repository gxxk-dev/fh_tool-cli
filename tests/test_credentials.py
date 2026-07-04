from __future__ import annotations

import unittest

from fh_tool_cli.cli import _telnet_credentials_from_args, parse_args
from fh_tool_cli.credentials import (
    HG5143F_SU_PASSWORD_PREFIX,
    HG5143F_TELNET_PASSWORD_PREFIX,
    derive_credentials,
    derive_hg5143f_su,
    derive_hg5143f_telnet,
)
from fh_tool_cli.errors import CliError


class CredentialsTests(unittest.TestCase):
    def test_hg5143f_telnet_derivation_uses_mac_suffix(self) -> None:
        credential = derive_hg5143f_telnet("D8:F5:07:36:BC:10")

        self.assertEqual(credential.kind, "hg5143f-telnet")
        self.assertEqual(credential.username, "telnetadmin")
        self.assertTrue(credential.password.startswith(HG5143F_TELNET_PASSWORD_PREFIX))
        self.assertTrue(credential.password.endswith("36BC10"))
        self.assertEqual(credential.integration_level, "explicit-opt-in-telnet-fallback")

    def test_hg5143f_su_derivation_is_display_only(self) -> None:
        credential = derive_hg5143f_su("D8F50736BC10")

        self.assertEqual(credential.kind, "hg5143f-su")
        self.assertEqual(credential.username, "root")
        self.assertTrue(credential.password.startswith(HG5143F_SU_PASSWORD_PREFIX))
        self.assertTrue(credential.password.endswith("36BC10"))
        self.assertFalse(credential.persistent)
        self.assertEqual(credential.integration_level, "derive-display-only")

    def test_render_redacts_by_default(self) -> None:
        rendered = derive_hg5143f_telnet("D8F50736BC10").render()

        self.assertEqual(rendered["password"], "[REDACTED]")
        self.assertTrue(rendered["redacted"])
        self.assertEqual(rendered["mac_suffix"], "36BC10")

    def test_render_can_reveal_explicitly(self) -> None:
        rendered = derive_hg5143f_telnet("D8F50736BC10").render(reveal_secrets=True)

        self.assertNotEqual(rendered["password"], "[REDACTED]")
        self.assertFalse(rendered["redacted"])

    def test_derive_credentials_all(self) -> None:
        credentials = derive_credentials("D8F50736BC10", "all")

        self.assertEqual([credential.kind for credential in credentials], ["hg5143f-telnet", "hg5143f-su"])

    def test_credentials_derive_command_redacts(self) -> None:
        args = parse_args(
            [
                "credentials",
                "derive",
                "--ip",
                "192.168.1.1",
                "--mac",
                "D8F50736BC10",
                "--kind",
                "hg5143f-telnet",
            ]
        )

        result = args.handler(args)

        self.assertEqual(result["credentials"][0]["password"], "[REDACTED]")
        self.assertEqual(result["credentials"][0]["target"], "telnet-login")

    def test_telnet_derived_credentials_are_explicit_fallback(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.168.1.1",
                "--mac",
                "D8F50736BC10",
                "--use-derived-credentials",
            ]
        )

        credentials = _telnet_credentials_from_args(args)

        self.assertEqual(credentials.username, "telnetadmin")
        self.assertIsNotNone(credentials.password)
        self.assertTrue(credentials.password.endswith("36BC10"))

    def test_explicit_telnet_password_overrides_derived_password(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.168.1.1",
                "--mac",
                "D8F50736BC10",
                "--username",
                "telnetadmin",
                "--password",
                "manual-secret",
                "--use-derived-credentials",
            ]
        )

        credentials = _telnet_credentials_from_args(args)

        self.assertEqual(credentials.username, "telnetadmin")
        self.assertEqual(credentials.password, "manual-secret")

    def test_custom_telnet_user_needs_explicit_password(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.168.1.1",
                "--mac",
                "D8F50736BC10",
                "--username",
                "custom",
                "--use-derived-credentials",
            ]
        )

        with self.assertRaises(CliError):
            _telnet_credentials_from_args(args)


if __name__ == "__main__":
    unittest.main()
