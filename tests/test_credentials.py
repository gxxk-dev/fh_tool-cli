from __future__ import annotations

import unittest

from fh_tool_cli.cli import _telnet_credentials_from_args, parse_args
from fh_tool_cli.commands.web import _web_telnet_login_from_args
from fh_tool_cli.credentials import (
    HG5143F_SU_PASSWORD_PREFIX,
    HG5143F_TELNET_PASSWORD_PREFIX,
    HG6142A3_SU_PASSWORD_PREFIX,
    HG6142A3_TELNET_PASSWORD_PREFIX,
    derive_credentials,
    derive_hg5143f_su,
    derive_hg5143f_telnet,
    derive_hg6142a3_root,
    derive_hg6142a3_telnet,
    su_password_candidates,
    telnet_login_candidates,
    verify_su_password_candidates,
)
from fh_tool_cli.errors import CliError


class CredentialsTests(unittest.TestCase):
    def test_hg5143f_telnet_derivation_uses_mac_suffix(self) -> None:
        credential = derive_hg5143f_telnet("D8:F5:07:36:BC:10")

        self.assertEqual(credential.kind, "hg5143f-telnet")
        self.assertEqual(credential.username, "telnetadmin")
        self.assertTrue(credential.password.startswith(HG5143F_TELNET_PASSWORD_PREFIX))
        self.assertTrue(credential.password.endswith("36BC10"))
        self.assertEqual(credential.integration_level, "automatic-telnet-fallback")

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

        self.assertEqual(
            [credential.kind for credential in credentials],
            ["hg5143f-telnet", "hg6142a3-telnet", "hg5143f-su", "hg6142a3-root"],
        )

    def test_hg6142a3_telnet_derivation_uses_f_h_prefix(self) -> None:
        credential = derive_hg6142a3_telnet("D8:F5:07:36:BC:10")

        self.assertEqual(credential.kind, "hg6142a3-telnet")
        self.assertEqual(credential.username, "admin")
        self.assertTrue(credential.password.startswith(HG6142A3_TELNET_PASSWORD_PREFIX))
        self.assertEqual(credential.password, "Fh@36BC10")
        self.assertEqual(credential.target, "telnet-login")
        self.assertEqual(credential.integration_level, "automatic-telnet-fallback")

    def test_telnet_login_candidates_are_ordered(self) -> None:
        candidates = telnet_login_candidates("D8F50736BC10")

        self.assertEqual(
            candidates,
            [
                ("hg5143f-telnet", "telnetadmin", "FH-nE7jA%5m36BC10"),
                ("hg6142a3-telnet", "admin", "Fh@36BC10"),
            ],
        )

    def test_hg6142a3_root_derivation_uses_unicom_prefix(self) -> None:
        credential = derive_hg6142a3_root("D8F50736BC10")

        self.assertEqual(credential.kind, "hg6142a3-root")
        self.assertEqual(credential.username, "root")
        self.assertTrue(credential.password.startswith(HG6142A3_SU_PASSWORD_PREFIX))
        self.assertEqual(credential.password, "hg2x036BC10")
        self.assertFalse(credential.persistent)
        self.assertEqual(credential.integration_level, "derive-display-only")
        self.assertIsNone(credential.verified)
        self.assertIn("CHINA_UNICOM", credential.note)

    def test_su_password_candidates_are_ordered(self) -> None:
        candidates = su_password_candidates("D8F50736BC10")

        self.assertEqual(
            candidates,
            [("hg5143f-su", "Fh@36BC10"), ("hg6142a3-root", "hg2x036BC10")],
        )

    def test_verify_su_password_candidates_matches_hg6142a3_hash(self) -> None:
        from fh_tool_cli.crypt_unix import sha256_crypt

        hashed = sha256_crypt("hg2x036BC10", "fh")
        verified = verify_su_password_candidates(hashed, "D8F50736BC10")

        self.assertEqual(verified, ("hg6142a3-root", "hg2x036BC10"))

    def test_verify_su_password_candidates_matches_hg5143f_hash(self) -> None:
        hashed = "$1$$c29kb1Alc4Ic54TuMH2iv."
        verified = verify_su_password_candidates(hashed, "D8F50736BC10")

        self.assertEqual(verified, ("hg5143f-su", "Fh@36BC10"))

    def test_verify_su_password_candidates_returns_none_on_mismatch(self) -> None:
        from fh_tool_cli.crypt_unix import sha256_crypt

        hashed = sha256_crypt("changed-password", "fh")

        self.assertIsNone(verify_su_password_candidates(hashed, "D8F50736BC10"))

    def test_render_includes_verified_field(self) -> None:
        rendered = derive_hg6142a3_root("D8F50736BC10").render()

        self.assertIsNone(rendered["verified"])
        self.assertEqual(rendered["kind"], "hg6142a3-root")

    def test_credentials_derive_command_redacts(self) -> None:
        args = parse_args(
            [
                "credentials",
                "derive",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
                "--kind",
                "hg5143f-telnet",
            ]
        )

        result = args.handler(args)

        self.assertEqual(result["credentials"][0]["password"], "[REDACTED]")
        self.assertEqual(result["credentials"][0]["target"], "telnet-login")

    def test_telnet_derived_credentials_are_default_fallback(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
            ]
        )

        credentials = _telnet_credentials_from_args(args)

        self.assertEqual(credentials.username, "telnetadmin")
        self.assertIsNotNone(credentials.password)
        self.assertTrue(credentials.password.endswith("36BC10"))
        # HG6142A3 admin 候选作为备用凭据，认证失败时自动重试。
        self.assertEqual(len(credentials.fallback_credentials), 1)
        fallback = credentials.fallback_credentials[0]
        self.assertEqual(fallback.username, "admin")
        self.assertEqual(fallback.password, "Fh@36BC10")

    def test_explicit_admin_username_gets_hg6142a3_password(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
                "--username",
                "admin",
            ]
        )

        credentials = _telnet_credentials_from_args(args)

        self.assertEqual(credentials.username, "admin")
        self.assertEqual(credentials.password, "Fh@36BC10")
        self.assertEqual(credentials.fallback_credentials, ())

    def test_telnet_derived_credentials_can_be_disabled(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
                "--no-derived-credentials",
            ]
        )

        credentials = _telnet_credentials_from_args(args)

        self.assertIsNone(credentials.username)
        self.assertIsNone(credentials.password)

    def test_explicit_telnet_password_overrides_derived_password(self) -> None:
        args = parse_args(
            [
                "cfg",
                "get",
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "--ip",
                "192.0.2.1",
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
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
                "--username",
                "custom",
                "--use-derived-credentials",
            ]
        )

        with self.assertRaises(CliError):
            _telnet_credentials_from_args(args)

    def test_web_cfg_telnet_source_uses_derived_credentials_by_default(self) -> None:
        args = parse_args(
            [
                "web",
                "ajax",
                "get",
                "get_base_info",
                "--ip",
                "192.0.2.1",
                "--mac",
                "D8F50736BC10",
            ]
        )

        username, password = _web_telnet_login_from_args(args, "192.0.2.1")

        self.assertEqual(username, "telnetadmin")
        self.assertIsNotNone(password)
        self.assertTrue(password.endswith("36BC10"))


if __name__ == "__main__":
    unittest.main()
