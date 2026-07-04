from __future__ import annotations

import unittest
from unittest.mock import patch

from fh_tool_cli.cli import parse_args
from fh_tool_cli.errors import CliError


class CliRiskTests(unittest.TestCase):
    def test_cfg_set_defaults_to_dry_run_before_backend_use(self) -> None:
        args = parse_args(
            [
                "cfg",
                "set",
                "InternetGatewayDevice.DeviceInfo.Name",
                "new",
                "--backend",
                "local-vm",
            ]
        )

        with patch("fh_tool_cli.cli._cfg_backend_from_args", side_effect=AssertionError("backend used")):
            result = args.handler(args)

        self.assertTrue(result["dry_run"])
        self.assertFalse(result["executed"])
        self.assertIn("--confirm", result["hint"])

    def test_deprecated_write_flags_are_rejected(self) -> None:
        args = parse_args(
            [
                "cfg",
                "set",
                "InternetGatewayDevice.DeviceInfo.Name",
                "new",
                "--backend",
                "local-vm",
                "--yes",
            ]
        )

        with self.assertRaisesRegex(CliError, "已弃用"):
            args.handler(args)

    def test_cfg_set_confirm_executes_without_legacy_flags(self) -> None:
        args = parse_args(
            [
                "cfg",
                "set",
                "InternetGatewayDevice.WANDevice.1.VLANID",
                "100",
                "--backend",
                "local-vm",
                "--confirm",
            ]
        )

        fake_backend = object()
        with (
            patch("fh_tool_cli.cli._cfg_backend_from_args", return_value=fake_backend),
            patch("fh_tool_cli.cli.cfg_set_with_verify", return_value={"ok": True}) as set_verify,
        ):
            result = args.handler(args)

        self.assertEqual(result, {"ok": True})
        set_verify.assert_called_once_with(fake_backend, "InternetGatewayDevice.WANDevice.1.VLANID", "100")

    def test_tr069_harden_defaults_to_dry_run(self) -> None:
        args = parse_args(
            [
                "tr069",
                "harden",
                "--periodic-inform",
                "off",
                "--ip",
                "192.168.1.1",
            ]
        )

        result = args.handler(args)

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["confirm_requires"], ["--confirm"])

    def test_cloud_disable_smartswitch_defaults_to_dry_run(self) -> None:
        args = parse_args(
            [
                "cloud",
                "disable-smartswitch",
                "--ip",
                "192.168.1.1",
            ]
        )

        result = args.handler(args)

        self.assertTrue(result["dry_run"])
        self.assertFalse(result["side_effects"]["cfg_set"])

    def test_reboot_defaults_to_dry_run(self) -> None:
        args = parse_args(
            [
                "reboot",
                "--ip",
                "192.168.1.1",
            ]
        )

        result = args.handler(args)

        self.assertTrue(result["dry_run"])
        self.assertFalse(result["side_effects"]["reboot"])

    def test_restore_execute_flag_is_deprecated(self) -> None:
        args = parse_args(
            [
                "restore",
                "backup.tgz",
                "--execute",
                "--target-root",
                "/tmp/fh-tool-restore-target",
            ]
        )

        with self.assertRaisesRegex(CliError, "已弃用"):
            args.handler(args)

    def test_web_typed_write_execute_flag_is_deprecated(self) -> None:
        args = parse_args(
            [
                "web",
                "firewall",
                "set",
                "--param",
                "Enable=1",
                "--execute",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "已弃用"):
            args.handler(args)

    def test_web_login_username_uses_auto_password_source(self) -> None:
        args = parse_args(
            [
                "web",
                "ajax",
                "get",
                "get_base_info",
                "--ip",
                "192.168.1.1",
                "--username",
                "telecomadmin",
            ]
        )

        class FakeClient:
            sessionid = None

            def login(self, username: str, password: str, *, port: str) -> dict[str, object]:
                return {
                    "ok": True,
                    "username": username,
                    "sessionid_present": True,
                    "login_result": 0,
                }

            def ajax_get(self, method: str) -> dict[str, object]:
                return {"method": method, "ok": True}

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=FakeClient()),
            patch("fh_tool_cli.commands.web._web_password_from_args", return_value=("auto-secret", "admin-account", [])),
        ):
            result = args.handler(args)

        self.assertEqual(result["method"], "get_base_info")
        self.assertNotIn("auto-secret", str(result))

    def test_diagnostics_accept_local_vm_backend_options(self) -> None:
        args = parse_args(
            [
                "wan",
                "list",
                "--backend",
                "local-vm",
                "--vm-root",
                "/tmp/fh-tool-vm",
                "--json",
            ]
        )

        self.assertEqual(args.backend, "local-vm")
        self.assertEqual(args.vm_root, "/tmp/fh-tool-vm")

        ip_args = parse_args(
            [
                "ip",
                "status",
                "--backend",
                "local-vm",
                "--vm-root",
                "/tmp/fh-tool-vm",
                "--json",
            ]
        )

        self.assertEqual(ip_args.backend, "local-vm")
        self.assertEqual(ip_args.vm_root, "/tmp/fh-tool-vm")


if __name__ == "__main__":
    unittest.main()
