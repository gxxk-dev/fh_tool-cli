from __future__ import annotations

import unittest

from fh_tool_cli.cli import parse_args
from fh_tool_cli.errors import CliError


class CliRiskTests(unittest.TestCase):
    def test_cfg_set_requires_yes_before_backend_use(self) -> None:
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

        with self.assertRaisesRegex(CliError, "--yes"):
            args.handler(args)

    def test_cfg_set_danger_path_requires_danger(self) -> None:
        args = parse_args(
            [
                "cfg",
                "set",
                "InternetGatewayDevice.WANDevice.1.VLANID",
                "100",
                "--backend",
                "local-vm",
                "--yes",
                "--backup-confirmed",
            ]
        )

        with self.assertRaisesRegex(CliError, "--danger"):
            args.handler(args)

    def test_tr069_harden_requires_backup_after_danger_flags(self) -> None:
        args = parse_args(
            [
                "tr069",
                "harden",
                "--periodic-inform",
                "off",
                "--yes",
                "--danger",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--backup-confirmed"):
            args.handler(args)

    def test_cloud_disable_smartswitch_requires_backup_after_danger_flags(self) -> None:
        args = parse_args(
            [
                "cloud",
                "disable-smartswitch",
                "--yes",
                "--danger",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--backup-confirmed"):
            args.handler(args)

    def test_extreme_reboot_requires_final_flag(self) -> None:
        args = parse_args(
            [
                "reboot",
                "--yes",
                "--danger",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--i-know-this-can-break-my-device"):
            args.handler(args)

    def test_restore_execute_requires_final_extreme_flag(self) -> None:
        args = parse_args(
            [
                "restore",
                "backup.tgz",
                "--execute",
                "--target-root",
                "/tmp/fh-tool-restore-target",
                "--yes",
                "--danger",
            ]
        )

        with self.assertRaisesRegex(CliError, "--i-know-this-can-break-my-device"):
            args.handler(args)

    def test_upload_execute_requires_final_extreme_flag(self) -> None:
        args = parse_args(
            [
                "upload",
                "--action",
                "preconfig",
                "--file",
                "preconfig.bin",
                "--sessionid",
                "secret-token",
                "--yes",
                "--danger",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--i-know-this-can-break-my-device"):
            args.handler(args)

    def test_web_typed_write_execute_requires_backup_after_danger_flags(self) -> None:
        args = parse_args(
            [
                "web",
                "firewall",
                "set",
                "--param",
                "Enable=1",
                "--execute",
                "--yes",
                "--danger",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--backup-confirmed"):
            args.handler(args)

    def test_web_login_requires_username_and_password_together(self) -> None:
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

        with self.assertRaisesRegex(CliError, "--username"):
            args.handler(args)

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
