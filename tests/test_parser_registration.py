from __future__ import annotations

import unittest

from fh_tool_cli import cli


class ParserRegistrationTests(unittest.TestCase):
    def test_representative_commands_bind_expected_handlers(self) -> None:
        cases = [
            (["probe", "--ip", "192.168.1.1"], cli.command_probe),
            (["cfg", "get", "InternetGatewayDevice.DeviceInfo.Manufacturer"], cli.command_cfg_get),
            (["wan", "list", "--backend", "local-vm"], cli.command_wan_list),
            (["vm", "collect", "--ip", "192.168.1.1", "--output", "/tmp/dumps"], cli.command_vm_collect),
            (["vm", "build", "--dump-dir", "/tmp/dumps", "--output", "/tmp/vm"], cli.command_vm_build),
            (["vm", "verify", "--vm-root", "/tmp/vm"], cli.command_vm_verify),
            (["config", "show"], cli.command_config_show),
            (["reboot", "--ip", "192.168.1.1"], cli.command_reboot),
        ]

        for argv, expected_handler in cases:
            with self.subTest(argv=argv):
                args = cli.parse_args(argv)
                self.assertIs(args.handler, expected_handler)

    def test_api_alias_binds_generated_handler(self) -> None:
        args = cli.parse_args(["info", "--ip", "192.168.1.1"])

        self.assertEqual(args.command, "info")
        self.assertTrue(callable(args.handler))

    def test_write_gate_flags_survive_parser_split(self) -> None:
        cfg_set = cli.parse_args(
            [
                "cfg",
                "set",
                "InternetGatewayDevice.DeviceInfo.Name",
                "new",
                "--confirm",
            ]
        )
        self.assertTrue(cfg_set.confirm)

        reboot = cli.parse_args(
            [
                "reboot",
                "--ip",
                "192.168.1.1",
                "--confirm",
            ]
        )
        self.assertTrue(reboot.confirm)

        deprecated = cli.parse_args(
            [
                "reboot",
                "--ip",
                "192.168.1.1",
                "--yes",
            ]
        )
        self.assertTrue(deprecated.deprecated_yes)

    def test_web_write_gate_flags_survive_parser_split(self) -> None:
        args = cli.parse_args(
            [
                "web",
                "firewall",
                "set",
                "--param",
                "Enable=1",
                "--confirm",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertTrue(args.confirm)

    def test_new_web_subcommands_bind_handlers(self) -> None:
        cases = [
            ["web", "discover", "live", "--ip", "192.168.1.1"],
            ["web", "discover", "static", "--root", "/tmp/rootfs"],
            ["web", "discover", "merge", "--input", "/tmp/live.json", "--input", "/tmp/static.json"],
            ["web", "ajax", "post", "set_fake", "--param", "Enable=1", "--ip", "192.168.1.1"],
            ["web", "ajax", "replay", "--catalog", "/tmp/catalog.json", "--method", "set_fake", "--param", "Enable=1"],
        ]

        for argv in cases:
            with self.subTest(argv=argv):
                args = cli.parse_args(argv)
                self.assertTrue(callable(args.handler))


if __name__ == "__main__":
    unittest.main()
