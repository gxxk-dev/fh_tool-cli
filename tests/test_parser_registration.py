from __future__ import annotations

import unittest

from fh_tool_cli import cli


class ParserRegistrationTests(unittest.TestCase):
    def test_representative_commands_bind_expected_handlers(self) -> None:
        cases = [
            (["probe", "--ip", "192.168.1.1"], cli.command_probe),
            (["cfg", "get", "InternetGatewayDevice.DeviceInfo.Manufacturer"], cli.command_cfg_get),
            (["wan", "list", "--backend", "local-vm"], cli.command_wan_list),
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
                "--yes",
                "--danger",
                "--backup-confirmed",
            ]
        )
        self.assertTrue(cfg_set.yes)
        self.assertTrue(cfg_set.danger)
        self.assertTrue(cfg_set.backup_confirmed)

        reboot = cli.parse_args(
            [
                "reboot",
                "--ip",
                "192.168.1.1",
                "--yes",
                "--danger",
                "--i-know-this-can-break-my-device",
            ]
        )
        self.assertTrue(reboot.i_know_this_can_break_my_device)

    def test_web_write_gate_flags_survive_parser_split(self) -> None:
        args = cli.parse_args(
            [
                "web",
                "firewall",
                "set",
                "--param",
                "Enable=1",
                "--execute",
                "--backup-confirmed",
                "--yes",
                "--danger",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertTrue(args.execute)
        self.assertTrue(args.backup_confirmed)
        self.assertTrue(args.yes)
        self.assertTrue(args.danger)


if __name__ == "__main__":
    unittest.main()
