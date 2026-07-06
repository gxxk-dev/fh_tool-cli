from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import patch

from fh_tool_cli.cli import parse_args
from fh_tool_cli.errors import CliError
from fh_tool_cli.web_writes import build_web_write_payload


class RecordingWebClient:
    def __init__(self) -> None:
        self.sessionid: str | None = None
        self.calls: list[tuple[str, object]] = []

    def login(self, username: str, password: str, *, port: str) -> dict[str, object]:
        self.calls.append(("login", (username, password, port)))
        self.sessionid = "sid-after-login"
        return {
            "ok": True,
            "username": username,
            "login_result": 0,
            "sessionid_present": True,
        }

    def typed_write(
        self,
        group: str,
        action: str,
        payload: dict[str, object],
        *,
        dry_run: bool = True,
    ) -> dict[str, object]:
        self.calls.append(("typed_write", (group, action, payload, dry_run)))
        return {
            "group": group,
            "action": action,
            "payload": payload,
            "dry_run": dry_run,
        }


def _run_web_command(argv: list[str]) -> dict[str, object]:
    args = parse_args(argv)
    with patch("fh_tool_cli.commands.web._web_client_from_args", return_value=RecordingWebClient()):
        return args.handler(args)


class WebWritePayloadTests(unittest.TestCase):
    def test_port_mapping_add_typed_payload_matches_vendor_fields(self) -> None:
        result = _run_web_command(
            [
                "web",
                "port-mapping",
                "set",
                "--operation",
                "add",
                "--wan-index",
                "1",
                "--wan-session-index",
                "2",
                "--wan-iporppp",
                "ppp",
                "--external-port",
                "8080",
                "--protocol",
                "tcp",
                "--internal-client",
                "192.168.1.20",
                "--internal-port",
                "80",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertTrue(result["dry_run"])
        self.assertIn("--confirm", result["hint"])
        self.assertEqual(
            result["payload"],
            {
                "action": "add",
                "wan_index": "1",
                "wan_session_index": "2",
                "wan_iporppp": "2",
                "ExternalPort": "8080",
                "PortMappingProtocol": "TCP",
                "InternalClient": "192.168.1.20",
                "InternalPort": "80",
            },
        )

    def test_port_mapping_enablechange_typed_payload(self) -> None:
        result = _run_web_command(
            [
                "web",
                "port-mapping",
                "set",
                "--operation",
                "enablechange",
                "--wan-index",
                "1",
                "--wan-session-index",
                "2",
                "--wan-iporppp",
                "1",
                "--mapping-index",
                "3",
                "--enabled",
                "off",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertEqual(
            result["payload"],
            {
                "action": "enablechange",
                "wan_index": "1",
                "wan_session_index": "2",
                "mapping_index": "3",
                "PortMappingEnabled": "0",
                "wan_iporppp": "1",
            },
        )

    def test_port_mapping_rejects_delete_with_add_only_fields(self) -> None:
        args = parse_args(
            [
                "web",
                "port-mapping",
                "set",
                "--operation",
                "delete",
                "--wan-index",
                "1",
                "--wan-session-index",
                "2",
                "--wan-iporppp",
                "1",
                "--mapping-index",
                "3",
                "--external-port",
                "8080",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--external-port"):
            build_web_write_payload("port-mapping", "set", args)

    def test_vlanbind_add_builds_vlan_part_and_optional_rebind_fields(self) -> None:
        result = _run_web_command(
            [
                "web",
                "vlanbind",
                "set",
                "--operation",
                "add",
                "--if-name",
                "eth1",
                "--user-vlan",
                "100",
                "--wan-vlan",
                "200",
                "--wan-index",
                "4",
                "--wan-session-index",
                "5",
                "--wan-iporppp",
                "ip",
                "--laninterface",
                "dev.eth.2,dev.eth.3",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertEqual(
            result["payload"],
            {
                "action": "add",
                "IfName": "eth1",
                "vlanPart": "100/200",
                "wan_index": "4",
                "wan_session_index": "5",
                "wan_iporppp": "1",
                "laninterface": "dev.eth.2,dev.eth.3",
            },
        )

    def test_vlanbind_delete_uses_explicit_vlan_part(self) -> None:
        result = _run_web_command(
            [
                "web",
                "vlanbind",
                "set",
                "--operation",
                "delete",
                "--if-name",
                "wl0.0",
                "--vlan-part",
                "101/-1",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertEqual(
            result["payload"],
            {
                "action": "delete",
                "IfName": "wl0.0",
                "vlanPart": "101/-1",
            },
        )

    def test_vlanbind_rejects_ambiguous_vlan_part_inputs(self) -> None:
        args = parse_args(
            [
                "web",
                "vlanbind",
                "set",
                "--operation",
                "add",
                "--if-name",
                "eth1",
                "--vlan-part",
                "100/200",
                "--user-vlan",
                "100",
                "--wan-vlan",
                "200",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "二选一"):
            build_web_write_payload("vlanbind", "set", args)

    def test_firewall_requires_complete_base_fields(self) -> None:
        args = parse_args(
            [
                "web",
                "firewall",
                "set",
                "--enable",
                "1",
                "--ip",
                "192.168.1.1",
            ]
        )

        with self.assertRaisesRegex(CliError, "--level"):
            args.handler(args)

    def test_firewall_full_typed_payload(self) -> None:
        result = _run_web_command(
            [
                "web",
                "firewall",
                "set",
                "--enable",
                "on",
                "--level",
                "medium",
                "--dos-enable",
                "off",
                "--ipv6-enable",
                "1",
                "--portscan-enable",
                "yes",
                "--bad-packets-enable",
                "no",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertEqual(
            result["payload"],
            {
                "Enable": 1,
                "LEVEL": "medium",
                "DOSFEnable": 0,
                "IPv6FirewallEnable": 1,
                "PORTSCANEnable": 1,
                "BADPACETSFEnable": 0,
            },
        )

    def test_services_switch_typed_payload(self) -> None:
        result = _run_web_command(
            [
                "web",
                "services",
                "set",
                "--service",
                "telnet",
                "--enabled",
                "0",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertEqual(result["payload"], {"action": "telnet", "telnet": "0"})

    def test_services_terminal_number_typed_payload(self) -> None:
        result = _run_web_command(
            [
                "web",
                "services",
                "set",
                "--terminal-number",
                "32",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertEqual(result["payload"], {"action": "terminal_number", "terminal_number": "32"})

    def test_typed_write_dry_run_does_not_login_even_with_password(self) -> None:
        client = RecordingWebClient()
        args = parse_args(
            [
                "web",
                "services",
                "set",
                "--service",
                "telnet",
                "--enabled",
                "0",
                "--password",
                "plain-secret",
                "--ip",
                "192.168.1.1",
            ]
        )

        with patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client):
            result = args.handler(args)

        self.assertTrue(result["dry_run"])
        self.assertEqual(
            client.calls,
            [("typed_write", ("services", "set", {"action": "telnet", "telnet": "0"}, True))],
        )

    def test_typed_write_confirm_logs_in_before_post(self) -> None:
        client = RecordingWebClient()
        args = parse_args(
            [
                "web",
                "services",
                "set",
                "--service",
                "telnet",
                "--enabled",
                "0",
                "--confirm",
                "--ip",
                "192.168.1.1",
            ]
        )

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch("fh_tool_cli.commands.web._web_password_from_args", return_value=("auto-secret", "cfg", [])),
        ):
            result = args.handler(args)

        self.assertFalse(result["dry_run"])
        self.assertEqual(
            client.calls,
            [
                ("login", ("useradmin", "auto-secret", "0")),
                ("typed_write", ("services", "set", {"action": "telnet", "telnet": "0"}, False)),
            ],
        )
        self.assertEqual(result["login"]["password_source"], "cfg")
        self.assertNotIn("auto-secret", str(result))

    def test_generic_payload_still_works_and_param_overrides_typed_values(self) -> None:
        result = _run_web_command(
            [
                "web",
                "services",
                "set",
                "--service",
                "telnet",
                "--enabled",
                "1",
                "--json-payload",
                '{"telnet":"json"}',
                "--param",
                "telnet=0",
                "--ip",
                "192.168.1.1",
            ]
        )

        self.assertEqual(result["payload"], {"action": "telnet", "telnet": "0"})

    def test_invalid_port_is_rejected_by_argparse(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(
                    [
                        "web",
                        "port-mapping",
                        "set",
                        "--operation",
                        "add",
                        "--external-port",
                        "0",
                    ]
                )

    def test_old_execute_flags_are_deprecated_before_client_creation(self) -> None:
        args = parse_args(
            [
                "web",
                "services",
                "set",
                "--service",
                "telnet",
                "--enabled",
                "0",
                "--execute",
                "--ip",
                "192.168.1.1",
            ]
        )

        with patch("fh_tool_cli.commands.web._web_client_from_args", side_effect=AssertionError("client used")):
            with self.assertRaisesRegex(CliError, "已弃用"):
                args.handler(args)


if __name__ == "__main__":
    unittest.main()
