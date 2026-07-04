from __future__ import annotations

import unittest

from fh_tool_cli.backends.cfg_cmd import CfgCmdBackend
from fh_tool_cli.diagnostics import (
    PON_PATHS,
    WAN_COLLECTION_PATH,
    firewall_status,
    ip_status,
    ipv6_status,
    pon_status,
    vlan_list,
    wan_list,
)


class DiagnosticsTests(unittest.TestCase):
    def test_pon_status_redacts_loid(self) -> None:
        values = {
            PON_PATHS["type"]: "GPON",
            PON_PATHS["register_status"]: "registered",
            PON_PATHS["rx_power"]: "-18.2",
            PON_PATHS["tx_power"]: "2.1",
            PON_PATHS["loid"]: "loid-secret",
        }
        backend = CfgCmdBackend(lambda command: f"{command.split()[-1]}={values[command.split()[-1]]}")

        result = pon_status(backend)

        self.assertEqual(result["pon"]["values"]["loid"]["value"], "[REDACTED]")
        self.assertEqual(result["pon"]["values"]["type"]["value"], "GPON")

    def test_wan_list_reports_missing_paths_as_errors(self) -> None:
        backend = CfgCmdBackend(lambda command: (_ for _ in ()).throw(RuntimeError("missing")))

        result = wan_list(backend)

        self.assertEqual(result["wan"]["connections"], [])
        self.assertTrue(result["wan"]["errors"])

    def test_wan_list_discovers_real_vm_style_wan_instances(self) -> None:
        values = {
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_CT-COM_ServiceList": "INTERNET",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.ConnectionType": "IP_Routed",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_CT-COM_IPMode": "3",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.NATEnabled": "1",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.Username": "pppoe-user",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.X_CT-COM_WANEponLinkConfig.VLANID": "1729",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANPPPConnection.1.X_CT-COM_ServiceList": "OTHER",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANPPPConnection.1.ConnectionType": "PPPoE_Bridged",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.X_CT-COM_WANEponLinkConfig.VLANID": "3726",
        }

        def runner(command: str) -> str:
            path = command.split()[-1]
            if path not in values:
                raise RuntimeError("missing")
            return f"{path}={values[path]}"

        result = wan_list(CfgCmdBackend(runner))

        connections = result["wan"]["connections"]
        self.assertEqual(result["wan"]["connection_count"], 2)
        self.assertEqual(connections[0]["wan_connection_device"], 2)
        self.assertEqual(connections[0]["values"]["service_list"]["value"], "INTERNET")
        self.assertEqual(connections[0]["values"]["vlan"]["value"], "1729")
        self.assertEqual(connections[0]["values"]["pppoe_username"]["value"], "[REDACTED]")
        self.assertEqual(connections[1]["values"]["service_list"]["value"], "OTHER")

    def test_wan_list_skips_expensive_scan_when_collection_is_empty(self) -> None:
        calls: list[str] = []

        def runner(command: str) -> str:
            path = command.split()[-1]
            calls.append(path)
            if path == WAN_COLLECTION_PATH:
                return f"{WAN_COLLECTION_PATH}="
            raise RuntimeError("unexpected exhaustive scan")

        result = wan_list(CfgCmdBackend(runner, expensive_missing_paths=True))

        self.assertEqual(calls, [WAN_COLLECTION_PATH])
        self.assertEqual(result["wan"]["connections"], [])
        self.assertEqual(result["wan"]["connection_count"], 0)
        self.assertEqual(result["wan"]["scanned_wan_connection_devices"], [])
        self.assertFalse(result["wan"]["partial_failure"])
        self.assertEqual(result["wan"]["scan_skipped"], "empty_wan_collection")

    def test_vlan_list_uses_discovered_wan_vlan(self) -> None:
        values = {
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_CT-COM_ServiceList": "INTERNET",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.X_CT-COM_WANEponLinkConfig.VLANID": "1729",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection.1.X_CT-COM_LanInterface": "LAN1,LAN2",
        }

        def runner(command: str) -> str:
            path = command.split()[-1]
            if path not in values:
                raise RuntimeError("missing")
            return f"{path}={values[path]}"

        result = vlan_list(CfgCmdBackend(runner))

        self.assertEqual(result["vlan"]["wan"][0]["wan_connection_device"], 2)
        self.assertEqual(result["vlan"]["wan"][0]["value"]["value"], "1729")
        self.assertEqual(result["vlan"]["wan"][0]["vlan"]["value"], "1729")
        self.assertEqual(result["vlan"]["wan"][0]["service_list"]["value"], "INTERNET")
        self.assertEqual(result["vlan"]["wan"][0]["lan_binding"]["value"], "LAN1,LAN2")

    def test_pon_status_uses_calibrated_gpon_and_loid_paths(self) -> None:
        values = {
            "InternetGatewayDevice.WANDevice.1.X_CT-COM_GponInterfaceConfig.Status": "Up",
            "InternetGatewayDevice.WANDevice.1.X_CT-COM_GponInterfaceConfig.RXPower": "-18.1",
            "InternetGatewayDevice.WANDevice.1.X_CT-COM_GponInterfaceConfig.TXPower": "2.2",
            "InternetGatewayDevice.X_FH_PON_MANAGE.reginfo.legal_loid": "loid-secret",
        }

        def runner(command: str) -> str:
            path = command.split()[-1]
            if path not in values:
                raise RuntimeError("missing")
            return f"{path}={values[path]}"

        result = pon_status(CfgCmdBackend(runner))

        self.assertEqual(result["pon"]["values"]["register_status"]["value"], "Up")
        self.assertEqual(result["pon"]["values"]["rx_power"]["value"], "-18.1")
        self.assertEqual(result["pon"]["values"]["loid"]["value"], "[REDACTED]")

    def test_ip_status_runs_read_only_shell_probes(self) -> None:
        calls: list[str] = []

        def shell(command: str) -> str:
            calls.append(command)
            return command

        result = ip_status(shell)

        self.assertEqual(calls, ["ip addr", "ip route", "cat /etc/resolv.conf"])
        self.assertFalse(result["ip"]["partial_failure"])
        self.assertEqual(result["ip"]["probes"]["route"]["output"], "ip route")

    def test_ip_status_marks_partial_failure_without_losing_successes(self) -> None:
        def shell(command: str) -> str:
            if command == "ip route":
                raise RuntimeError("ip tool missing")
            return command

        result = ip_status(shell)

        self.assertTrue(result["ip"]["partial_failure"])
        self.assertEqual(result["ip"]["probes"]["addr"]["output"], "ip addr")
        self.assertFalse(result["ip"]["probes"]["route"]["ok"])
        self.assertEqual(result["ip"]["errors"], {"route": "ip tool missing"})

    def test_firewall_status_has_stable_partial_failure_fields(self) -> None:
        values = {
            "InternetGatewayDevice.Firewall.Enable": "1",
            "InternetGatewayDevice.X_CT-COM_ALG.Enable": "1",
            "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPServerEnable": "1",
        }

        def runner(command: str) -> str:
            path = command.split()[-1]
            if path not in values:
                raise RuntimeError("missing")
            return f"{path}={values[path]}"

        result = firewall_status(CfgCmdBackend(runner))

        self.assertIn("partial_failure", result["firewall"])
        self.assertIn("errors", result["firewall"])
        self.assertEqual(result["firewall"]["values"]["firewall_enable"]["value"], "1")
        self.assertEqual(result["firewall"]["values"]["alg_enable"]["value"], "1")
        self.assertEqual(result["firewall"]["values"]["lan_dhcp_enable"]["value"], "1")

    def test_ipv6_status_has_stable_partial_failure_fields(self) -> None:
        values = {
            "InternetGatewayDevice.LANDevice.1.X_CT-COM_IPv6LAN.LocalAddress": "fe80::1",
            "InternetGatewayDevice.LANDevice.1.X_CT-COM_DHCPv6.ServerEnable": "1",
            "InternetGatewayDevice.LANDevice.1.X_CT-COM_RA.Enable": "1",
        }

        def runner(command: str) -> str:
            path = command.split()[-1]
            if path not in values:
                raise RuntimeError("missing")
            return f"{path}={values[path]}"

        result = ipv6_status(CfgCmdBackend(runner))

        self.assertIn("partial_failure", result["ipv6"])
        self.assertIn("errors", result["ipv6"])
        self.assertEqual(result["ipv6"]["wan"], [])
        self.assertEqual(result["ipv6"]["lan"]["values"]["lan_ipv6_address"]["value"], "fe80::1")
        self.assertEqual(result["ipv6"]["lan"]["values"]["dhcpv6_server"]["value"], "1")
        self.assertEqual(result["ipv6"]["lan"]["values"]["router_advertisement"]["value"], "1")


if __name__ == "__main__":
    unittest.main()
