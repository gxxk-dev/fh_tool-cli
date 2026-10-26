from __future__ import annotations

import argparse
import unittest
from unittest.mock import patch

from fh_tool_cli import cli
from fh_tool_cli.argparse_utils import parse_paths, parse_port_spec
from fh_tool_cli.config_store import format_mac
from fh_tool_cli.errors import CliError, FHToolResponseError
from fh_tool_cli.scan import ensure_local_scan_target, scan_fh_tool_endpoints

TEST_IP = "192.168.1.1"
TEST_MAC = "AABBCCDDEEFF"


class ParsePortSpecTests(unittest.TestCase):
    def test_comma_list(self) -> None:
        self.assertEqual(parse_port_spec("8080,80"), [8080, 80])

    def test_range(self) -> None:
        self.assertEqual(parse_port_spec("80-82"), [80, 81, 82])

    def test_duplicates_are_removed_in_first_seen_order(self) -> None:
        self.assertEqual(parse_port_spec("80,80-81,81"), [80, 81])

    def test_reversed_range_is_rejected(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_spec("82-80")

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_spec("0")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_spec("65536")

    def test_scan_size_is_bounded(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_spec("1-4097")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port_spec("")

    def test_paths_are_deduplicated(self) -> None:
        self.assertEqual(
            parse_paths("/fh_tool/api,/cgi-bin/tool_api,/fh_tool/api"),
            ["/fh_tool/api", "/cgi-bin/tool_api"],
        )


class ScanTargetTests(unittest.TestCase):
    def test_private_and_loopback_targets_are_allowed(self) -> None:
        for ip in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1", "100.64.0.1"):
            with self.subTest(ip=ip):
                ensure_local_scan_target(ip)

    def test_public_target_is_rejected(self) -> None:
        with self.assertRaises(CliError):
            ensure_local_scan_target("8.8.8.8")

    def test_invalid_target_is_rejected(self) -> None:
        with self.assertRaises(CliError):
            ensure_local_scan_target("not-an-ip")


class ScanEndpointTests(unittest.TestCase):
    def _surface(self, ip: str, port: int, path: str, timeout: float, *, diagnose: bool = False):
        assert diagnose is True
        return {
            "status_code": 200,
            "content_type": "text/html",
            "server": "nginx",
            "header_names": ["content-type", "server"],
        }

    def test_finds_getdevinfo_endpoint_and_stops(self) -> None:
        with (
            patch("fh_tool_cli.scan.tcp_open", side_effect=lambda ip, port, timeout: port == 80),
            patch("fh_tool_cli.scan.http_get_surface", side_effect=self._surface),
            patch(
                "fh_tool_cli.scan.fh_tool_call",
                side_effect=lambda ip, mac, payload, timeout, *, port, path, diagnose: (
                    {"result": 0, "Model": "HG5143F"}
                    if (port, path) == (80, "/fh_tool/api")
                    else (_ for _ in ()).throw(AssertionError("should stop after first path"))
                ),
            ),
        ):
            result = scan_fh_tool_endpoints(
                TEST_IP,
                TEST_MAC,
                1.0,
                ports=[8080, 80],
                paths=["/fh_tool/api", "/cgi-bin/tool_api"],
                workers=1,
            )

        self.assertTrue(result["stopped_early"])
        self.assertEqual(result["skipped_ports"], [8080])
        self.assertEqual(result["endpoint"], {"port": 80, "path": "/fh_tool/api"})
        self.assertEqual(result["verified"][0]["response"]["Model"], "HG5143F")
        self.assertFalse(result["results"]["8080"]["tcp"])
        self.assertTrue(result["results"]["80"]["tcp"])

    def test_http_error_on_first_path_then_success_on_second(self) -> None:
        def fake_call(ip, mac, payload, timeout, *, port, path, diagnose):
            if path == "/fh_tool/api":
                raise FHToolResponseError(
                    "not fh_tool",
                    status_code=200,
                    content_type="text/html",
                    body_kind="html",
                    body_length=20,
                    server="nginx",
                    header_names=["content-type", "server"],
                    response_headers={"Server": "nginx", "Content-Type": "text/html"},
                )
            return {"result": 0}

        with (
            patch("fh_tool_cli.scan.tcp_open", return_value=True),
            patch("fh_tool_cli.scan.http_get_surface", side_effect=self._surface),
            patch("fh_tool_cli.scan.fh_tool_call", side_effect=fake_call),
        ):
            result = scan_fh_tool_endpoints(
                TEST_IP,
                TEST_MAC,
                1.0,
                ports=[80],
                paths=["/fh_tool/api", "/cgi-bin/tool_api"],
            )

        first = result["results"]["80"]["paths"]["/fh_tool/api"]["getdevinfo"]
        self.assertFalse(first["ok"])
        self.assertEqual(first["server"], "nginx")
        self.assertEqual(first["body_kind"], "html")
        self.assertEqual(
            result["endpoint"], {"port": 80, "path": "/cgi-bin/tool_api"}
        )

    def test_missing_mac_only_records_surface(self) -> None:
        with (
            patch("fh_tool_cli.scan.tcp_open", return_value=True),
            patch("fh_tool_cli.scan.http_get_surface", side_effect=self._surface),
            patch("fh_tool_cli.scan.fh_tool_call") as call_mock,
        ):
            result = scan_fh_tool_endpoints(
                TEST_IP,
                None,
                1.0,
                ports=[80],
                paths=["/fh_tool/api"],
            )

        call_mock.assert_not_called()
        self.assertEqual(result["verified"], [])
        self.assertIsNone(result["endpoint"])
        self.assertEqual(
            result["results"]["80"]["paths"]["/fh_tool/api"]["getdevinfo"],
            {"ok": None, "error": "missing mac"},
        )

    def test_workers_must_be_bounded(self) -> None:
        with self.assertRaises(CliError):
            scan_fh_tool_endpoints(
                TEST_IP, TEST_MAC, 1.0, ports=[80], paths=["/fh_tool/api"], workers=65
            )

    def test_timeouts_must_be_positive(self) -> None:
        with self.assertRaises(CliError):
            scan_fh_tool_endpoints(
                TEST_IP, TEST_MAC, 0, ports=[80], paths=["/fh_tool/api"]
            )
        with self.assertRaises(CliError):
            scan_fh_tool_endpoints(
                TEST_IP,
                TEST_MAC,
                1.0,
                ports=[80],
                paths=["/fh_tool/api"],
                connect_timeout=0,
            )

    def test_direct_call_rejects_invalid_ports(self) -> None:
        with self.assertRaises(CliError):
            scan_fh_tool_endpoints(
                TEST_IP, TEST_MAC, 1.0, ports=[0], paths=["/fh_tool/api"]
            )


class CommandScanTests(unittest.TestCase):
    def test_command_scan_adds_mac_and_hint(self) -> None:
        args = argparse.Namespace(
            timeout=1.0,
            ports=[80],
            paths=["/fh_tool/api"],
            connect_timeout=0.4,
            workers=2,
            ask_mac=False,
            json=True,
        )
        with (
            patch("fh_tool_cli.cli.resolve_ip", return_value=(TEST_IP, "argument")),
            patch("fh_tool_cli.cli.resolve_mac", return_value=(TEST_MAC, "argument")),
            patch(
                "fh_tool_cli.cli.scan_fh_tool_endpoints",
                return_value={
                    "mode": "scan",
                    "ip": TEST_IP,
                    "verified": [],
                    "endpoint": None,
                },
            ),
        ):
            result = cli.command_scan(args)

        self.assertEqual(result["mac"], format_mac(TEST_MAC))
        self.assertEqual(result["mac_source"], "argument")
        self.assertIn("未找到", result["hint"])

    def test_command_scan_without_mac_explains_verification_limit(self) -> None:
        args = argparse.Namespace(
            timeout=1.0,
            ports=[80],
            paths=["/fh_tool/api"],
            connect_timeout=0.4,
            workers=2,
            ask_mac=False,
            json=True,
        )
        with (
            patch("fh_tool_cli.cli.resolve_ip", return_value=(TEST_IP, "argument")),
            patch("fh_tool_cli.cli.resolve_mac", return_value=(None, "missing")),
            patch(
                "fh_tool_cli.cli.scan_fh_tool_endpoints",
                return_value={"mode": "scan", "ip": TEST_IP, "verified": []},
            ),
        ):
            result = cli.command_scan(args)

        self.assertIsNone(result["mac"])
        self.assertIn("缺少 MAC", result["hint"])


if __name__ == "__main__":
    unittest.main()
