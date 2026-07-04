from __future__ import annotations

import argparse
import unittest

from fh_tool_cli.config_store import format_mac, normalize_ip, normalize_mac
from fh_tool_cli.crypto import decrypt_payload, derive_crypto, encrypt_payload
from fh_tool_cli.errors import CliError
from fh_tool_cli.risk import require_danger, require_extreme, require_yes


class CryptoTests(unittest.TestCase):
    def test_fh_tool_payload_roundtrip(self) -> None:
        crypto = derive_crypto("AABBCCDDEEFF")
        payload = {"index": "1", "func": "GetDevInfo", "name": "value"}

        encrypted = encrypt_payload(payload, crypto)

        self.assertEqual(decrypt_payload(encrypted, crypto), payload)


class ConfigStoreTests(unittest.TestCase):
    def test_normalizes_supported_ip_and_mac_formats(self) -> None:
        self.assertEqual(normalize_ip(" 192.168.1.1 "), "192.168.1.1")
        self.assertEqual(normalize_mac("aa:bb:cc:dd:ee:ff"), "AABBCCDDEEFF")
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "AABBCCDDEEFF")
        self.assertEqual(format_mac("AABBCCDDEEFF"), "AA:BB:CC:DD:EE:FF")

    def test_rejects_ipv6_gateway(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_ip("fe80::1")


class RiskTests(unittest.TestCase):
    def test_write_gate_requires_yes(self) -> None:
        with self.assertRaises(CliError):
            require_yes(argparse.Namespace(yes=False), "write")

        require_yes(argparse.Namespace(yes=True), "write")

    def test_danger_and_extreme_gates_require_layered_flags(self) -> None:
        with self.assertRaises(CliError):
            require_danger(argparse.Namespace(yes=True, danger=False), "danger")
        require_danger(argparse.Namespace(yes=True, danger=True), "danger")

        with self.assertRaises(CliError):
            require_extreme(
                argparse.Namespace(
                    yes=True,
                    danger=True,
                    i_know_this_can_break_my_device=False,
                ),
                "extreme",
            )
        require_extreme(
            argparse.Namespace(
                yes=True,
                danger=True,
                i_know_this_can_break_my_device=True,
            ),
            "extreme",
        )


if __name__ == "__main__":
    unittest.main()
