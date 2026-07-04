from __future__ import annotations

import argparse
import unittest

from fh_tool_cli.config_store import format_mac, normalize_ip, normalize_mac
from fh_tool_cli.crypto import decrypt_payload, derive_crypto, encrypt_payload
from fh_tool_cli.errors import CliError
from fh_tool_cli.risk import dry_run_notice, is_confirmed, reject_deprecated_confirmation_args


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
    def test_confirm_gate_is_single_execution_flag(self) -> None:
        self.assertFalse(is_confirmed(argparse.Namespace(confirm=False)))
        self.assertTrue(is_confirmed(argparse.Namespace(confirm=True)))

    def test_deprecated_confirmation_flags_are_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "已弃用"):
            reject_deprecated_confirmation_args(argparse.Namespace(deprecated_yes=True))

    def test_dry_run_notice_points_to_confirm(self) -> None:
        notice = dry_run_notice()
        self.assertTrue(notice["dry_run"])
        self.assertFalse(notice["executed"])
        self.assertEqual(notice["confirm_requires"], ["--confirm"])


if __name__ == "__main__":
    unittest.main()
