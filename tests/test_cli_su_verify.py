from __future__ import annotations

import unittest
from unittest.mock import patch

from fh_tool_cli.cli import _telnet_root_shell_runner_from_args, parse_args
from fh_tool_cli.credential_sources import resolve_su_password_from_shell
from fh_tool_cli.crypt_unix import sha256_crypt
from fh_tool_cli.errors import CliError

HG5143F_HASH = "$1$$c29kb1Alc4Ic54TuMH2iv."  # Fh@36BC10 的 md5-crypt 实机 oracle
MAC = "D8F50736BC10"
# TEST-NET-1,不可路由,防止单测意外触到局域网真实设备
UNREACHABLE_IP = "192.0.2.1"
HG5143F_TELSU_LINE = f"root:{HG5143F_HASH}:0:0:Telnet user:/:/bin/ash\r\n# "


def _derive_args(extra: list[str] | None = None):
    return parse_args(
        [
            "cfg",
            "get",
            "InternetGatewayDevice.DeviceInfo.Manufacturer",
            "--ip",
            UNREACHABLE_IP,
            "--mac",
            MAC,
            *(extra or []),
        ]
    )


class FakeShell:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.run_calls: list[str] = []
        self.root_calls: list[tuple[str, str]] = []

    def run(self, command: str) -> str:
        self.run_calls.append(command)
        return self.raw

    def run_as_root(self, command: str, *, su_password: str) -> str:
        self.root_calls.append((command, su_password))
        return "ok"


class ResolveSuPasswordTests(unittest.TestCase):
    def test_verified_hg5143f_hash(self) -> None:
        shell = FakeShell(HG5143F_TELSU_LINE)
        args = _derive_args()

        password, source = resolve_su_password_from_shell(args, ip=UNREACHABLE_IP, shell=shell)

        self.assertEqual((password, source), ("Fh@36BC10", "verified-telsu:hg5143f-su"))
        self.assertEqual(shell.run_calls, ["cat /var/telsu"])

    def test_verified_hg6142a3_hash(self) -> None:
        hashed = sha256_crypt("hg2x036BC10", "fh")
        shell = FakeShell(f"root:{hashed}:0:0:Telnet user:/:/bin/ash\r\n# ")
        args = _derive_args()

        password, source = resolve_su_password_from_shell(args, ip=UNREACHABLE_IP, shell=shell)

        self.assertEqual((password, source), ("hg2x036BC10", "verified-telsu:hg6142a3-root"))

    def test_explicit_password_skips_probe(self) -> None:
        shell = FakeShell("should-not-be-read")
        args = _derive_args(["--su-password", "manual-secret"])

        password, source = resolve_su_password_from_shell(args, ip=UNREACHABLE_IP, shell=shell)

        self.assertEqual((password, source), ("manual-secret", "argument"))
        self.assertEqual(shell.run_calls, [])

    def test_unreadable_hash_raises_with_guidance(self) -> None:
        shell = FakeShell("cat: can't open '/var/telsu': Permission denied\r\n# ")
        args = _derive_args()

        with self.assertRaises(CliError) as cm:
            resolve_su_password_from_shell(args, ip=UNREACHABLE_IP, shell=shell)

        self.assertIn("--su-password", str(cm.exception))

    def test_mismatched_hash_raises(self) -> None:
        hashed = sha256_crypt("changed-password", "fh")
        shell = FakeShell(f"root:{hashed}:0:0:Telnet user:/:/bin/ash\r\n# ")
        args = _derive_args()

        with self.assertRaises(CliError) as cm:
            resolve_su_password_from_shell(args, ip=UNREACHABLE_IP, shell=shell)

        self.assertIn("adapt-prompt", str(cm.exception))


class LazyRootRunnerTests(unittest.TestCase):
    def test_runner_probes_once_and_caches(self) -> None:
        shell = FakeShell(HG5143F_TELSU_LINE)
        args = _derive_args()

        with patch("fh_tool_cli.cli._telnet_shell_from_args", return_value=shell):
            runner = _telnet_root_shell_runner_from_args(args)
            self.assertEqual(shell.run_calls, [], "构造 runner 不应触发 probe")
            runner("cmd1")
            runner("cmd2")

        self.assertEqual(shell.run_calls, ["cat /var/telsu"], "多次 root 命令只 probe 一次")
        self.assertEqual([command for command, _ in shell.root_calls], ["cmd1", "cmd2"])
        self.assertEqual([password for _, password in shell.root_calls], ["Fh@36BC10", "Fh@36BC10"])

    def test_runner_uses_preresolved_password_without_probe(self) -> None:
        shell = FakeShell("should-not-be-read")
        args = _derive_args()

        with patch("fh_tool_cli.cli._telnet_shell_from_args", return_value=shell):
            runner = _telnet_root_shell_runner_from_args(args, su_password=("pw", "argument"))
            runner("cmd")

        self.assertEqual(shell.run_calls, [])
        self.assertEqual(shell.root_calls, [("cmd", "pw")])


class CredentialsDeriveVerifyTests(unittest.TestCase):
    def _derive_command_args(self, extra: list[str] | None = None):
        return parse_args(
            [
                "credentials",
                "derive",
                "--ip",
                UNREACHABLE_IP,
                "--mac",
                MAC,
                *(extra or []),
            ]
        )

    def test_derive_without_verify_has_null_verify_field(self) -> None:
        args = self._derive_command_args(["--kind", "hg6142a3-root"])

        result = args.handler(args)

        self.assertIsNone(result["verify"])
        self.assertEqual(result["credentials"][0]["verified"], None)

    def test_derive_verify_marks_matching_candidate(self) -> None:
        args = self._derive_command_args(["--verify"])
        fake_shell = FakeShell(HG5143F_TELSU_LINE)

        with patch("fh_tool_cli.cli._telnet_shell_from_args", return_value=fake_shell):
            result = args.handler(args)

        by_kind = {credential["kind"]: credential for credential in result["credentials"]}
        self.assertEqual(result["verify"], "verified-telsu:hg5143f-su")
        self.assertTrue(by_kind["hg5143f-su"]["verified"])
        self.assertEqual(
            by_kind["hg5143f-su"]["confidence"],
            "high-hg5143f-su-local-live-verified",
        )
        self.assertFalse(by_kind["hg6142a3-root"]["verified"])
        self.assertIsNone(by_kind["hg5143f-telnet"]["verified"])


if __name__ == "__main__":
    unittest.main()
