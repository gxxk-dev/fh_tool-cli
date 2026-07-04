from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fh_tool_cli.backends.cfg_cmd import (
    CfgCmdBackend,
    cfg_path_risk,
    cfg_read_risk,
    cfg_set_with_verify,
    diff_cfg_snapshots,
    parse_cfg_get_output,
    redact_cfg_value,
)
from fh_tool_cli.backends.local_vm import LocalVmShell
from fh_tool_cli.errors import FHToolError


class CfgCmdTests(unittest.TestCase):
    def test_parse_cfg_get_output_prefers_matching_path_assignment(self) -> None:
        self.assertEqual(
            parse_cfg_get_output(
                "InternetGatewayDevice.DeviceInfo.Name",
                "cfg_cmd get x\nInternetGatewayDevice.DeviceInfo.Name=HG5143F\n# ",
            ),
            "HG5143F",
        )

    def test_parse_cfg_get_output_accepts_vendor_success_line(self) -> None:
        self.assertEqual(
            parse_cfg_get_output(
                "InternetGatewayDevice.DeviceInfo.Manufacturer",
                "argc = 3\nget success!value=FiberHome\n",
            ),
            "FiberHome",
        )

    def test_backend_quotes_commands_and_verifies_set(self) -> None:
        calls: list[str] = []
        values = {"Device.Name": "old"}

        def runner(command: str) -> str:
            calls.append(command)
            if command == "cfg_cmd set Device.Name new":
                values["Device.Name"] = "new"
                return "ok"
            if command == "cfg_cmd get Device.Name":
                return f"Device.Name={values['Device.Name']}"
            raise AssertionError(command)

        result = cfg_set_with_verify(CfgCmdBackend(runner), "Device.Name", "new")

        self.assertEqual(calls, ["cfg_cmd set Device.Name new", "cfg_cmd get Device.Name"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["risk"], "write")

    def test_cfg_risk_and_redaction(self) -> None:
        self.assertEqual(cfg_path_risk("InternetGatewayDevice.WAN.VLAN"), "danger")
        self.assertEqual(cfg_path_risk("InternetGatewayDevice.X_CT-COM_SmartSwitch.Enable"), "danger")
        self.assertEqual(cfg_read_risk("InternetGatewayDevice.PPPoE.Password"), "sensitive")
        self.assertEqual(
            redact_cfg_value(
                "InternetGatewayDevice.PPPoE.Password",
                "secret",
                reveal_secrets=False,
            ),
            ("[REDACTED]", True),
        )
        self.assertEqual(
            redact_cfg_value(
                "InternetGatewayDevice.DeviceInfo.Name",
                "HG5143F",
                reveal_secrets=False,
            ),
            ("HG5143F", False),
        )

    def test_diff_cfg_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            before = Path(temp_dir) / "before.json"
            after = Path(temp_dir) / "after.json"
            before.write_text(
                json.dumps({"values": {"a": "1", "b": "same"}}),
                encoding="utf-8",
            )
            after.write_text(
                json.dumps({"values": {"a": "2", "b": "same", "c": "3"}}),
                encoding="utf-8",
            )

            diff = diff_cfg_snapshots(before, after)

            self.assertEqual(diff["change_count"], 2)
            self.assertEqual(diff["changes"][0], {"path": "a", "before": "1", "after": "2"})
            self.assertEqual(diff["changes"][1], {"path": "c", "before": None, "after": "3"})

    def test_local_vm_shell_requires_proot_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            shell = LocalVmShell(Path(temp_dir))

            with self.assertRaisesRegex(FHToolError, "bin/proot-shell"):
                shell.run("cfg_cmd get Device.Name")

    def test_local_vm_shell_rejects_rootfs_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            rootfs = Path(temp_dir)
            (rootfs / "fhrom" / "bin").mkdir(parents=True)
            (rootfs / "fhrom" / "bin" / "cfg_cmd").write_text("", encoding="utf-8")
            shell = LocalVmShell(rootfs)

            with self.assertRaisesRegex(FHToolError, "not rootfs-vm"):
                shell.run("cfg_cmd get Device.Name")

    def test_local_vm_shell_requires_cfg_cmd_inside_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            vm_root = Path(temp_dir)
            (vm_root / "bin").mkdir()
            (vm_root / "bin" / "proot-shell").write_text("", encoding="utf-8")
            shell = LocalVmShell(vm_root)

            with self.assertRaisesRegex(FHToolError, "rootfs-vm/fhrom/bin/cfg_cmd"):
                shell.run("cfg_cmd get Device.Name")


if __name__ == "__main__":
    unittest.main()
