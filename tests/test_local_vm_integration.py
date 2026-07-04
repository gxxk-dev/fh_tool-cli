from __future__ import annotations

import os
import unittest
from pathlib import Path

from fh_tool_cli.backends.cfg_cmd import CfgCmdBackend
from fh_tool_cli.backends.local_vm import LocalVmShell
from fh_tool_cli.backends.web_ajax import WebAjaxClient
from fh_tool_cli.diagnostics import ip_status
from fh_tool_cli.errors import FHToolError


def _vm_root() -> Path | None:
    value = os.environ.get("FH_TOOL_CLI_VM_ROOT")
    if not value:
        return None
    return Path(value).expanduser()


@unittest.skipUnless(
    os.environ.get("FH_TOOL_CLI_VM_ROOT"),
    "set FH_TOOL_CLI_VM_ROOT to run local VM integration tests",
)
class LocalVmIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        vm_root = _vm_root()
        assert vm_root is not None
        cls.vm_root = vm_root
        cls.proot_shell = vm_root / "bin" / "proot-shell"
        cls.cfg_cmd = vm_root / "rootfs-vm" / "fhrom" / "bin" / "cfg_cmd"

    def test_vm_root_has_expected_shape(self) -> None:
        self.assertTrue(self.vm_root.is_dir(), self.vm_root)
        self.assertTrue(self.proot_shell.is_file(), self.proot_shell)
        self.assertTrue(self.cfg_cmd.is_file(), self.cfg_cmd)

    def test_cfg_cmd_reads_device_info(self) -> None:
        backend = CfgCmdBackend(LocalVmShell(self.vm_root, timeout=10).run)
        try:
            manufacturer = backend.get("InternetGatewayDevice.DeviceInfo.Manufacturer")
            model = backend.get("InternetGatewayDevice.DeviceInfo.ModelName")
        except FHToolError as exc:
            self.skipTest(f"local VM FHAPI runtime is not ready: {exc}")

        self.assertEqual(manufacturer, "FiberHome")
        self.assertTrue(model)

    def test_http_stack_serves_vendor_index(self) -> None:
        client = WebAjaxClient("http://127.0.0.1:8080/", timeout=2)
        try:
            result = client.login_check()
        except FHToolError as exc:
            self.skipTest(f"local VM HTTP stack is not ready: {exc}")

        self.assertEqual(result["status_code"], 200)
        self.assertTrue(result["ok"])

    def test_ajax_cgi_executes(self) -> None:
        client = WebAjaxClient("http://127.0.0.1:8080/", timeout=2)
        try:
            result = client.ajax_get("get_factory_mode")
        except FHToolError as exc:
            self.skipTest(f"local VM HTTP stack is not ready: {exc}")

        self.assertEqual(result["status_code"], 200)
        self.assertIn("response", result)

    def test_ip_diagnostics_report_partial_failures_in_local_vm(self) -> None:
        result = ip_status(LocalVmShell(self.vm_root, timeout=5).run)

        self.assertIn("probes", result["ip"])
        self.assertIn("partial_failure", result["ip"])
        self.assertIn("route", result["ip"]["probes"])


if __name__ == "__main__":
    unittest.main()
