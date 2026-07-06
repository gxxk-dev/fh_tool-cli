from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fh_tool_cli.vm_verify import verify_vm


class VmVerifyTests(unittest.TestCase):
    def test_verify_fake_vm_root_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            vm_root = Path(temp_dir)
            _make_fake_vm(vm_root)

            result = verify_vm(vm_root=vm_root, with_fhapi=False, with_http=False)
            manifest = json.loads((vm_root / "verify-manifest.json").read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertEqual(manifest["command"], "vm verify")
        self.assertTrue(any(check["name"] == "cfg_cmd binary loads" and check["ok"] for check in result["checks"]))


def _make_fake_vm(vm_root: Path) -> None:
    for directory in (
        vm_root / "bin",
        vm_root / "rootfs-vm" / "bin",
        vm_root / "rootfs-vm" / "sbin",
        vm_root / "rootfs-vm" / "lib",
        vm_root / "rootfs-vm" / "fhrom" / "bin",
        vm_root / "rootfs-vm" / "fhconf",
        vm_root / "rootfs-vm" / "fhdata",
        vm_root / "rootfs-vm" / "opt" / "upt" / "apps",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    for relative in (
        "rootfs-vm/bin/busybox",
        "rootfs-vm/sbin/uci",
        "rootfs-vm/lib/ld-linux.so.3",
        "rootfs-vm/fhrom/bin/cfg_cmd",
        "rootfs-vm/fhconf/sysinfo_conf",
        "rootfs-vm/fhconf/usrconfig_conf",
        "rootfs-vm/fhconf/attrconfig_conf",
        "rootfs-vm/fhdata/factory_conf",
        "rootfs-vm/fhdata/pre_usrconfig_conf",
        "rootfs-vm/fhdata/pre_attrconfig_conf",
    ):
        path = vm_root / relative
        path.write_text("x", encoding="utf-8")
    _script(
        vm_root / "bin" / "qemu-exec",
        """#!/usr/bin/env sh
case "$*" in
  *cfg_cmd*) echo "FHAPI_INIT Error" >&2; exit 1 ;;
  *) exit 0 ;;
esac
""",
    )
    _script(vm_root / "bin" / "proot-shell", "#!/usr/bin/env sh\nexit 0\n")
    for name in ("prepare-runtime", "start-fhapi-proot", "stop-fhapi-proot", "start-http-stack-proot", "verify"):
        _script(vm_root / "bin" / name, "#!/usr/bin/env sh\nexit 0\n")
    (vm_root / "rootfs-vm" / "bin" / "busybox").chmod(0o755)
    (vm_root / "rootfs-vm" / "fhrom" / "bin" / "cfg_cmd").chmod(0o755)


def _script(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
