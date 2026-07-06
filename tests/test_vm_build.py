from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from fh_tool_cli.vm_build import build_vm, find_dump, select_rootfs_slot


class VmBuildTests(unittest.TestCase):
    def test_select_rootfs_slot_defaults_to_a_when_active_metadata_is_missing(self) -> None:
        slot, warning = select_rootfs_slot("active", manifest=None)

        self.assertEqual(slot, "A")
        self.assertIn("defaulting to rootfsA", warning or "")

    def test_find_dump_prefers_padbad_data_dump(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "mtd2_data.bin").write_bytes(b"a")
            preferred = root / "mtd2_data_padbad.bin"
            preferred.write_bytes(b"b")

            self.assertEqual(find_dump(root, index=2, name_contains="data", prefer_contains="padbad"), preferred)

    def test_build_vm_with_fake_tools_generates_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dump_dir = root / "dumps"
            output_dir = root / "vm"
            tools_dir = root / "tools"
            dump_dir.mkdir()
            tools_dir.mkdir()
            for name in ("mtd0_rootfsA.bin", "mtd2_data_padbad.bin", "mtd6_factory.bin"):
                (dump_dir / name).write_bytes((name * 128).encode("utf-8"))
            _write_fake_tools(tools_dir)

            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{tools_dir}{os.pathsep}{old_path}"
            try:
                result = build_vm(dump_dir=dump_dir, output_dir=output_dir, rootfs_slot="A", force=False)
            finally:
                os.environ["PATH"] = old_path

            manifest = json.loads((output_dir / "build-manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(result["ok"])
            self.assertTrue((output_dir / "rootfs-vm" / "fhconf" / "usrconfig_conf").is_file())
            self.assertTrue((output_dir / "rootfs-vm" / "fhdata" / "factory_conf").is_file())
            self.assertTrue((output_dir / "bin" / "proot-shell").stat().st_mode & 0o111)
            self.assertEqual(manifest["rootfs_slot"], "A")


def _write_fake_tools(tools_dir: Path) -> None:
    _script(
        tools_dir / "ubireader_extract_images",
        """#!/usr/bin/env sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
mkdir -p "$out/input.bin"
printf squashfs > "$out/input.bin/img-1_vol-rootfs_ubifs.ubifs"
""",
    )
    _script(
        tools_dir / "unsquashfs",
        """#!/usr/bin/env sh
set -eu
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then dest="$2"; shift 2; else shift; fi
done
mkdir -p "$dest/bin" "$dest/sbin" "$dest/lib" "$dest/fhrom/bin" "$dest/fhconf" "$dest/etc"
printf busybox > "$dest/bin/busybox"
printf uci > "$dest/sbin/uci"
printf ld > "$dest/lib/ld-linux.so.3"
printf cfg > "$dest/fhrom/bin/cfg_cmd"
printf tool > "$dest/fhrom/bin/cfg_tool"
printf pass > "$dest/etc/passwd_old"
chmod +x "$dest/bin/busybox" "$dest/sbin/uci" "$dest/fhrom/bin/cfg_cmd" "$dest/fhrom/bin/cfg_tool"
""",
    )
    _script(
        tools_dir / "ubireader_extract_files",
        """#!/usr/bin/env sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
mkdir -p "$out/1/apps" "$out/1/userdata"
printf app > "$out/1/apps/app.bin"
printf sys > "$out/1/userdata/sysinfo_conf"
printf usr > "$out/1/userdata/usrconfig_conf"
printf attr > "$out/1/userdata/attrconfig_conf"
printf param > "$out/1/userdata/param.tar.gz.enc"
""",
    )
    _script(
        tools_dir / "jefferson",
        """#!/usr/bin/env sh
set -eu
dest=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-d" ]; then dest="$2"; shift 2; else shift; fi
done
mkdir -p "$dest"
printf factory > "$dest/factory_conf"
printf preusr > "$dest/pre_usrconfig_conf"
printf preattr > "$dest/pre_attrconfig_conf"
""",
    )
    for name in ("qemu-arm-static", "proot"):
        _script(tools_dir / name, "#!/usr/bin/env sh\nexit 0\n")


def _script(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
