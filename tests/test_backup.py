from __future__ import annotations

import base64
import hashlib
import io
import json
import shlex
import tarfile
import tempfile
import unittest
from pathlib import Path

from fh_tool_cli.backup import (
    create_backup,
    restore_backup_archive,
    restore_backup_to_device,
    verify_backup,
    verify_backup_archive,
)
from fh_tool_cli.errors import CliError


class BackupTests(unittest.TestCase):
    def test_create_backup_archive_and_verify_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            output = Path(temp_dir) / "backup.tgz"
            (root / "fhconf").mkdir(parents=True)
            (root / "fhdata").mkdir(parents=True)
            (root / "fhconf" / "usrconfig_conf").write_text("config data", encoding="utf-8")
            (root / "fhdata" / "sysinfo_conf").write_text("sysinfo", encoding="utf-8")

            result = create_backup(
                root,
                output_path=output,
                paths=["/fhconf/usrconfig_conf", "/fhdata/sysinfo_conf", "/missing"],
            )

            self.assertEqual(result["included"], 2)
            self.assertEqual(result["missing"], 1)
            verify = verify_backup_archive(output)
            self.assertTrue(verify["ok"])
            self.assertEqual(verify["verified"], 2)
            self.assertEqual(verify["missing_recorded"], 1)

            with tarfile.open(output, "r:gz") as archive:
                self.assertIsNotNone(archive.getmember("manifest.json"))
                self.assertIsNotNone(archive.getmember("files/fhconf/usrconfig_conf"))

    def test_create_and_verify_sidecar_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            manifest = Path(temp_dir) / "backup.json"
            (root / "fhconf").mkdir(parents=True)
            (root / "fhconf" / "attrconfig_conf").write_text("attrs", encoding="utf-8")

            create_backup(
                root,
                manifest_path=manifest,
                paths=["/fhconf/attrconfig_conf"],
            )

            verify = verify_backup(manifest)
            self.assertTrue(verify["ok"])
            self.assertEqual(verify["files"], 1)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(data["files"][0]["path"], "/fhconf/attrconfig_conf")

    def test_restore_dry_run_only_plans_allowlisted_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            output = Path(temp_dir) / "backup.tgz"
            (root / "fhconf").mkdir(parents=True)
            (root / "proc").mkdir(parents=True)
            (root / "fhconf" / "usrconfig_conf").write_text("config data", encoding="utf-8")
            (root / "proc" / "mtd").write_text("readonly status", encoding="utf-8")

            create_backup(
                root,
                output_path=output,
                paths=["/fhconf/usrconfig_conf", "/proc/mtd"],
            )

            result = restore_backup_archive(output, dry_run=True)

            self.assertTrue(result["ok"])
            self.assertTrue(result["dry_run"])
            self.assertEqual([entry["path"] for entry in result["planned"]], ["/fhconf/usrconfig_conf"])
            self.assertEqual(result["skipped"], [{"path": "/proc/mtd", "reason": "not_allowlisted"}])
            self.assertFalse(result["side_effects"]["reboot"])
            self.assertFalse(result["side_effects"]["factory_reset"])

    def test_restore_execute_writes_and_readback_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            target = Path(temp_dir) / "target"
            output = Path(temp_dir) / "backup.tgz"
            (root / "fhconf").mkdir(parents=True)
            (root / "fhdata").mkdir(parents=True)
            (root / "fhconf" / "usrconfig_conf").write_text("config data", encoding="utf-8")
            (root / "fhdata" / "sysinfo_conf").write_text("sysinfo", encoding="utf-8")

            create_backup(
                root,
                output_path=output,
                paths=["/fhconf/usrconfig_conf", "/fhdata/sysinfo_conf"],
            )

            result = restore_backup_archive(output, target_root=target, dry_run=False)

            self.assertTrue(result["ok"])
            self.assertFalse(result["dry_run"])
            self.assertEqual(len(result["restored"]), 2)
            self.assertTrue(all(entry["ok"] for entry in result["restored"]))
            self.assertEqual((target / "fhconf" / "usrconfig_conf").read_text(encoding="utf-8"), "config data")
            self.assertEqual((target / "fhdata" / "sysinfo_conf").read_text(encoding="utf-8"), "sysinfo")

    def test_restore_rejects_explicit_non_allowlisted_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            output = Path(temp_dir) / "backup.tgz"
            (root / "var").mkdir(parents=True)
            (root / "var" / "telsu").write_text("runtime password", encoding="utf-8")

            create_backup(root, output_path=output, paths=["/var/telsu"])

            with self.assertRaisesRegex(CliError, "allowlist"):
                restore_backup_archive(output, dry_run=True, paths=["/var/telsu"])

    def test_restore_rejects_manifest_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "backup.tgz"
            data = b"evil"
            manifest = {
                "version": 1,
                "created_at": "2026-07-04T00:00:00Z",
                "source_root": "/tmp/source",
                "files": [
                    {
                        "path": "/fhconf/../evil",
                        "archive_name": "files/fhconf/usrconfig_conf",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                ],
                "missing": [],
            }
            with tarfile.open(output, "w:gz") as archive:
                manifest_bytes = json.dumps(manifest).encode("utf-8")
                manifest_info = tarfile.TarInfo("manifest.json")
                manifest_info.size = len(manifest_bytes)
                archive.addfile(manifest_info, io.BytesIO(manifest_bytes))
                data_info = tarfile.TarInfo("files/fhconf/usrconfig_conf")
                data_info.size = len(data)
                archive.addfile(data_info, io.BytesIO(data))

            with self.assertRaisesRegex(CliError, "路径穿越"):
                restore_backup_archive(output, dry_run=True)

    def test_restore_device_dry_run_does_not_call_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            output = Path(temp_dir) / "backup.tgz"
            (root / "fhconf").mkdir(parents=True)
            (root / "fhconf" / "usrconfig_conf").write_text("config data", encoding="utf-8")
            create_backup(root, output_path=output, paths=["/fhconf/usrconfig_conf"])

            calls: list[str] = []
            result = restore_backup_to_device(
                output,
                shell_runner=lambda command: calls.append(command) or "",
                dry_run=True,
            )

            self.assertTrue(result["ok"])
            self.assertTrue(result["dry_run"])
            self.assertEqual(calls, [])
            self.assertNotIn("_write_queue", result)
            self.assertNotIn("config data", str(result))
            self.assertFalse(result["device_transfer"]["executed"])

    def test_restore_device_uploads_staging_and_readback_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            output = Path(temp_dir) / "backup.tgz"
            (root / "fhconf").mkdir(parents=True)
            (root / "fhconf" / "usrconfig_conf").write_text("config data", encoding="utf-8")
            create_backup(root, output_path=output, paths=["/fhconf/usrconfig_conf"])
            shell = FakeRestoreShell()

            result = restore_backup_to_device(
                output,
                shell_runner=shell.run,
                dry_run=False,
                chunk_size=512,
            )

            self.assertTrue(result["ok"])
            self.assertFalse(result["dry_run"])
            self.assertTrue(result["device_transfer"]["executed"])
            self.assertEqual(shell.files["/fhconf/usrconfig_conf"], b"config data")
            self.assertTrue(result["restored"][0]["ok"])
            self.assertIn("cat /tmp/fh-tool-restore/restore-1.tmp > /fhconf/usrconfig_conf", shell.commands)


class FakeRestoreShell:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.files: dict[str, bytes] = {}

    def run(self, command: str) -> str:
        self.commands.append(command)
        parts = shlex.split(command)
        if command.startswith("mkdir -p "):
            return ""
        if command.startswith(": > ") and len(parts) == 3:
            self.files[parts[2]] = b""
            return ""
        if command.startswith("printf %s ") and " >> " in command:
            chunk = parts[2].encode("ascii")
            target = parts[4]
            self.files[target] = self.files.get(target, b"") + chunk
            return ""
        if command.startswith("base64 -d ") and " > " in command:
            source = parts[2]
            target = parts[4]
            self.files[target] = base64.b64decode(self.files[source])
            return ""
        if command.startswith("sha256sum ") and len(parts) == 2:
            digest = hashlib.sha256(self.files[parts[1]]).hexdigest()
            return f"{digest}  {parts[1]}"
        if command.startswith("cat ") and " > " in command:
            source = parts[1]
            target = parts[3]
            self.files[target] = self.files[source]
            return ""
        if command.startswith("chmod "):
            return ""
        if command.startswith("rm -f "):
            for path in parts[2:]:
                self.files.pop(path, None)
            return ""
        raise AssertionError(command)


if __name__ == "__main__":
    unittest.main()
