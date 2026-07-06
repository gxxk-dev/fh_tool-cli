from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fh_tool_cli import cli
from fh_tool_cli.errors import FHToolError
from fh_tool_cli.vm_collect import decode_chunk_output, parse_proc_mtd, selected_partitions


PROC_MTD = """dev:    size   erasesize  name
mtd0: 03000000 00020000 "rootfsA"
mtd1: 03000000 00020000 "rootfsB"
mtd2: 07800000 00020000 "data"
mtd6: 00400000 00020000 "factory"
mtd8: 02000000 00020000 "rootfs_ubifs"
"""


class VmCollectTests(unittest.TestCase):
    def test_parse_proc_mtd_and_default_selection(self) -> None:
        partitions = parse_proc_mtd(PROC_MTD)

        self.assertEqual([partition.dev for partition in partitions], ["mtd0", "mtd1", "mtd2", "mtd6", "mtd8"])
        self.assertEqual([partition.dev for partition in selected_partitions(partitions)], ["mtd0", "mtd2", "mtd6"])
        self.assertEqual([partition.dev for partition in selected_partitions(partitions, all_mtd=True)], ["mtd0", "mtd1", "mtd2", "mtd6"])
        self.assertEqual([partition.dev for partition in selected_partitions(partitions, requested=["mtd1"])], ["mtd1"])

    def test_decode_chunk_output_rejects_bad_base64(self) -> None:
        with self.assertRaisesRegex(FHToolError, "invalid base64"):
            decode_chunk_output(
                "__FH_TOOL_CHUNK_BEGIN__ 0 4 4\nnot@@base64\n__FH_TOOL_CHUNK_END__\n",
                expected_offset=0,
                expected_length=4,
            )

    def test_collect_is_dry_run_without_confirm(self) -> None:
        args = argparse.Namespace(
            output="/tmp/fh-tool-dumps",
            all_mtd=False,
            partition=[],
            chunk_size=262144,
            retries=3,
            confirm=False,
            auto_enable_telnet=True,
        )

        result = cli.command_vm_collect(args)

        self.assertTrue(result["dry_run"])
        self.assertFalse(result["side_effects"]["flash_reads"])
        self.assertFalse(result["side_effects"]["telnet_state_change"])

    def test_collect_rejects_deprecated_confirmation_flags(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = cli.main(
                    [
                        "vm",
                        "collect",
                        "--ip",
                        "192.168.1.1",
                        "--output",
                        temp_dir,
                        "--yes",
                        "--json",
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("--yes 已弃用", stderr.getvalue())

    def test_collect_writes_manifest_and_sha256sums_with_retry(self) -> None:
        calls = {"chunk": 0}

        def runner(command: str) -> str:
            if "cat /proc/mtd" in command:
                return PROC_MTD
            if "nanddump" in command:
                calls["chunk"] += 1
                if calls["chunk"] == 1:
                    return "__FH_TOOL_CHUNK_BEGIN__ 0 4 4\nbad\n__FH_TOOL_CHUNK_END__\n"
                return "__FH_TOOL_CHUNK_BEGIN__ 0 4 4\nQUJDRA==\n__FH_TOOL_CHUNK_END__\n"
            return ""

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("fh_tool_cli.vm_collect.collect_device_metadata") as metadata:
                metadata.return_value = {"commands": {"proc_mtd": {"ok": True, "stdout": 'mtd0: 00000004 00020000 "rootfsA"\n'}}}
                result = cli.collect_vm_dumps(
                    shell_runner=runner,
                    output_dir=Path(temp_dir),
                    confirmed=True,
                    all_mtd=False,
                    requested_partitions=[],
                    chunk_size=4,
                    retries=2,
                )
            manifest = json.loads((Path(temp_dir) / "dump-manifest.json").read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertEqual(manifest["partitions"][0]["chunks"][0]["retries"], 1)
        self.assertIn("mtd0_rootfsA.bin", manifest["partitions"][0]["path"])


if __name__ == "__main__":
    unittest.main()
