from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import FHToolError
from .risk import dry_run_notice
from .vm_common import VM_SCHEMA_VERSION, append_event, sha256_file, utc_now, write_json


CHUNK_BEGIN = "__FH_TOOL_CHUNK_BEGIN__"
CHUNK_END = "__FH_TOOL_CHUNK_END__"


@dataclass(frozen=True)
class MtdPartition:
    index: int
    dev: str
    size: int
    erasesize: int
    name: str

    @property
    def device_path(self) -> str:
        return f"/dev/{self.dev}"

    @property
    def safe_name(self) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.name).strip("_")
        return safe or f"mtd{self.index}"

    @property
    def dump_name(self) -> str:
        return f"mtd{self.index}_{self.safe_name}.bin"


def parse_proc_mtd(text: str) -> list[MtdPartition]:
    partitions: list[MtdPartition] = []
    pattern = re.compile(r"^(mtd(?P<index>\d+)):\s+(?P<size>[0-9a-fA-F]+)\s+(?P<erase>[0-9a-fA-F]+)\s+\"(?P<name>.*)\"$")
    for line in text.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        partitions.append(
            MtdPartition(
                index=int(match.group("index")),
                dev=f"mtd{int(match.group('index'))}",
                size=int(match.group("size"), 16),
                erasesize=int(match.group("erase"), 16),
                name=match.group("name"),
            )
        )
    return partitions


def selected_partitions(
    partitions: list[MtdPartition],
    *,
    all_mtd: bool = False,
    requested: list[str] | None = None,
) -> list[MtdPartition]:
    by_dev = {partition.dev: partition for partition in partitions}
    by_name = {partition.name: partition for partition in partitions}
    if requested:
        selected: list[MtdPartition] = []
        for item in requested:
            key = item.removeprefix("/dev/")
            partition = by_dev.get(key) or by_name.get(item)
            if partition is None:
                raise FHToolError(f"unknown MTD partition: {item}")
            selected.append(partition)
        return selected
    if all_mtd:
        return [partition for partition in partitions if partition.index <= 7]
    wanted = {"mtd0", "mtd2", "mtd6"}
    return [partition for partition in partitions if partition.dev in wanted]


def collect_vm_dumps(
    *,
    shell_runner: Callable[[str], str],
    output_dir: Path,
    confirmed: bool,
    all_mtd: bool,
    requested_partitions: list[str],
    chunk_size: int,
    retries: int,
) -> dict[str, Any]:
    if chunk_size <= 0:
        raise FHToolError("--chunk-size must be positive")
    if retries < 1:
        raise FHToolError("--retries must be at least 1")

    if not confirmed:
        result: dict[str, Any] = {
            "schema_version": VM_SCHEMA_VERSION,
            "command": "vm collect",
            "mode": "dry-run",
            "output_dir": str(output_dir),
            "selection": {
                "all_mtd": all_mtd,
                "partitions": requested_partitions,
                "default_partitions": ["mtd0", "mtd2", "mtd6"],
            },
            "side_effects": {"flash_reads": False, "telnet_state_change": False},
        }
        result.update(dry_run_notice())
        return result

    output_dir.mkdir(parents=True, exist_ok=True)
    events_path = output_dir / "events.ndjson"
    append_event(events_path, "collect.start", output_dir=str(output_dir))

    metadata = collect_device_metadata(shell_runner)
    proc_mtd = metadata["commands"].get("proc_mtd", {}).get("stdout", "")
    partitions = parse_proc_mtd(proc_mtd)
    if not partitions:
        raise FHToolError("could not parse /proc/mtd from device output")
    selected = selected_partitions(partitions, all_mtd=all_mtd, requested=requested_partitions)
    append_event(events_path, "collect.partitions.selected", partitions=[partition.dev for partition in selected])

    partition_records: list[dict[str, Any]] = []
    sha_lines: list[str] = []
    for partition in selected:
        record = _collect_partition(
            shell_runner,
            output_dir,
            partition,
            chunk_size=chunk_size,
            retries=retries,
            events_path=events_path,
        )
        partition_records.append(record)
        if record.get("sha256"):
            sha_lines.append(f"{record['sha256']}  {Path(record['path']).name}")

    if sha_lines:
        (output_dir / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n", encoding="utf-8")

    manifest: dict[str, Any] = {
        "schema_version": VM_SCHEMA_VERSION,
        "command": "vm collect",
        "created_at": utc_now(),
        "output_dir": str(output_dir),
        "device_metadata": metadata,
        "partition_table": [asdict(partition) for partition in partitions],
        "partitions": partition_records,
        "outputs": {
            "manifest": str(output_dir / "dump-manifest.json"),
            "sha256sums": str(output_dir / "SHA256SUMS"),
            "events": str(events_path),
        },
        "warnings": [],
        "limitations": [
            "Collected through Telnet-safe base64 framing; no raw binary is streamed directly.",
            "mtd8 and later are treated as UBI logical volumes unless explicitly requested.",
        ],
    }
    manifest["ok"] = all(record.get("ok") for record in partition_records)
    write_json(output_dir / "dump-manifest.json", manifest)
    append_event(events_path, "collect.done", ok=manifest["ok"])
    return manifest


def collect_device_metadata(shell_runner: Callable[[str], str]) -> dict[str, Any]:
    commands = {
        "proc_mtd": "cat /proc/mtd",
        "proc_cmdline": "cat /proc/cmdline",
        "mount": "mount",
        "df_h": "df -h",
        "ubinfo_a": "ubinfo -a",
        "mtd_ubi_nodes": "ls -l /dev/mtd* /dev/ubi*",
        "bcm_bootstate": "cat /proc/bcm_bootstate 2>/dev/null || bcm_bootstate 2>/dev/null || true",
        "active_flag": "cat /proc/active_flag 2>/dev/null || cat /fhconf/active_flag 2>/dev/null || true",
        "version": "cat /proc/version 2>/dev/null; cat /etc/version 2>/dev/null; cat /etc/openwrt_version 2>/dev/null",
        "model": "cat /proc/device-tree/model 2>/dev/null; cat /fhconf/device_info/hg5143f 2>/dev/null | head -40",
    }
    results: dict[str, Any] = {}
    for name, command in commands.items():
        wrapped = f"({command}) 2>&1 || true"
        try:
            output = shell_runner(wrapped)
            results[name] = {"ok": True, "stdout": output}
        except Exception as exc:  # noqa: BLE001 - keep metadata collection best-effort.
            results[name] = {"ok": False, "error": str(exc)}
    return {"commands": results}


def _collect_partition(
    shell_runner: Callable[[str], str],
    output_dir: Path,
    partition: MtdPartition,
    *,
    chunk_size: int,
    retries: int,
    events_path: Path,
) -> dict[str, Any]:
    output_path = output_dir / partition.dump_name
    digest = hashlib.sha256()
    chunks: list[dict[str, Any]] = []
    ok = True
    error: str | None = None
    append_event(events_path, "collect.partition.start", partition=partition.dev, size=partition.size)
    with output_path.open("wb") as handle:
        for offset in range(0, partition.size, chunk_size):
            length = min(chunk_size, partition.size - offset)
            try:
                chunk, record = _read_chunk_with_retries(
                    shell_runner,
                    partition,
                    offset=offset,
                    length=length,
                    retries=retries,
                )
            except FHToolError as exc:
                ok = False
                error = str(exc)
                chunks.append(
                    {
                        "offset": offset,
                        "length": length,
                        "ok": False,
                        "error": error,
                        "retries": retries,
                    }
                )
                append_event(events_path, "collect.chunk.error", partition=partition.dev, offset=offset, error=error)
                break
            handle.write(chunk)
            digest.update(chunk)
            chunks.append(record)
            append_event(events_path, "collect.chunk.done", partition=partition.dev, offset=offset, bytes=len(chunk))

    if not ok:
        return {
            "ok": False,
            "partition": asdict(partition),
            "path": str(output_path),
            "chunks": chunks,
            "error": error,
        }

    final_sha = digest.hexdigest()
    file_sha = sha256_file(output_path)
    if final_sha != file_sha:
        ok = False
        error = "stream sha256 does not match local file sha256"
    append_event(events_path, "collect.partition.done", partition=partition.dev, ok=ok, sha256=file_sha)
    return {
        "ok": ok,
        "partition": asdict(partition),
        "path": str(output_path),
        "bytes": output_path.stat().st_size,
        "sha256": file_sha,
        "chunks": chunks,
        "error": error,
    }


def _read_chunk_with_retries(
    shell_runner: Callable[[str], str],
    partition: MtdPartition,
    *,
    offset: int,
    length: int,
    retries: int,
) -> tuple[bytes, dict[str, Any]]:
    failures: list[str] = []
    for attempt in range(1, retries + 1):
        output = shell_runner(_chunk_command(partition.device_path, offset, length))
        try:
            chunk, reported_bytes = decode_chunk_output(output, expected_offset=offset, expected_length=length)
        except FHToolError as exc:
            failures.append(str(exc))
            continue
        if len(chunk) != length or reported_bytes != length:
            failures.append(f"bytes mismatch: decoded={len(chunk)} reported={reported_bytes} expected={length}")
            continue
        return chunk, {
            "offset": offset,
            "length": length,
            "bytes": len(chunk),
            "ok": True,
            "retries": attempt - 1,
            "sha256": hashlib.sha256(chunk).hexdigest(),
        }
    raise FHToolError("; ".join(failures) or "chunk read failed")


def _chunk_command(device: str, offset: int, length: int) -> str:
    token = f"fh-tool-mtd-{offset}-{length}.$$"
    return (
        "set -eu; "
        f'T="/tmp/{token}"; '
        f'nanddump -q --omitoob --bb=padbad -s {offset} -l {length} -f "$T" {device} >/dev/null; '
        'B=$(wc -c <"$T" | tr -d " "); '
        f'printf "{CHUNK_BEGIN} {offset} {length} $B\\n"; '
        'base64 "$T"; '
        f'printf "\\n{CHUNK_END}\\n"; '
        'rm -f "$T"'
    )


def decode_chunk_output(output: str, *, expected_offset: int, expected_length: int) -> tuple[bytes, int]:
    begin = re.search(
        rf"{re.escape(CHUNK_BEGIN)}\s+(?P<offset>\d+)\s+(?P<length>\d+)\s+(?P<bytes>\d+)\s*\n",
        output,
    )
    if not begin:
        raise FHToolError("chunk begin marker not found")
    end_index = output.find(CHUNK_END, begin.end())
    if end_index < 0:
        raise FHToolError("chunk end marker not found")
    offset = int(begin.group("offset"))
    length = int(begin.group("length"))
    reported_bytes = int(begin.group("bytes"))
    if offset != expected_offset or length != expected_length:
        raise FHToolError(f"chunk header mismatch: got offset={offset} length={length}")
    encoded = "".join(output[begin.end():end_index].split())
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except binascii.Error as exc:
        raise FHToolError(f"invalid base64 chunk: {exc}") from exc
    return decoded, reported_bytes
