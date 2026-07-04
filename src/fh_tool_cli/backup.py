from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import tarfile
import base64
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath
from collections.abc import Callable
from typing import Any

from .errors import CliError

BACKUP_PATHS = [
    "/fhconf/usrconfig_conf",
    "/fhconf/usrconfig_conf_bak",
    "/fhconf/attrconfig_conf",
    "/fhconf/status_version_flag",
    "/fhconf/cfgmgr_restore_flag_conf",
    "/fhconf/factory_reset_conf",
    "/fhconf/process_start_list",
    "/fhconf/tr069_control_conf",
    "/fhconf/xpon_tr069cfg_conf",
    "/fhdata/factory_conf",
    "/fhdata/sysinfo_conf",
    "/fhdata/pre_usrconfig_conf",
    "/fhdata/pre_attrconfig_conf",
    "/var/tel_passwd",
    "/var/telWan_passwd",
    "/var/telsu",
    "/proc/mtd",
]

RESTORE_ALLOWLIST = [
    "/fhconf/usrconfig_conf",
    "/fhconf/usrconfig_conf_bak",
    "/fhconf/attrconfig_conf",
    "/fhconf/status_version_flag",
    "/fhconf/tr069_control_conf",
    "/fhconf/xpon_tr069cfg_conf",
    "/fhdata/factory_conf",
    "/fhdata/sysinfo_conf",
    "/fhdata/pre_usrconfig_conf",
    "/fhdata/pre_attrconfig_conf",
]
DEFAULT_DEVICE_RESTORE_TMPDIR = "/tmp/fh-tool-restore"
DEFAULT_DEVICE_RESTORE_CHUNK_SIZE = 3072


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _source_path(source_root: Path, device_path: str) -> Path:
    return source_root / device_path.lstrip("/")


def _archive_name(device_path: str) -> str:
    return f"files/{device_path.lstrip('/')}"


def _normalize_device_path(device_path: str) -> str:
    path = PurePosixPath(device_path)
    if not path.is_absolute() or path == PurePosixPath("/"):
        raise CliError(f"backup manifest path 必须是绝对设备路径: {device_path}")
    if ".." in path.parts:
        raise CliError(f"backup manifest path 禁止路径穿越: {device_path}")
    return "/" + "/".join(part for part in path.parts if part != "/")


def _normalize_archive_name(archive_name: str) -> str:
    path = PurePosixPath(archive_name)
    if path.is_absolute() or not path.parts:
        raise CliError(f"backup manifest archive_name 必须是相对路径: {archive_name}")
    if ".." in path.parts:
        raise CliError(f"backup manifest archive_name 禁止路径穿越: {archive_name}")
    if path.parts[0] != "files":
        raise CliError(f"backup manifest archive_name 必须位于 files/: {archive_name}")
    return str(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_backup_manifest(source_root: Path, paths: list[str] | None = None) -> dict[str, Any]:
    source_root = source_root.resolve()
    files: list[dict[str, Any]] = []
    missing: list[str] = []

    for device_path in paths or BACKUP_PATHS:
        path = _source_path(source_root, device_path)
        if not path.exists():
            missing.append(device_path)
            continue
        if not path.is_file():
            missing.append(device_path)
            continue

        stat = path.stat()
        files.append(
            {
                "path": device_path,
                "archive_name": _archive_name(device_path),
                "size": stat.st_size,
                "sha256": _sha256_file(path),
                "mode": oct(stat.st_mode & 0o777),
                "mtime": int(stat.st_mtime),
            }
        )

    return {
        "version": 1,
        "created_at": _utc_now(),
        "source_root": str(source_root),
        "files": files,
        "missing": missing,
    }


def create_backup(
    source_root: Path,
    *,
    output_path: Path | None = None,
    manifest_path: Path | None = None,
    paths: list[str] | None = None,
) -> dict[str, Any]:
    if output_path is None and manifest_path is None:
        raise CliError("backup 需要 --output 或 --manifest")

    manifest = build_backup_manifest(source_root, paths)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output_path, "w:gz") as archive:
            manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = int(datetime.now(timezone.utc).timestamp())

            archive.addfile(info, io.BytesIO(manifest_bytes))
            for entry in manifest["files"]:
                archive.add(
                    _source_path(Path(manifest["source_root"]), entry["path"]),
                    arcname=entry["archive_name"],
                    recursive=False,
                )

    if manifest_path:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    return {
        "output": str(output_path) if output_path else None,
        "manifest": str(manifest_path) if manifest_path else None,
        "source_root": manifest["source_root"],
        "included": len(manifest["files"]),
        "missing": len(manifest["missing"]),
        "missing_paths": manifest["missing"],
    }


def _load_archive_manifest(archive: tarfile.TarFile) -> dict[str, Any]:
    try:
        member = archive.getmember("manifest.json")
        manifest_file = archive.extractfile(member)
    except (KeyError, tarfile.TarError) as exc:
        raise CliError("backup archive 缺少 manifest.json") from exc
    if manifest_file is None:
        raise CliError("backup archive manifest.json 无法读取")
    try:
        data = json.loads(manifest_file.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError("backup manifest JSON 无法解析") from exc
    if not isinstance(data, dict):
        raise CliError("backup manifest 必须是 object")
    return data


def _validate_manifest_shape(manifest: dict[str, Any]) -> None:
    if manifest.get("version") != 1:
        raise CliError("backup manifest version 不支持")
    if not isinstance(manifest.get("files"), list):
        raise CliError("backup manifest files 格式错误")
    if not isinstance(manifest.get("missing"), list):
        raise CliError("backup manifest missing 格式错误")


def _validate_file_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise CliError("backup manifest files entry 必须是 object")

    raw_path = entry.get("path")
    if not isinstance(raw_path, str):
        raise CliError("backup manifest files entry 缺少 path")
    device_path = _normalize_device_path(raw_path)

    raw_archive_name = entry.get("archive_name")
    if not isinstance(raw_archive_name, str):
        raise CliError(f"{device_path}: archive_name missing")
    archive_name = _normalize_archive_name(raw_archive_name)

    size = entry.get("size")
    if not isinstance(size, int) or size < 0:
        raise CliError(f"{device_path}: size 格式错误")

    sha256 = entry.get("sha256")
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(char not in "0123456789abcdefABCDEF" for char in sha256)
    ):
        raise CliError(f"{device_path}: sha256 格式错误")

    return {
        **entry,
        "path": device_path,
        "archive_name": archive_name,
        "size": size,
        "sha256": sha256.lower(),
    }


def _read_archive_member(
    archive: tarfile.TarFile,
    entry: dict[str, Any],
) -> bytes:
    archive_name = entry["archive_name"]
    try:
        member = archive.getmember(archive_name)
    except (KeyError, tarfile.TarError) as exc:
        raise CliError(f"{entry['path']}: backup archive 缺少成员 {archive_name}") from exc
    if not member.isfile():
        raise CliError(f"{entry['path']}: backup archive member 不是普通文件")
    file_obj = archive.extractfile(member)
    if file_obj is None:
        raise CliError(f"{entry['path']}: backup archive member 无法读取")
    return file_obj.read()


def verify_backup_archive(path: Path) -> dict[str, Any]:
    try:
        archive = tarfile.open(path, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise CliError(f"backup archive 无法读取: {path}: {exc}") from exc

    with archive:
        manifest = _load_archive_manifest(archive)
        _validate_manifest_shape(manifest)
        verified: list[str] = []
        errors: list[str] = []

        for raw_entry in manifest["files"]:
            try:
                entry = _validate_file_entry(raw_entry)
                data = _read_archive_member(archive, entry)
            except CliError as exc:
                errors.append(str(exc))
                continue

            actual_sha = hashlib.sha256(data).hexdigest()
            if len(data) != entry["size"]:
                errors.append(f"{entry['path']}: size mismatch")
                continue
            if actual_sha != entry["sha256"]:
                errors.append(f"{entry['path']}: sha256 mismatch")
                continue
            verified.append(entry["path"])

    return {
        "path": str(path),
        "ok": not errors,
        "verified": len(verified),
        "errors": errors,
        "missing_recorded": len(manifest["missing"]),
    }


def verify_backup_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"backup manifest 无法读取: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CliError("backup manifest 必须是 object")
    _validate_manifest_shape(data)
    return {
        "path": str(path),
        "ok": True,
        "files": len(data["files"]),
        "missing_recorded": len(data["missing"]),
    }


def verify_backup(path: Path) -> dict[str, Any]:
    if path.suffix == ".json":
        return verify_backup_manifest(path)
    return verify_backup_archive(path)


def _target_path(target_root: Path, device_path: str) -> Path:
    normalized = _normalize_device_path(device_path)
    root = target_root.resolve()
    target = root / normalized.lstrip("/")
    try:
        target.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise CliError(f"restore target 路径逃逸: {device_path}") from exc
    return target


def _restore_mode(entry: dict[str, Any]) -> int | None:
    mode = entry.get("mode")
    if not isinstance(mode, str):
        return None
    try:
        parsed = int(mode, 8)
    except ValueError:
        return None
    return parsed & 0o777


def restore_backup_archive(
    archive_path: Path,
    *,
    target_root: Path | None = None,
    dry_run: bool = True,
    paths: list[str] | None = None,
    allowlist: list[str] | None = None,
) -> dict[str, Any]:
    if not dry_run and target_root is None:
        raise CliError("restore --execute 需要显式指定 --target-root")

    allowed = set(allowlist or RESTORE_ALLOWLIST)
    requested = {_normalize_device_path(path) for path in paths or []}
    disallowed_requested = sorted(requested - allowed)
    if disallowed_requested:
        raise CliError(
            "restore 请求路径不在 allowlist 内: " + ", ".join(disallowed_requested)
        )

    verification = verify_backup_archive(archive_path)
    if not verification["ok"]:
        raise CliError(
            "restore 前 backup manifest/sha256 验证失败: "
            + "; ".join(verification["errors"])
        )

    try:
        archive = tarfile.open(archive_path, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise CliError(f"backup archive 无法读取: {archive_path}: {exc}") from exc

    planned: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    restored: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_paths: set[str] = set()
    write_queue: list[tuple[dict[str, Any], bytes]] = []

    with archive:
        manifest = _load_archive_manifest(archive)
        _validate_manifest_shape(manifest)
        for raw_entry in manifest["files"]:
            entry = _validate_file_entry(raw_entry)
            device_path = entry["path"]
            if requested and device_path not in requested:
                skipped.append({"path": device_path, "reason": "not_requested"})
                continue
            if device_path not in allowed:
                skipped.append({"path": device_path, "reason": "not_allowlisted"})
                continue

            data = _read_archive_member(archive, entry)
            actual_sha = hashlib.sha256(data).hexdigest()
            if len(data) != entry["size"] or actual_sha != entry["sha256"]:
                errors.append(f"{device_path}: sha256/size mismatch")
                continue

            target = (
                str(_target_path(target_root, device_path))
                if target_root is not None
                else device_path
            )
            plan_entry = {
                "path": device_path,
                "target": target,
                "archive_name": entry["archive_name"],
                "size": entry["size"],
                "sha256": entry["sha256"],
                "risk": "extreme",
            }
            planned.append(plan_entry)
            seen_paths.add(device_path)
            write_queue.append((entry, data))

    missing_requested = sorted(requested - seen_paths)
    if missing_requested:
        errors.append("backup 缺少请求恢复路径: " + ", ".join(missing_requested))

    if not dry_run and not errors:
        assert target_root is not None
        for entry, data in write_queue:
            device_path = entry["path"]
            target_path = _target_path(target_root, device_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(data)
            mode = _restore_mode(entry)
            if mode is not None:
                target_path.chmod(mode)
            mtime = entry.get("mtime")
            if isinstance(mtime, int):
                os.utime(target_path, (mtime, mtime))

            readback_sha = _sha256_file(target_path)
            readback_size = target_path.stat().st_size
            ok = readback_sha == entry["sha256"] and readback_size == entry["size"]
            restored.append(
                {
                    "path": device_path,
                    "target": str(target_path),
                    "ok": ok,
                    "size": readback_size,
                    "sha256": readback_sha,
                }
            )
            if not ok:
                errors.append(f"{device_path}: read-back hash verify failed")

    return {
        "mode": "restore",
        "backup": str(archive_path),
        "dry_run": dry_run,
        "risk": "extreme",
        "target_root": str(target_root.resolve()) if target_root else None,
        "allowlist": sorted(allowed),
        "planned": planned,
        "skipped": skipped,
        "restored": restored,
        "verified": {
            "backup_ok": verification["ok"],
            "backup_verified_files": verification["verified"],
            "readback_ok": not errors if not dry_run else None,
        },
        "errors": errors,
        "ok": not errors,
        "side_effects": {
            "reboot": False,
            "factory_reset": False,
        },
    }


def restore_backup_to_device(
    archive_path: Path,
    *,
    shell_runner: Callable[[str], str],
    dry_run: bool = True,
    paths: list[str] | None = None,
    allowlist: list[str] | None = None,
    remote_tmpdir: str = DEFAULT_DEVICE_RESTORE_TMPDIR,
    chunk_size: int = DEFAULT_DEVICE_RESTORE_CHUNK_SIZE,
) -> dict[str, Any]:
    if chunk_size < 512:
        raise CliError("device restore chunk_size 不能小于 512")

    plan = _restore_plan_from_archive(
        archive_path,
        paths=paths,
        allowlist=allowlist,
        target_mapper=lambda device_path: device_path,
    )
    if dry_run or plan["errors"]:
        return {
            **{key: value for key, value in plan.items() if key != "_write_queue"},
            "target": "device",
            "dry_run": dry_run,
            "device_transfer": {
                "tmpdir": remote_tmpdir,
                "chunk_size": chunk_size,
                "executed": False,
            },
        }

    restored: list[dict[str, Any]] = []
    errors: list[str] = []
    _device_run(shell_runner, f"mkdir -p {shlex.quote(remote_tmpdir)}")
    for index, (entry, data) in enumerate(plan["_write_queue"], start=1):
        device_path = entry["path"]
        staging = f"{remote_tmpdir}/restore-{index}.tmp"
        staging_b64 = f"{staging}.b64"
        target_dir = str(PurePosixPath(device_path).parent)
        try:
            _device_write_file(
                shell_runner,
                staging,
                data,
                chunk_size=chunk_size,
            )
            staging_sha = _device_sha256(shell_runner, staging)
            if staging_sha != entry["sha256"]:
                raise CliError(
                    f"{device_path}: remote staging sha256 mismatch "
                    f"{staging_sha} != {entry['sha256']}"
                )
            _device_run(shell_runner, f"mkdir -p {shlex.quote(target_dir)}")
            _device_run(
                shell_runner,
                f"cat {shlex.quote(staging)} > {shlex.quote(device_path)}",
            )
            mode = _restore_mode(entry)
            if mode is not None:
                _device_run(shell_runner, f"chmod {mode:o} {shlex.quote(device_path)}")
            observed_sha = _device_sha256(shell_runner, device_path)
            ok = observed_sha == entry["sha256"]
            restored.append(
                {
                    "path": device_path,
                    "target": device_path,
                    "ok": ok,
                    "sha256": observed_sha,
                    "expected_sha256": entry["sha256"],
                }
            )
            if not ok:
                errors.append(f"{device_path}: read-back hash verify failed")
        except CliError as exc:
            errors.append(str(exc))
            break
        finally:
            _device_run(
                shell_runner,
                f"rm -f {shlex.quote(staging)} {shlex.quote(staging_b64)}",
                check=False,
            )

    return {
        **{key: value for key, value in plan.items() if key != "_write_queue"},
        "target": "device",
        "dry_run": False,
        "restored": restored,
        "verified": {
            **plan["verified"],
            "readback_ok": not errors,
        },
        "errors": errors,
        "ok": not errors,
        "device_transfer": {
            "tmpdir": remote_tmpdir,
            "chunk_size": chunk_size,
            "executed": True,
        },
    }


def _restore_plan_from_archive(
    archive_path: Path,
    *,
    paths: list[str] | None,
    allowlist: list[str] | None,
    target_mapper: Callable[[str], str],
) -> dict[str, Any]:
    allowed = set(allowlist or RESTORE_ALLOWLIST)
    requested = {_normalize_device_path(path) for path in paths or []}
    disallowed_requested = sorted(requested - allowed)
    if disallowed_requested:
        raise CliError(
            "restore 请求路径不在 allowlist 内: " + ", ".join(disallowed_requested)
        )

    verification = verify_backup_archive(archive_path)
    if not verification["ok"]:
        raise CliError(
            "restore 前 backup manifest/sha256 验证失败: "
            + "; ".join(verification["errors"])
        )

    try:
        archive = tarfile.open(archive_path, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise CliError(f"backup archive 无法读取: {archive_path}: {exc}") from exc

    planned: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_paths: set[str] = set()
    write_queue: list[tuple[dict[str, Any], bytes]] = []

    with archive:
        manifest = _load_archive_manifest(archive)
        _validate_manifest_shape(manifest)
        for raw_entry in manifest["files"]:
            entry = _validate_file_entry(raw_entry)
            device_path = entry["path"]
            if requested and device_path not in requested:
                skipped.append({"path": device_path, "reason": "not_requested"})
                continue
            if device_path not in allowed:
                skipped.append({"path": device_path, "reason": "not_allowlisted"})
                continue

            data = _read_archive_member(archive, entry)
            actual_sha = hashlib.sha256(data).hexdigest()
            if len(data) != entry["size"] or actual_sha != entry["sha256"]:
                errors.append(f"{device_path}: sha256/size mismatch")
                continue

            planned.append(
                {
                    "path": device_path,
                    "target": target_mapper(device_path),
                    "archive_name": entry["archive_name"],
                    "size": entry["size"],
                    "sha256": entry["sha256"],
                    "risk": "extreme",
                }
            )
            seen_paths.add(device_path)
            write_queue.append((entry, data))

    missing_requested = sorted(requested - seen_paths)
    if missing_requested:
        errors.append("backup 缺少请求恢复路径: " + ", ".join(missing_requested))

    return {
        "mode": "restore",
        "backup": str(archive_path),
        "risk": "extreme",
        "allowlist": sorted(allowed),
        "planned": planned,
        "skipped": skipped,
        "restored": [],
        "verified": {
            "backup_ok": verification["ok"],
            "backup_verified_files": verification["verified"],
            "readback_ok": None,
        },
        "errors": errors,
        "ok": not errors,
        "side_effects": {
            "reboot": False,
            "factory_reset": False,
        },
        "_write_queue": write_queue,
    }


def _device_write_file(
    shell_runner: Callable[[str], str],
    remote_path: str,
    data: bytes,
    *,
    chunk_size: int,
) -> None:
    encoded = base64.b64encode(data).decode("ascii")
    remote_b64 = f"{remote_path}.b64"
    _device_run(shell_runner, f": > {shlex.quote(remote_b64)}")
    for offset in range(0, len(encoded), chunk_size):
        chunk = encoded[offset : offset + chunk_size]
        _device_run(
            shell_runner,
            f"printf %s {shlex.quote(chunk)} >> {shlex.quote(remote_b64)}",
        )
    _device_run(
        shell_runner,
        f"base64 -d {shlex.quote(remote_b64)} > {shlex.quote(remote_path)}",
    )


def _device_sha256(shell_runner: Callable[[str], str], remote_path: str) -> str:
    output = _device_run(shell_runner, f"sha256sum {shlex.quote(remote_path)}")
    match = re.search(r"\b[0-9a-fA-F]{64}\b", output)
    if not match:
        raise CliError(f"{remote_path}: remote sha256sum 输出无法解析")
    return match.group(0).lower()


def _device_run(
    shell_runner: Callable[[str], str],
    command: str,
    *,
    check: bool = True,
) -> str:
    try:
        output = str(shell_runner(command))
    except Exception as exc:  # noqa: BLE001 - backend error becomes restore detail.
        if check:
            raise CliError(f"device restore command failed: {command}: {exc}") from exc
        return str(exc)
    if check and re.search(r"\b(not found|permission denied|read-only file system)\b", output, re.I):
        raise CliError(f"device restore command failed: {command}: {output.strip()}")
    return output
