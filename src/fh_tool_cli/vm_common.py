from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config_store import decode_text
from .errors import FHToolError


VM_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class HostTool:
    name: str
    path: str | None
    version: str | None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_event(path: Path, event: str, **fields: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"timestamp": utc_now(), "event": event, **fields}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def require_empty_or_force(path: Path, *, force: bool) -> None:
    if not path.exists():
        return
    if force:
        shutil.rmtree(path)
        return
    if any(path.iterdir()) if path.is_dir() else True:
        raise FHToolError(f"output already exists; use --force to overwrite: {path}")


def find_tool(name: str) -> HostTool:
    found = shutil.which(name)
    version = None
    if found:
        version = _tool_version(found)
    return HostTool(name=name, path=found, version=version)


def collect_host_tools(names: Iterable[str]) -> dict[str, dict[str, Any]]:
    return {tool.name: asdict(tool) for tool in (find_tool(name) for name in names)}


def require_host_tools(names: Iterable[str]) -> dict[str, dict[str, Any]]:
    tools = collect_host_tools(names)
    missing = [name for name, info in tools.items() if not info["path"]]
    if missing:
        raise FHToolError(f"missing host tools: {', '.join(missing)}")
    return tools


def run_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    log_path: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "$ " + " ".join(argv) + "\n\n"
            + "stdout:\n"
            + decode_text(completed.stdout)
            + "\n\nstderr:\n"
            + decode_text(completed.stderr),
            encoding="utf-8",
        )
    if completed.returncode != 0:
        detail = decode_text(completed.stderr).strip() or decode_text(completed.stdout).strip()
        raise FHToolError(f"command failed ({' '.join(argv)}): {detail or completed.returncode}")
    return completed


def copy_tree_contents(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        destination = target / item.name
        if item.is_dir() and not item.is_symlink():
            shutil.copytree(item, destination, symlinks=True, dirs_exist_ok=True)
        else:
            if destination.exists() or destination.is_symlink():
                if destination.is_dir() and not destination.is_symlink():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()
            shutil.copy2(item, destination, follow_symlinks=False)


def _tool_version(path: str) -> str | None:
    probes = ([path, "--version"], [path, "-V"], [path, "-h"])
    for argv in probes:
        try:
            completed = subprocess.run(
                argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = decode_text(completed.stdout).strip().splitlines()
        if text:
            return text[0][:240]
    return None
