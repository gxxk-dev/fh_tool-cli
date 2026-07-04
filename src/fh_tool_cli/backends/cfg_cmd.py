from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..errors import CliError

DANGER_CFG_PATH_RE = re.compile(
    r"(tr-?069|wan|pon|loid|vlan|preconfig|servicelist|smartswitch|cloudplat)",
    re.IGNORECASE,
)
SENSITIVE_CFG_PATH_RE = re.compile(
    r"(loid|pppoe|acs|tr-?069|token|password|passwd|pwd|secret|psk|wepkey|wpakey)",
    re.IGNORECASE,
)


def cfg_path_risk(path: str) -> str:
    return "danger" if DANGER_CFG_PATH_RE.search(path) else "write"


def cfg_read_risk(path: str) -> str:
    return "sensitive" if SENSITIVE_CFG_PATH_RE.search(path) else "safe"


def redact_cfg_value(path: str, value: str, *, reveal_secrets: bool) -> tuple[str, bool]:
    if cfg_read_risk(path) == "sensitive" and not reveal_secrets:
        return "[REDACTED]", True
    return value, False


def _cfg_command(*parts: str) -> str:
    return " ".join(["cfg_cmd", *(shlex.quote(part) for part in parts)])


def parse_cfg_get_output(path: str, output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith(f"{path}="):
            return line.split("=", 1)[1]
    for line in reversed(lines):
        if line.startswith("get success!value="):
            return line.split("=", 1)[1]
    for line in reversed(lines):
        if not line.startswith("cfg_cmd"):
            return line
    return ""


class CfgCmdBackend:
    def __init__(self, runner: Callable[[str], str], *, expensive_missing_paths: bool = False):
        self._runner = runner
        self.expensive_missing_paths = expensive_missing_paths

    def get(self, path: str) -> str:
        return parse_cfg_get_output(path, self._runner(_cfg_command("get", path)))

    def set(self, path: str, value: str) -> str:
        return self._runner(_cfg_command("set", path, value))

    def attr(self, path: str) -> str:
        return self._runner(_cfg_command("attr", path)).strip()


def cfg_set_with_verify(backend: CfgCmdBackend, path: str, value: str) -> dict[str, Any]:
    risk = cfg_path_risk(path)
    backend.set(path, value)
    observed = backend.get(path)
    return {
        "path": path,
        "value": value,
        "risk": risk,
        "verified": observed == value,
        "observed": observed,
    }


def cfg_snapshot(backend: CfgCmdBackend, paths: list[str]) -> dict[str, Any]:
    if not paths:
        raise CliError("cfg snapshot 需要至少一个 --path")
    return {
        "paths": paths,
        "values": {path: backend.get(path) for path in paths},
    }


def write_cfg_snapshot(snapshot: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return {"output": str(output), "paths": len(snapshot["paths"])}
    return snapshot


def diff_cfg_snapshots(before_path: Path, after_path: Path) -> dict[str, Any]:
    try:
        before = json.loads(before_path.read_text(encoding="utf-8"))
        after = json.loads(after_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"cfg snapshot 读取失败: {exc}") from exc

    before_values = before.get("values")
    after_values = after.get("values")
    if not isinstance(before_values, dict) or not isinstance(after_values, dict):
        raise CliError("cfg snapshot 必须包含 values object")

    paths = sorted(set(before_values) | set(after_values))
    changes = [
        {
            "path": path,
            "before": before_values.get(path),
            "after": after_values.get(path),
        }
        for path in paths
        if before_values.get(path) != after_values.get(path)
    ]
    return {"changes": changes, "change_count": len(changes)}
