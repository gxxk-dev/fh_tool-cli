from __future__ import annotations

import argparse
import json
from typing import Any

from .errors import CliError


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part, 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"不符规范的 port: {part}") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port 超出范围: {part}")
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("至少需要一个 port")
    return ports


def normalize_port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"不符规范的 port: {value}") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port 超出范围: {value}")
    return port


def normalize_path(value: str) -> str:
    if not value.startswith("/"):
        raise argparse.ArgumentTypeError(f"路径必须以 / 开头: {value}")
    for char in "?# \t\r\n":
        if char in value:
            raise argparse.ArgumentTypeError(f"路径不能包含 {char!r}: {value}")
    return value


def parse_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    return value


def parse_kv(values: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for value in values:
        if "=" not in value:
            raise CliError(f"--param 需要 k=v 格式: {value}")
        key, raw = value.split("=", 1)
        key = key.strip()
        if not key:
            raise CliError(f"--param key 不能为空: {value}")
        result[key] = parse_scalar(raw)
    return result


def parse_json_object(value: str) -> dict[str, Any]:
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise CliError(f"JSON 解析失败: {exc}") from exc
    if not isinstance(data, dict):
        raise CliError("JSON payload 必须是 object")
    return data
