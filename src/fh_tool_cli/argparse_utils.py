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


def parse_port_spec(value: str, *, max_ports: int = 4096) -> list[int]:
    """解析 `80,8080` 或 `1-1024` 形式的 port 表达式。

    scan 只用于用户自己的网关，但仍限制单次扫描规模，避免误把范围写成
    `1-65535` 后对设备造成不必要的压力。
    """
    ports: list[int] = []
    seen: set[int] = set()
    for raw in value.split(","):
        part = raw.strip()
        if not part:
            continue
        if "-" in part:
            start_text, separator, end_text = part.partition("-")
            start_text = start_text.strip()
            end_text = end_text.strip()
            if not separator or not start_text or not end_text:
                raise argparse.ArgumentTypeError(f"不符规范的 port 范围: {part}")
            start = normalize_port(start_text)
            end = normalize_port(end_text)
            if start > end:
                raise argparse.ArgumentTypeError(f"port 范围起点大于终点: {part}")
            if end - start + 1 > max_ports:
                raise argparse.ArgumentTypeError(f"单个 port 范围最多 {max_ports} 个: {part}")
            candidates: range | tuple[int, ...] = range(start, end + 1)
        else:
            candidates = (normalize_port(part),)
        for port in candidates:
            if port in seen:
                continue
            seen.add(port)
            ports.append(port)
            if len(ports) > max_ports:
                raise argparse.ArgumentTypeError(f"单次扫描最多 {max_ports} 个 port")
    if not ports:
        raise argparse.ArgumentTypeError("至少需要一个 port")
    return ports


def parse_paths(value: str, *, max_paths: int = 16) -> list[str]:
    """解析逗号分隔的 URL path 列表，去重并限制数量。"""
    paths: list[str] = []
    for raw in value.split(","):
        part = raw.strip()
        if not part:
            continue
        path = normalize_path(part)
        if path not in paths:
            paths.append(path)
        if len(paths) > max_paths:
            raise argparse.ArgumentTypeError(f"单次扫描最多 {max_paths} 个 path")
    if not paths:
        raise argparse.ArgumentTypeError("至少需要一个 path")
    return paths


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
