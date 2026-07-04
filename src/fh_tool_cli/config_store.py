from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any

from .errors import CliError

DEFAULT_IP = "192.168.1.1"
DEFAULT_CONFIG_PATH = Path(
    os.environ.get("FH_TOOL_CLI_CONFIG", "~/.config/fh_tool-cli/config.json")
).expanduser()


def normalize_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("不符规范的 IP 地址") from exc
    if ip.version != 4:
        raise argparse.ArgumentTypeError("目前只支持 IPv4 网关地址")
    return str(ip)


def normalize_mac(value: str) -> str:
    mac = value.strip().upper().replace(":", "").replace("-", "")
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        raise argparse.ArgumentTypeError("不符规范的 MAC 地址，应为 AABBCCDDEEFF 格式")
    return mac


def format_mac(mac: str) -> str:
    return ":".join(mac[i : i + 2] for i in range(0, 12, 2))


def decode_text(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


def run_output(command: list[str]) -> str | None:
    try:
        return decode_text(subprocess.check_output(command, stderr=subprocess.DEVNULL))
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def detect_default_gateway() -> str | None:
    system = platform.system()
    commands: list[list[str]]

    if system == "Windows":
        commands = [["route", "print", "-4", "0.0.0.0"]]
    elif system == "Darwin":
        commands = [["route", "-n", "get", "default"]]
    else:
        commands = [["ip", "-4", "route", "show", "default"], ["route", "-n"]]

    for command in commands:
        output = run_output(command)
        if not output:
            continue

        if system == "Darwin":
            match = re.search(r"gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})", output)
            if match:
                return normalize_ip(match.group(1))
            continue

        if command[:2] == ["ip", "-4"]:
            match = re.search(r"\bdefault\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", output)
            if match:
                return normalize_ip(match.group(1))
            continue

        for line in output.splitlines():
            if "0.0.0.0" not in line:
                continue
            candidates = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
            for candidate in candidates:
                if candidate != "0.0.0.0":
                    return normalize_ip(candidate)

    return None


def get_mac_address(ip: str) -> str | None:
    system = platform.system()
    commands: list[list[str]]

    if system == "Windows":
        commands = [["arp", "-a", ip]]
    elif system == "Darwin":
        commands = [["arp", "-n", ip]]
    else:
        commands = [["ip", "neigh", "show", ip], ["arp", "-n", ip]]

    for command in commands:
        output = run_output(command)
        if not output:
            continue
        match = re.search(
            r"([A-Fa-f0-9]{2}(?::[A-Fa-f0-9]{2}){5}|[A-Fa-f0-9]{2}(?:-[A-Fa-f0-9]{2}){5})",
            output,
        )
        if match:
            return normalize_mac(match.group(1))

    return None


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"配置文件读取失败: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CliError(f"配置文件格式错误: {path}")
    return data


def save_config(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass


def config_path_from_args(args: argparse.Namespace) -> Path:
    return Path(args.config).expanduser()


def resolve_ip(args: argparse.Namespace) -> tuple[str, str]:
    config = load_config(config_path_from_args(args))
    if args.ip:
        return args.ip, "argument"
    if config.get("ip"):
        return normalize_ip(str(config["ip"])), "config"
    detected = detect_default_gateway()
    if detected:
        return detected, "default_gateway"
    return DEFAULT_IP, "fallback"


def resolve_mac(
    args: argparse.Namespace,
    ip: str,
    *,
    required: bool,
    allow_prompt: bool = True,
) -> tuple[str | None, str]:
    config = load_config(config_path_from_args(args))
    if args.mac:
        return normalize_mac(args.mac), "argument"
    if config.get("mac"):
        return normalize_mac(str(config["mac"])), "config"

    detected = get_mac_address(ip)
    if detected:
        return detected, "arp"

    if getattr(args, "ask_mac", False) and allow_prompt and not getattr(args, "json", False):
        manual = input("请手动输入网关 MAC(AABBCCDDEEFF): ")
        return normalize_mac(manual), "prompt"

    if required:
        raise CliError("缺少网关 MAC。请使用 --mac AABBCCDDEEFF，或先运行 config set。")
    return None, "missing"
