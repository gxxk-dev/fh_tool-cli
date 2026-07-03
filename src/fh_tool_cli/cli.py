from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

DEFAULT_IP = "192.168.1.1"
FH_TOOL_API_PATH = "/fh_tool/api"
FH_TOOL_UPLOAD_PATH = "/fh_tool/upload"
DEFAULT_PORTS = "23,80,443,8080"
DEFAULT_CONFIG_PATH = Path(
    os.environ.get("FH_TOOL_CLI_CONFIG", "~/.config/fh_tool-cli/config.json")
).expanduser()


@dataclass(frozen=True)
class FHToolCrypto:
    key: bytes
    iv: bytes
    digest: str


class CliError(RuntimeError):
    pass


class FHToolError(RuntimeError):
    pass


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


def derive_crypto(mac: str) -> FHToolCrypto:
    digest = hashlib.sha256(mac.encode("ascii")).hexdigest()
    key = "".join(digest[2 * i + 2] for i in range(16)).encode("ascii")
    iv = "".join(digest[3 * i + 3] for i in range(16)).encode("ascii")
    return FHToolCrypto(key=key, iv=iv, digest=digest)


def pkcs7_pad(data: bytes) -> bytes:
    padder = PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt_payload(payload: dict[str, Any], crypto: FHToolCrypto) -> str:
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    encryptor = Cipher(algorithms.AES(crypto.key), modes.CBC(crypto.iv)).encryptor()
    ciphertext = encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_payload(body: str, crypto: FHToolCrypto) -> dict[str, Any]:
    raw = base64.b64decode(body.strip())
    decryptor = Cipher(algorithms.AES(crypto.key), modes.CBC(crypto.iv)).decryptor()
    plaintext = pkcs7_unpad(decryptor.update(raw) + decryptor.finalize())
    return json.loads(plaintext.decode("utf-8"))


def fh_tool_call(
    ip: str,
    mac: str,
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    crypto = derive_crypto(mac)
    encrypted = encrypt_payload(payload, crypto)
    url = f"http://{ip}:8080{FH_TOOL_API_PATH}"
    try:
        response = requests.post(
            url,
            data=encrypted,
            headers={
                "Content-Type": "text/plain",
                "Connection": "close",
            },
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise FHToolError(f"无法连接 {url}: {exc}") from exc

    if response.status_code != 200:
        raise FHToolError(f"{FH_TOOL_API_PATH} 返回 HTTP {response.status_code}")

    try:
        return decrypt_payload(response.text, crypto)
    except Exception as exc:
        raise FHToolError("响应解密失败，MAC 可能不匹配或固件协议不同") from exc


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


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


def api_payload(func: str, params: dict[str, Any] | None = None, index: str = "1") -> dict[str, Any]:
    payload: dict[str, Any] = {"index": str(index), "func": func}
    if params:
        payload.update(params)
    return payload


def call_method(args: argparse.Namespace, func: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    ip, ip_source = resolve_ip(args)
    mac, mac_source = resolve_mac(args, ip, required=True)
    assert mac is not None
    response = fh_tool_call(ip, mac, api_payload(func, params), args.timeout)
    return {
        "ip": ip,
        "ip_source": ip_source,
        "mac": format_mac(mac),
        "mac_source": mac_source,
        "request": api_payload(func, params),
        "response": response,
    }


def require_yes(args: argparse.Namespace, message: str) -> None:
    if not getattr(args, "yes", False):
        raise CliError(f"{message}。如确认执行，请加 --yes")


def require_danger(args: argparse.Namespace, message: str) -> None:
    require_yes(args, message)
    if not getattr(args, "danger", False):
        raise CliError(f"{message}。如确认危险动作，请加 --danger")


def require_extreme(args: argparse.Namespace, message: str) -> None:
    require_danger(args, message)
    if not getattr(args, "i_know_this_can_break_my_device", False):
        raise CliError(
            f"{message}。最后确认参数是 --i-know-this-can-break-my-device"
        )


def response_download_url(response: dict[str, Any]) -> str:
    url = response.get("Dowloadurl") or response.get("Downloadurl") or response.get("downloadurl")
    if not isinstance(url, str) or not url:
        raise FHToolError(f"响应中没有 Dowloadurl: {response}")
    return url


def make_download_url(ip: str, value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return urljoin(f"http://{ip}:8080", value)


def download_to_file(ip: str, url_value: str, output: Path, timeout: float) -> dict[str, Any]:
    url = make_download_url(ip, url_value)
    try:
        response = requests.get(url, timeout=timeout, stream=True)
    except requests.RequestException as exc:
        raise FHToolError(f"下载失败 {url}: {exc}") from exc
    if response.status_code != 200:
        raise FHToolError(f"下载失败 {url}: HTTP {response.status_code}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as file:
        for chunk in response.iter_content(chunk_size=1024 * 128):
            if chunk:
                file.write(chunk)
    return {
        "url": url,
        "output": str(output),
        "bytes": output.stat().st_size,
        "content_type": response.headers.get("Content-Type"),
    }


def emit(data: Any, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    if isinstance(data, dict):
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(data)


def command_probe(args: argparse.Namespace) -> dict[str, Any]:
    ip, ip_source = resolve_ip(args)
    mac, mac_source = resolve_mac(args, ip, required=False, allow_prompt=False)
    ports = parse_ports(args.ports)

    result: dict[str, Any] = {
        "mode": "probe",
        "ip": ip,
        "ip_source": ip_source,
        "mac": format_mac(mac) if mac else None,
        "mac_source": mac_source,
        "tcp": {str(port): tcp_open(ip, port, args.timeout) for port in ports},
        "surface": {},
        "fh_tool_probe": None,
    }

    for path in [FH_TOOL_API_PATH, FH_TOOL_UPLOAD_PATH, "/fh_tool/tool_download"]:
        url = f"http://{ip}:8080{path}"
        try:
            response = requests.get(url, timeout=args.timeout, allow_redirects=False)
            result["surface"][path] = {
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type"),
            }
        except requests.RequestException as exc:
            result["surface"][path] = {"error": str(exc)}

    if mac:
        try:
            dev_info = fh_tool_call(
                ip,
                mac,
                api_payload("GetDevInfo"),
                args.timeout,
            )
            result["fh_tool_probe"] = {
                "func": "GetDevInfo",
                "ok": dev_info.get("result") == 0,
                "response": dev_info,
            }
        except FHToolError as exc:
            result["fh_tool_probe"] = {
                "func": "GetDevInfo",
                "ok": False,
                "error": str(exc),
            }
    else:
        result["fh_tool_probe"] = {
            "func": "GetDevInfo",
            "ok": False,
            "error": "missing mac",
        }

    return result


def command_ports(args: argparse.Namespace) -> dict[str, Any]:
    ip, ip_source = resolve_ip(args)
    ports = parse_ports(args.ports)
    return {
        "ip": ip,
        "ip_source": ip_source,
        "tcp": {str(port): tcp_open(ip, port, args.timeout) for port in ports},
    }


def command_config_show(args: argparse.Namespace) -> dict[str, Any]:
    path = config_path_from_args(args)
    return {"path": str(path), "config": load_config(path)}


def command_config_set(args: argparse.Namespace) -> dict[str, Any]:
    path = config_path_from_args(args)
    config = load_config(path)
    if args.ip:
        config["ip"] = normalize_ip(args.ip)
    if args.mac:
        config["mac"] = normalize_mac(args.mac)
    if not args.ip and not args.mac:
        raise CliError("config set 至少需要 --ip 或 --mac")
    save_config(path, config)
    return {"path": str(path), "config": config}


def command_config_clear(args: argparse.Namespace) -> dict[str, Any]:
    path = config_path_from_args(args)
    existed = path.exists()
    if existed:
        path.unlink()
    return {"path": str(path), "removed": existed}


def command_simple(func: str, params: dict[str, Any] | None = None) -> Callable[[argparse.Namespace], dict[str, Any]]:
    def handler(args: argparse.Namespace) -> dict[str, Any]:
        return call_method(args, func, params)

    return handler


def command_set_result(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "SetResult 会写入注册结果配置")
    return call_method(args, "SetResult", {"result": args.result})


def command_set_port_mirror(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "SetPortMirror 会修改 port mirror 配置")
    return call_method(
        args,
        "SetPortMirror",
        {
            "enable": args.enable,
            "direction": args.direction,
            "srcport": args.srcport,
            "dstport": args.dstport,
        },
    )


def command_log_download(args: argparse.Namespace) -> dict[str, Any]:
    result = call_method(args, "LogDownload")
    if args.output:
        ip = result["ip"]
        url_value = response_download_url(result["response"])
        result["download"] = download_to_file(
            ip,
            url_value,
            Path(args.output).expanduser(),
            args.timeout,
        )
    return result


def command_set_reg_account(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "SetRegAccount 会修改 operator registration account")
    return call_method(
        args,
        "SetRegAccount",
        {"regname": args.regname, "regpwd": args.regpwd},
    )


def command_set_pwd_reg_password(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "SetPwdRegPassword 会修改 CMCC registration password")
    return call_method(args, "SetPwdRegPassword", {"password": args.password})


def command_download_file(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "DownloadFile 会在设备上打包并导出指定文件")
    result = call_method(args, "DownloadFile", {"fileName": args.file_name})
    url_value = response_download_url(result["response"])
    if args.output:
        output = Path(args.output).expanduser()
    else:
        output = Path.cwd() / Path(url_value.split("?", 1)[0]).name
    result["download"] = download_to_file(result["ip"], url_value, output, args.timeout)
    return result


def command_restore_default_settings(args: argparse.Namespace) -> dict[str, Any]:
    require_extreme(args, "RestoreDefaultSettings 会恢复出厂设置")
    return call_method(args, "RestoreDefaultSettings")


def command_upload_prepare(args: argparse.Namespace) -> dict[str, Any]:
    return call_method(args, "UploadPrepare")


def command_reboot(args: argparse.Namespace) -> dict[str, Any]:
    require_extreme(args, "DeviceReboot 会重启设备")
    return call_method(args, "DeviceReboot")


def command_set_preconfig(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "SetPreconfig 会切换地区/运营商预配置")
    return call_method(args, "SetPreconfig", {"fullname": args.fullname})


def command_telnet_enable(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "TelnetEnable=1 会启动 runtime Telnet 服务")
    result = call_method(args, "TelnetEnable", {"telnet": "1"})
    result["telnet_port_open"] = tcp_open(result["ip"], 23, args.timeout)
    return result


def command_telnet_disable(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "TelnetEnable=0 会关闭 runtime Telnet 服务")
    result = call_method(args, "TelnetEnable", {"telnet": "0"})
    result["telnet_port_open"] = tcp_open(result["ip"], 23, args.timeout)
    return result


def command_set_fh_debug_log(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "SetFHDebugLog 会执行设备上的 debug shell script")
    return call_method(args, "SetFHDebugLog", {"module": args.module, "data": args.data})


def command_close_fh_debug_log(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "CloseFHDebugLog 会修改 debug log 配置")
    return call_method(args, "CloseFHDebugLog")


def command_open_fh_debug_log(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "OpenFHDebugLog 会修改 debug log 配置")
    return call_method(args, "OpenFHDebugLog")


def command_raw_call(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if args.json_payload:
        params.update(parse_json_object(args.json_payload))
    params.update(parse_kv(args.param))

    risky_prefixes = ("Set", "Close", "Open", "Restore", "Device", "Upload")
    if args.func.startswith(risky_prefixes) or args.func == "TelnetEnable":
        if not args.allow_risky:
            raise CliError("raw call 调用 risky func 需要 --allow-risky")

    return call_method(args, args.func, params)


def command_download_url(args: argparse.Namespace) -> dict[str, Any]:
    ip, ip_source = resolve_ip(args)
    return {
        "ip": ip,
        "ip_source": ip_source,
        "download": download_to_file(
            ip,
            args.url,
            Path(args.output).expanduser(),
            args.timeout,
        ),
    }


def command_upload(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "upload 会写入 firmware/preconfig staging path")
    ip, ip_source = resolve_ip(args)
    file_path = Path(args.file).expanduser()
    if not file_path.is_file():
        raise CliError(f"上传文件不存在: {file_path}")
    url = f"http://{ip}:8080{FH_TOOL_UPLOAD_PATH}?action={args.action}"
    try:
        with file_path.open("rb") as file:
            response = requests.post(
                url,
                headers={"fh_upgrade_api_token": args.sessionid},
                files={"file": (file_path.name, file)},
                timeout=args.timeout,
                allow_redirects=False,
            )
    except requests.RequestException as exc:
        raise FHToolError(f"上传失败 {url}: {exc}") from exc
    return {
        "ip": ip,
        "ip_source": ip_source,
        "url": url,
        "status_code": response.status_code,
        "text": response.text[:1000],
    }


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ip", type=normalize_ip, help="网关 IPv4 地址")
    parser.add_argument(
        "--mac",
        help="网关 MAC，支持 AABBCCDDEEFF / AA:BB:CC:DD:EE:FF / AA-BB-CC-DD-EE-FF",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP/TCP timeout 秒数，默认 5",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"配置文件路径，默认 {DEFAULT_CONFIG_PATH}",
    )
    parser.add_argument(
        "--ask-mac",
        action="store_true",
        help="无法自动获取 MAC 时交互式询问；--json 下不会询问",
    )
    parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")


def add_yes(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--yes", action="store_true", help="确认执行会改变设备状态的动作")


def add_danger(parser: argparse.ArgumentParser) -> None:
    add_yes(parser)
    parser.add_argument("--danger", action="store_true", help="确认执行高风险动作")


def add_extreme(parser: argparse.ArgumentParser) -> None:
    add_danger(parser)
    parser.add_argument(
        "--i-know-this-can-break-my-device",
        dest="i_know_this_can_break_my_device",
        action="store_true",
        help="确认该动作可能导致设备断网、重启或恢复出厂",
    )


def add_api_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    func: str,
    *,
    aliases: list[str] | None = None,
    help_text: str,
) -> None:
    parser = subparsers.add_parser(name, aliases=aliases or [], help=help_text)
    add_common_options(parser)
    parser.set_defaults(handler=command_simple(func))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name or "fh-tool",
        description="本地管理 FiberHome /fh_tool 接口的 CLI。",
        epilog="使用 COMMAND -h 查看具体命令参数。",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="COMMAND",
        title="commands",
    )

    probe = subparsers.add_parser("probe", help="低风险探测 fh_tool 是否可用")
    add_common_options(probe)
    probe.add_argument("--ports", default=DEFAULT_PORTS, help=f"逗号分隔 port，默认 {DEFAULT_PORTS}")
    probe.set_defaults(handler=command_probe)

    ports = subparsers.add_parser("ports", help="检查 TCP port 是否打开")
    add_common_options(ports)
    ports.add_argument("--ports", default=DEFAULT_PORTS, help=f"逗号分隔 port，默认 {DEFAULT_PORTS}")
    ports.set_defaults(handler=command_ports)

    config = subparsers.add_parser("config", help="管理本机 CLI 配置")
    config_subparsers = config.add_subparsers(
        dest="config_command",
        required=True,
        metavar="SUBCOMMAND",
        title="config commands",
    )
    config_show = config_subparsers.add_parser("show", help="显示配置")
    config_show.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    config_show.add_argument("--json", action="store_true")
    config_show.set_defaults(handler=command_config_show)
    config_set = config_subparsers.add_parser("set", help="保存默认 IP/MAC")
    config_set.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    config_set.add_argument("--json", action="store_true")
    config_set.add_argument("--ip", type=normalize_ip)
    config_set.add_argument("--mac")
    config_set.set_defaults(handler=command_config_set)
    config_clear = config_subparsers.add_parser("clear", help="删除配置文件")
    config_clear.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    config_clear.add_argument("--json", action="store_true")
    config_clear.set_defaults(handler=command_config_clear)

    add_api_command(subparsers, "get-result", "GetResult", help_text="读取 operator registration result")
    add_api_command(subparsers, "get-port-mirror", "GetPortMirror", help_text="读取 port mirror 配置")

    log_download = subparsers.add_parser("log-download", help="调用 LogDownload，可选下载 tar")
    add_common_options(log_download)
    log_download.add_argument("--output", help="保存返回的 tool_download 文件")
    log_download.set_defaults(handler=command_log_download)

    add_api_command(subparsers, "dev-info", "GetDevInfo", aliases=["info"], help_text="读取设备基础信息")
    add_api_command(subparsers, "admin-account", "GetAdminAccount", help_text="读取 telecomadmin account")
    add_api_command(subparsers, "reg-account", "GetRegAccount", help_text="读取 registration account")
    add_api_command(subparsers, "pwd-reg-password", "GetPwdRegPassword", help_text="读取 CMCC registration password")
    add_api_command(subparsers, "get-preconfig", "GetPreconfig", help_text="读取 preconfig 列表")
    add_api_command(subparsers, "pppoe-account", "GetPppoeAccount", help_text="读取 PPPoE account")

    set_result = subparsers.add_parser("set-result", help="写入 registration result")
    add_common_options(set_result)
    add_yes(set_result)
    set_result.add_argument("--result", required=True)
    set_result.set_defaults(handler=command_set_result)

    set_port_mirror = subparsers.add_parser("set-port-mirror", help="写入 port mirror 配置")
    add_common_options(set_port_mirror)
    add_yes(set_port_mirror)
    set_port_mirror.add_argument("--enable", required=True)
    set_port_mirror.add_argument("--direction", required=True)
    set_port_mirror.add_argument("--srcport", required=True)
    set_port_mirror.add_argument("--dstport", required=True)
    set_port_mirror.set_defaults(handler=command_set_port_mirror)

    set_reg_account = subparsers.add_parser("set-reg-account", help="写入 registration account")
    add_common_options(set_reg_account)
    add_yes(set_reg_account)
    set_reg_account.add_argument("--regname", required=True)
    set_reg_account.add_argument("--regpwd", required=True)
    set_reg_account.set_defaults(handler=command_set_reg_account)

    set_pwd_reg_password = subparsers.add_parser("set-pwd-reg-password", help="写入 CMCC registration password")
    add_common_options(set_pwd_reg_password)
    add_yes(set_pwd_reg_password)
    set_pwd_reg_password.add_argument("--password", required=True)
    set_pwd_reg_password.set_defaults(handler=command_set_pwd_reg_password)

    download_file = subparsers.add_parser("download-file", help="调用 DownloadFile 并保存返回文件")
    add_common_options(download_file)
    add_yes(download_file)
    download_file.add_argument("--file-name", required=True)
    download_file.add_argument("--output", help="本地保存路径；默认使用返回文件名")
    download_file.set_defaults(handler=command_download_file)

    restore = subparsers.add_parser("restore-default-settings", help="恢复出厂设置")
    add_common_options(restore)
    add_extreme(restore)
    restore.set_defaults(handler=command_restore_default_settings)

    upload_prepare = subparsers.add_parser("upload-prepare", help="调用 UploadPrepare 获取 sessionid")
    add_common_options(upload_prepare)
    upload_prepare.set_defaults(handler=command_upload_prepare)

    reboot = subparsers.add_parser("reboot", help="重启设备")
    add_common_options(reboot)
    add_extreme(reboot)
    reboot.set_defaults(handler=command_reboot)

    set_preconfig = subparsers.add_parser("set-preconfig", help="切换 preconfig")
    add_common_options(set_preconfig)
    add_danger(set_preconfig)
    set_preconfig.add_argument("--fullname", required=True)
    set_preconfig.set_defaults(handler=command_set_preconfig)

    telnet = subparsers.add_parser("telnet", help="管理 runtime Telnet")
    telnet_subparsers = telnet.add_subparsers(
        dest="telnet_command",
        required=True,
        metavar="SUBCOMMAND",
        title="telnet commands",
    )
    telnet_enable = telnet_subparsers.add_parser("enable", help="调用 TelnetEnable=1")
    add_common_options(telnet_enable)
    add_yes(telnet_enable)
    telnet_enable.set_defaults(handler=command_telnet_enable)
    telnet_disable = telnet_subparsers.add_parser("disable", help="调用 TelnetEnable=0")
    add_common_options(telnet_disable)
    add_danger(telnet_disable)
    telnet_disable.set_defaults(handler=command_telnet_disable)

    set_fh_debug_log = subparsers.add_parser("set-fh-debug-log", help="调用 SetFHDebugLog")
    add_common_options(set_fh_debug_log)
    add_danger(set_fh_debug_log)
    set_fh_debug_log.add_argument("--module", required=True)
    set_fh_debug_log.add_argument("--data", required=True)
    set_fh_debug_log.set_defaults(handler=command_set_fh_debug_log)

    close_fh_debug_log = subparsers.add_parser("close-fh-debug-log", help="关闭 FH debug log")
    add_common_options(close_fh_debug_log)
    add_yes(close_fh_debug_log)
    close_fh_debug_log.set_defaults(handler=command_close_fh_debug_log)

    open_fh_debug_log = subparsers.add_parser("open-fh-debug-log", help="开启 FH debug log")
    add_common_options(open_fh_debug_log)
    add_yes(open_fh_debug_log)
    open_fh_debug_log.set_defaults(handler=command_open_fh_debug_log)

    raw_call = subparsers.add_parser("call", help="raw fh_tool/api call")
    add_common_options(raw_call)
    raw_call.add_argument("--func", required=True)
    raw_call.add_argument("--param", action="append", default=[], help="k=v，可重复")
    raw_call.add_argument("--json-payload", help="额外 JSON object 参数")
    raw_call.add_argument("--allow-risky", action="store_true", help="允许 raw call 调用 risky func")
    raw_call.set_defaults(handler=command_raw_call)

    download_url = subparsers.add_parser("download-url", help="下载 /fh_tool/tool_download 返回文件")
    add_common_options(download_url)
    download_url.add_argument("--url", required=True)
    download_url.add_argument("--output", required=True)
    download_url.set_defaults(handler=command_download_url)

    upload = subparsers.add_parser("upload", help="调用 /fh_tool/upload")
    add_common_options(upload)
    add_danger(upload)
    upload.add_argument("--action", choices=["upgradeimage", "preconfig"], required=True)
    upload.add_argument("--file", required=True)
    upload.add_argument("--sessionid", required=True)
    upload.set_defaults(handler=command_upload)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = args.handler(args)
    except (argparse.ArgumentTypeError, CliError, FHToolError, ValueError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已取消", file=sys.stderr)
        return 130

    emit(result, getattr(args, "json", False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
