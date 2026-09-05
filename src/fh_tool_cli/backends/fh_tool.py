from __future__ import annotations

import argparse
import logging
from typing import Any

import requests

from ..client import tcp_open
from ..config_store import format_mac, resolve_ip, resolve_mac
from ..crypto import decrypt_payload, derive_crypto, encrypt_payload
from ..errors import FHToolError
from ..fh_endpoints import (
    DEFAULT_FH_TOOL_PORT,
    FALLBACK_FH_TOOL_PORTS,
    PORT_PROBE_TCP_TIMEOUT,
    fh_tool_url,
)
from ..output import log_event

FH_TOOL_API_PATH = "/fh_tool/api"
FH_TOOL_UPLOAD_PATH = "/fh_tool/upload"
TOOL_DOWNLOAD_PATH = "/fh_tool/tool_download"
SURFACE_PROBE_PATHS = (FH_TOOL_API_PATH, FH_TOOL_UPLOAD_PATH, TOOL_DOWNLOAD_PATH)


def fh_tool_call(
    ip: str,
    mac: str,
    payload: dict[str, Any],
    timeout: float,
    *,
    port: int = DEFAULT_FH_TOOL_PORT,
) -> dict[str, Any]:
    crypto = derive_crypto(mac)
    encrypted = encrypt_payload(payload, crypto)
    url = fh_tool_url(ip, port, FH_TOOL_API_PATH)
    func = str(payload.get("func", "unknown"))
    log_event(logging.INFO, "fh_tool.api.request", ip=ip, port=port, path=FH_TOOL_API_PATH, func=func)
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
        log_event(logging.INFO, "fh_tool.api.error", ip=ip, path=FH_TOOL_API_PATH, func=func, error=str(exc))
        raise FHToolError(f"无法连接 {url}: {exc}") from exc

    if response.status_code != 200:
        log_event(
            logging.INFO,
            "fh_tool.api.http_error",
            ip=ip,
            path=FH_TOOL_API_PATH,
            func=func,
            status_code=response.status_code,
        )
        raise FHToolError(f"{FH_TOOL_API_PATH} 返回 HTTP {response.status_code}")

    try:
        result = decrypt_payload(response.text, crypto)
    except Exception as exc:
        log_event(logging.INFO, "fh_tool.api.decrypt_error", ip=ip, path=FH_TOOL_API_PATH, func=func)
        raise FHToolError("响应解密失败，MAC 可能不匹配或固件协议不同") from exc
    log_event(
        logging.INFO,
        "fh_tool.api.response",
        ip=ip,
        path=FH_TOOL_API_PATH,
        func=func,
        status_code=response.status_code,
        result=result.get("result") if isinstance(result, dict) else None,
    )
    return result


def api_payload(func: str, params: dict[str, Any] | None = None, index: str = "1") -> dict[str, Any]:
    payload: dict[str, Any] = {"index": str(index), "func": func}
    if params:
        payload.update(params)
    return payload


def verify_fh_tool_port(ip: str, port: int, mac: str, timeout: float) -> bool:
    try:
        result = fh_tool_call(ip, mac, api_payload("GetDevInfo"), timeout, port=port)
    except FHToolError:
        return False
    return result.get("result") == 0


def _surface_reachable(ip: str, port: int, timeout: float) -> bool:
    url = fh_tool_url(ip, port, FH_TOOL_API_PATH)
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return False
    log_event(logging.DEBUG, "fh_tool.port.surface", ip=ip, port=port, status_code=response.status_code)
    return True


def resolve_fh_port(
    args: argparse.Namespace,
    ip: str,
    *,
    mac: str | None = None,
    timeout: float,
    candidates: tuple[int, ...] = FALLBACK_FH_TOOL_PORTS,
) -> tuple[int, str]:
    """解析 fh_tool 后端端口：显式 --fh-port > 8080 TCP 快筛 > 候选端口探测 > 回退默认。

    仅当 8080 TCP 不可达时才触发候选端口探测；HTTP 4xx/5xx、解密失败不触发切换。
    """
    explicit = getattr(args, "fh_port", None)
    if explicit is not None:
        log_event(logging.DEBUG, "fh_tool.port.explicit", ip=ip, port=explicit)
        return explicit, "argument"

    tcp_timeout = min(timeout, PORT_PROBE_TCP_TIMEOUT)
    if tcp_open(ip, DEFAULT_FH_TOOL_PORT, tcp_timeout):
        log_event(logging.DEBUG, "fh_tool.port.default_ok", ip=ip, port=DEFAULT_FH_TOOL_PORT)
        return DEFAULT_FH_TOOL_PORT, "default"

    tried: list[int] = []
    for port in candidates:
        if port == DEFAULT_FH_TOOL_PORT:
            continue
        tried.append(port)
        if not tcp_open(ip, port, tcp_timeout):
            continue
        verified_by = "surface"
        if mac:
            if verify_fh_tool_port(ip, port, mac, timeout):
                verified_by = "getdevinfo"
            elif not _surface_reachable(ip, port, timeout):
                continue
        log_event(
            logging.INFO,
            "fh_tool.port.fallback_selected",
            ip=ip,
            port=port,
            default_port=DEFAULT_FH_TOOL_PORT,
            verified_by=verified_by,
        )
        return port, "auto_detected"

    log_event(
        logging.INFO,
        "fh_tool.port.fallback_failed",
        ip=ip,
        tried=tried,
        default_port=DEFAULT_FH_TOOL_PORT,
    )
    return DEFAULT_FH_TOOL_PORT, "default_unverified"


def _unverified_port_hint(exc: FHToolError) -> FHToolError:
    candidates = ", ".join(str(port) for port in FALLBACK_FH_TOOL_PORTS)
    return FHToolError(
        f"{exc}\n"
        f"（提示：已自动探测候选端口 {candidates}，未发现 fh_tool 服务。"
        "可运行 fh-tool probe 查看各端口/路径状态，或用 --fh-port 显式指定端口；"
        "部分型号/固件（如 HG6142A3 V03.00.M0000）的 fh_tool API 在 80 端口）"
    )


def probe_fh_port_candidates(
    ip: str,
    mac: str | None,
    timeout: float,
    ports: tuple[int, ...] | None = None,
) -> dict[str, dict[str, Any]]:
    """对候选端口逐个报告 tcp/surface/getdevinfo 状态，供 probe 命令诊断端点。"""
    if ports is None:
        ports = tuple(dict.fromkeys([DEFAULT_FH_TOOL_PORT, *FALLBACK_FH_TOOL_PORTS]))
    tcp_timeout = min(timeout, PORT_PROBE_TCP_TIMEOUT)
    report: dict[str, dict[str, Any]] = {}
    for port in ports:
        entry: dict[str, Any] = {
            "tcp": tcp_open(ip, port, tcp_timeout),
            "surface": {},
            "getdevinfo": None,
        }
        for path in SURFACE_PROBE_PATHS:
            url = fh_tool_url(ip, port, path)
            try:
                response = requests.get(url, timeout=timeout, allow_redirects=False)
                entry["surface"][path] = {
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type"),
                }
            except requests.RequestException as exc:
                entry["surface"][path] = {"error": str(exc)}
        if mac and entry["tcp"]:
            try:
                dev_info = fh_tool_call(ip, mac, api_payload("GetDevInfo"), timeout, port=port)
                entry["getdevinfo"] = {
                    "ok": dev_info.get("result") == 0,
                    "response": dev_info,
                }
            except FHToolError as exc:
                entry["getdevinfo"] = {"ok": False, "error": str(exc)}
        report[str(port)] = entry
    return report


def call_method(args: argparse.Namespace, func: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    ip, ip_source = resolve_ip(args)
    mac, mac_source = resolve_mac(args, ip, required=True)
    assert mac is not None
    port, port_source = resolve_fh_port(args, ip, mac=mac, timeout=args.timeout)
    try:
        response = fh_tool_call(ip, mac, api_payload(func, params), args.timeout, port=port)
    except FHToolError as exc:
        if port_source == "default_unverified":
            raise _unverified_port_hint(exc) from exc
        raise
    return {
        "ip": ip,
        "ip_source": ip_source,
        "mac": format_mac(mac),
        "mac_source": mac_source,
        "fh_port": port,
        "fh_port_source": port_source,
        "request": api_payload(func, params),
        "response": response,
    }


def response_download_url(response: dict[str, Any]) -> str:
    url = response.get("Dowloadurl") or response.get("Downloadurl") or response.get("downloadurl")
    if not isinstance(url, str) or not url:
        raise FHToolError(f"响应中没有 Dowloadurl: {response}")
    return url
