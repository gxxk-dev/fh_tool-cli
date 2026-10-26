from __future__ import annotations

import ipaddress
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .backends.fh_tool import api_payload, fh_tool_call, http_get_surface
from .client import tcp_open
from .errors import CliError, FHToolError, FHToolHttpError, FHToolResponseError

# 除 RFC1918 外，部分运营商网关使用 CGNAT 地址段；它们同样不是公网目标。
_EXTRA_LOCAL_NETWORKS = (ipaddress.ip_network("100.64.0.0/10"),)


def ensure_local_scan_target(ip: str) -> None:
    """拒绝扫描公网地址，避免把诊断命令误用成对任意主机的端口扫描。"""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise CliError(f"无效 IPv4 地址: {ip}") from exc
    allowed = address.is_private or address.is_loopback or address.is_link_local
    if not allowed:
        allowed = any(address in network for network in _EXTRA_LOCAL_NETWORKS)
    if not allowed:
        raise CliError(
            f"scan 仅允许扫描私有/环回/链路本地/CGNAT 地址，拒绝公网目标: {ip}"
        )


def _scan_port(
    ip: str,
    port: int,
    mac: str | None,
    timeout: float,
    tcp_timeout: float,
    paths: list[str],
    stop: threading.Event,
) -> dict[str, Any]:
    if stop.is_set():
        return {"tcp": None, "skipped": "already found on another port"}

    entry: dict[str, Any] = {"tcp": False}
    if not tcp_open(ip, port, tcp_timeout):
        return entry

    entry["tcp"] = True
    entry["root"] = http_get_surface(ip, port, "/", timeout, diagnose=True)
    entry["paths"] = {}
    for path in paths:
        if stop.is_set():
            entry["stopped"] = "already found on another port"
            break
        path_entry: dict[str, Any] = {
            "surface": http_get_surface(ip, port, path, timeout, diagnose=True),
        }
        if not mac:
            path_entry["getdevinfo"] = {"ok": None, "error": "missing mac"}
        else:
            try:
                response = fh_tool_call(
                    ip,
                    mac,
                    api_payload("GetDevInfo"),
                    timeout,
                    port=port,
                    path=path,
                    diagnose=True,
                )
            except FHToolResponseError as exc:
                path_entry["getdevinfo"] = {
                    "ok": False,
                    "error": str(exc),
                    "status_code": exc.status_code,
                    "content_type": exc.content_type,
                    "server": exc.server,
                    "body_kind": exc.body_kind,
                    "body_length": exc.body_length,
                    "header_names": exc.header_names,
                    "response_headers": exc.response_headers,
                }
            except FHToolHttpError as exc:
                path_entry["getdevinfo"] = {
                    "ok": False,
                    "error": str(exc),
                    "status_code": exc.status_code,
                }
            except FHToolError as exc:
                path_entry["getdevinfo"] = {"ok": False, "error": str(exc)}
            else:
                ok = response.get("result") == 0
                path_entry["getdevinfo"] = {"ok": ok, "response": response}
                if ok:
                    # 找到第一个可用端点后让其它 worker 尽快收手，避免大范围扫描继续打设备。
                    stop.set()
        entry["paths"][path] = path_entry
        if path_entry["getdevinfo"].get("ok"):
            break
    return entry


def scan_fh_tool_endpoints(
    ip: str,
    mac: str | None,
    timeout: float,
    *,
    ports: Iterable[int],
    paths: Iterable[str],
    connect_timeout: float = 0.4,
    workers: int = 32,
) -> dict[str, Any]:
    """只读扫描 fh_tool 端点。

    先 TCP 探测端口，再对开放端口尝试候选 RPC 路径；给了 MAC 时用
    GetDevInfo 的 `result == 0` 作为唯一可信的“找到了”标准。未给 MAC 时
    只记录 HTTP 表面状态，不猜测端点是否可用。
    """
    ensure_local_scan_target(ip)
    port_list = sorted(dict.fromkeys(int(port) for port in ports))
    path_list = list(dict.fromkeys(paths))
    if not port_list:
        raise CliError("--ports 至少需要一个 port")
    if any(port < 1 or port > 65535 for port in port_list):
        raise CliError("port 必须在 1-65535 之间")
    if not path_list:
        raise CliError("--paths 至少需要一个 path")
    if not 1 <= workers <= 64:
        raise CliError("--workers 必须在 1-64 之间")
    if connect_timeout <= 0:
        raise CliError("--connect-timeout 必须大于 0")
    if timeout <= 0:
        raise CliError("--timeout 必须大于 0")
    tcp_timeout = min(connect_timeout, timeout)

    stop = threading.Event()
    results: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(workers, len(port_list))) as executor:
        futures = {
            executor.submit(
                _scan_port,
                ip,
                port,
                mac,
                timeout,
                tcp_timeout,
                path_list,
                stop,
            ): port
            for port in port_list
        }
        for future in as_completed(futures):
            port = futures[future]
            results[port] = future.result()

    verified: list[dict[str, Any]] = []
    for port in port_list:
        entry = results.get(port) or {}
        for path, path_entry in (entry.get("paths") or {}).items():
            dev_info = path_entry.get("getdevinfo") or {}
            if dev_info.get("ok"):
                verified.append(
                    {
                        "port": port,
                        "path": path,
                        "response": dev_info.get("response"),
                    }
                )

    scanned_ports = [
        port
        for port in port_list
        if (results.get(port) or {}).get("tcp") is not None
    ]
    skipped_ports = [port for port in port_list if port not in scanned_ports]
    return {
        "mode": "scan",
        "ip": ip,
        "ports": port_list,
        "paths": path_list,
        "connect_timeout": tcp_timeout,
        "results": {str(port): results[port] for port in port_list if port in results},
        "verified": verified,
        "endpoint": (
            {"port": verified[0]["port"], "path": verified[0]["path"]}
            if verified
            else None
        ),
        "scanned_ports": scanned_ports,
        "skipped_ports": skipped_ports,
        "stopped_early": bool(skipped_ports),
    }
