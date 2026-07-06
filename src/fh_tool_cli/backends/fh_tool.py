from __future__ import annotations

import argparse
import logging
from typing import Any

import requests

from ..config_store import format_mac, resolve_ip, resolve_mac
from ..crypto import decrypt_payload, derive_crypto, encrypt_payload
from ..errors import FHToolError
from ..output import log_event

FH_TOOL_API_PATH = "/fh_tool/api"
FH_TOOL_UPLOAD_PATH = "/fh_tool/upload"


def fh_tool_call(
    ip: str,
    mac: str,
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    crypto = derive_crypto(mac)
    encrypted = encrypt_payload(payload, crypto)
    url = f"http://{ip}:8080{FH_TOOL_API_PATH}"
    func = str(payload.get("func", "unknown"))
    log_event(logging.INFO, "fh_tool.api.request", ip=ip, path=FH_TOOL_API_PATH, func=func)
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


def response_download_url(response: dict[str, Any]) -> str:
    url = response.get("Dowloadurl") or response.get("Downloadurl") or response.get("downloadurl")
    if not isinstance(url, str) or not url:
        raise FHToolError(f"响应中没有 Dowloadurl: {response}")
    return url
