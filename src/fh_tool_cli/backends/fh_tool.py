from __future__ import annotations

import argparse
import base64
import json
import logging
import re
import time
from typing import Any, NamedTuple

import requests

from ..client import tcp_open
from ..config_store import format_mac, resolve_ip, resolve_mac
from ..crypto import decrypt_payload, derive_crypto, encrypt_payload
from ..errors import FHToolError, FHToolHttpError, FHToolResponseError
from ..fh_endpoints import (
    DEFAULT_FH_TOOL_PORT,
    FALLBACK_FH_TOOL_PORTS,
    FH_TOOL_API_PATH,
    FH_TOOL_UPLOAD_PATH,
    PORT_PROBE_TCP_TIMEOUT,
    TOOL_DOWNLOAD_PATH,
    fh_tool_url,
)
from ..output import log_event, redact_log_fields


class FhPaths(NamedTuple):
    """三个 fh_tool 端点的实际请求路径（默认值或 --fh-*-path 覆盖值）。"""

    api: str
    upload: str
    download: str


def fh_paths_from_args(args: argparse.Namespace) -> FhPaths:
    """解析端点路径；parser 没有对应选项时（如 web 命令族）回退默认值。"""
    return FhPaths(
        api=getattr(args, "fh_api_path", None) or FH_TOOL_API_PATH,
        upload=getattr(args, "fh_upload_path", None) or FH_TOOL_UPLOAD_PATH,
        download=getattr(args, "fh_download_path", None) or TOOL_DOWNLOAD_PATH,
    )


_BASE64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)

_BODY_KIND_LABELS = {
    "empty": "空响应",
    "html": "HTML/XML 网页",
    "json": "明文 JSON",
    "base64": "无法用当前 MAC 解密的 base64 密文",
    "text": "非 base64 文本",
}


def classify_response_body(body: str) -> str:
    """按内容给 200 响应体分类,用于把“解密失败”变成可诊断结论。

    只返回类别,不回显原文:明文 JSON 响应可能包含 adminpwd 等敏感值。
    """
    text = "".join(body.split())
    if not text:
        return "empty"
    if text.lstrip().startswith("<"):
        return "html"
    if text.startswith(("{", "[")):
        return "json"
    if all(ch in _BASE64_ALPHABET for ch in text):
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception:  # noqa: BLE001 - 非法 base64 归入普通文本
            return "text"
        if len(raw) % 16 == 0:
            return "base64"
    return "text"


_RESPONSE_PREVIEW_LIMIT = 240
# 普通文本只在形态安全时展示;出现 "=" 等赋值符号可能是凭据回显,一律隐藏。
_TEXT_PREVIEW_SAFE_RE = re.compile(r"^[A-Za-z0-9 .,;:!?/()\[\]{}'\"<>_+%#@&*\-]{0,120}$")


def _truncate_preview(text: str, limit: int = _RESPONSE_PREVIEW_LIMIT) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[:limit]}…(+{len(compact) - limit} chars)"


def response_body_preview(body: str, body_kind: str) -> str:
    """生成可安全写入日志的响应预览。

    明文 JSON 可能是设备返回的配置（含 adminpwd 等），先递归脱敏再序列化；
    普通文本无法可靠区分是否含凭据，只在形态安全时展示。密文与 HTML 原样截断。
    """
    if body_kind == "empty":
        return ""
    if body_kind == "json":
        try:
            parsed = json.loads(body)
        except Exception:  # noqa: BLE001 - 分类器已判定 json,解析失败时保守隐藏
            return "[JSON 解析失败，内容已隐藏]"
        return _truncate_preview(
            json.dumps(redact_log_fields(parsed), ensure_ascii=False, sort_keys=True)
        )
    if body_kind == "text" and not _TEXT_PREVIEW_SAFE_RE.match(" ".join(body.split())):
        return "[文本内容已隐藏]"
    return _truncate_preview(body)


def fh_tool_call(
    ip: str,
    mac: str,
    payload: dict[str, Any],
    timeout: float,
    *,
    port: int = DEFAULT_FH_TOOL_PORT,
    path: str = FH_TOOL_API_PATH,
) -> dict[str, Any]:
    crypto = derive_crypto(mac)
    encrypted = encrypt_payload(payload, crypto)
    url = fh_tool_url(ip, port, path)
    func = str(payload.get("func", "unknown"))
    log_event(
        logging.INFO,
        "fh_tool.api.request",
        ip=ip,
        port=port,
        path=path,
        func=func,
        request_bytes=len(encrypted),
    )
    started = time.monotonic()
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
        log_event(
            logging.INFO,
            "fh_tool.api.error",
            ip=ip,
            port=port,
            path=path,
            func=func,
            error=str(exc),
            elapsed_ms=round((time.monotonic() - started) * 1000, 1),
        )
        raise FHToolError(f"无法连接 {url}: {exc}") from exc
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)

    if response.status_code != 200:
        body_kind = classify_response_body(response.text)
        log_event(
            logging.INFO,
            "fh_tool.api.http_error",
            ip=ip,
            port=port,
            path=path,
            func=func,
            status_code=response.status_code,
            content_type=response.headers.get("Content-Type"),
            body_kind=body_kind,
            body_length=len(response.text or ""),
            body_preview=response_body_preview(response.text or "", body_kind),
            elapsed_ms=elapsed_ms,
        )
        raise FHToolHttpError(
            f"{path} 返回 HTTP {response.status_code}",
            status_code=response.status_code,
        )

    try:
        result = decrypt_payload(response.text, crypto)
    except Exception as exc:
        body_kind = classify_response_body(response.text)
        body_length = len(response.text or "")
        content_type = response.headers.get("Content-Type")
        log_event(
            logging.INFO,
            "fh_tool.api.decrypt_error",
            ip=ip,
            port=port,
            path=path,
            func=func,
            status_code=response.status_code,
            content_type=content_type,
            body_kind=body_kind,
            body_length=body_length,
            body_preview=response_body_preview(response.text or "", body_kind),
            elapsed_ms=elapsed_ms,
        )
        raise FHToolResponseError(
            "响应解密失败："
            f"HTTP {response.status_code}，Content-Type={content_type or 'unknown'}，"
            f"body 长度={body_length}，疑似{_BODY_KIND_LABELS[body_kind]}。"
            "MAC 不匹配时设备通常返回 HTTP 400，因此这条错误大概率与 MAC 无关；"
            "更可能是该端口/路径上的服务不是 fh_tool API，或固件协议已变化。"
            "可运行 fh-tool probe --json 查看各端口/路径状态，"
            "或用 --fh-port / --fh-api-path 显式指定。",
            status_code=response.status_code,
            content_type=content_type,
            body_kind=body_kind,
            body_length=body_length,
        ) from exc
    log_event(
        logging.INFO,
        "fh_tool.api.response",
        ip=ip,
        port=port,
        path=path,
        func=func,
        status_code=response.status_code,
        result=result.get("result") if isinstance(result, dict) else None,
        body_length=len(response.text or ""),
        elapsed_ms=elapsed_ms,
    )
    if logging.getLogger("fh_tool_cli").isEnabledFor(logging.DEBUG):
        # 解密后的完整响应只在 -vv 输出；log_event 会按 password/token 等字段名脱敏。
        log_event(logging.DEBUG, "fh_tool.api.result", func=func, response=result)
    return result


def api_payload(func: str, params: dict[str, Any] | None = None, index: str = "1") -> dict[str, Any]:
    payload: dict[str, Any] = {"index": str(index), "func": func}
    if params:
        payload.update(params)
    return payload


def check_fh_tool_port(
    ip: str,
    port: int,
    mac: str,
    timeout: float,
    *,
    path: str = FH_TOOL_API_PATH,
) -> tuple[bool, bool]:
    """检查端口上的 fh_tool API。

    返回 (是否确认可用, 是否明显不是 fh_tool)。第二个值只在响应表明“这里不是
    fh_tool”时为 True（200 但响应体不是密文、403/404/405），用于决定是否继续探测
    候选端口；连接超时、HTTP 400/500 等 API 自身错误不会触发换端口。
    """
    try:
        result = fh_tool_call(ip, mac, api_payload("GetDevInfo"), timeout, port=port, path=path)
    except FHToolResponseError:
        return False, True
    except FHToolHttpError as exc:
        return False, exc.status_code in {403, 404, 405}
    except FHToolError:
        return False, False
    return result.get("result") == 0, False


def verify_fh_tool_port(ip: str, port: int, mac: str, timeout: float, *, path: str = FH_TOOL_API_PATH) -> bool:
    return check_fh_tool_port(ip, port, mac, timeout, path=path)[0]


def _surface_reachable(ip: str, port: int, timeout: float, *, path: str = FH_TOOL_API_PATH) -> bool:
    url = fh_tool_url(ip, port, path)
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
    path: str = FH_TOOL_API_PATH,
) -> tuple[int, str]:
    """解析 fh_tool 后端端口：显式 --fh-port > 8080 实测校验 > 候选端口探测 > 回退默认。

    8080 TCP 可达时不再直接采信，而是用 GetDevInfo 确认它确实是 fh_tool API；
    如果 8080 返回 200 但响应体不是密文（典型：8080 是 Web UI、API 在 80），
    继续探测候选端口。连接超时、HTTP 400/500 等 API 自身错误仍保留 8080。
    """
    explicit = getattr(args, "fh_port", None)
    if explicit is not None:
        log_event(logging.DEBUG, "fh_tool.port.explicit", ip=ip, port=explicit)
        return explicit, "argument"

    tcp_timeout = min(timeout, PORT_PROBE_TCP_TIMEOUT)
    if tcp_open(ip, DEFAULT_FH_TOOL_PORT, tcp_timeout):
        if mac is None:
            log_event(logging.DEBUG, "fh_tool.port.default_ok", ip=ip, port=DEFAULT_FH_TOOL_PORT)
            return DEFAULT_FH_TOOL_PORT, "default"
        verified, try_elsewhere = check_fh_tool_port(
            ip, DEFAULT_FH_TOOL_PORT, mac, timeout, path=path
        )
        if verified or not try_elsewhere:
            log_event(logging.DEBUG, "fh_tool.port.default_ok", ip=ip, port=DEFAULT_FH_TOOL_PORT)
            return DEFAULT_FH_TOOL_PORT, "default"
        log_event(
            logging.INFO,
            "fh_tool.port.default_wrong_service",
            ip=ip,
            port=DEFAULT_FH_TOOL_PORT,
            default_port=DEFAULT_FH_TOOL_PORT,
        )

    tried: list[int] = []
    for port in candidates:
        if port == DEFAULT_FH_TOOL_PORT:
            continue
        tried.append(port)
        if not tcp_open(ip, port, tcp_timeout):
            continue
        if mac:
            verified, _ = check_fh_tool_port(ip, port, mac, timeout, path=path)
            if not verified:
                continue
            verified_by = "getdevinfo"
        else:
            if not _surface_reachable(ip, port, timeout, path=path):
                continue
            verified_by = "surface"
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


def _unverified_port_hint(exc: FHToolError, *, path: str = FH_TOOL_API_PATH) -> FHToolError:
    candidates = ", ".join(str(port) for port in FALLBACK_FH_TOOL_PORTS)
    return FHToolError(
        f"{exc}\n"
        f"（提示：已实测 8080 与候选端口 {candidates} 的 {path}，均未通过 GetDevInfo 校验。"
        "可运行 fh-tool probe 查看各端口/路径状态，或用 --fh-port 显式指定端口、"
        "用 --mac 确认网关 MAC；"
        "部分型号/固件（如 HG6142A3 V03.00.M0000）的 fh_tool API 在 80 端口）"
    )


def probe_fh_port_candidates(
    ip: str,
    mac: str | None,
    timeout: float,
    ports: tuple[int, ...] | None = None,
    paths: FhPaths | None = None,
) -> dict[str, dict[str, Any]]:
    """对候选端口逐个报告 tcp/surface/getdevinfo 状态，供 probe 命令诊断端点。"""
    if ports is None:
        ports = tuple(dict.fromkeys([DEFAULT_FH_TOOL_PORT, *FALLBACK_FH_TOOL_PORTS]))
    if paths is None:
        paths = FhPaths(FH_TOOL_API_PATH, FH_TOOL_UPLOAD_PATH, TOOL_DOWNLOAD_PATH)
    tcp_timeout = min(timeout, PORT_PROBE_TCP_TIMEOUT)
    report: dict[str, dict[str, Any]] = {}
    for port in ports:
        entry: dict[str, Any] = {
            "tcp": tcp_open(ip, port, tcp_timeout),
            "surface": {},
            "getdevinfo": None,
        }
        for path in (paths.api, paths.upload, paths.download):
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
                dev_info = fh_tool_call(ip, mac, api_payload("GetDevInfo"), timeout, port=port, path=paths.api)
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
    paths = fh_paths_from_args(args)
    port, port_source = resolve_fh_port(args, ip, mac=mac, timeout=args.timeout, path=paths.api)
    try:
        response = fh_tool_call(ip, mac, api_payload(func, params), args.timeout, port=port, path=paths.api)
    except FHToolError as exc:
        if port_source == "default_unverified":
            raise _unverified_port_hint(exc, path=paths.api) from exc
        raise
    return {
        "ip": ip,
        "ip_source": ip_source,
        "mac": format_mac(mac),
        "mac_source": mac_source,
        "fh_port": port,
        "fh_port_source": port_source,
        "fh_api_path": paths.api,
        "request": api_payload(func, params),
        "response": response,
    }


def response_download_url(response: dict[str, Any]) -> str:
    url = response.get("Dowloadurl") or response.get("Downloadurl") or response.get("downloadurl")
    if not isinstance(url, str) or not url:
        raise FHToolError(f"响应中没有 Dowloadurl: {response}")
    return url
