from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..account import WEB_ADMIN_PASSWORD_PATH
from ..argparse_utils import parse_json_object, parse_kv
from ..backends.cfg_cmd import CfgCmdBackend
from ..backends.fh_tool import api_payload, fh_tool_call, resolve_fh_port
from ..backends.local_vm import DEFAULT_VM_ROOT, LocalVmShell
from ..backends.telnet import TelnetCredentials, TelnetShell
from ..backends.web_ajax import DEFAULT_AJAX_PATH, DEFAULT_WEB_LOGIN_PORT, WebAjaxClient
from ..config_store import DEFAULT_CONFIG_PATH, normalize_ip, resolve_ip, resolve_mac
from ..credential_sources import complete_hg5143f_telnet_login
from ..errors import CliError, FHToolError
from ..risk import dry_run_notice, is_confirmed
from ..web_discovery import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_RESOURCES,
    crawl_same_origin_resources,
    empty_catalog,
    find_catalog_method,
    merge_catalogs,
    probe_read_methods,
    read_catalog,
    static_catalog,
    write_catalog,
)
from ..web_writes import (
    WEB_SERVICE_NAMES,
    build_web_write_payload,
    parse_web_bool,
    parse_web_if_name,
    parse_web_index,
    parse_web_ipv4,
    parse_web_port,
    parse_web_terminal_number,
    parse_web_vlan,
    parse_web_vlan_part,
    parse_web_wan_iporppp,
    parse_web_wan_iporppp_or_null,
    parse_web_wan_vlan,
)

DEFAULT_WEB_USERNAME = "useradmin"
WEB_PASSWORD_SOURCES = ("auto", "admin-account", "cfg", "none")


def _web_client_from_args(args: argparse.Namespace) -> WebAjaxClient:
    ip, _ip_source = resolve_ip(args)
    scheme = "https" if args.https else "http"
    base_url = f"{scheme}://{ip}:{args.web_port}/"
    return WebAjaxClient(
        base_url,
        ajax_path=args.ajax_path,
        timeout=args.timeout,
        sessionid=getattr(args, "sessionid", None),
        reveal_secrets=getattr(args, "reveal_secrets", False),
    )


def _web_base_url_from_args(args: argparse.Namespace) -> str:
    ip, _ip_source = resolve_ip(args)
    scheme = "https" if args.https else "http"
    return f"{scheme}://{ip}:{args.web_port}/"


def _web_login_if_requested(
    client: WebAjaxClient,
    args: argparse.Namespace,
    *,
    require_success: bool = True,
    force_auto: bool = False,
) -> dict[str, Any] | None:
    password_source = getattr(args, "password_source", "auto")
    explicit_secret = getattr(args, "password", None) is not None or getattr(args, "password_stdin", False)
    explicit_username = getattr(args, "username", None) is not None
    explicit_source = password_source != "auto"
    if _has_explicit_web_sessionid(args) and force_auto and not (explicit_secret or explicit_source):
        return {
            "attempted": False,
            "username": getattr(args, "username", None) or DEFAULT_WEB_USERNAME,
            "password_source": "sessionid",
            "sessionid_present": True,
        }
    if not (force_auto or explicit_secret or explicit_username or explicit_source):
        return None

    username = getattr(args, "username", None) or DEFAULT_WEB_USERNAME
    password, source, errors = _web_password_from_args(args)
    if password is None:
        if password_source == "none":
            if require_success and not client.sessionid:
                raise CliError("Web login 需要密码或显式 --sessionid")
            return {
                "attempted": False,
                "username": username,
                "password_source": "none",
                "sessionid_present": bool(client.sessionid),
            }
        error = "; ".join(errors) if errors else "未获取到 Web 登录密码"
        if require_success or explicit_secret or explicit_source or explicit_username:
            raise CliError(f"Web login 自动获取密码失败: {error}")
        return {
            "attempted": False,
            "username": username,
            "password_source": source,
            "sessionid_present": bool(client.sessionid),
            "error": error,
        }

    try:
        result = client.login(
            username,
            password,
            port=getattr(args, "web_login_port", DEFAULT_WEB_LOGIN_PORT),
        )
    except FHToolError as exc:
        if require_success:
            raise CliError(f"Web login failed: {exc}") from exc
        return {
            "attempted": True,
            "username": username,
            "password_source": source,
            "sessionid_present": bool(client.sessionid),
            "ok": False,
            "error": str(exc),
        }
    result["attempted"] = True
    result["password_source"] = source
    if require_success and not result["ok"]:
        raise CliError(f"Web login failed: login_result={result.get('login_result')}")
    if not result["ok"]:
        result["error"] = f"login_result={result.get('login_result')}"
    return result


def _has_explicit_web_sessionid(args: argparse.Namespace) -> bool:
    return getattr(args, "sessionid", None) is not None


def _web_password_from_args(args: argparse.Namespace) -> tuple[str | None, str, list[str]]:
    has_password = getattr(args, "password", None) is not None
    has_stdin = getattr(args, "password_stdin", False)
    if has_password and has_stdin:
        raise CliError("Web login 只能选择 --password 或 --password-stdin")
    if has_password:
        return str(args.password), "argument", []
    if has_stdin:
        return sys.stdin.readline().rstrip("\n"), "stdin", []

    source = getattr(args, "password_source", "auto")
    if source == "none":
        return None, "none", []

    errors: list[str] = []
    if source in {"auto", "admin-account"}:
        try:
            return _web_password_from_admin_account(args), "admin-account", []
        except (CliError, FHToolError, ValueError) as exc:
            errors.append(f"admin-account: {exc}")
            if source == "admin-account":
                return None, "admin-account", errors

    if source in {"auto", "cfg"}:
        try:
            return _web_password_from_cfg(args), "cfg", []
        except (CliError, FHToolError, ValueError) as exc:
            errors.append(f"cfg: {exc}")
            if source == "cfg":
                return None, "cfg", errors

    return None, source, errors


def _web_password_from_admin_account(args: argparse.Namespace) -> str:
    ip, _ip_source = resolve_ip(args)
    mac, _mac_source = resolve_mac(args, ip, required=True, allow_prompt=True)
    assert mac is not None
    fh_port, _fh_port_source = resolve_fh_port(args, ip, mac=mac, timeout=args.timeout)
    result = fh_tool_call(ip, mac, api_payload("GetAdminAccount"), args.timeout, port=fh_port)
    password = _extract_password_from_mapping(result)
    if not password:
        raise FHToolError("GetAdminAccount 响应中没有可用 password 字段")
    return password


def _web_password_from_cfg(args: argparse.Namespace) -> str:
    backend = _cfg_backend_from_web_args(args)
    password = backend.get(WEB_ADMIN_PASSWORD_PATH)
    if not password:
        raise FHToolError(f"cfg path 为空: {WEB_ADMIN_PASSWORD_PATH}")
    return password


def _cfg_backend_from_web_args(args: argparse.Namespace) -> CfgCmdBackend:
    if getattr(args, "backend", "telnet") == "local-vm":
        return CfgCmdBackend(
            LocalVmShell(
                Path(args.vm_root).expanduser(),
                timeout=args.timeout,
            ).run,
            expensive_missing_paths=True,
        )
    ip, _ip_source = resolve_ip(args)
    username, password = _web_telnet_login_from_args(args, ip)
    return CfgCmdBackend(
        TelnetShell(
            TelnetCredentials(
                host=ip,
                port=getattr(args, "telnet_port", 23),
                username=username,
                password=password,
                timeout=args.timeout,
            )
        ).run
    )


def _web_telnet_login_from_args(
    args: argparse.Namespace,
    ip: str,
) -> tuple[str | None, str | None]:
    has_password = getattr(args, "telnet_password", None) is not None
    has_stdin = getattr(args, "telnet_password_stdin", False)
    if has_password and has_stdin:
        raise CliError("cfg password source 只能选择 --telnet-password 或 --telnet-password-stdin")
    username = getattr(args, "telnet_username", None)
    password: str | None = None
    if has_stdin:
        password = sys.stdin.readline().rstrip("\n")
    elif has_password:
        password = str(args.telnet_password)
    return complete_hg5143f_telnet_login(
        args,
        ip=ip,
        username=username,
        password=password,
    )


def _extract_password_from_mapping(value: Any) -> str | None:
    if isinstance(value, dict):
        prioritized: list[str] = []
        fallback: list[str] = []
        for key, item in value.items():
            lowered = str(key).lower()
            if isinstance(item, str) and item:
                if any(marker in lowered for marker in ("password", "passwd", "pwd")):
                    if any(marker in lowered for marker in ("web", "admin", "telecom", "super")):
                        prioritized.append(item)
                    else:
                        fallback.append(item)
            nested = _extract_password_from_mapping(item)
            if nested:
                fallback.append(nested)
        if prioritized:
            return prioritized[0]
        if fallback:
            return fallback[0]
    if isinstance(value, list):
        for item in value:
            nested = _extract_password_from_mapping(item)
            if nested:
                return nested
    return None


def command_web_login_check(args: argparse.Namespace) -> dict[str, Any]:
    client = _web_client_from_args(args)
    login_result = _web_login_if_requested(client, args, require_success=False, force_auto=True)
    check_result = client.login_check()
    if login_result is not None:
        return {"login": login_result, "check": check_result}
    return check_result


def command_web_ajax_get(args: argparse.Namespace) -> dict[str, Any]:
    client = _web_client_from_args(args)
    login_result = _web_read_login(client, args)
    result = client.ajax_get(args.method)
    result["login"] = _auth_summary(login_result)
    return result


def command_web_ajax_post(args: argparse.Namespace) -> dict[str, Any]:
    dry_run = not is_confirmed(args)
    payload = _web_ajax_payload_from_args(args)
    _require_raw_post_payload(args, payload)
    if not dry_run:
        _require_lan_target(args)
    client = _web_client_from_args(args)
    login_result = None
    if not dry_run:
        login_result = _web_login_if_requested(client, args, require_success=True, force_auto=True)
    result = client.raw_post(args.method, payload, dry_run=dry_run)
    if login_result is not None:
        result["login"] = _auth_summary(login_result)
    if dry_run:
        result["plan"] = {
            "execute_requires": ["--confirm"],
            "allow_empty_payload": bool(args.allow_empty_payload),
        }
        result.update(dry_run_notice())
    return result


def command_web_ajax_replay(args: argparse.Namespace) -> dict[str, Any]:
    dry_run = not is_confirmed(args)
    payload = _web_ajax_payload_from_args(args)
    catalog = read_catalog(Path(args.catalog).expanduser())
    try:
        entry = find_catalog_method(catalog, args.method)
    except KeyError as exc:
        raise CliError(f"catalog 中没有 method: {args.method}") from exc
    _require_raw_post_payload(args, payload)
    if not dry_run:
        _require_lan_target(args)
    client = _web_client_from_args(args)
    login_result = None
    if not dry_run:
        login_result = _web_login_if_requested(client, args, require_success=True, force_auto=True)
    result = client.raw_post(args.method, payload, dry_run=dry_run)
    result["catalog"] = {
        "method": entry.get("method"),
        "kind": entry.get("kind"),
        "http_methods": entry.get("http_methods", []),
        "params": entry.get("params", []),
        "verify_candidates": entry.get("verify_candidates", []),
    }
    if login_result is not None:
        result["login"] = _auth_summary(login_result)
    if dry_run:
        result["plan"] = {
            "execute_requires": ["--confirm"],
            "allow_empty_payload": bool(args.allow_empty_payload),
        }
        result.update(dry_run_notice())
        return result
    result["verify"] = _run_replay_verify(client, entry)
    return result


def command_web_discover_static(args: argparse.Namespace) -> dict[str, Any]:
    catalog = static_catalog(Path(args.root).expanduser(), ajax_path=args.ajax_path)
    return write_catalog(catalog, Path(args.output).expanduser() if args.output else None)


def command_web_discover_merge(args: argparse.Namespace) -> dict[str, Any]:
    catalogs = [read_catalog(Path(path).expanduser()) for path in args.input]
    catalog = merge_catalogs(catalogs)
    return write_catalog(catalog, Path(args.output).expanduser() if args.output else None)


def command_web_discover_live(args: argparse.Namespace) -> dict[str, Any]:
    _require_lan_target(args)
    client = _web_client_from_args(args)
    base_url = _web_base_url_from_args(args)
    unauth = crawl_same_origin_resources(
        client.session,
        base_url,
        timeout=args.timeout,
        max_resources=args.max_resources,
        max_depth=args.max_depth,
        max_file_size=args.max_file_size,
    )
    auth = _web_login_if_requested(client, args, require_success=False, force_auto=True)
    authed = crawl_same_origin_resources(
        client.session,
        base_url,
        timeout=args.timeout,
        max_resources=args.max_resources,
        max_depth=args.max_depth,
        max_file_size=args.max_file_size,
    )
    catalog = merge_catalogs(
        [
            {
                **empty_catalog(
                    base_url=base_url,
                    ajax_path=args.ajax_path,
                    discovery_mode="live",
                    auth=_auth_summary(auth),
                ),
                "resources": unauth["resources"],
                "skipped_resources": unauth["skipped_resources"],
                "methods": unauth["methods"],
            },
            {
                **empty_catalog(
                    base_url=base_url,
                    ajax_path=args.ajax_path,
                    discovery_mode="live",
                    auth=_auth_summary(auth),
                ),
                "resources": authed["resources"],
                "skipped_resources": authed["skipped_resources"],
                "methods": authed["methods"],
            },
        ]
    )
    catalog["discovery"] = {
        "mode": "live",
        "max_resources": args.max_resources,
        "max_depth": args.max_depth,
        "max_file_size": args.max_file_size,
    }
    probe_read_methods(client, catalog, save_samples=args.save_samples)
    return write_catalog(catalog, Path(args.output).expanduser() if args.output else None)


def _web_ajax_payload_from_args(args: argparse.Namespace) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if args.json_payload:
        payload.update(parse_json_object(args.json_payload))
    payload.update(parse_kv(args.param))
    return payload


def _require_raw_post_payload(args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if payload or getattr(args, "allow_empty_payload", False):
        return
    raise CliError("Web AJAX POST 需要 --param/--json-payload；空 payload 需显式 --allow-empty-payload")


def _run_replay_verify(client: WebAjaxClient, entry: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for method in entry.get("verify_candidates", []):
        if not isinstance(method, str) or not method:
            continue
        try:
            raw = client.ajax_get(method)
        except FHToolError as exc:
            results.append({"method": method, "ok": False, "error": str(exc)})
            continue
        results.append(
            {
                "method": method,
                "ok": bool(raw.get("ok")),
                "status_code": raw.get("status_code"),
                "content_type": raw.get("content_type"),
                "sessionid_present": bool(raw.get("sessionid_present")),
                "response": raw.get("response"),
            }
        )
    return results


def _auth_summary(auth: dict[str, Any] | None) -> dict[str, Any]:
    if not auth:
        return {
            "attempted": False,
            "username": DEFAULT_WEB_USERNAME,
            "password_source": "auto",
            "sessionid_present": False,
        }
    summary = {
        "attempted": bool(auth.get("attempted", True)),
        "username": auth.get("username") or DEFAULT_WEB_USERNAME,
        "password_source": auth.get("password_source", "auto"),
        "sessionid_present": bool(auth.get("sessionid_present")),
    }
    if auth.get("ok") is not None:
        summary["ok"] = bool(auth.get("ok"))
    if auth.get("error"):
        summary["error"] = auth["error"]
    if auth.get("login_result") is not None:
        summary["login_result"] = auth["login_result"]
    return summary


def _web_read_login(client: WebAjaxClient, args: argparse.Namespace) -> dict[str, Any] | None:
    return _web_login_if_requested(client, args, require_success=False, force_auto=True)


def _require_lan_target(args: argparse.Namespace) -> None:
    ip, _ip_source = resolve_ip(args)
    address = ipaddress.ip_address(ip)
    if address.is_private or address.is_loopback or address.is_link_local:
        return
    raise CliError("Web 后台自动化默认只允许 RFC1918/LAN/loopback 目标")


def command_web_typed(group: str, action: str) -> Callable[[argparse.Namespace], dict[str, Any]]:
    def handler(args: argparse.Namespace) -> dict[str, Any]:
        client = _web_client_from_args(args)
        login_result = _web_read_login(client, args)
        result = client.typed(group, action)
        result["login"] = _auth_summary(login_result)
        return result

    return handler


def command_web_diagnostics_show(args: argparse.Namespace) -> dict[str, Any]:
    client = _web_client_from_args(args)
    login_result = _web_read_login(client, args)
    requested = args.view or [
        "wan",
        "port-mapping",
        "vlanbind",
        "firewall",
        "services",
    ]
    view_actions = {
        "wan": ("wan", "list"),
        "port-mapping": ("port-mapping", "list"),
        "vlanbind": ("vlanbind", "show"),
        "firewall": ("firewall", "show"),
        "services": ("services", "show"),
    }
    views: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name in requested:
        group, action = view_actions[name]
        try:
            views[name] = client.typed(group, action)
        except FHToolError as exc:
            errors[name] = str(exc)
    return {
        "web_diagnostics": {
            "views": views,
            "errors": errors,
            "partial_failure": bool(errors),
            "sessionid_present": bool(client.sessionid),
            "login": _auth_summary(login_result),
        }
    }


def command_web_typed_write(group: str, action: str) -> Callable[[argparse.Namespace], dict[str, Any]]:
    def handler(args: argparse.Namespace) -> dict[str, Any]:
        dry_run = not is_confirmed(args)
        if not dry_run:
            _require_lan_target(args)
        payload = build_web_write_payload(group, action, args)
        if args.json_payload:
            payload.update(parse_json_object(args.json_payload))
        payload.update(parse_kv(args.param))
        if not payload:
            raise CliError("Web AJAX write 需要 typed 参数、--param 或 --json-payload")
        client = _web_client_from_args(args)
        login_result = None
        if not dry_run:
            login_result = _web_login_if_requested(client, args, require_success=True, force_auto=True)
        result = client.typed_write(group, action, payload, dry_run=dry_run)
        if login_result is not None:
            result["login"] = _auth_summary(login_result)
        if dry_run:
            result["plan"] = {"execute_requires": ["--confirm"]}
            result.update(dry_run_notice())
        return result

    return handler


def add_web_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ip", type=normalize_ip, help="网关 IPv4 地址")
    parser.add_argument(
        "--mac",
        help="网关 MAC，供 --password-source admin-account 自动取 Web 密码使用",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout 秒数，默认 5",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"配置文件路径，默认 {DEFAULT_CONFIG_PATH}",
    )
    parser.add_argument("--web-port", type=int, default=80, help="Web port，默认 80")
    parser.add_argument("--https", action="store_true", help="使用 HTTPS")
    parser.add_argument("--ajax-path", default=DEFAULT_AJAX_PATH, help=f"AJAX path，默认 {DEFAULT_AJAX_PATH}")
    parser.add_argument("--sessionid", help="复用已有 Web AJAX sessionid；默认不输出明文")
    parser.add_argument("--username", help=f"Web 登录用户名，默认 {DEFAULT_WEB_USERNAME}")
    parser.add_argument("--password", help="Web 登录密码；输出不会回显明文")
    parser.add_argument("--password-stdin", action="store_true", help="从 stdin 读取 Web 登录密码")
    parser.add_argument(
        "--password-source",
        choices=WEB_PASSWORD_SOURCES,
        default="auto",
        help="未显式提供密码时的来源，默认 auto",
    )
    parser.add_argument(
        "--web-login-port",
        default=DEFAULT_WEB_LOGIN_PORT,
        help=f"Web do_login port 字段，默认 {DEFAULT_WEB_LOGIN_PORT}",
    )
    parser.add_argument("--ask-mac", action="store_true", help="无法自动获取 MAC 时交互式询问；--json 下不会询问")
    parser.add_argument("--backend", choices=["telnet", "local-vm"], default="telnet", help="cfg 密码来源 backend")
    parser.add_argument("--vm-root", default=str(DEFAULT_VM_ROOT), help=f"local-vm 根目录，默认 {DEFAULT_VM_ROOT}")
    parser.add_argument("--telnet-port", type=int, default=23, help="cfg 密码来源 Telnet port，默认 23")
    parser.add_argument("--telnet-username", help="cfg 密码来源 Telnet 用户名")
    parser.add_argument("--telnet-password", help="cfg 密码来源 Telnet 密码")
    parser.add_argument("--telnet-password-stdin", action="store_true", help="从 stdin 读取 cfg 密码来源 Telnet 密码")
    parser.add_argument(
        "--no-derived-credentials",
        action="store_true",
        help="关闭 cfg 密码来源的默认 HG5143F 派生 Telnet 凭据 fallback",
    )
    parser.add_argument("--reveal-secrets", action="store_true", help="输出 Web AJAX sensitive 明文")
    parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")


def add_web_write_options(parser: argparse.ArgumentParser) -> None:
    add_web_options(parser)
    parser.add_argument("--param", action="append", default=[], help="POST 参数 k=v，可重复")
    parser.add_argument("--json-payload", help="POST JSON object，会与 --param 合并")
    add_web_write_confirmation(parser)


def add_web_raw_post_options(parser: argparse.ArgumentParser) -> None:
    add_web_options(parser)
    parser.add_argument("method")
    parser.add_argument("--param", action="append", default=[], help="POST 参数 k=v，可重复")
    parser.add_argument("--json-payload", help="POST JSON object，会与 --param 合并")
    parser.add_argument("--allow-empty-payload", action="store_true", help="允许空 payload POST")
    add_web_write_confirmation(parser)


def add_web_replay_options(parser: argparse.ArgumentParser) -> None:
    add_web_options(parser)
    parser.add_argument("--catalog", required=True, help="web discover 生成的 catalog JSON")
    parser.add_argument("--method", required=True, help="要 replay 的 AJAX method")
    parser.add_argument("--param", action="append", default=[], help="POST 参数 k=v，可重复")
    parser.add_argument("--json-payload", help="POST JSON object，会与 --param 合并")
    parser.add_argument("--allow-empty-payload", action="store_true", help="允许空 payload POST")
    add_web_write_confirmation(parser)


def add_web_discover_options(parser: argparse.ArgumentParser) -> None:
    add_web_options(parser)
    parser.add_argument("--output", help="写入 catalog JSON")


def add_web_crawl_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-resources", type=int, default=DEFAULT_MAX_RESOURCES, help="同源资源抓取上限")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="同源资源抓取深度上限")
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE, help="单资源大小上限 bytes")
    parser.add_argument("--save-samples", action="store_true", help="保存脱敏响应 sample；默认只保存 shape")


def add_web_write_confirmation(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="确认执行 Web 写入；不加时只输出 dry-run 计划",
    )
    parser.add_argument("--yes", dest="deprecated_yes", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--danger", dest="deprecated_danger", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--backup-confirmed", dest="deprecated_backup_confirmed", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--execute", dest="deprecated_execute", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", dest="deprecated_dry_run", action="store_true", help=argparse.SUPPRESS)


def add_web_port_mapping_write_options(parser: argparse.ArgumentParser) -> None:
    typed = parser.add_argument_group("typed port-mapping parameters")
    typed.add_argument(
        "--operation",
        choices=["add", "delete", "enablechange"],
        help="厂商 action：add/delete/enablechange",
    )
    typed.add_argument("--wan-index", type=parse_web_index, help="WAN connection index")
    typed.add_argument("--wan-session-index", type=parse_web_index, help="WAN IP/PPP session index")
    typed.add_argument(
        "--wan-iporppp",
        type=parse_web_wan_iporppp,
        help="WAN 连接类型，支持 1/ip/ipoe 或 2/ppp/pppoe",
    )
    typed.add_argument("--mapping-index", type=parse_web_index, help="已有 port mapping index")
    typed.add_argument("--external-port", type=parse_web_port, help="外部端口，1..65535")
    typed.add_argument("--internal-client", type=parse_web_ipv4, help="内部客户端 IPv4")
    typed.add_argument("--internal-port", type=parse_web_port, help="内部端口，1..65535")
    typed.add_argument("--protocol", type=str.upper, choices=["TCP", "UDP"], help="端口映射协议")
    typed.add_argument("--enabled", type=parse_web_bool, help="enablechange 目标状态，0/1/on/off")


def add_web_vlanbind_write_options(parser: argparse.ArgumentParser) -> None:
    typed = parser.add_argument_group("typed vlanbind parameters")
    typed.add_argument("--operation", choices=["add", "delete"], help="厂商 action：add/delete")
    typed.add_argument("--if-name", type=parse_web_if_name, help="端口 IfName，例如 eth1/pon4/wl0.0")
    typed.add_argument("--vlan-part", type=parse_web_vlan_part, help="USER_VLAN/WAN_VLAN，例如 100/100")
    typed.add_argument("--user-vlan", type=parse_web_vlan, help="用户侧 VLAN，1..4094")
    typed.add_argument("--wan-vlan", type=parse_web_wan_vlan, help="WAN VLAN，-1 或 1..4094")
    typed.add_argument("--wan-index", type=parse_web_index, help="Jiangsu rebind WAN connection index")
    typed.add_argument("--wan-session-index", type=parse_web_index, help="Jiangsu rebind WAN session index")
    typed.add_argument(
        "--wan-iporppp",
        type=parse_web_wan_iporppp_or_null,
        help="Jiangsu rebind WAN 类型，支持 1/ip、2/ppp 或 null",
    )
    typed.add_argument(
        "--laninterface",
        "--lan-interface",
        dest="laninterface",
        help="Jiangsu rebind 后的 LanInterface 字符串",
    )


def add_web_firewall_write_options(parser: argparse.ArgumentParser) -> None:
    typed = parser.add_argument_group("typed firewall parameters")
    typed.add_argument("--enable", dest="firewall_enable", type=parse_web_bool, help="Enable，0/1/on/off")
    typed.add_argument(
        "--level",
        dest="firewall_level",
        choices=["high", "medium", "low"],
        help="LEVEL，high/medium/low",
    )
    typed.add_argument("--dos-enable", type=parse_web_bool, help="DOSFEnable，0/1/on/off")
    typed.add_argument("--ipv6-enable", dest="ipv6_firewall_enable", type=parse_web_bool, help="IPv6FirewallEnable")
    typed.add_argument("--portscan-enable", type=parse_web_bool, help="PORTSCANEnable，部分地区字段")
    typed.add_argument("--bad-packets-enable", type=parse_web_bool, help="BADPACETSFEnable，部分地区字段")


def add_web_services_write_options(parser: argparse.ArgumentParser) -> None:
    typed = parser.add_argument_group("typed services parameters")
    typed.add_argument(
        "--service",
        choices=WEB_SERVICE_NAMES,
        help="服务开关 action，例如 telnet/ftp/dnsrelay/portal/access/scan",
    )
    typed.add_argument("--enabled", type=parse_web_bool, help="服务目标状态，0/1/on/off")
    typed.add_argument("--terminal-number", type=parse_web_terminal_number, help="多终端上网数量，2..254")


def register_web_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    web = subparsers.add_parser("web", help="标准 Web AJAX read-only backend")
    web_subparsers = web.add_subparsers(
        dest="web_command",
        required=True,
        metavar="SUBCOMMAND",
        title="web commands",
    )
    web_login_check = web_subparsers.add_parser("login-check", help="检查 Web session/login surface")
    add_web_options(web_login_check)
    web_login_check.set_defaults(handler=command_web_login_check)
    web_ajax = web_subparsers.add_parser("ajax", help="调用只读 AJAX method")
    web_ajax_subparsers = web_ajax.add_subparsers(
        dest="web_ajax_command",
        required=True,
        metavar="SUBCOMMAND",
        title="web ajax commands",
    )
    web_ajax_get = web_ajax_subparsers.add_parser("get", help="GET ajaxmethod")
    add_web_options(web_ajax_get)
    web_ajax_get.add_argument("method")
    web_ajax_get.set_defaults(handler=command_web_ajax_get)
    web_ajax_post = web_ajax_subparsers.add_parser("post", help="dry-run 或执行任意 AJAX POST")
    add_web_raw_post_options(web_ajax_post)
    web_ajax_post.set_defaults(handler=command_web_ajax_post)
    web_ajax_replay = web_ajax_subparsers.add_parser("replay", help="从 catalog dry-run 或执行 AJAX POST")
    add_web_replay_options(web_ajax_replay)
    web_ajax_replay.set_defaults(handler=command_web_ajax_replay)
    web_discover = web_subparsers.add_parser("discover", help="发现 Web AJAX 后台接口 catalog")
    web_discover_subparsers = web_discover.add_subparsers(
        dest="web_discover_command",
        required=True,
        metavar="SUBCOMMAND",
        title="web discover commands",
    )
    web_discover_live = web_discover_subparsers.add_parser("live", help="连接实机后台并生成 AJAX catalog")
    add_web_discover_options(web_discover_live)
    add_web_crawl_options(web_discover_live)
    web_discover_live.set_defaults(handler=command_web_discover_live)
    web_discover_static = web_discover_subparsers.add_parser("static", help="扫描 rootfs/备份目录生成 AJAX catalog")
    web_discover_static.add_argument("--root", required=True, help="rootfs 或备份目录")
    web_discover_static.add_argument("--ajax-path", default=DEFAULT_AJAX_PATH, help=f"AJAX path，默认 {DEFAULT_AJAX_PATH}")
    web_discover_static.add_argument("--output", help="写入 catalog JSON")
    web_discover_static.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    web_discover_static.set_defaults(handler=command_web_discover_static)
    web_discover_merge = web_discover_subparsers.add_parser("merge", help="合并多个 AJAX catalog")
    web_discover_merge.add_argument("--input", action="append", required=True, help="输入 catalog JSON，可重复")
    web_discover_merge.add_argument("--output", help="写入合并后的 catalog JSON")
    web_discover_merge.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    web_discover_merge.set_defaults(handler=command_web_discover_merge)
    web_diagnostics = web_subparsers.add_parser("diagnostics", help="Web AJAX read-only diagnostics fusion")
    web_diagnostics_subparsers = web_diagnostics.add_subparsers(
        dest="web_diagnostics_command",
        required=True,
        metavar="SUBCOMMAND",
        title="web diagnostics commands",
    )
    web_diagnostics_show = web_diagnostics_subparsers.add_parser(
        "show",
        help="聚合 Web WAN/port-mapping/vlanbind/firewall/services 只读视图",
    )
    add_web_options(web_diagnostics_show)
    web_diagnostics_show.add_argument(
        "--view",
        action="append",
        choices=["wan", "port-mapping", "vlanbind", "firewall", "services"],
        help="只读取指定 view，可重复；默认读取全部",
    )
    web_diagnostics_show.set_defaults(handler=command_web_diagnostics_show)
    web_wan = web_subparsers.add_parser("wan", help="Web WAN read-only views")
    web_wan_subparsers = web_wan.add_subparsers(
        dest="web_wan_command",
        required=True,
        metavar="SUBCOMMAND",
        title="web wan commands",
    )
    web_wan_list = web_wan_subparsers.add_parser("list", help="读取 Web WAN list")
    add_web_options(web_wan_list)
    web_wan_list.set_defaults(handler=command_web_typed("wan", "list"))
    web_port_mapping = web_subparsers.add_parser("port-mapping", help="Web port mapping read-only views")
    web_port_mapping_subparsers = web_port_mapping.add_subparsers(
        dest="web_port_mapping_command",
        required=True,
        metavar="SUBCOMMAND",
        title="web port-mapping commands",
    )
    web_port_mapping_list = web_port_mapping_subparsers.add_parser(
        "list",
        help="读取 Web port mapping list",
    )
    add_web_options(web_port_mapping_list)
    web_port_mapping_list.set_defaults(handler=command_web_typed("port-mapping", "list"))
    web_port_mapping_set = web_port_mapping_subparsers.add_parser(
        "set",
        help="dry-run 或执行 Web port mapping POST",
    )
    add_web_write_options(web_port_mapping_set)
    add_web_port_mapping_write_options(web_port_mapping_set)
    web_port_mapping_set.set_defaults(
        handler=command_web_typed_write("port-mapping", "set"),
        execute=False,
    )
    web_vlanbind = web_subparsers.add_parser("vlanbind", help="Web vlanbind read-only views")
    web_vlanbind_subparsers = web_vlanbind.add_subparsers(
        dest="web_vlanbind_command",
        required=True,
        metavar="SUBCOMMAND",
        title="web vlanbind commands",
    )
    web_vlanbind_show = web_vlanbind_subparsers.add_parser("show", help="读取 Web vlanbind 状态")
    add_web_options(web_vlanbind_show)
    web_vlanbind_show.set_defaults(handler=command_web_typed("vlanbind", "show"))
    web_vlanbind_set = web_vlanbind_subparsers.add_parser(
        "set",
        help="dry-run 或执行 Web vlanbind POST",
    )
    add_web_write_options(web_vlanbind_set)
    add_web_vlanbind_write_options(web_vlanbind_set)
    web_vlanbind_set.set_defaults(
        handler=command_web_typed_write("vlanbind", "set"),
        execute=False,
    )
    for group, help_text, command_help in [
        ("tr069", "Web TR-069 read-only views", "读取 Web TR-069 状态"),
        ("services", "Web services read-only views", "读取 Web service switches"),
        ("firewall", "Web firewall read-only views", "读取 Web firewall 状态"),
    ]:
        group_parser = web_subparsers.add_parser(group, help=help_text)
        group_subparsers = group_parser.add_subparsers(
            dest=f"web_{group}_command",
            required=True,
            metavar="SUBCOMMAND",
            title=f"web {group} commands",
        )
        show_parser = group_subparsers.add_parser("show", help=command_help)
        add_web_options(show_parser)
        show_parser.set_defaults(handler=command_web_typed(group, "show"))
        if group in {"services", "firewall"}:
            set_parser = group_subparsers.add_parser(
                "set",
                help=f"dry-run 或执行 Web {group} POST",
            )
            add_web_write_options(set_parser)
            if group == "firewall":
                add_web_firewall_write_options(set_parser)
            else:
                add_web_services_write_options(set_parser)
            set_parser.set_defaults(
                handler=command_web_typed_write(group, "set"),
                execute=False,
            )
