from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from typing import Any

from ..argparse_utils import parse_json_object, parse_kv
from ..backends.web_ajax import DEFAULT_AJAX_PATH, DEFAULT_WEB_LOGIN_PORT, WebAjaxClient
from ..config_store import DEFAULT_CONFIG_PATH, normalize_ip, resolve_ip
from ..errors import CliError, FHToolError
from ..risk import require_danger
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


def _web_login_if_requested(
    client: WebAjaxClient,
    args: argparse.Namespace,
    *,
    require_success: bool = True,
) -> dict[str, Any] | None:
    username = getattr(args, "username", None)
    password = _web_password_from_args(args)
    if username or password is not None:
        if not username or password is None:
            raise CliError("Web login 需要同时提供 --username 和 --password/--password-stdin")
        result = client.login(
            username,
            password,
            port=getattr(args, "web_login_port", DEFAULT_WEB_LOGIN_PORT),
        )
        if require_success and not result["ok"]:
            raise CliError(f"Web login failed: login_result={result.get('login_result')}")
        return result
    return None


def _web_password_from_args(args: argparse.Namespace) -> str | None:
    has_password = getattr(args, "password", None) is not None
    has_stdin = getattr(args, "password_stdin", False)
    if has_password and has_stdin:
        raise CliError("Web login 只能选择 --password 或 --password-stdin")
    if has_stdin:
        return sys.stdin.readline().rstrip("\n")
    if has_password:
        return str(args.password)
    return None


def command_web_login_check(args: argparse.Namespace) -> dict[str, Any]:
    client = _web_client_from_args(args)
    login_result = _web_login_if_requested(client, args, require_success=False)
    check_result = client.login_check()
    if login_result is not None:
        return {"login": login_result, "check": check_result}
    return check_result


def command_web_ajax_get(args: argparse.Namespace) -> dict[str, Any]:
    client = _web_client_from_args(args)
    _web_login_if_requested(client, args)
    return client.ajax_get(args.method)


def command_web_typed(group: str, action: str) -> Callable[[argparse.Namespace], dict[str, Any]]:
    def handler(args: argparse.Namespace) -> dict[str, Any]:
        client = _web_client_from_args(args)
        _web_login_if_requested(client, args)
        return client.typed(group, action)

    return handler


def command_web_diagnostics_show(args: argparse.Namespace) -> dict[str, Any]:
    client = _web_client_from_args(args)
    _web_login_if_requested(client, args)
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
        }
    }


def command_web_typed_write(group: str, action: str) -> Callable[[argparse.Namespace], dict[str, Any]]:
    def handler(args: argparse.Namespace) -> dict[str, Any]:
        dry_run = not args.execute
        if not dry_run:
            require_danger(args, f"web {group} {action} 会修改 Web AJAX 配置")
            _require_backup_confirmed(args, f"web {group} {action}")
        payload = build_web_write_payload(group, action, args)
        if args.json_payload:
            payload.update(parse_json_object(args.json_payload))
        payload.update(parse_kv(args.param))
        if not payload:
            raise CliError("Web AJAX write 需要 typed 参数、--param 或 --json-payload")
        client = _web_client_from_args(args)
        _web_login_if_requested(client, args)
        return client.typed_write(group, action, payload, dry_run=dry_run)

    return handler


def _require_backup_confirmed(args: argparse.Namespace, message: str) -> None:
    if not getattr(args, "backup_confirmed", False):
        raise CliError(f"{message} 需要先完成备份，并传 --backup-confirmed")


def add_web_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ip", type=normalize_ip, help="网关 IPv4 地址")
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
    parser.add_argument("--username", help="Web 登录用户名；需同时提供密码输入")
    parser.add_argument("--password", help="Web 登录密码；输出不会回显明文")
    parser.add_argument("--password-stdin", action="store_true", help="从 stdin 读取 Web 登录密码")
    parser.add_argument(
        "--web-login-port",
        default=DEFAULT_WEB_LOGIN_PORT,
        help=f"Web do_login port 字段，默认 {DEFAULT_WEB_LOGIN_PORT}",
    )
    parser.add_argument("--reveal-secrets", action="store_true", help="输出 Web AJAX sensitive 明文")
    parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")


def add_web_write_options(parser: argparse.ArgumentParser) -> None:
    add_web_options(parser)
    parser.add_argument("--param", action="append", default=[], help="POST 参数 k=v，可重复")
    parser.add_argument("--json-payload", help="POST JSON object，会与 --param 合并")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        dest="execute",
        action="store_false",
        help="只显示 POST 计划；默认行为",
    )
    mode.add_argument("--execute", action="store_true", help="执行 Web AJAX POST")
    add_danger(parser)
    parser.add_argument("--backup-confirmed", action="store_true", help="确认已完成备份")
    parser.set_defaults(execute=False)


def add_danger(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--yes", action="store_true", help="确认执行写入动作")
    parser.add_argument("--danger", action="store_true", help="确认该动作属于高风险")


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
