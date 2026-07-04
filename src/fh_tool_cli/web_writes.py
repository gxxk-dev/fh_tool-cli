from __future__ import annotations

import argparse
import ipaddress
import re
from typing import Any

from .errors import CliError

WEB_SERVICE_NAMES = (
    "ftp",
    "telnet",
    "dnsrelay",
    "portal",
    "scan",
    "access",
    "force",
    "led_control",
)

_IF_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_OPTION_LABELS = {
    "bad_packets_enable": "--bad-packets-enable",
    "dos_enable": "--dos-enable",
    "external_port": "--external-port",
    "firewall_enable": "--enable",
    "firewall_level": "--level",
    "if_name": "--if-name",
    "internal_client": "--internal-client",
    "internal_port": "--internal-port",
    "ipv6_firewall_enable": "--ipv6-enable",
    "mapping_index": "--mapping-index",
    "portscan_enable": "--portscan-enable",
    "terminal_number": "--terminal-number",
    "user_vlan": "--user-vlan",
    "vlan_part": "--vlan-part",
    "wan_index": "--wan-index",
    "wan_iporppp": "--wan-iporppp",
    "wan_session_index": "--wan-session-index",
    "wan_vlan": "--wan-vlan",
}


def _parse_int_range(value: str, *, name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} 必须是整数: {value}") from exc
    if not minimum <= parsed <= maximum:
        raise argparse.ArgumentTypeError(f"{name} 超出范围 {minimum}..{maximum}: {value}")
    return parsed


def parse_web_index(value: str) -> int:
    return _parse_int_range(value, name="index", minimum=0, maximum=65535)


def parse_web_port(value: str) -> int:
    return _parse_int_range(value, name="port", minimum=1, maximum=65535)


def parse_web_vlan(value: str) -> int:
    return _parse_int_range(value, name="VLAN", minimum=1, maximum=4094)


def parse_web_wan_vlan(value: str) -> int:
    return _parse_int_range(value, name="WAN VLAN", minimum=-1, maximum=4094)


def parse_web_terminal_number(value: str) -> int:
    return _parse_int_range(value, name="terminal_number", minimum=2, maximum=254)


def parse_web_bool(value: str) -> int:
    lowered = value.strip().lower()
    truthy = {"1", "true", "yes", "y", "on", "enable", "enabled"}
    falsy = {"0", "false", "no", "n", "off", "disable", "disabled"}
    if lowered in truthy:
        return 1
    if lowered in falsy:
        return 0
    raise argparse.ArgumentTypeError(f"boolean 必须是 0/1/on/off/true/false: {value}")


def parse_web_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"IPv4 地址不合法: {value}") from exc
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_reserved
        or str(address) == "255.255.255.255"
    ):
        raise argparse.ArgumentTypeError(f"IPv4 地址不能作为内部客户端: {value}")
    return str(address)


def parse_web_if_name(value: str) -> str:
    if not value or not _IF_NAME_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(f"IfName 不合法: {value}")
    return value


def parse_web_vlan_part(value: str) -> str:
    parts = value.split("/")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("vlanPart 必须是 USER_VLAN/WAN_VLAN 格式")
    user_vlan = _parse_int_range(parts[0], name="USER VLAN", minimum=1, maximum=4094)
    wan_vlan = _parse_int_range(parts[1], name="WAN VLAN", minimum=-1, maximum=4094)
    return f"{user_vlan}/{wan_vlan}"


def parse_web_wan_iporppp(value: str) -> str:
    normalized = _normalize_wan_iporppp(value, allow_null=False)
    assert normalized is not None
    return normalized


def parse_web_wan_iporppp_or_null(value: str) -> str:
    normalized = _normalize_wan_iporppp(value, allow_null=True)
    assert normalized is not None
    return normalized


def _normalize_wan_iporppp(value: str | int, *, allow_null: bool) -> str | None:
    raw = str(value).strip()
    aliases = {
        "1": "1",
        "ip": "1",
        "ipoe": "1",
        "wanip": "1",
        "wanipconnection": "1",
        "2": "2",
        "ppp": "2",
        "pppoe": "2",
        "wanppp": "2",
        "wanpppconnection": "2",
    }
    lowered = raw.lower()
    if allow_null and lowered == "null":
        return "null"
    if lowered in aliases:
        return aliases[lowered]
    choices = "1/2/ip/ppp"
    if allow_null:
        choices += "/null"
    raise argparse.ArgumentTypeError(f"wan_iporppp 必须是 {choices}: {value}")


def build_web_write_payload(group: str, action: str, args: argparse.Namespace) -> dict[str, Any]:
    if action != "set":
        return {}
    if group == "port-mapping":
        return _build_port_mapping_payload(args)
    if group == "vlanbind":
        return _build_vlanbind_payload(args)
    if group == "firewall":
        return _build_firewall_payload(args)
    if group == "services":
        return _build_services_payload(args)
    return {}


def _has_any(args: argparse.Namespace, names: tuple[str, ...]) -> bool:
    return any(getattr(args, name, None) is not None for name in names)


def _option_label(name: str) -> str:
    return _OPTION_LABELS.get(name, f"--{name.replace('_', '-')}")


def _require_fields(args: argparse.Namespace, names: tuple[str, ...], context: str) -> None:
    missing = [_option_label(name) for name in names if getattr(args, name, None) is None]
    if missing:
        raise CliError(f"{context} 缺少 typed 参数: {', '.join(missing)}")


def _reject_fields(args: argparse.Namespace, names: tuple[str, ...], context: str) -> None:
    present = [_option_label(name) for name in names if getattr(args, name, None) is not None]
    if present:
        raise CliError(f"{context} 不接受 typed 参数: {', '.join(present)}")


def _build_port_mapping_payload(args: argparse.Namespace) -> dict[str, Any]:
    fields = (
        "operation",
        "wan_index",
        "wan_session_index",
        "wan_iporppp",
        "external_port",
        "protocol",
        "internal_client",
        "internal_port",
        "mapping_index",
        "enabled",
    )
    if not _has_any(args, fields):
        return {}

    operation = getattr(args, "operation", None)
    if operation is None:
        raise CliError("web port-mapping set typed 参数需要 --operation")

    base_fields = ("wan_index", "wan_session_index", "wan_iporppp")
    payload: dict[str, Any] = {
        "action": operation,
    }
    if operation == "add":
        _require_fields(
            args,
            base_fields + ("external_port", "protocol", "internal_client", "internal_port"),
            "web port-mapping set --operation add",
        )
        _reject_fields(args, ("mapping_index", "enabled"), "web port-mapping set --operation add")
        payload.update(
            {
                "wan_index": str(args.wan_index),
                "wan_session_index": str(args.wan_session_index),
                "wan_iporppp": str(args.wan_iporppp),
                "ExternalPort": str(args.external_port),
                "PortMappingProtocol": str(args.protocol),
                "InternalClient": str(args.internal_client),
                "InternalPort": str(args.internal_port),
            }
        )
        return payload

    if operation == "delete":
        _require_fields(
            args,
            base_fields + ("mapping_index",),
            "web port-mapping set --operation delete",
        )
        _reject_fields(
            args,
            ("external_port", "protocol", "internal_client", "internal_port", "enabled"),
            "web port-mapping set --operation delete",
        )
        payload.update(
            {
                "wan_index": str(args.wan_index),
                "wan_session_index": str(args.wan_session_index),
                "mapping_index": str(args.mapping_index),
                "wan_iporppp": str(args.wan_iporppp),
            }
        )
        return payload

    if operation == "enablechange":
        _require_fields(
            args,
            base_fields + ("mapping_index", "enabled"),
            "web port-mapping set --operation enablechange",
        )
        _reject_fields(
            args,
            ("external_port", "protocol", "internal_client", "internal_port"),
            "web port-mapping set --operation enablechange",
        )
        payload.update(
            {
                "wan_index": str(args.wan_index),
                "wan_session_index": str(args.wan_session_index),
                "mapping_index": str(args.mapping_index),
                "PortMappingEnabled": str(args.enabled),
                "wan_iporppp": str(args.wan_iporppp),
            }
        )
        return payload

    raise CliError(f"不支持的 port-mapping operation: {operation}")


def _build_vlanbind_payload(args: argparse.Namespace) -> dict[str, Any]:
    fields = (
        "operation",
        "if_name",
        "vlan_part",
        "user_vlan",
        "wan_vlan",
        "wan_index",
        "wan_session_index",
        "wan_iporppp",
        "laninterface",
    )
    if not _has_any(args, fields):
        return {}

    operation = getattr(args, "operation", None)
    if operation is None:
        raise CliError("web vlanbind set typed 参数需要 --operation")
    if getattr(args, "vlan_part", None) is not None and (
        getattr(args, "user_vlan", None) is not None or getattr(args, "wan_vlan", None) is not None
    ):
        raise CliError("web vlanbind set 只能二选一：--vlan-part 或 --user-vlan/--wan-vlan")

    vlan_part = getattr(args, "vlan_part", None)
    if vlan_part is None and (
        getattr(args, "user_vlan", None) is not None or getattr(args, "wan_vlan", None) is not None
    ):
        _require_fields(args, ("user_vlan", "wan_vlan"), "web vlanbind set")
        vlan_part = f"{args.user_vlan}/{args.wan_vlan}"

    _require_fields(args, ("if_name",), f"web vlanbind set --operation {operation}")
    if vlan_part is None:
        raise CliError("web vlanbind set 缺少 typed 参数: --vlan-part 或 --user-vlan/--wan-vlan")

    payload: dict[str, Any] = {
        "action": operation,
        "IfName": args.if_name,
        "vlanPart": vlan_part,
    }
    rebind_fields = ("wan_index", "wan_session_index", "wan_iporppp", "laninterface")
    if operation == "add":
        if _has_any(args, rebind_fields):
            _require_fields(args, rebind_fields, "web vlanbind set --operation add Jiangsu WAN rebind")
            payload.update(
                {
                    "wan_index": str(args.wan_index),
                    "wan_session_index": str(args.wan_session_index),
                    "wan_iporppp": str(args.wan_iporppp),
                    "laninterface": str(args.laninterface),
                }
            )
        return payload

    if operation == "delete":
        _reject_fields(args, rebind_fields, "web vlanbind set --operation delete")
        return payload

    raise CliError(f"不支持的 vlanbind operation: {operation}")


def _build_firewall_payload(args: argparse.Namespace) -> dict[str, Any]:
    fields = (
        "firewall_enable",
        "firewall_level",
        "dos_enable",
        "ipv6_firewall_enable",
        "portscan_enable",
        "bad_packets_enable",
    )
    if not _has_any(args, fields):
        return {}

    required = ("firewall_enable", "firewall_level", "dos_enable", "ipv6_firewall_enable")
    _require_fields(args, required, "web firewall set")
    payload: dict[str, Any] = {
        "Enable": args.firewall_enable,
        "LEVEL": args.firewall_level,
        "DOSFEnable": args.dos_enable,
        "IPv6FirewallEnable": args.ipv6_firewall_enable,
    }
    if getattr(args, "portscan_enable", None) is not None:
        payload["PORTSCANEnable"] = args.portscan_enable
    if getattr(args, "bad_packets_enable", None) is not None:
        payload["BADPACETSFEnable"] = args.bad_packets_enable
    return payload


def _build_services_payload(args: argparse.Namespace) -> dict[str, Any]:
    fields = ("service", "enabled", "terminal_number")
    if not _has_any(args, fields):
        return {}

    service = getattr(args, "service", None)
    enabled = getattr(args, "enabled", None)
    terminal_number = getattr(args, "terminal_number", None)

    if terminal_number is not None:
        if service is not None or enabled is not None:
            raise CliError("web services set --terminal-number 不能和 --service/--enabled 同时使用")
        return {
            "action": "terminal_number",
            "terminal_number": str(terminal_number),
        }

    if service is None:
        raise CliError("web services set typed 参数需要 --service")
    if enabled is None:
        raise CliError("web services set --service 需要 --enabled")
    return {
        "action": service,
        service: str(enabled),
    }
