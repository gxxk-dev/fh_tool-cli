from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .backends.cfg_cmd import CfgCmdBackend, cfg_read_risk, redact_cfg_value
from .remote import collect_cfg_status

PON_PATHS = {
    "type": "InternetGatewayDevice.X_CT-COM_PON.Type",
    "register_status": "InternetGatewayDevice.X_CT-COM_PON.RegisterStatus",
    "rx_power": "InternetGatewayDevice.X_CT-COM_PON.RXPower",
    "tx_power": "InternetGatewayDevice.X_CT-COM_PON.TXPower",
    "loid": "InternetGatewayDevice.X_CT-COM_PON.LOID",
}

WAN_PATHS = {
    "service_list": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.ServiceList",
    "connection_type": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.ConnectionType",
    "vlan": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.VLANID",
    "ip_mode": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.IPMode",
    "nat": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.NATEnabled",
    "pppoe_username": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.PPPoE.Username",
}

WAN_COLLECTION_PATH = "InternetGatewayDevice.WANDevice.1.WANConnectionDevice"

VLAN_PATHS = {
    "wan_vlan": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.VLANID",
    "tr069_vlan": "InternetGatewayDevice.ManagementServer.X_CT-COM_VLANID",
}

IPV6_PATHS = {
    "wan_ipv6_enable": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.X_CT-COM_IPv6Enable",
    "prefix_delegation": "InternetGatewayDevice.LANDevice.1.X_CT-COM_IPv6PrefixDelegation",
}

FIREWALL_PATHS = {
    "firewall_enable": "InternetGatewayDevice.Firewall.Enable",
    "dos_enable": "InternetGatewayDevice.Firewall.X_CT-COM_DosEnable",
    "upnp_enable": "InternetGatewayDevice.X_CT-COM_UPnP.Enable",
    "igmp_enable": "InternetGatewayDevice.X_CT-COM_IGMP.Enable",
}

PON_CANDIDATES = {
    "type": [
        "InternetGatewayDevice.X_CT-COM_PON.Type",
        "InternetGatewayDevice.DeviceInfo.X_CT-COM_PONType",
        "InternetGatewayDevice.DeviceInfo.X_CT-COM_PonMode",
        "InternetGatewayDevice.DeviceInfo.X_FH_PonMode",
    ],
    "register_status": [
        "InternetGatewayDevice.X_CT-COM_PON.RegisterStatus",
        "InternetGatewayDevice.WANDevice.1.X_CT-COM_GponInterfaceConfig.Status",
        "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.Status",
        "InternetGatewayDevice.X_FH_PON_MANAGE.reginfo.loid_reg_ok",
        "InternetGatewayDevice.ManagementServer.X_FH_ITMSLOID_Reg_Status",
    ],
    "rx_power": [
        "InternetGatewayDevice.X_CT-COM_PON.RXPower",
        "InternetGatewayDevice.WANDevice.1.X_CT-COM_GponInterfaceConfig.RXPower",
        "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.RXPower",
    ],
    "tx_power": [
        "InternetGatewayDevice.X_CT-COM_PON.TXPower",
        "InternetGatewayDevice.WANDevice.1.X_CT-COM_GponInterfaceConfig.TXPower",
        "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.TXPower",
    ],
    "loid": [
        "InternetGatewayDevice.X_CT-COM_PON.LOID",
        "InternetGatewayDevice.X_FH_PON_MANAGE.reginfo.legal_loid",
        "InternetGatewayDevice.ManagementServer.X_FH_ITMSLOID_Username",
    ],
}

WAN_INSTANCE_IDS = tuple(range(1, 17))
WAN_CONNECTION_TYPES = ("WANPPPConnection", "WANIPConnection")
WAN_VENDOR_PREFIXES = ("X_CT-COM", "X_CT111COM")

FIREWALL_CANDIDATES = {
    "firewall_enable": [
        "InternetGatewayDevice.Firewall.Enable",
        "InternetGatewayDevice.X_CT-COM_Firewall.Enable",
    ],
    "dos_enable": [
        "InternetGatewayDevice.Firewall.X_CT-COM_DosEnable",
        "InternetGatewayDevice.Firewall.X_CT111COM_DosEnable",
    ],
    "upnp_enable": [
        "InternetGatewayDevice.X_CT-COM_UPnP.Enable",
        "InternetGatewayDevice.X_CT-COM_UPNP.Enable",
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_UPnP.Enable",
    ],
    "igmp_enable": [
        "InternetGatewayDevice.X_CT-COM_IGMP.Enable",
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_IGMP.Enable",
    ],
    "alg_enable": [
        "InternetGatewayDevice.X_CT-COM_ALG.Enable",
        "InternetGatewayDevice.Services.X_CT-COM_ALG.Enable",
        "InternetGatewayDevice.X_CT-COM_ALG.SIPEnable",
    ],
    "lan_dhcp_enable": [
        "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPServerEnable",
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_DHCPServer.Enable",
    ],
}

IPV6_CANDIDATES = {
    "wan_ipv6_enable": [
        "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.X_CT-COM_IPv6Enable",
        "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.X_CT111COM_IPv6Enable",
    ],
    "prefix_delegation": [
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_IPv6PrefixDelegation",
        "InternetGatewayDevice.LANDevice.1.X_CT111COM_IPv6PrefixDelegation",
        "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.X_CT-COM_IPv6PrefixDelegation",
    ],
    "lan_ipv6_address": [
        "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPv6InterfaceAddress",
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_IPv6LAN.LocalAddress",
    ],
    "dhcpv6_server": [
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_DHCPv6.ServerEnable",
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_DHCPV6S.Enable",
    ],
    "router_advertisement": [
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_RouterAdvertisement.Enable",
        "InternetGatewayDevice.LANDevice.1.X_CT-COM_RA.Enable",
    ],
}


def pon_status(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    status = collect_candidate_status(
        backend,
        PON_CANDIDATES,
        reveal_secrets=reveal_secrets,
    )
    if not status["values"] and status["errors"]:
        status["legacy"] = collect_cfg_status(
            backend,
            PON_PATHS,
            reveal_secrets=reveal_secrets,
        )
    return {"pon": status}


def wan_list(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    empty_collection = _empty_wan_collection_probe(
        backend,
        reveal_secrets=reveal_secrets,
    )
    if empty_collection is not None:
        return {
            "wan": {
                "connections": [],
                "connection_count": 0,
                "scanned_wan_connection_devices": [],
                "partial_failure": False,
                "errors": {},
                "collection_probe": empty_collection,
                "scan_skipped": "empty_wan_collection",
            }
        }

    connections = []
    discovery_errors: dict[str, Any] = {}
    for instance in WAN_INSTANCE_IDS:
        connection = _read_wan_instance(
            backend,
            instance,
            reveal_secrets=reveal_secrets,
        )
        if _wan_connection_has_values(connection):
            connections.append(connection)
        elif connection["errors"]:
            discovery_errors[str(instance)] = connection["errors"]

    result: dict[str, Any] = {
        "connections": connections,
        "connection_count": len(connections),
        "scanned_wan_connection_devices": list(WAN_INSTANCE_IDS),
        "partial_failure": bool(discovery_errors and not connections),
        "errors": {} if connections else discovery_errors,
    }
    if not connections:
        result["legacy"] = collect_cfg_status(
            backend,
            WAN_PATHS,
            reveal_secrets=reveal_secrets,
        )
    return {"wan": result}


def _empty_wan_collection_probe(
    backend: CfgCmdBackend,
    *,
    reveal_secrets: bool,
) -> dict[str, Any] | None:
    if not getattr(backend, "expensive_missing_paths", False):
        return None
    try:
        raw_value = backend.get(WAN_COLLECTION_PATH)
    except Exception:  # noqa: BLE001 - fall back to regular discovery if probe fails.
        return None
    if raw_value != "":
        return None
    rendered, redacted = _redact_diagnostic_value(
        WAN_COLLECTION_PATH,
        raw_value,
        reveal_secrets=reveal_secrets,
    )
    return {
        "path": WAN_COLLECTION_PATH,
        "value": rendered,
        "redacted": redacted,
    }


def vlan_list(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    wan = wan_list(backend, reveal_secrets=reveal_secrets)["wan"]
    vlan_entries = []
    for connection in wan.get("connections", []):
        values = connection["values"]
        vlan = values.get("vlan")
        if vlan or values.get("service_list") or values.get("lan_binding"):
            vlan_entries.append(
                {
                    "wan_connection_device": connection["wan_connection_device"],
                    "name": values.get("name"),
                    "service_list": values.get("service_list"),
                    "connection_type": values.get("connection_type"),
                    "vlan": vlan,
                    "lan_binding": values.get("lan_binding"),
                    "value": vlan,
                }
            )
    tr069 = collect_candidate_status(
        backend,
        {
            "tr069_vlan": [
                "InternetGatewayDevice.ManagementServer.X_CT-COM_VLANID",
                "InternetGatewayDevice.ManagementServer.X_CT111COM_VLANID",
            ]
        },
        reveal_secrets=reveal_secrets,
    )
    return {
        "vlan": {
            "wan": vlan_entries,
            "tr069": tr069,
            "partial_failure": bool(wan.get("partial_failure")),
            "errors": wan.get("errors", {}),
            "legacy": collect_cfg_status(
                backend,
                VLAN_PATHS,
                reveal_secrets=reveal_secrets,
            )
            if not vlan_entries and not tr069["values"]
            else None,
        }
    }


def ipv6_status(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    wan = wan_list(backend, reveal_secrets=reveal_secrets)["wan"]
    ipv6_entries = []
    for connection in wan.get("connections", []):
        values = connection["values"]
        entry = {
            "wan_connection_device": connection["wan_connection_device"],
            "ip_mode": values.get("ip_mode"),
            "prefix_delegation": values.get("prefix_delegation"),
        }
        if entry["ip_mode"] or entry["prefix_delegation"]:
            ipv6_entries.append(entry)
    lan = collect_candidate_status(
        backend,
        IPV6_CANDIDATES,
        reveal_secrets=reveal_secrets,
    )
    return {
        "ipv6": {
            "wan": ipv6_entries,
            "lan": lan,
            "partial_failure": bool(wan.get("partial_failure")),
            "errors": wan.get("errors", {}),
            "legacy": collect_cfg_status(
                backend,
                IPV6_PATHS,
                reveal_secrets=reveal_secrets,
            )
            if not ipv6_entries and not lan["values"]
            else None,
        }
    }


def firewall_status(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    status = collect_candidate_status(
        backend,
        FIREWALL_CANDIDATES,
        reveal_secrets=reveal_secrets,
    )
    if not status["values"]:
        status["legacy"] = collect_cfg_status(
            backend,
            FIREWALL_PATHS,
            reveal_secrets=reveal_secrets,
        )
    return {"firewall": status}


def ip_status(shell_runner: Any) -> dict[str, Any]:
    probes = {
        "addr": _safe_shell_result(shell_runner, "ip addr"),
        "route": _safe_shell_result(shell_runner, "ip route"),
        "dns": _safe_shell_result(shell_runner, "cat /etc/resolv.conf"),
    }
    errors = {
        name: probe["error"]
        for name, probe in probes.items()
        if not probe["ok"]
    }
    return {
        "ip": {
            "probes": probes,
            "partial_failure": bool(errors),
            "errors": errors,
        }
    }


def ports_status(shell_runner: Any) -> dict[str, Any]:
    probe = _safe_shell_result(shell_runner, "netstat -lntup")
    return {
        "ports": {
            "listening": probe,
            "partial_failure": not probe["ok"],
            "errors": {"listening": probe["error"]} if not probe["ok"] else {},
        }
    }


def collect_candidate_status(
    backend: CfgCmdBackend,
    candidates: dict[str, Iterable[str]],
    *,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    errors: dict[str, Any] = {}
    for name, paths in candidates.items():
        result = _first_existing_value(
            backend,
            list(paths),
            reveal_secrets=reveal_secrets,
        )
        if result.get("found"):
            values[name] = result["value"]
        if result.get("errors"):
            errors[name] = result["errors"]
    return {
        "values": values,
        "errors": errors,
        "partial_failure": bool(errors and not values),
    }


def _read_wan_instance(
    backend: CfgCmdBackend,
    instance: int,
    *,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    anchor = _first_existing_value(
        backend,
        _wan_anchor_candidates(instance),
        reveal_secrets=reveal_secrets,
        require_nonempty=True,
    )
    if not anchor.get("found"):
        return {
            "wan_connection_device": instance,
            "values": {},
            "errors": {"discovery": anchor.get("errors", {})},
        }

    candidates = _wan_instance_candidates(instance)
    status = collect_candidate_status(
        backend,
        candidates,
        reveal_secrets=reveal_secrets,
    )
    return {
        "wan_connection_device": instance,
        "values": status["values"],
        "errors": status["errors"],
    }


def _wan_connection_has_values(connection: dict[str, Any]) -> bool:
    values = connection["values"]
    useful_names = {"service_list", "connection_type", "vlan", "ip_mode", "nat", "name"}
    return any(name in values and values[name]["value"] != "" for name in useful_names)


def _wan_instance_candidates(instance: int) -> dict[str, list[str]]:
    base = f"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{instance}"
    ppp = f"{base}.WANPPPConnection.1"
    ip = f"{base}.WANIPConnection.1"
    candidates: dict[str, list[str]] = {
        "name": [f"{ppp}.Name", f"{ip}.Name", f"{base}.Name"],
        "enable": [f"{ppp}.Enable", f"{ip}.Enable", f"{base}.Enable"],
        "service_list": _wan_service_list_candidates(instance),
        "connection_type": [
            f"{ppp}.ConnectionType",
            f"{ip}.ConnectionType",
            f"{base}.ConnectionType",
        ],
        "addressing_type": [f"{ppp}.AddressingType", f"{ip}.AddressingType"],
        "ip_mode": [
            f"{ppp}.X_CT-COM_IPMode",
            f"{ppp}.X_CT111COM_IPMode",
            f"{ppp}.IPMode",
            f"{ip}.X_CT-COM_IPMode",
            f"{ip}.X_CT111COM_IPMode",
            f"{ip}.IPMode",
            f"{base}.IPMode",
        ],
        "nat": [f"{ppp}.NATEnabled", f"{ip}.NATEnabled", f"{base}.NATEnabled"],
        "pppoe_username": [f"{ppp}.Username", f"{ppp}.PPPoE.Username"],
        "lan_binding": [
            f"{ppp}.X_CT-COM_LanInterface",
            f"{ppp}.X_CT111COM_LanInterface",
            f"{ppp}.LanInterface",
            f"{ip}.X_CT-COM_LanInterface",
            f"{ip}.X_CT111COM_LanInterface",
            f"{ip}.LanInterface",
        ],
        "prefix_delegation": [
            f"{ppp}.X_CT-COM_IPv6PrefixDelegationEnabled",
            f"{ppp}.X_CT111COM_IPv6PrefixDelegationEnabled",
            f"{ppp}.X_CT-COM_IPv6Enable",
            f"{ppp}.X_CT111COM_IPv6Enable",
            f"{ip}.X_CT-COM_IPv6PrefixDelegationEnabled",
            f"{ip}.X_CT111COM_IPv6PrefixDelegationEnabled",
            f"{ip}.X_CT-COM_IPv6Enable",
            f"{ip}.X_CT111COM_IPv6Enable",
        ],
    }

    link_config_bases = [
        f"{base}.{prefix}_WANEponLinkConfig"
        for prefix in WAN_VENDOR_PREFIXES
    ] + [
        f"{base}.{prefix}_WANGponLinkConfig"
        for prefix in WAN_VENDOR_PREFIXES
    ]
    candidates["vlan"] = _unique(
        [f"{link_base}.VLANID" for link_base in link_config_bases]
        + [f"{link_base}.VLANIDMark" for link_base in link_config_bases]
        + [f"{base}.VLANID"]
    )
    return candidates


def _wan_anchor_candidates(instance: int) -> list[str]:
    base = f"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{instance}"
    return _unique(
        _wan_service_list_candidates(instance)
        + [
            f"{base}.WANPPPConnection.1.Name",
            f"{base}.WANIPConnection.1.Name",
            f"{base}.WANPPPConnection.1.ConnectionType",
            f"{base}.WANIPConnection.1.ConnectionType",
            f"{base}.Name",
        ]
    )


def _wan_service_list_candidates(instance: int) -> list[str]:
    base = f"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{instance}"
    paths: list[str] = []
    for connection_type in WAN_CONNECTION_TYPES:
        connection_base = f"{base}.{connection_type}.1"
        paths.extend(
            [
                f"{connection_base}.X_CT-COM_ServiceList",
                f"{connection_base}.X_CT111COM_ServiceList",
                f"{connection_base}.ServiceList",
            ]
        )
    paths.append(f"{base}.ServiceList")
    return _unique(paths)


def _first_existing_value(
    backend: CfgCmdBackend,
    paths: list[str],
    *,
    reveal_secrets: bool,
    require_nonempty: bool = False,
) -> dict[str, Any]:
    errors: dict[str, str] = {}
    first_empty: dict[str, Any] | None = None
    for path in paths:
        try:
            raw_value = backend.get(path)
        except Exception as exc:  # noqa: BLE001 - missing cfg paths are report data.
            errors[path] = str(exc)
            continue
        rendered, redacted = _redact_diagnostic_value(
            path,
            raw_value,
            reveal_secrets=reveal_secrets,
        )
        value = {
            "path": path,
            "value": rendered,
            "redacted": redacted,
        }
        if raw_value != "":
            return {"found": True, "value": value, "errors": {}}
        if first_empty is None:
            first_empty = value
    if first_empty is not None and not require_nonempty:
        return {"found": True, "value": first_empty, "errors": {}}
    return {"found": False, "errors": errors}


def _redact_diagnostic_value(
    path: str,
    value: str,
    *,
    reveal_secrets: bool,
) -> tuple[str, bool]:
    sensitive_path = path
    if ".WANPPPConnection." in path and path.endswith(".Username"):
        sensitive_path = f"{path}.PPPoE"
    if ".WANIPConnection." in path and path.endswith(".Username"):
        sensitive_path = f"{path}.PPPoE"
    if cfg_read_risk(sensitive_path) == "sensitive":
        return redact_cfg_value(sensitive_path, value, reveal_secrets=reveal_secrets)
    return redact_cfg_value(path, value, reveal_secrets=reveal_secrets)


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _safe_shell_result(shell_runner: Any, command: str) -> dict[str, Any]:
    try:
        return {
            "command": command,
            "ok": True,
            "output": str(shell_runner(command)),
        }
    except Exception as exc:  # noqa: BLE001 - diagnostics should report partial failures.
        return {
            "command": command,
            "ok": False,
            "error": str(exc),
        }
