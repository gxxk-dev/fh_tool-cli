from __future__ import annotations

import json
from pathlib import Path
from secrets import token_urlsafe
from typing import Any

from .backends.cfg_cmd import CfgCmdBackend, cfg_set_with_verify, redact_cfg_value

TR069_PATHS = {
    "acs_url": "InternetGatewayDevice.ManagementServer.URL",
    "acs_username": "InternetGatewayDevice.ManagementServer.Username",
    "acs_password": "InternetGatewayDevice.ManagementServer.Password",
    "periodic_inform_enable": "InternetGatewayDevice.ManagementServer.PeriodicInformEnable",
    "periodic_inform_interval": "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
    "connection_request_url": "InternetGatewayDevice.ManagementServer.ConnectionRequestURL",
    "connection_request_username": "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername",
    "connection_request_password": "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
    "upgrades_managed": "InternetGatewayDevice.ManagementServer.UpgradesManaged",
}

AUTOUPDATE_PATHS = {
    "upgrades_managed": "InternetGatewayDevice.ManagementServer.UpgradesManaged",
    "periodic_inform_enable": "InternetGatewayDevice.ManagementServer.PeriodicInformEnable",
    "periodic_inform_interval": "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
}

CLOUD_ENDPOINT_PATHS = {
    "cloud_server": "InternetGatewayDevice.X_CT-COM_CloudPlat.Server",
    "file_server": "InternetGatewayDevice.X_CT-COM_CloudPlat.FileServer",
    "bss_server": "InternetGatewayDevice.X_CT-COM_CloudPlat.BSSServer",
    "abi_server": "InternetGatewayDevice.X_CT-COM_CloudPlat.ABIServer",
    "smart_switch": "InternetGatewayDevice.X_CT-COM_SmartSwitch.Enable",
}

CLOUD_PROCESSES = ("gdecms", "saf", "appmgr", "cloudclient", "cloudclocal", "cloudclt")
SMARTSWITCH_PATH = CLOUD_ENDPOINT_PATHS["smart_switch"]
SMARTSWITCH_DISABLED_VALUE = "0"
SMARTSWITCH_CONFIRMED_STORAGE_PATH = "/fhdata/sysinfo_conf"
SMARTSWITCH_IMPACT = [
    "Blocks SAF/appframework cloud integration paths controlled by SmartSwitch.",
    "May affect operator cloud management features exposed through CloudPlat.",
]
SMARTSWITCH_FORBIDDEN_CHANGES = [
    "LOID",
    "PON",
    "WAN VLAN",
    "ServiceList",
    "TR-069 VLAN",
]


def collect_cfg_status(
    backend: CfgCmdBackend,
    paths: dict[str, str],
    *,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, path in paths.items():
        try:
            value = backend.get(path)
        except Exception as exc:  # noqa: BLE001 - backend errors are report data here.
            errors[name] = str(exc)
            continue
        rendered, redacted = redact_cfg_value(path, value, reveal_secrets=reveal_secrets)
        values[name] = {
            "path": path,
            "value": rendered,
            "redacted": redacted,
        }
    return {"values": values, "errors": errors}


def tr069_status(
    backend: CfgCmdBackend,
    shell_runner: Any | None = None,
    *,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    status = collect_cfg_status(backend, TR069_PATHS, reveal_secrets=reveal_secrets)
    if shell_runner:
        status["runtime"] = {
            "processes": _safe_shell(shell_runner, "ps"),
            "netstat": _safe_shell(shell_runner, "netstat -an"),
            "iptables": _safe_shell(shell_runner, "iptables -S"),
        }
    return {"tr069": status}


def autoupdate_status(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    return {
        "autoupdate": collect_cfg_status(
            backend,
            AUTOUPDATE_PATHS,
            reveal_secrets=reveal_secrets,
        )
    }


def cloud_status(
    backend: CfgCmdBackend,
    shell_runner: Any | None = None,
    *,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    status = collect_cfg_status(backend, CLOUD_ENDPOINT_PATHS, reveal_secrets=reveal_secrets)
    status["smart_switch"] = _smart_switch_status(status)
    if shell_runner:
        ps_output = _safe_shell(shell_runner, "ps")
        netstat_output = _safe_shell(shell_runner, "netstat -an")
        status["runtime"] = {
            "processes": {
                name: name in ps_output
                for name in CLOUD_PROCESSES
            },
            "netstat": netstat_output,
        }
    return {"cloud": status}


def cloud_endpoints(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    return {
        "cloud_endpoints": collect_cfg_status(
            backend,
            CLOUD_ENDPOINT_PATHS,
            reveal_secrets=reveal_secrets,
        )
    }


def remote_plan(kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "actions": [
            {
                "level": "L0",
                "mode": "external",
                "description": "Generate upstream router/firewall/DNS blocking recommendations only.",
                "device_write": False,
            },
            {
                "level": "L1",
                "mode": "config",
                "description": "Disable TR-069 periodic inform or randomize connection-request credentials.",
                "device_write": True,
                "risk": "danger",
            },
            {
                "level": "L2",
                "mode": "process/container",
                "description": "Stop or disable cloud client process inside SAF container.",
                "device_write": True,
                "risk": "danger",
            },
            {
                "level": "L3",
                "mode": "SmartSwitch",
                "description": "Set SmartSwitch=0 to block SAF/appframework.",
                "path": SMARTSWITCH_PATH,
                "target_value": SMARTSWITCH_DISABLED_VALUE,
                "confirmed_storage_path": SMARTSWITCH_CONFIRMED_STORAGE_PATH,
                "storage_path_basis": "research_confirmed",
                "impact": SMARTSWITCH_IMPACT,
                "forbidden_changes": SMARTSWITCH_FORBIDDEN_CHANGES,
                "device_write": True,
                "risk": "danger",
            },
            {
                "level": "L4",
                "mode": "manual-plan-only",
                "description": "Startup or binary changes are not implemented by default.",
                "device_write": False,
            },
        ],
    }


def tr069_harden_periodic_inform(backend: CfgCmdBackend, mode: str) -> dict[str, Any]:
    if mode not in {"off", "on"}:
        raise ValueError("periodic inform mode must be off or on")
    value = "0" if mode == "off" else "1"
    return cfg_set_with_verify(backend, TR069_PATHS["periodic_inform_enable"], value)


def tr069_randomize_connection_request(backend: CfgCmdBackend) -> dict[str, Any]:
    username = f"cr-{token_urlsafe(9)}"
    password = token_urlsafe(24)
    username_result = cfg_set_with_verify(
        backend,
        TR069_PATHS["connection_request_username"],
        username,
    )
    password_result = cfg_set_with_verify(
        backend,
        TR069_PATHS["connection_request_password"],
        password,
    )
    password_result["value"] = "[REDACTED]"
    password_result["observed"] = "[REDACTED]"
    password_result["redacted"] = True
    return {
        "connection_request_username": username_result,
        "connection_request_password": password_result,
        "generated": True,
    }


def cloud_disable_cloudclt(shell_runner: Any) -> dict[str, Any]:
    commands = [
        "lxc-attach -n saf -- /etc/init.d/cloudclt stop 2>&1 || true",
        "lxc-attach -n saf -- /etc/init.d/cloudclt disable 2>&1 || true",
    ]
    command_results = [
        {
            "command": command,
            "output": str(shell_runner(command)),
        }
        for command in commands
    ]
    return {
        "action": "disable-cloudclt",
        "risk": "danger",
        "target": {
            "container": "saf",
            "service": "cloudclt",
        },
        "command": " && ".join(commands),
        "output": "\n".join(result["output"] for result in command_results),
        "commands": command_results,
    }


def cloud_disable_smartswitch(backend: CfgCmdBackend) -> dict[str, Any]:
    result = cfg_set_with_verify(
        backend,
        SMARTSWITCH_PATH,
        SMARTSWITCH_DISABLED_VALUE,
    )
    return {
        "action": "disable-smartswitch",
        "risk": "danger",
        "path": SMARTSWITCH_PATH,
        "target_value": SMARTSWITCH_DISABLED_VALUE,
        "confirmed_storage_path": SMARTSWITCH_CONFIRMED_STORAGE_PATH,
        "storage_path_basis": "research_confirmed",
        "impact": SMARTSWITCH_IMPACT,
        "forbidden_changes": SMARTSWITCH_FORBIDDEN_CHANGES,
        "write": {
            **result,
            "risk": "danger",
        },
        "verified": result["verified"],
        "observed": result["observed"],
    }


def write_audit_report(report: dict[str, Any], output: Path | None = None) -> dict[str, Any]:
    if output is None:
        return report
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_markdown_report(report), encoding="utf-8")
    return {"output": str(output), "sections": list(report)}


def _safe_shell(shell_runner: Any, command: str) -> str:
    try:
        return str(shell_runner(command))
    except Exception as exc:  # noqa: BLE001 - read-only probe failures are report data.
        return f"ERROR: {exc}"


def _smart_switch_status(status: dict[str, Any]) -> dict[str, Any]:
    value = status.get("values", {}).get("smart_switch")
    error = status.get("errors", {}).get("smart_switch")
    result: dict[str, Any] = {
        "path": SMARTSWITCH_PATH,
        "disable_value": SMARTSWITCH_DISABLED_VALUE,
        "confirmed_storage_path": SMARTSWITCH_CONFIRMED_STORAGE_PATH,
        "storage_path_basis": "research_confirmed",
        "risk": "danger",
        "impact": SMARTSWITCH_IMPACT,
        "forbidden_changes": SMARTSWITCH_FORBIDDEN_CHANGES,
    }
    if isinstance(value, dict):
        result["value"] = value.get("value")
        result["redacted"] = value.get("redacted", False)
    if error:
        result["error"] = error
    return result


def _markdown_report(report: dict[str, Any]) -> str:
    lines = ["# fh-tool audit report", ""]
    for section, data in report.items():
        lines.extend([f"## {section}", "", "```json"])
        lines.append(json.dumps(data, ensure_ascii=False, indent=2))
        lines.extend(["```", ""])
    return "\n".join(lines)
