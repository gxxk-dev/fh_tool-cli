from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

import requests

from .account import (
    account_show,
    read_secret_from_args,
    set_su_runtime_password,
    set_telnet_password,
    set_telnet_username,
    set_web_admin_password,
)
from .argparse_utils import parse_json_object, parse_kv, parse_ports
from .backends.fh_tool import (
    FH_TOOL_API_PATH,
    FH_TOOL_UPLOAD_PATH,
    api_payload,
    call_method,
    fh_tool_call,
    response_download_url,
)
from .backup import (
    create_backup,
    restore_backup_archive,
    restore_backup_to_device,
    verify_backup,
)
from .backends.cfg_cmd import (
    CfgCmdBackend,
    cfg_path_risk,
    cfg_read_risk,
    cfg_set_with_verify,
    cfg_snapshot,
    diff_cfg_snapshots,
    redact_cfg_value,
    write_cfg_snapshot,
)
from .backends.local_vm import LocalVmShell
from .backends.telnet import TelnetCredentials, TelnetShell
from .client import download_to_file, tcp_open
from .commands.web import (
    command_web_ajax_get,
    command_web_diagnostics_show,
    command_web_login_check,
    command_web_typed,
    command_web_typed_write,
)
from .config_decrypt import decrypt_config_file
from .config_store import (
    config_path_from_args,
    format_mac,
    load_config,
    normalize_ip,
    normalize_mac,
    resolve_ip,
    resolve_mac,
    save_config,
)
from .credentials import (
    derive_credentials,
    derive_hg5143f_telnet,
)
from .diagnostics import (
    firewall_status,
    ip_status,
    ipv6_status,
    pon_status,
    vlan_list,
    wan_list,
)
from .errors import CliError, FHToolError
from .parser import (
    DEFAULT_PORTS,
    add_cfg_backend_options,
    add_common_options,
    add_danger,
    add_extreme,
    add_password_input_options,
    add_telnet_options,
    add_yes,
    add_api_command as _add_parser_api_command,
    parse_args as _parse_cli_args,
)
from .remote import (
    autoupdate_status,
    cloud_disable_cloudclt,
    cloud_disable_smartswitch,
    cloud_endpoints,
    cloud_status,
    remote_plan,
    tr069_harden_periodic_inform,
    tr069_randomize_connection_request,
    tr069_status,
    write_audit_report,
)
from .risk import require_danger, require_extreme, require_yes
from .upload import (
    redact_upload_prepare_result,
    upload_file,
    upload_file_info,
    upload_workflow_plan,
)


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


def command_config_decrypt(args: argparse.Namespace) -> dict[str, Any]:
    return decrypt_config_file(
        Path(args.input).expanduser(),
        attr_path=Path(args.attr).expanduser() if args.attr else None,
        output_path=Path(args.output).expanduser() if args.output else None,
        reveal_secrets=args.reveal_secrets,
        key=args.key,
        key_hex=args.key_hex,
    )


def command_backup_create(args: argparse.Namespace) -> dict[str, Any]:
    return create_backup(
        Path(args.source_root).expanduser(),
        output_path=Path(args.output).expanduser() if args.output else None,
        manifest_path=Path(args.manifest).expanduser() if args.manifest else None,
    )


def command_backup_verify(args: argparse.Namespace) -> dict[str, Any]:
    return verify_backup(Path(args.path).expanduser())


def command_restore_backup(args: argparse.Namespace) -> dict[str, Any]:
    dry_run = not args.execute
    if not dry_run:
        require_extreme(args, "restore 会覆盖设备配置文件")
    if args.target == "device":
        return restore_backup_to_device(
            Path(args.backup).expanduser(),
            shell_runner=_telnet_shell_from_args(args).run,
            dry_run=dry_run,
            paths=args.path,
            remote_tmpdir=args.remote_tmpdir,
            chunk_size=args.chunk_size,
        )
    return restore_backup_archive(
        Path(args.backup).expanduser(),
        target_root=Path(args.target_root).expanduser() if args.target_root else None,
        dry_run=dry_run,
        paths=args.path,
    )


def command_credentials_derive(args: argparse.Namespace) -> dict[str, Any]:
    ip, ip_source = resolve_ip(args)
    mac, mac_source = resolve_mac(args, ip, required=True)
    assert mac is not None
    credentials = derive_credentials(mac, args.kind)
    return {
        "kind": args.kind,
        "ip": ip,
        "ip_source": ip_source,
        "mac_source": mac_source,
        "credentials": [
            credential.render(reveal_secrets=args.reveal_secrets)
            for credential in credentials
        ],
    }


def _password_from_args(args: argparse.Namespace) -> str | None:
    if getattr(args, "telnet_password_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    if getattr(args, "telnet_password", None) is not None:
        return args.telnet_password
    if hasattr(args, "telnet_password"):
        return None
    return getattr(args, "password", None)


def _telnet_credentials_from_args(args: argparse.Namespace) -> TelnetCredentials:
    ip, _ip_source = resolve_ip(args)
    username = getattr(args, "username", None)
    password = _password_from_args(args)

    if getattr(args, "use_derived_credentials", False):
        mac, _mac_source = resolve_mac(args, ip, required=True)
        assert mac is not None
        derived = derive_hg5143f_telnet(mac)
        if username and username != derived.username and password is None:
            raise CliError(
                "--use-derived-credentials 只能为默认 HG5143F Telnet 账号补齐密码；"
                "自定义 --username 需要同时提供密码"
            )
        username = username or derived.username
        password = password or derived.password

    return TelnetCredentials(
        host=ip,
        port=args.telnet_port,
        username=username,
        password=password,
        timeout=args.timeout,
    )


def _cfg_backend_from_args(args: argparse.Namespace) -> CfgCmdBackend:
    if getattr(args, "backend", "telnet") == "local-vm":
        return CfgCmdBackend(
            LocalVmShell(
                Path(args.vm_root).expanduser(),
                timeout=args.timeout,
            ).run,
            expensive_missing_paths=True,
        )
    return CfgCmdBackend(TelnetShell(_telnet_credentials_from_args(args)).run)


def _telnet_shell_from_args(args: argparse.Namespace) -> TelnetShell:
    return TelnetShell(_telnet_credentials_from_args(args))


def _shell_runner_from_args(args: argparse.Namespace) -> Callable[[str], str]:
    if getattr(args, "backend", "telnet") == "local-vm":
        return LocalVmShell(
            Path(args.vm_root).expanduser(),
            timeout=args.timeout,
        ).run
    return _telnet_shell_from_args(args).run


def command_cfg_get(args: argparse.Namespace) -> dict[str, Any]:
    backend = _cfg_backend_from_args(args)
    value = backend.get(args.path)
    rendered_value, redacted = redact_cfg_value(
        args.path,
        value,
        reveal_secrets=args.reveal_secrets,
    )
    return {
        "path": args.path,
        "value": rendered_value,
        "risk": cfg_read_risk(args.path),
        "redacted": redacted,
    }


def command_cfg_attr(args: argparse.Namespace) -> dict[str, Any]:
    backend = _cfg_backend_from_args(args)
    return {
        "path": args.path,
        "attr": backend.attr(args.path),
        "risk": cfg_read_risk(args.path),
    }


def command_cfg_set(args: argparse.Namespace) -> dict[str, Any]:
    risk = cfg_path_risk(args.path)
    if risk == "danger":
        require_danger(args, "cfg set 会修改高风险配置路径")
    else:
        require_yes(args, "cfg set 会修改设备配置")
    if not args.backup_confirmed:
        raise CliError("cfg set 前需要先完成备份；确认已有备份请加 --backup-confirmed")
    backend = _cfg_backend_from_args(args)
    return cfg_set_with_verify(backend, args.path, args.value)


def command_cfg_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    backend = _cfg_backend_from_args(args)
    snapshot = cfg_snapshot(backend, args.path)
    if not args.reveal_secrets:
        snapshot["values"] = {
            path: redact_cfg_value(path, value, reveal_secrets=False)[0]
            for path, value in snapshot["values"].items()
        }
        snapshot["redacted"] = True
    else:
        snapshot["redacted"] = False
    return write_cfg_snapshot(
        snapshot,
        Path(args.output).expanduser() if args.output else None,
    )


def command_cfg_diff(args: argparse.Namespace) -> dict[str, Any]:
    return diff_cfg_snapshots(
        Path(args.before).expanduser(),
        Path(args.after).expanduser(),
    )


def _require_backup_confirmed(args: argparse.Namespace, message: str) -> None:
    if not args.backup_confirmed:
        raise CliError(f"{message} 前需要先完成备份；确认已有备份请加 --backup-confirmed")


def command_account_show(args: argparse.Namespace) -> dict[str, Any]:
    return account_show(
        _cfg_backend_from_args(args),
        reveal_secrets=args.reveal_secrets,
    )


def command_account_set_web_admin_password(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "set-web-admin-password 会修改 Web superadmin password")
    _require_backup_confirmed(args, "set-web-admin-password")
    secret = read_secret_from_args(args)
    result = set_web_admin_password(_cfg_backend_from_args(args), secret.password)
    result["generated"] = secret.generated
    return result


def command_account_set_telnet_password(args: argparse.Namespace) -> dict[str, Any]:
    require_yes(args, "set-telnet-password 会修改 Telnet login password")
    _require_backup_confirmed(args, "set-telnet-password")
    secret = read_secret_from_args(args)
    result = set_telnet_password(_cfg_backend_from_args(args), secret.password)
    result["generated"] = secret.generated
    return result


def command_account_set_telnet_username(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "set-telnet-username 会修改 Telnet login username")
    _require_backup_confirmed(args, "set-telnet-username")
    return set_telnet_username(_cfg_backend_from_args(args), args.name)


def command_account_set_su_runtime_password(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "set-su-runtime-password 会覆写 runtime su password")
    secret = read_secret_from_args(args)
    result = set_su_runtime_password(_telnet_shell_from_args(args).run, secret.password)
    result["generated"] = secret.generated
    return result


def command_autoupdate_status(args: argparse.Namespace) -> dict[str, Any]:
    return autoupdate_status(
        _cfg_backend_from_args(args),
        reveal_secrets=args.reveal_secrets,
    )


def command_autoupdate_audit(args: argparse.Namespace) -> dict[str, Any]:
    report = command_autoupdate_status(args)
    report["plan"] = remote_plan("autoupdate")
    return write_audit_report(
        report,
        Path(args.output).expanduser() if args.output else None,
    )


def command_autoupdate_plan(args: argparse.Namespace) -> dict[str, Any]:
    return remote_plan("autoupdate")


def command_tr069_status(args: argparse.Namespace) -> dict[str, Any]:
    shell = _telnet_shell_from_args(args)
    return tr069_status(
        _cfg_backend_from_args(args),
        shell.run,
        reveal_secrets=args.reveal_secrets,
    )


def command_tr069_audit(args: argparse.Namespace) -> dict[str, Any]:
    report = command_tr069_status(args)
    report["plan"] = remote_plan("tr069")
    return write_audit_report(
        report,
        Path(args.output).expanduser() if args.output else None,
    )


def command_tr069_plan(args: argparse.Namespace) -> dict[str, Any]:
    return remote_plan("tr069")


def command_tr069_harden(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "tr069 harden 会修改远程管理配置")
    _require_backup_confirmed(args, "tr069 harden")
    result: dict[str, Any] = {"actions": []}
    if args.periodic_inform:
        result["actions"].append(
            tr069_harden_periodic_inform(
                _cfg_backend_from_args(args),
                args.periodic_inform,
            )
        )
    if not result["actions"]:
        raise CliError("tr069 harden 至少需要一个 harden 选项")
    return result


def command_tr069_randomize_connection_request(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "tr069 randomize-connection-request 会修改远程管理凭据")
    _require_backup_confirmed(args, "tr069 randomize-connection-request")
    return tr069_randomize_connection_request(_cfg_backend_from_args(args))


def command_cloud_status(args: argparse.Namespace) -> dict[str, Any]:
    shell = _telnet_shell_from_args(args)
    return cloud_status(
        _cfg_backend_from_args(args),
        shell.run,
        reveal_secrets=args.reveal_secrets,
    )


def command_cloud_endpoints(args: argparse.Namespace) -> dict[str, Any]:
    return cloud_endpoints(
        _cfg_backend_from_args(args),
        reveal_secrets=args.reveal_secrets,
    )


def command_cloud_audit(args: argparse.Namespace) -> dict[str, Any]:
    report = command_cloud_status(args)
    report["plan"] = remote_plan("cloud")
    return write_audit_report(
        report,
        Path(args.output).expanduser() if args.output else None,
    )


def command_cloud_plan(args: argparse.Namespace) -> dict[str, Any]:
    return remote_plan("cloud")


def command_cloud_disable_cloudclt(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "cloud disable-cloudclt 会停止/禁用 cloud client")
    return cloud_disable_cloudclt(_telnet_shell_from_args(args).run)


def command_cloud_disable_smartswitch(args: argparse.Namespace) -> dict[str, Any]:
    require_danger(args, "cloud disable-smartswitch 会修改 SmartSwitch")
    _require_backup_confirmed(args, "cloud disable-smartswitch")
    return cloud_disable_smartswitch(_cfg_backend_from_args(args))


def command_pon_status(args: argparse.Namespace) -> dict[str, Any]:
    return pon_status(_cfg_backend_from_args(args), reveal_secrets=args.reveal_secrets)


def command_wan_list(args: argparse.Namespace) -> dict[str, Any]:
    return wan_list(_cfg_backend_from_args(args), reveal_secrets=args.reveal_secrets)


def command_vlan_list(args: argparse.Namespace) -> dict[str, Any]:
    return vlan_list(_cfg_backend_from_args(args), reveal_secrets=args.reveal_secrets)


def command_ip_status(args: argparse.Namespace) -> dict[str, Any]:
    return ip_status(_shell_runner_from_args(args))


def command_firewall_status(args: argparse.Namespace) -> dict[str, Any]:
    return firewall_status(_cfg_backend_from_args(args), reveal_secrets=args.reveal_secrets)


def command_ipv6_status(args: argparse.Namespace) -> dict[str, Any]:
    return ipv6_status(_cfg_backend_from_args(args), reveal_secrets=args.reveal_secrets)


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
    return redact_upload_prepare_result(
        call_method(args, "UploadPrepare"),
        reveal_secrets=args.reveal_secrets,
    )


def command_upload_plan(args: argparse.Namespace) -> dict[str, Any]:
    return upload_workflow_plan(
        args.action,
        file_info=upload_file_info(Path(args.file).expanduser()) if args.file else None,
        uploaded=False,
    )


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
    dry_run = args.dry_run
    if not dry_run:
        require_extreme(args, "upload 会写入 firmware/preconfig staging path")
    ip, ip_source = resolve_ip(args)
    file_path = Path(args.file).expanduser()
    result = upload_file(
        ip=ip,
        action=args.action,
        file_path=file_path,
        sessionid=args.sessionid,
        timeout=args.timeout,
        dry_run=dry_run,
    )
    result["ip_source"] = ip_source
    return result


def _command_handlers() -> dict[str, Any]:
    return {
        "command_probe": command_probe,
        "command_ports": command_ports,
        "command_config_decrypt": command_config_decrypt,
        "command_backup_create": command_backup_create,
        "command_backup_verify": command_backup_verify,
        "command_restore_backup": command_restore_backup,
        "command_credentials_derive": command_credentials_derive,
        "command_cfg_get": command_cfg_get,
        "command_cfg_set": command_cfg_set,
        "command_cfg_attr": command_cfg_attr,
        "command_cfg_snapshot": command_cfg_snapshot,
        "command_cfg_diff": command_cfg_diff,
        "command_account_show": command_account_show,
        "command_account_set_web_admin_password": command_account_set_web_admin_password,
        "command_account_set_telnet_password": command_account_set_telnet_password,
        "command_account_set_telnet_username": command_account_set_telnet_username,
        "command_account_set_su_runtime_password": command_account_set_su_runtime_password,
        "command_autoupdate_status": command_autoupdate_status,
        "command_autoupdate_audit": command_autoupdate_audit,
        "command_autoupdate_plan": command_autoupdate_plan,
        "command_tr069_status": command_tr069_status,
        "command_tr069_audit": command_tr069_audit,
        "command_tr069_plan": command_tr069_plan,
        "command_tr069_harden": command_tr069_harden,
        "command_tr069_randomize_connection_request": command_tr069_randomize_connection_request,
        "command_cloud_status": command_cloud_status,
        "command_cloud_endpoints": command_cloud_endpoints,
        "command_cloud_audit": command_cloud_audit,
        "command_cloud_plan": command_cloud_plan,
        "command_cloud_disable_cloudclt": command_cloud_disable_cloudclt,
        "command_cloud_disable_smartswitch": command_cloud_disable_smartswitch,
        "command_pon_status": command_pon_status,
        "command_wan_list": command_wan_list,
        "command_vlan_list": command_vlan_list,
        "command_ip_status": command_ip_status,
        "command_firewall_status": command_firewall_status,
        "command_ipv6_status": command_ipv6_status,
        "command_config_show": command_config_show,
        "command_config_set": command_config_set,
        "command_config_clear": command_config_clear,
        "command_log_download": command_log_download,
        "command_simple": command_simple,
        "command_set_result": command_set_result,
        "command_set_port_mirror": command_set_port_mirror,
        "command_set_reg_account": command_set_reg_account,
        "command_set_pwd_reg_password": command_set_pwd_reg_password,
        "command_download_file": command_download_file,
        "command_restore_default_settings": command_restore_default_settings,
        "command_upload_prepare": command_upload_prepare,
        "command_upload_plan": command_upload_plan,
        "command_reboot": command_reboot,
        "command_set_preconfig": command_set_preconfig,
        "command_telnet_enable": command_telnet_enable,
        "command_telnet_disable": command_telnet_disable,
        "command_set_fh_debug_log": command_set_fh_debug_log,
        "command_close_fh_debug_log": command_close_fh_debug_log,
        "command_open_fh_debug_log": command_open_fh_debug_log,
        "command_raw_call": command_raw_call,
        "command_download_url": command_download_url,
        "command_upload": command_upload,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return _parse_cli_args(argv, handlers=_command_handlers())


def add_api_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    func: str,
    *,
    aliases: list[str] | None = None,
    help_text: str,
) -> None:
    _add_parser_api_command(
        subparsers,
        name,
        func,
        aliases=aliases,
        help_text=help_text,
        handlers=_command_handlers(),
    )


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
