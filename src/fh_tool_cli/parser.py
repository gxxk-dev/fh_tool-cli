from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .argparse_utils import normalize_port
from .backends.local_vm import DEFAULT_VM_ROOT
from .backup import DEFAULT_DEVICE_RESTORE_CHUNK_SIZE, DEFAULT_DEVICE_RESTORE_TMPDIR
from .commands.web import register_web_commands
from .config_store import DEFAULT_CONFIG_PATH, normalize_ip
from .credentials import DERIVED_CREDENTIAL_KINDS
from .upload import UPLOAD_ACTIONS

DEFAULT_PORTS = "23,80,443,8080"

HandlerMap = Mapping[str, Any]


def _handler(handlers: HandlerMap, name: str) -> Any:
    return handlers[name]


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ip", type=normalize_ip, help="网关 IPv4 地址")
    parser.add_argument(
        "--mac",
        help="网关 MAC，支持 AABBCCDDEEFF / AA:BB:CC:DD:EE:FF / AA-BB-CC-DD-EE-FF",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP/TCP timeout 秒数，默认 5",
    )
    parser.add_argument(
        "--fh-port",
        type=normalize_port,
        default=None,
        help="fh_tool API 端口；默认先 8080，TCP 不可达时自动探测候选端口（如 80）。显式指定后跳过探测",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"配置文件路径，默认 {DEFAULT_CONFIG_PATH}",
    )
    parser.add_argument(
        "--ask-mac",
        action="store_true",
        help="无法自动获取 MAC 时交互式询问；--json 下不会询问",
    )
    parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")


def add_confirm(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="确认执行写入；不加时只输出 dry-run 计划",
    )


def add_deprecated_confirmation_options(
    parser: argparse.ArgumentParser,
    *,
    yes: bool = True,
    danger: bool = True,
    extreme: bool = True,
    backup_confirmed: bool = True,
    execute: bool = True,
    dry_run: bool = True,
    allow_risky: bool = True,
) -> None:
    if yes:
        parser.add_argument("--yes", dest="deprecated_yes", action="store_true", help=argparse.SUPPRESS)
    if danger:
        parser.add_argument("--danger", dest="deprecated_danger", action="store_true", help=argparse.SUPPRESS)
    if extreme:
        parser.add_argument(
            "--i-know-this-can-break-my-device",
            dest="deprecated_extreme",
            action="store_true",
            help=argparse.SUPPRESS,
        )
    if backup_confirmed:
        parser.add_argument(
            "--backup-confirmed",
            dest="deprecated_backup_confirmed",
            action="store_true",
            help=argparse.SUPPRESS,
        )
    if execute:
        parser.add_argument("--execute", dest="deprecated_execute", action="store_true", help=argparse.SUPPRESS)
    if dry_run:
        parser.add_argument("--dry-run", dest="deprecated_dry_run", action="store_true", help=argparse.SUPPRESS)
    if allow_risky:
        parser.add_argument("--allow-risky", dest="deprecated_allow_risky", action="store_true", help=argparse.SUPPRESS)


def add_write_confirmation(parser: argparse.ArgumentParser) -> None:
    add_confirm(parser)
    add_deprecated_confirmation_options(parser)


def add_telnet_options(
    parser: argparse.ArgumentParser,
    *,
    password_arg: str = "--password",
    password_dest: str = "password",
    password_stdin_arg: str = "--password-stdin",
    password_stdin_dest: str = "password_stdin",
) -> None:
    add_common_options(parser)
    parser.add_argument("--telnet-port", type=int, default=23, help="Telnet port，默认 23")
    parser.add_argument("--username", help="Telnet 用户名")
    parser.add_argument(password_arg, dest=password_dest, help="Telnet 密码")
    parser.add_argument(
        password_stdin_arg,
        dest=password_stdin_dest,
        action="store_true",
        help="从 stdin 读取 Telnet 密码",
    )
    parser.add_argument(
        "--use-derived-credentials",
        action="store_true",
        help="兼容参数；HG5143F 派生 Telnet 凭据现在默认作为 fallback",
    )
    parser.add_argument(
        "--no-derived-credentials",
        action="store_true",
        help="关闭默认 HG5143F 派生 Telnet 凭据 fallback",
    )
    parser.add_argument("--su-password", help="当前 su root 密码；未提供时默认使用 HG5143F 派生候选")
    parser.add_argument("--su-password-stdin", action="store_true", help="从 stdin 读取当前 su root 密码")


def add_cfg_backend_options(parser: argparse.ArgumentParser) -> None:
    add_telnet_options(parser)
    parser.add_argument(
        "--backend",
        choices=["telnet", "local-vm"],
        default="telnet",
        help="cfg_cmd backend，默认 telnet；local-vm 使用本机 proot VM",
    )
    parser.add_argument(
        "--vm-root",
        default=str(DEFAULT_VM_ROOT),
        help=(
            "local-vm 工作区目录，必须包含 bin/proot-shell 和 "
            f"rootfs-vm/fhrom/bin/cfg_cmd，默认 {DEFAULT_VM_ROOT}"
        ),
    )


def add_password_input_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--password", help="目标密码；输出不会回显明文")
    parser.add_argument("--password-stdin", action="store_true", help="从 stdin 读取目标密码")
    parser.add_argument("--generate", action="store_true", help="生成随机目标密码")


def add_api_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    func: str,
    *,
    aliases: list[str] | None = None,
    help_text: str,
    handlers: HandlerMap,
) -> None:
    parser = subparsers.add_parser(name, aliases=aliases or [], help=help_text)
    add_common_options(parser)
    parser.set_defaults(handler=_handler(handlers, "command_simple")(func))


def build_parser(handlers: HandlerMap) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name or "fh-tool",
        description="本地管理 FiberHome /fh_tool 接口的 CLI。",
        epilog="使用 COMMAND -h 查看具体命令参数。",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="COMMAND",
        title="commands",
    )

    probe = subparsers.add_parser("probe", help="低风险探测 fh_tool 是否可用")
    add_common_options(probe)
    probe.add_argument("--ports", default=DEFAULT_PORTS, help=f"逗号分隔 port，默认 {DEFAULT_PORTS}")
    probe.set_defaults(handler=_handler(handlers, "command_probe"))

    ports = subparsers.add_parser("ports", help="检查 TCP port 是否打开")
    add_common_options(ports)
    ports.add_argument("--ports", default=DEFAULT_PORTS, help=f"逗号分隔 port，默认 {DEFAULT_PORTS}")
    ports.set_defaults(handler=_handler(handlers, "command_ports"))

    config_decrypt = subparsers.add_parser("config-decrypt", help="离线解密 UCI-like 配置 dump")
    config_decrypt.add_argument("--input", required=True, help="usrconfig_conf 输入文件")
    config_decrypt.add_argument("--attr", help="可选 attrconfig_conf 输入文件")
    config_decrypt.add_argument("--output", help="写入 decrypted JSON；默认输出到 stdout")
    config_decrypt.add_argument("--redact", dest="deprecated_redact", action="store_true", help=argparse.SUPPRESS)
    config_decrypt.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    config_decrypt.add_argument("--key", help="encrymode=2 AES-128 static key 文本，必须 16 bytes")
    config_decrypt.add_argument("--key-hex", help="encrymode=2 AES-128 static key hex，必须 16 bytes")
    config_decrypt.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    config_decrypt.set_defaults(handler=_handler(handlers, "command_config_decrypt"))

    backup = subparsers.add_parser("backup", help="创建或验证只读配置备份")
    backup.add_argument("--source-root", default="/", help="本地源根目录，默认 /")
    backup.add_argument("--output", help="写入 backup .tgz archive")
    backup.add_argument("--manifest", help="写入 sidecar manifest JSON")
    backup.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    backup.set_defaults(handler=_handler(handlers, "command_backup_create"))
    backup_subparsers = backup.add_subparsers(
        dest="backup_command",
        metavar="SUBCOMMAND",
        title="backup commands",
    )
    backup_verify = backup_subparsers.add_parser("verify", help="验证 backup archive 或 manifest")
    backup_verify.add_argument("path", help="backup.tgz 或 backup.json")
    backup_verify.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    backup_verify.set_defaults(handler=_handler(handlers, "command_backup_verify"))

    vm = subparsers.add_parser("vm", help="采集、构建和验证 HG5143F userspace VM")
    vm_subparsers = vm.add_subparsers(
        dest="vm_command",
        required=True,
        metavar="SUBCOMMAND",
        title="vm commands",
    )
    vm_collect = vm_subparsers.add_parser("collect", help="通过 Telnet 安全采集 VM 所需 MTD dump")
    add_telnet_options(vm_collect)
    for action in vm_collect._actions:
        if action.dest == "timeout":
            action.default = 60.0
            action.help = "Telnet command timeout 秒数，默认 60"
            break
    add_write_confirmation(vm_collect)
    vm_collect.add_argument("--output", required=True, help="写入 dump 目录")
    vm_collect.add_argument("--auto-enable-telnet", action="store_true", help="确认后先调用 TelnetEnable=1")
    vm_collect.add_argument("--all-mtd", action="store_true", help="采集 mtd0-mtd7 物理分区")
    vm_collect.add_argument("--partition", action="append", default=[], help="只采集指定 mtdN/name，可重复")
    vm_collect.add_argument("--chunk-size", type=int, default=262144, help="nanddump/base64 chunk bytes，默认 262144")
    vm_collect.add_argument("--retries", type=int, default=3, help="chunk decode/长度不匹配重试次数，默认 3")
    vm_collect.set_defaults(handler=_handler(handlers, "command_vm_collect"))
    vm_build = vm_subparsers.add_parser("build", help="从 dump 构建本地 proot/qemu-arm-static VM")
    vm_build.add_argument("--dump-dir", required=True, help="包含 MTD dump 的目录")
    vm_build.add_argument("--output", required=True, help="写入 VM 工作区目录")
    vm_build.add_argument("--rootfs-slot", choices=["active", "A", "B"], default="active", help="rootfs slot，默认 active")
    vm_build.add_argument("--force", action="store_true", help="覆盖已有输出目录")
    vm_build.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    vm_build.set_defaults(handler=_handler(handlers, "command_vm_build"))
    vm_verify = vm_subparsers.add_parser("verify", help="验证本地 VM 工作区")
    vm_verify.add_argument("--vm-root", required=True, help="VM 工作区目录，不是 rootfs-vm 子目录")
    vm_verify.add_argument("--with-fhapi", action="store_true", help="启动 ubusd + cfgmgr 并验证 cfg_cmd read")
    vm_verify.add_argument("--with-http", action="store_true", help="端口空闲时启动并验证 HTTP stack")
    vm_verify.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    vm_verify.set_defaults(handler=_handler(handlers, "command_vm_verify"))

    restore_backup = subparsers.add_parser("restore", help="从 backup archive 安全恢复 allowlist 配置")
    add_telnet_options(restore_backup)
    restore_backup.add_argument("backup", help="fh-tool backup 生成的 backup.tgz")
    restore_backup.add_argument(
        "--target",
        choices=["local", "device"],
        default="local",
        help="恢复目标：local 写入本地/fake root；device 通过 Telnet 写入设备",
    )
    restore_backup.add_argument("--target-root", help="local 恢复目标根目录；local --confirm 时必须显式指定")
    restore_backup.add_argument(
        "--remote-tmpdir",
        default=DEFAULT_DEVICE_RESTORE_TMPDIR,
        help=f"device restore 临时目录，默认 {DEFAULT_DEVICE_RESTORE_TMPDIR}",
    )
    restore_backup.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_DEVICE_RESTORE_CHUNK_SIZE,
        help=f"device restore base64 分片大小，默认 {DEFAULT_DEVICE_RESTORE_CHUNK_SIZE}",
    )
    restore_backup.add_argument("--path", action="append", default=[], help="只恢复指定设备路径，可重复")
    add_write_confirmation(restore_backup)
    restore_backup.set_defaults(handler=_handler(handlers, "command_restore_backup"))

    credentials = subparsers.add_parser("credentials", help="只读派生/展示光猫管理面凭据候选")
    credentials_subparsers = credentials.add_subparsers(
        dest="credentials_command",
        required=True,
        metavar="SUBCOMMAND",
        title="credentials commands",
    )
    credentials_derive = credentials_subparsers.add_parser(
        "derive",
        help="按已验证规则派生凭据候选，默认脱敏",
    )
    add_common_options(credentials_derive)
    credentials_derive.add_argument(
        "--kind",
        choices=DERIVED_CREDENTIAL_KINDS,
        default="all",
        help="派生规则，默认 all",
    )
    credentials_derive.add_argument("--reveal-secrets", action="store_true", help="输出派生明文")
    credentials_derive.set_defaults(handler=_handler(handlers, "command_credentials_derive"))

    cfg = subparsers.add_parser("cfg", help="通过 Telnet/root shell 包装 cfg_cmd")
    cfg_subparsers = cfg.add_subparsers(
        dest="cfg_command",
        required=True,
        metavar="SUBCOMMAND",
        title="cfg commands",
    )
    cfg_get = cfg_subparsers.add_parser("get", help="读取 cfg_cmd PATH")
    add_cfg_backend_options(cfg_get)
    cfg_get.add_argument("path")
    cfg_get.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    cfg_get.set_defaults(handler=_handler(handlers, "command_cfg_get"))
    cfg_set = cfg_subparsers.add_parser("set", help="写入 cfg_cmd PATH VALUE")
    add_cfg_backend_options(cfg_set)
    add_write_confirmation(cfg_set)
    cfg_set.add_argument("path")
    cfg_set.add_argument("value")
    cfg_set.set_defaults(handler=_handler(handlers, "command_cfg_set"))
    cfg_attr = cfg_subparsers.add_parser("attr", help="读取 cfg_cmd attr PATH")
    add_cfg_backend_options(cfg_attr)
    cfg_attr.add_argument("path")
    cfg_attr.set_defaults(handler=_handler(handlers, "command_cfg_attr"))
    cfg_snapshot_parser = cfg_subparsers.add_parser("snapshot", help="读取多个 cfg PATH 到 JSON")
    add_cfg_backend_options(cfg_snapshot_parser)
    cfg_snapshot_parser.add_argument("--path", action="append", default=[], help="要读取的 cfg path，可重复")
    cfg_snapshot_parser.add_argument("--output", help="写入 snapshot JSON")
    cfg_snapshot_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    cfg_snapshot_parser.set_defaults(handler=_handler(handlers, "command_cfg_snapshot"))
    cfg_diff = cfg_subparsers.add_parser("diff", help="比较两个 cfg snapshot JSON")
    cfg_diff.add_argument("before")
    cfg_diff.add_argument("after")
    cfg_diff.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    cfg_diff.set_defaults(handler=_handler(handlers, "command_cfg_diff"))

    account = subparsers.add_parser("account", help="管理 Web/Telnet/runtime account")
    account_subparsers = account.add_subparsers(
        dest="account_command",
        required=True,
        metavar="SUBCOMMAND",
        title="account commands",
    )
    account_show_parser = account_subparsers.add_parser("show", help="显示账号相关配置")
    add_telnet_options(
        account_show_parser,
        password_arg="--telnet-password",
        password_dest="telnet_password",
        password_stdin_arg="--telnet-password-stdin",
        password_stdin_dest="telnet_password_stdin",
    )
    account_show_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    account_show_parser.set_defaults(handler=_handler(handlers, "command_account_show"))
    account_web_password = account_subparsers.add_parser(
        "set-web-admin-password",
        help="设置 Web superadmin password",
    )
    add_telnet_options(
        account_web_password,
        password_arg="--telnet-password",
        password_dest="telnet_password",
        password_stdin_arg="--telnet-password-stdin",
        password_stdin_dest="telnet_password_stdin",
    )
    add_write_confirmation(account_web_password)
    add_password_input_options(account_web_password)
    account_web_password.set_defaults(handler=_handler(handlers, "command_account_set_web_admin_password"))
    account_telnet_password = account_subparsers.add_parser(
        "set-telnet-password",
        help="设置 Telnet login password",
    )
    add_telnet_options(
        account_telnet_password,
        password_arg="--telnet-password",
        password_dest="telnet_password",
        password_stdin_arg="--telnet-password-stdin",
        password_stdin_dest="telnet_password_stdin",
    )
    add_write_confirmation(account_telnet_password)
    add_password_input_options(account_telnet_password)
    account_telnet_password.set_defaults(handler=_handler(handlers, "command_account_set_telnet_password"))
    account_telnet_username = account_subparsers.add_parser(
        "set-telnet-username",
        help="设置 Telnet login username",
    )
    add_telnet_options(
        account_telnet_username,
        password_arg="--telnet-password",
        password_dest="telnet_password",
        password_stdin_arg="--telnet-password-stdin",
        password_stdin_dest="telnet_password_stdin",
    )
    add_write_confirmation(account_telnet_username)
    account_telnet_username.add_argument("--name", required=True)
    account_telnet_username.set_defaults(handler=_handler(handlers, "command_account_set_telnet_username"))
    account_su_password = account_subparsers.add_parser(
        "set-su-runtime-password",
        help="设置 runtime su password",
    )
    add_telnet_options(
        account_su_password,
        password_arg="--telnet-password",
        password_dest="telnet_password",
        password_stdin_arg="--telnet-password-stdin",
        password_stdin_dest="telnet_password_stdin",
    )
    add_write_confirmation(account_su_password)
    add_password_input_options(account_su_password)
    account_su_password.set_defaults(handler=_handler(handlers, "command_account_set_su_runtime_password"))

    autoupdate = subparsers.add_parser("autoupdate", help="自动更新状态、审计和计划")
    autoupdate_subparsers = autoupdate.add_subparsers(
        dest="autoupdate_command",
        required=True,
        metavar="SUBCOMMAND",
        title="autoupdate commands",
    )
    autoupdate_status_parser = autoupdate_subparsers.add_parser("status", help="读取自动更新状态")
    add_telnet_options(autoupdate_status_parser)
    autoupdate_status_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    autoupdate_status_parser.set_defaults(handler=_handler(handlers, "command_autoupdate_status"))
    autoupdate_audit = autoupdate_subparsers.add_parser("audit", help="生成自动更新只读审计")
    add_telnet_options(autoupdate_audit)
    autoupdate_audit.add_argument("--output", help="写入 Markdown report")
    autoupdate_audit.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    autoupdate_audit.set_defaults(handler=_handler(handlers, "command_autoupdate_audit"))
    autoupdate_plan_parser = autoupdate_subparsers.add_parser("plan", help="生成自动更新分层计划")
    autoupdate_plan_parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    autoupdate_plan_parser.set_defaults(handler=_handler(handlers, "command_autoupdate_plan"))

    tr069 = subparsers.add_parser("tr069", help="TR-069 状态、审计和计划")
    tr069_subparsers = tr069.add_subparsers(
        dest="tr069_command",
        required=True,
        metavar="SUBCOMMAND",
        title="tr069 commands",
    )
    tr069_status_parser = tr069_subparsers.add_parser("status", help="读取 TR-069 状态")
    add_telnet_options(tr069_status_parser)
    tr069_status_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    tr069_status_parser.set_defaults(handler=_handler(handlers, "command_tr069_status"))
    tr069_audit = tr069_subparsers.add_parser("audit", help="生成 TR-069 只读审计")
    add_telnet_options(tr069_audit)
    tr069_audit.add_argument("--output", help="写入 Markdown report")
    tr069_audit.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    tr069_audit.set_defaults(handler=_handler(handlers, "command_tr069_audit"))
    tr069_plan_parser = tr069_subparsers.add_parser("plan", help="生成 TR-069 分层计划")
    tr069_plan_parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    tr069_plan_parser.set_defaults(handler=_handler(handlers, "command_tr069_plan"))
    tr069_harden = tr069_subparsers.add_parser("harden", help="按选项加固 TR-069 配置")
    add_telnet_options(tr069_harden)
    add_write_confirmation(tr069_harden)
    tr069_harden.add_argument("--periodic-inform", choices=["off", "on"], help="设置 PeriodicInformEnable")
    tr069_harden.set_defaults(handler=_handler(handlers, "command_tr069_harden"))
    tr069_randomize = tr069_subparsers.add_parser(
        "randomize-connection-request",
        help="随机化 TR-069 connection request 凭据",
    )
    add_telnet_options(tr069_randomize)
    add_write_confirmation(tr069_randomize)
    tr069_randomize.set_defaults(handler=_handler(handlers, "command_tr069_randomize_connection_request"))

    cloud = subparsers.add_parser("cloud", help="CloudPlat 状态、endpoint 和计划")
    cloud_subparsers = cloud.add_subparsers(
        dest="cloud_command",
        required=True,
        metavar="SUBCOMMAND",
        title="cloud commands",
    )
    cloud_status_parser = cloud_subparsers.add_parser("status", help="读取 CloudPlat 状态")
    add_telnet_options(cloud_status_parser)
    cloud_status_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    cloud_status_parser.set_defaults(handler=_handler(handlers, "command_cloud_status"))
    cloud_endpoints_parser = cloud_subparsers.add_parser("endpoints", help="读取 CloudPlat endpoints")
    add_telnet_options(cloud_endpoints_parser)
    cloud_endpoints_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    cloud_endpoints_parser.set_defaults(handler=_handler(handlers, "command_cloud_endpoints"))
    cloud_audit = cloud_subparsers.add_parser("audit", help="生成 CloudPlat 只读审计")
    add_telnet_options(cloud_audit)
    cloud_audit.add_argument("--output", help="写入 Markdown report")
    cloud_audit.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    cloud_audit.set_defaults(handler=_handler(handlers, "command_cloud_audit"))
    cloud_plan_parser = cloud_subparsers.add_parser("plan", help="生成 CloudPlat 分层计划")
    cloud_plan_parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    cloud_plan_parser.set_defaults(handler=_handler(handlers, "command_cloud_plan"))
    cloud_disable = cloud_subparsers.add_parser("disable-cloudclt", help="停止/禁用 SAF cloud client")
    add_telnet_options(cloud_disable)
    add_write_confirmation(cloud_disable)
    cloud_disable.set_defaults(handler=_handler(handlers, "command_cloud_disable_cloudclt"))
    cloud_disable_smartswitch_parser = cloud_subparsers.add_parser(
        "disable-smartswitch",
        help="设置 SmartSwitch=0 并回读验证",
    )
    add_telnet_options(cloud_disable_smartswitch_parser)
    add_write_confirmation(cloud_disable_smartswitch_parser)
    cloud_disable_smartswitch_parser.set_defaults(handler=_handler(handlers, "command_cloud_disable_smartswitch"))

    register_web_commands(subparsers)

    pon = subparsers.add_parser("pon", help="PON read-only diagnostics")
    pon_subparsers = pon.add_subparsers(
        dest="pon_command",
        required=True,
        metavar="SUBCOMMAND",
        title="pon commands",
    )
    pon_status_parser = pon_subparsers.add_parser("status", help="读取 PON 状态")
    add_cfg_backend_options(pon_status_parser)
    pon_status_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    pon_status_parser.set_defaults(handler=_handler(handlers, "command_pon_status"))

    wan = subparsers.add_parser("wan", help="WAN read-only diagnostics")
    wan_subparsers = wan.add_subparsers(
        dest="wan_command",
        required=True,
        metavar="SUBCOMMAND",
        title="wan commands",
    )
    wan_list_parser = wan_subparsers.add_parser("list", help="读取 WAN connection 列表")
    add_cfg_backend_options(wan_list_parser)
    wan_list_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    wan_list_parser.set_defaults(handler=_handler(handlers, "command_wan_list"))

    vlan = subparsers.add_parser("vlan", help="VLAN read-only diagnostics")
    vlan_subparsers = vlan.add_subparsers(
        dest="vlan_command",
        required=True,
        metavar="SUBCOMMAND",
        title="vlan commands",
    )
    vlan_list_parser = vlan_subparsers.add_parser("list", help="读取 VLAN 状态")
    add_cfg_backend_options(vlan_list_parser)
    vlan_list_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    vlan_list_parser.set_defaults(handler=_handler(handlers, "command_vlan_list"))

    ip_diag = subparsers.add_parser("ip", help="IP read-only diagnostics")
    ip_subparsers = ip_diag.add_subparsers(
        dest="ip_command",
        required=True,
        metavar="SUBCOMMAND",
        title="ip commands",
    )
    ip_status_parser = ip_subparsers.add_parser("status", help="读取 IP/route/DNS 状态")
    add_cfg_backend_options(ip_status_parser)
    ip_status_parser.set_defaults(handler=_handler(handlers, "command_ip_status"))

    firewall = subparsers.add_parser("firewall", help="Firewall read-only diagnostics")
    firewall_subparsers = firewall.add_subparsers(
        dest="firewall_command",
        required=True,
        metavar="SUBCOMMAND",
        title="firewall commands",
    )
    firewall_status_parser = firewall_subparsers.add_parser("status", help="读取 firewall/UPnP/IGMP 状态")
    add_cfg_backend_options(firewall_status_parser)
    firewall_status_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    firewall_status_parser.set_defaults(handler=_handler(handlers, "command_firewall_status"))

    ipv6 = subparsers.add_parser("ipv6", help="IPv6 read-only diagnostics")
    ipv6_subparsers = ipv6.add_subparsers(
        dest="ipv6_command",
        required=True,
        metavar="SUBCOMMAND",
        title="ipv6 commands",
    )
    ipv6_status_parser = ipv6_subparsers.add_parser("status", help="读取 IPv6 状态")
    add_cfg_backend_options(ipv6_status_parser)
    ipv6_status_parser.add_argument("--reveal-secrets", action="store_true", help="输出 sensitive 明文")
    ipv6_status_parser.set_defaults(handler=_handler(handlers, "command_ipv6_status"))

    config = subparsers.add_parser("config", help="管理本机 CLI 配置")
    config_subparsers = config.add_subparsers(
        dest="config_command",
        required=True,
        metavar="SUBCOMMAND",
        title="config commands",
    )
    config_show = config_subparsers.add_parser("show", help="显示配置")
    config_show.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    config_show.add_argument("--json", action="store_true")
    config_show.set_defaults(handler=_handler(handlers, "command_config_show"))
    config_set = config_subparsers.add_parser("set", help="保存默认 IP/MAC")
    config_set.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    config_set.add_argument("--json", action="store_true")
    config_set.add_argument("--ip", type=normalize_ip)
    config_set.add_argument("--mac")
    config_set.set_defaults(handler=_handler(handlers, "command_config_set"))
    config_clear = config_subparsers.add_parser("clear", help="删除配置文件")
    config_clear.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    config_clear.add_argument("--json", action="store_true")
    config_clear.set_defaults(handler=_handler(handlers, "command_config_clear"))

    add_api_command(subparsers, "get-result", "GetResult", help_text="读取 operator registration result", handlers=handlers)
    add_api_command(subparsers, "get-port-mirror", "GetPortMirror", help_text="读取 port mirror 配置", handlers=handlers)

    log_download = subparsers.add_parser("log-download", help="调用 LogDownload，可选下载 tar")
    add_common_options(log_download)
    log_download.add_argument("--output", help="保存返回的 tool_download 文件")
    log_download.set_defaults(handler=_handler(handlers, "command_log_download"))

    add_api_command(subparsers, "dev-info", "GetDevInfo", aliases=["info"], help_text="读取设备基础信息", handlers=handlers)
    add_api_command(subparsers, "admin-account", "GetAdminAccount", help_text="读取 telecomadmin account", handlers=handlers)
    add_api_command(subparsers, "reg-account", "GetRegAccount", help_text="读取 registration account", handlers=handlers)
    add_api_command(subparsers, "pwd-reg-password", "GetPwdRegPassword", help_text="读取 CMCC registration password", handlers=handlers)
    add_api_command(subparsers, "get-preconfig", "GetPreconfig", help_text="读取 preconfig 列表", handlers=handlers)
    add_api_command(subparsers, "pppoe-account", "GetPppoeAccount", help_text="读取 PPPoE account", handlers=handlers)

    set_result = subparsers.add_parser("set-result", help="写入 registration result")
    add_common_options(set_result)
    add_write_confirmation(set_result)
    set_result.add_argument("--result", required=True)
    set_result.set_defaults(handler=_handler(handlers, "command_set_result"))

    set_port_mirror = subparsers.add_parser("set-port-mirror", help="写入 port mirror 配置")
    add_common_options(set_port_mirror)
    add_write_confirmation(set_port_mirror)
    set_port_mirror.add_argument("--enable", required=True)
    set_port_mirror.add_argument("--direction", required=True)
    set_port_mirror.add_argument("--srcport", required=True)
    set_port_mirror.add_argument("--dstport", required=True)
    set_port_mirror.set_defaults(handler=_handler(handlers, "command_set_port_mirror"))

    set_reg_account = subparsers.add_parser("set-reg-account", help="写入 registration account")
    add_common_options(set_reg_account)
    add_write_confirmation(set_reg_account)
    set_reg_account.add_argument("--regname", required=True)
    set_reg_account.add_argument("--regpwd", required=True)
    set_reg_account.set_defaults(handler=_handler(handlers, "command_set_reg_account"))

    set_pwd_reg_password = subparsers.add_parser("set-pwd-reg-password", help="写入 CMCC registration password")
    add_common_options(set_pwd_reg_password)
    add_write_confirmation(set_pwd_reg_password)
    set_pwd_reg_password.add_argument("--password", required=True)
    set_pwd_reg_password.set_defaults(handler=_handler(handlers, "command_set_pwd_reg_password"))

    download_file = subparsers.add_parser("download-file", help="调用 DownloadFile 并保存返回文件")
    add_common_options(download_file)
    add_write_confirmation(download_file)
    download_file.add_argument("--file-name", required=True)
    download_file.add_argument("--output", help="本地保存路径；默认使用返回文件名")
    download_file.set_defaults(handler=_handler(handlers, "command_download_file"))

    restore = subparsers.add_parser("restore-default-settings", help="恢复出厂设置")
    add_common_options(restore)
    add_write_confirmation(restore)
    restore.set_defaults(handler=_handler(handlers, "command_restore_default_settings"))

    upload_prepare = subparsers.add_parser("upload-prepare", help="调用 UploadPrepare 获取 sessionid")
    add_common_options(upload_prepare)
    upload_prepare.add_argument("--reveal-secrets", action="store_true", help="输出 session/token 明文")
    upload_prepare.set_defaults(handler=_handler(handlers, "command_upload_prepare"))
    upload_plan_parser = subparsers.add_parser("upload-plan", help="生成 firmware/preconfig upload 工作流计划")
    upload_plan_parser.add_argument("--action", choices=sorted(UPLOAD_ACTIONS), required=True)
    upload_plan_parser.add_argument("--file", help="可选：计算待上传文件 size/sha256")
    upload_plan_parser.add_argument("--json", action="store_true", help="输出 machine-readable JSON")
    upload_plan_parser.set_defaults(handler=_handler(handlers, "command_upload_plan"))

    reboot = subparsers.add_parser("reboot", help="重启设备")
    add_common_options(reboot)
    add_write_confirmation(reboot)
    reboot.set_defaults(handler=_handler(handlers, "command_reboot"))

    set_preconfig = subparsers.add_parser("set-preconfig", help="切换 preconfig")
    add_common_options(set_preconfig)
    add_write_confirmation(set_preconfig)
    set_preconfig.add_argument("--fullname", required=True)
    set_preconfig.set_defaults(handler=_handler(handlers, "command_set_preconfig"))

    telnet = subparsers.add_parser("telnet", help="管理 runtime Telnet")
    telnet_subparsers = telnet.add_subparsers(
        dest="telnet_command",
        required=True,
        metavar="SUBCOMMAND",
        title="telnet commands",
    )
    telnet_enable = telnet_subparsers.add_parser("enable", help="调用 TelnetEnable=1")
    add_common_options(telnet_enable)
    add_write_confirmation(telnet_enable)
    telnet_enable.set_defaults(handler=_handler(handlers, "command_telnet_enable"))
    telnet_disable = telnet_subparsers.add_parser("disable", help="调用 TelnetEnable=0")
    add_common_options(telnet_disable)
    add_write_confirmation(telnet_disable)
    telnet_disable.set_defaults(handler=_handler(handlers, "command_telnet_disable"))

    set_fh_debug_log = subparsers.add_parser("set-fh-debug-log", help="调用 SetFHDebugLog")
    add_common_options(set_fh_debug_log)
    add_write_confirmation(set_fh_debug_log)
    set_fh_debug_log.add_argument("--module", required=True)
    set_fh_debug_log.add_argument("--data", required=True)
    set_fh_debug_log.set_defaults(handler=_handler(handlers, "command_set_fh_debug_log"))

    close_fh_debug_log = subparsers.add_parser("close-fh-debug-log", help="关闭 FH debug log")
    add_common_options(close_fh_debug_log)
    add_write_confirmation(close_fh_debug_log)
    close_fh_debug_log.set_defaults(handler=_handler(handlers, "command_close_fh_debug_log"))

    open_fh_debug_log = subparsers.add_parser("open-fh-debug-log", help="开启 FH debug log")
    add_common_options(open_fh_debug_log)
    add_write_confirmation(open_fh_debug_log)
    open_fh_debug_log.set_defaults(handler=_handler(handlers, "command_open_fh_debug_log"))

    raw_call = subparsers.add_parser("call", help="原始 fh_tool/api 调用")
    add_common_options(raw_call)
    raw_call.add_argument("--func", required=True, help="要调用的 fh_tool/api 方法名")
    raw_call.add_argument("--param", action="append", default=[], help="k=v，可重复")
    raw_call.add_argument("--json-payload", help="额外 JSON 对象参数")
    add_confirm(raw_call)
    add_deprecated_confirmation_options(raw_call)
    raw_call.set_defaults(handler=_handler(handlers, "command_raw_call"))

    download_url = subparsers.add_parser("download-url", help="下载 /fh_tool/tool_download 返回文件")
    add_common_options(download_url)
    download_url.add_argument("--url", required=True)
    download_url.add_argument("--output", required=True)
    download_url.set_defaults(handler=_handler(handlers, "command_download_url"))

    upload = subparsers.add_parser("upload", help="调用 /fh_tool/upload")
    add_common_options(upload)
    add_write_confirmation(upload)
    upload.add_argument("--action", choices=sorted(UPLOAD_ACTIONS), required=True)
    upload.add_argument("--file", required=True)
    upload.add_argument("--sessionid", required=True)
    upload.set_defaults(handler=_handler(handlers, "command_upload"))

    return parser


def parse_args(argv: list[str] | None = None, *, handlers: HandlerMap) -> argparse.Namespace:
    return build_parser(handlers).parse_args(argv)
