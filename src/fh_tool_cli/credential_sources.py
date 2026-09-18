from __future__ import annotations

import argparse
from typing import Any

from .account import SU_RUNTIME_PASSWORD_FILE, read_stdin_secret
from .config_store import resolve_mac
from .credentials import (
    DERIVED_TELNET_USERNAMES,
    su_password_candidates,
    telnet_login_candidates,
    verify_su_password_candidates,
)
from .crypt_unix import crypt_kind, extract_crypt_hash
from .errors import CliError


def derived_credentials_enabled(args: argparse.Namespace) -> bool:
    return not getattr(args, "no_derived_credentials", False)


def complete_derived_telnet_login(
    args: argparse.Namespace,
    *,
    ip: str,
    username: str | None,
    password: str | None,
    explicit_flag_name: str = "--use-derived-credentials",
) -> list[tuple[str | None, str | None]]:
    """解析 Telnet 登录凭据，返回按优先级排列的 (username, password) 候选。

    显式密码优先（单候选原样返回）；否则按型号公式补齐派生密码，
    登录失败时由 TelnetShell 逐候选重试（HG5143F telnetadmin 优先）。
    显式给出的用户名只补同名派生账号的密码。
    """
    if password is not None or not derived_credentials_enabled(args):
        return [(username, password)]

    explicit_derived = bool(getattr(args, "use_derived_credentials", False))
    if username and username not in DERIVED_TELNET_USERNAMES:
        if explicit_derived:
            raise CliError(
                f"{explicit_flag_name} 只能为默认 Telnet 账号"
                f"（{'/'.join(sorted(DERIVED_TELNET_USERNAMES))}）补齐密码；"
                "自定义用户名需要同时提供密码"
            )
        return [(username, None)]

    mac, _mac_source = resolve_mac(args, ip, required=True)
    assert mac is not None
    candidates = telnet_login_candidates(mac)
    if username:
        return [(u, p) for _kind, u, p in candidates if u == username]
    return [(u, p) for _kind, u, p in candidates]


def resolve_su_password_from_shell(
    args: argparse.Namespace,
    *,
    ip: str,
    shell: Any,
) -> tuple[str, str]:
    """解析当前 su root 密码:显式参数优先,否则读 /var/telsu hash 本地验证候选公式。

    返回 (password, source);source 形如 "argument"/"stdin"/"verified-telsu:<kind>"。
    无法自动验证时抛 CliError,绝不盲猜密码。
    """
    has_password = getattr(args, "su_password", None) is not None
    has_stdin = getattr(args, "su_password_stdin", False)
    if has_password and has_stdin:
        raise CliError("当前 su root 密码只能选择 --su-password 或 --su-password-stdin")
    if has_stdin:
        if getattr(args, "password_stdin", False) or getattr(args, "telnet_password_stdin", False):
            raise CliError("--su-password-stdin 不能和其它 stdin 密码选项同时使用")
        return (
            read_stdin_secret("请输入当前 su root 密码(--su-password-stdin)，回车确认："),
            "stdin",
        )
    if has_password:
        return str(args.su_password), "argument"

    mac, _mac_source = resolve_mac(args, ip, required=True)
    assert mac is not None
    raw = shell.run(f"cat {SU_RUNTIME_PASSWORD_FILE}")
    hashed = extract_crypt_hash(raw)
    if hashed is None:
        raise CliError(
            f"无法从 admin shell 读取或识别 {SU_RUNTIME_PASSWORD_FILE} 中的密码 hash"
            "（可能权限不足或输出异常）；"
            "请显式提供 --su-password 或 --su-password-stdin"
        )
    verified = verify_su_password_candidates(hashed, mac)
    if verified is None:
        raise CliError(
            f"{SU_RUNTIME_PASSWORD_FILE} hash（{crypt_kind(hashed)}）与已知候选公式"
            f"（{'/'.join(kind for kind, _ in su_password_candidates(mac))}）都不匹配，"
            "root 密码可能已被修改或来自未知固件公式；"
            "请显式提供 --su-password 或 --su-password-stdin。"
            "该型号可能尚未收录：想让 fh-tool 支持它？运行 fh-tool adapt-prompt 生成"
            "调研 prompt 交给你的 AI agent，或参考 "
            "https://github.com/gxxk-dev/fh_tool-cli/blob/main/ADAPT.md 提交适配"
        )
    kind, password = verified
    return password, f"verified-telsu:{kind}"
