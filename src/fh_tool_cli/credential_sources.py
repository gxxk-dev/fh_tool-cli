from __future__ import annotations

import argparse

from .config_store import resolve_mac
from .credentials import HG5143F_TELNET_USERNAME, derive_hg5143f_su, derive_hg5143f_telnet
from .errors import CliError


def derived_credentials_enabled(args: argparse.Namespace) -> bool:
    return not getattr(args, "no_derived_credentials", False)


def complete_hg5143f_telnet_login(
    args: argparse.Namespace,
    *,
    ip: str,
    username: str | None,
    password: str | None,
    explicit_flag_name: str = "--use-derived-credentials",
) -> tuple[str | None, str | None]:
    if password is not None or not derived_credentials_enabled(args):
        return username, password

    explicit_derived = bool(getattr(args, "use_derived_credentials", False))
    if username and username != HG5143F_TELNET_USERNAME:
        if explicit_derived:
            raise CliError(
                f"{explicit_flag_name} 只能为默认 HG5143F Telnet 账号补齐密码；"
                "自定义用户名需要同时提供密码"
            )
        return username, password

    mac, _mac_source = resolve_mac(args, ip, required=True)
    assert mac is not None
    derived = derive_hg5143f_telnet(mac)
    return username or derived.username, derived.password


def derive_hg5143f_su_password_from_args(
    args: argparse.Namespace,
    *,
    ip: str,
) -> str:
    mac, _mac_source = resolve_mac(args, ip, required=True)
    assert mac is not None
    return derive_hg5143f_su(mac).password
