from __future__ import annotations

import shlex
import sys
from dataclasses import dataclass
from secrets import token_urlsafe
from typing import Any

from .backends.cfg_cmd import CfgCmdBackend, cfg_set_with_verify, redact_cfg_value
from .errors import CliError

WEB_ADMIN_PASSWORD_PATH = "InternetGatewayDevice.DeviceInfo.X_CT-COM_TeleComAccount.Password"
TELNET_PASSWORD_PATH = "InternetGatewayDevice.DeviceInfo.X_CT-COM_ServiceManage.TelnetPassword"
TELNET_USERNAME_PATH = "InternetGatewayDevice.DeviceInfo.X_CT-COM_ServiceManage.TelnetUserName"
SU_RUNTIME_PASSWORD_FILE = "/var/telsu"


@dataclass(frozen=True)
class PasswordInput:
    password: str
    generated: bool = False


def read_secret_from_args(args: Any) -> PasswordInput:
    selected = [
        getattr(args, "password", None) is not None,
        getattr(args, "password_stdin", False),
        getattr(args, "generate", False),
    ]
    if sum(1 for item in selected if item) != 1:
        raise CliError("必须且只能选择 --password、--password-stdin 或 --generate")
    if getattr(args, "password", None) is not None:
        return PasswordInput(str(args.password), generated=False)
    if getattr(args, "password_stdin", False):
        return PasswordInput(sys.stdin.readline().rstrip("\n"), generated=False)
    return PasswordInput(token_urlsafe(18), generated=True)


def account_show(backend: CfgCmdBackend, *, reveal_secrets: bool = False) -> dict[str, Any]:
    paths = {
        "web_admin_password": WEB_ADMIN_PASSWORD_PATH,
        "telnet_password": TELNET_PASSWORD_PATH,
        "telnet_username": TELNET_USERNAME_PATH,
    }
    values: dict[str, Any] = {}
    for name, path in paths.items():
        value = backend.get(path)
        rendered, redacted = redact_cfg_value(path, value, reveal_secrets=reveal_secrets)
        values[name] = {
            "path": path,
            "value": rendered,
            "redacted": redacted,
        }
    return {"accounts": values}


def set_web_admin_password(backend: CfgCmdBackend, password: str) -> dict[str, Any]:
    result = cfg_set_with_verify(backend, WEB_ADMIN_PASSWORD_PATH, password)
    return _redact_write_result(result)


def set_telnet_password(backend: CfgCmdBackend, password: str) -> dict[str, Any]:
    result = cfg_set_with_verify(backend, TELNET_PASSWORD_PATH, password)
    return _redact_write_result(result)


def set_telnet_username(backend: CfgCmdBackend, name: str) -> dict[str, Any]:
    return cfg_set_with_verify(backend, TELNET_USERNAME_PATH, name)


def set_su_runtime_password(shell_runner: Any, password: str) -> dict[str, Any]:
    command = f"printf %s {shlex.quote(password)} > {shlex.quote(SU_RUNTIME_PASSWORD_FILE)}"
    shell_runner(command)
    return {
        "path": SU_RUNTIME_PASSWORD_FILE,
        "runtime_only": True,
        "persistent": False,
        "value": "[REDACTED]",
        "risk": "danger",
    }


def _redact_write_result(result: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(result)
    redacted["value"] = "[REDACTED]"
    if "observed" in redacted:
        redacted["observed"] = "[REDACTED]"
    redacted["redacted"] = True
    return redacted
