from __future__ import annotations

import shlex
import sys
from dataclasses import dataclass
from hashlib import md5
from secrets import token_urlsafe
from typing import Any

from .backends.cfg_cmd import CfgCmdBackend, cfg_set_with_verify, redact_cfg_value
from .errors import CliError

WEB_ADMIN_PASSWORD_PATH = "InternetGatewayDevice.DeviceInfo.X_CT-COM_TeleComAccount.Password"
TELNET_PASSWORD_PATH = "InternetGatewayDevice.DeviceInfo.X_CT-COM_ServiceManage.TelnetPassword"
TELNET_USERNAME_PATH = "InternetGatewayDevice.DeviceInfo.X_CT-COM_ServiceManage.TelnetUserName"
SU_RUNTIME_PASSWORD_FILE = "/var/telsu"
_MD5_CRYPT_MAGIC = b"$1$"
_MD5_CRYPT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


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
    hashed_password = _md5_crypt_empty_salt(password)
    passwd_entry = f"root:{hashed_password}:0:0:Telnet user:/:/bin/ash"
    command = f"printf '%s\\n' {shlex.quote(passwd_entry)} > {shlex.quote(SU_RUNTIME_PASSWORD_FILE)}"
    shell_runner(command)
    return {
        "path": SU_RUNTIME_PASSWORD_FILE,
        "runtime_only": True,
        "persistent": False,
        "value": "[REDACTED]",
        "risk": "danger",
    }


def _md5_crypt_empty_salt(password: str) -> str:
    return _md5_crypt(password.encode(), b"")


def _md5_crypt(password: bytes, salt: bytes) -> str:
    if len(salt) > 8:
        salt = salt[:8]

    digest = md5(password + _MD5_CRYPT_MAGIC + salt)
    alternate = md5(password + salt + password).digest()
    password_len = len(password)

    remaining = password_len
    while remaining > 0:
        digest.update(alternate[: min(16, remaining)])
        remaining -= 16

    remaining = password_len
    while remaining > 0:
        if remaining & 1:
            digest.update(b"\x00")
        else:
            digest.update(password[:1])
        remaining >>= 1

    final = digest.digest()
    for index in range(1000):
        digest = md5()
        digest.update(password if index & 1 else final)
        if index % 3:
            digest.update(salt)
        if index % 7:
            digest.update(password)
        digest.update(final if index & 1 else password)
        final = digest.digest()

    encoded = (
        _md5_crypt_base64(final[0], final[6], final[12], 4)
        + _md5_crypt_base64(final[1], final[7], final[13], 4)
        + _md5_crypt_base64(final[2], final[8], final[14], 4)
        + _md5_crypt_base64(final[3], final[9], final[15], 4)
        + _md5_crypt_base64(final[4], final[10], final[5], 4)
        + _md5_crypt_base64(0, 0, final[11], 2)
    )
    return f"$1${salt.decode()}${encoded}"


def _md5_crypt_base64(byte2: int, byte1: int, byte0: int, length: int) -> str:
    value = (byte2 << 16) | (byte1 << 8) | byte0
    encoded = []
    for _ in range(length):
        encoded.append(_MD5_CRYPT_ALPHABET[value & 0x3F])
        value >>= 6
    return "".join(encoded)


def _redact_write_result(result: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(result)
    redacted["value"] = "[REDACTED]"
    if "observed" in redacted:
        redacted["observed"] = "[REDACTED]"
    redacted["redacted"] = True
    return redacted
