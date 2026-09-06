from __future__ import annotations

import logging
import socket
from dataclasses import dataclass

from ..config_store import decode_text
from ..errors import FHToolError
from ..output import log_event

# Telnet 协议控制字节（RFC 854）。
_IAC = 0xFF
_SB = 0xFA
_SE = 0xF0
_WILL = 0xFB
_WONT = 0xFC
_DO = 0xFD
_DONT = 0xFE

# 登录提示与失败标记统一小写比较：HG6142A3 telnetd 输出 "Login:"/"Password:"（首字母大写），
# HG5143F 输出小写 "login:"，匹配不能依赖大小写。
_LOGIN_PROMPTS = (b"login:", b"username:")
_PASSWORD_PROMPTS = (b"password:",)
_AUTH_PROMPTS = _LOGIN_PROMPTS + _PASSWORD_PROMPTS
_AUTH_FAILURE_MARKERS = (b"incorrect", b"failed", b"denied", b"rejected", b"bad password")
_SHELL_PROMPT_CHARS = (b"#", b"$", b">")


@dataclass(frozen=True)
class TelnetCredentials:
    host: str
    port: int = 23
    username: str | None = None
    password: str | None = None
    timeout: float = 5.0


class TelnetShell:
    def __init__(self, credentials: TelnetCredentials):
        self.credentials = credentials

    def run(self, command: str) -> str:
        log_event(
            logging.INFO,
            "telnet.command.start",
            host=self.credentials.host,
            port=self.credentials.port,
            username_present=bool(self.credentials.username),
            password_present=bool(self.credentials.password),
        )
        try:
            output = self._session(command)
        except OSError as exc:
            log_event(
                logging.INFO,
                "telnet.command.error",
                host=self.credentials.host,
                port=self.credentials.port,
                error=str(exc),
            )
            raise FHToolError(f"Telnet command failed: {exc}") from exc
        log_event(
            logging.INFO,
            "telnet.command.success",
            host=self.credentials.host,
            port=self.credentials.port,
            output_bytes=len(output.encode("utf-8")),
        )
        return output

    def run_as_root(self, command: str, *, su_password: str) -> str:
        log_event(
            logging.INFO,
            "telnet.root_command.start",
            host=self.credentials.host,
            port=self.credentials.port,
            username_present=bool(self.credentials.username),
            telnet_password_present=bool(self.credentials.password),
            su_password_present=bool(su_password),
        )
        try:
            output = self._root_session(command, su_password=su_password)
        except OSError as exc:
            log_event(
                logging.INFO,
                "telnet.root_command.error",
                host=self.credentials.host,
                port=self.credentials.port,
                error=str(exc),
            )
            raise FHToolError(f"Telnet root command failed: {exc}") from exc
        log_event(
            logging.INFO,
            "telnet.root_command.success",
            host=self.credentials.host,
            port=self.credentials.port,
            output_bytes=len(output.encode("utf-8")),
        )
        return output

    def _session(self, command: str) -> str:
        with socket.create_connection(
            (self.credentials.host, self.credentials.port),
            timeout=self.credentials.timeout,
        ) as sock:
            sock.settimeout(self.credentials.timeout)
            reader = _TelnetReader(sock)
            _authenticate(reader, self.credentials)
            _send_line(sock, command)
            _send_line(sock, "exit")
            return decode_text(_read_all(sock))

    def _root_session(self, command: str, *, su_password: str) -> str:
        with socket.create_connection(
            (self.credentials.host, self.credentials.port),
            timeout=self.credentials.timeout,
        ) as sock:
            sock.settimeout(self.credentials.timeout)
            reader = _TelnetReader(sock)
            _authenticate(reader, self.credentials)
            _send_line(sock, "su root")
            if reader.read_until(_PASSWORD_PROMPTS, stage="su") is None:
                _warn_prompt_unconfirmed(self.credentials, "su")
            _send_line(sock, su_password)
            if not reader.wait_shell_prompt(stage="su"):
                _warn_prompt_unconfirmed(self.credentials, "shell")
            _send_line(sock, command)
            _send_line(sock, "exit")
            _send_line(sock, "exit")
            return decode_text(_read_all(sock))


def _authenticate(reader: _TelnetReader, credentials: TelnetCredentials) -> None:
    """等 Login: → 发用户名 → 等 Password: → 发密码 → 等 shell prompt。

    所有提示符大小写不敏感；认证失败（失败标记/登录提示回弹）或连接关闭直接抛
    FHToolError；超时未确认 prompt 时降级为继续发送（记录 warning）。
    """
    if credentials.username:
        if reader.read_until(_LOGIN_PROMPTS, stage="login", check_failures=False) is None:
            _warn_prompt_unconfirmed(credentials, "login")
        _send_line(reader.sock, credentials.username)
    if credentials.password:
        if reader.read_until(_PASSWORD_PROMPTS, stage="login") is None:
            _warn_prompt_unconfirmed(credentials, "password")
        _send_line(reader.sock, credentials.password)
        if not reader.wait_shell_prompt(stage="login"):
            _warn_prompt_unconfirmed(credentials, "shell")
    elif credentials.username:
        # 只有用户名：等 shell 出现；若设备反而要求密码会显式报认证失败。
        if not reader.wait_shell_prompt(stage="login"):
            _warn_prompt_unconfirmed(credentials, "shell")


class _TelnetReader:
    """单次连接内的读状态机：剥离 IAC、等待提示符、识别认证失败。

    marker 匹配全部大小写不敏感；`_scan` 记录上一阶段已消费位置，
    避免把上一阶段的提示符/横幅误判为本阶段的失败信号。
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._pending = b""
        self._clean = bytearray()
        self._scan = 0

    def _feed(self, chunk: bytes) -> None:
        data = self._pending + chunk
        clean, replies, consumed = _strip_iac(data)
        self._pending = data[consumed:]
        if replies:
            self.sock.sendall(replies)
        self._clean.extend(clean)

    def _lowered(self) -> bytes:
        return bytes(self._clean).lower()

    def read_until(
        self,
        markers: tuple[bytes, ...],
        *,
        stage: str,
        check_failures: bool = True,
    ) -> bytes | None:
        """等待任一 marker（case-insensitive）；命中返回匹配的小写 marker，超时返回 None。

        EOF 与认证失败（失败标记/回弹到其它登录提示）直接抛 FHToolError。
        check_failures=False 用于认证前的登录提示阶段，横幅内容不做失败判定。
        """
        needles = tuple(marker.lower() for marker in markers)
        while True:
            lowered = self._lowered()
            region = lowered[self._scan :]
            if check_failures:
                _raise_on_failure_markers(stage, region)
                _raise_on_reprompts(stage, region, exclude=needles)
            for needle in needles:
                index = lowered.find(needle, self._scan)
                if index != -1:
                    self._scan = index + len(needle)
                    return needle
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                return None
            if not chunk:
                raise FHToolError(f"Telnet connection closed during {stage}")
            self._feed(chunk)

    def wait_shell_prompt(self, *, stage: str) -> bool:
        """等待行尾 shell prompt（#/$/>）。

        失败标记或回弹登录提示抛 FHToolError；返回是否确认到 prompt，
        超时返回 False，由调用方降级为直接发送命令。
        """
        while True:
            lowered = self._lowered()
            region = lowered[self._scan :]
            _raise_on_failure_markers(stage, region)
            _raise_on_reprompts(stage, region, exclude=())
            tail = bytes(self._clean[self._scan :]).replace(b"\r", b"").rstrip()
            if tail.endswith(_SHELL_PROMPT_CHARS):
                self._scan = len(self._clean)
                return True
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                self._scan = len(self._clean)
                return False
            if not chunk:
                raise FHToolError(f"Telnet connection closed during {stage}")
            self._feed(chunk)


def _strip_iac(data: bytes) -> tuple[bytes, bytes, int]:
    """剥离 IAC 控制序列，返回 (净数据, 应答字节, 已消费字节数)。

    对 DO/WILL 回应 WONT/DONT（不启用任何选项），SB 子协商整段跳过；
    末尾不完整的序列留待下一个 chunk 拼接后重新解析。
    """
    clean = bytearray()
    replies = bytearray()
    index = 0
    total = len(data)
    while index < total:
        byte = data[index]
        if byte != _IAC:
            clean.append(byte)
            index += 1
            continue
        if index + 1 >= total:
            break
        command = data[index + 1]
        if command == _IAC:
            clean.append(_IAC)
            index += 2
        elif command in (_DO, _WILL, _DONT, _WONT):
            if index + 2 >= total:
                break
            option = data[index + 2]
            if command == _DO:
                replies.extend((_IAC, _WONT, option))
            elif command == _WILL:
                replies.extend((_IAC, _DONT, option))
            index += 3
        elif command == _SB:
            end = _find_subnegotiation_end(data, index + 2)
            if end is None:
                break
            index = end
        else:
            index += 2
    return bytes(clean), bytes(replies), index


def _find_subnegotiation_end(data: bytes, start: int) -> int | None:
    index = start
    while index + 1 < len(data):
        if data[index] == _IAC and data[index + 1] == _SE:
            return index + 2
        index += 1
    return None


def _raise_on_failure_markers(stage: str, region: bytes) -> None:
    for marker in _AUTH_FAILURE_MARKERS:
        if marker in region:
            raise _auth_failure(stage, marker)


def _raise_on_reprompts(stage: str, region: bytes, *, exclude: tuple[bytes, ...]) -> None:
    """重新出现登录/密码提示说明认证被弹回（排除本阶段正在等待的提示）。

    前导空白（上一提示符残留空格、\r\n）不算内容；"Last login:" 这类横幅里
    login: 前有非空白字符，不会误判。
    """
    stripped = region.lstrip(b" \t\r\n")
    for prompt in _AUTH_PROMPTS:
        if prompt in exclude:
            continue
        if stripped.startswith(prompt) or b"\n" + prompt in stripped:
            raise _auth_failure(stage, prompt)


def _auth_failure(stage: str, marker: bytes) -> FHToolError:
    reason = marker.decode("ascii", errors="replace")
    log_event(logging.INFO, "telnet.auth.failed", stage=stage, marker=reason)
    return FHToolError(f"Telnet {stage} failed: {reason}")


def _warn_prompt_unconfirmed(credentials: TelnetCredentials, stage: str) -> None:
    log_event(
        logging.WARNING,
        "telnet.prompt.unconfirmed",
        host=credentials.host,
        port=credentials.port,
        stage=stage,
    )


def _send_line(sock: socket.socket, text: str) -> None:
    sock.sendall(text.encode("utf-8") + b"\n")


def _read_all(sock: socket.socket) -> bytes:
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        data.extend(chunk)
    # 命令输出阶段同样剥离 IAC；exit 已发送，无需再回应协商。
    clean, _replies, _consumed = _strip_iac(bytes(data))
    return clean
