from __future__ import annotations

import socket
from dataclasses import dataclass

from ..config_store import decode_text
from ..errors import FHToolError


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
        try:
            with socket.create_connection(
                (self.credentials.host, self.credentials.port),
                timeout=self.credentials.timeout,
            ) as sock:
                sock.settimeout(self.credentials.timeout)
                if self.credentials.username:
                    _read_until(sock, b"login:")
                    sock.sendall(self.credentials.username.encode("utf-8") + b"\n")
                if self.credentials.password:
                    _read_until(sock, b"Password:")
                    sock.sendall(self.credentials.password.encode("utf-8") + b"\n")
                sock.sendall(command.encode("utf-8") + b"\n")
                sock.sendall(b"exit\n")
                return decode_text(_read_all(sock))
        except OSError as exc:
            raise FHToolError(f"Telnet command failed: {exc}") from exc


def _read_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


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
    return bytes(data)
