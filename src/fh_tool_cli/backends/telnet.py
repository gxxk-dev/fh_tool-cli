from __future__ import annotations

import socket
import logging
from dataclasses import dataclass

from ..config_store import decode_text
from ..errors import FHToolError
from ..output import log_event


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
                output = decode_text(_read_all(sock))
                log_event(
                    logging.INFO,
                    "telnet.command.success",
                    host=self.credentials.host,
                    port=self.credentials.port,
                    output_bytes=len(output.encode("utf-8")),
                )
                return output
        except OSError as exc:
            log_event(
                logging.INFO,
                "telnet.command.error",
                host=self.credentials.host,
                port=self.credentials.port,
                error=str(exc),
            )
            raise FHToolError(f"Telnet command failed: {exc}") from exc

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
                sock.sendall(b"su root\n")
                _read_until(sock, b"Password:")
                sock.sendall(su_password.encode("utf-8") + b"\n")
                sock.sendall(command.encode("utf-8") + b"\n")
                sock.sendall(b"exit\n")
                sock.sendall(b"exit\n")
                output = decode_text(_read_all(sock))
                log_event(
                    logging.INFO,
                    "telnet.root_command.success",
                    host=self.credentials.host,
                    port=self.credentials.port,
                    output_bytes=len(output.encode("utf-8")),
                )
                return output
        except OSError as exc:
            log_event(
                logging.INFO,
                "telnet.root_command.error",
                host=self.credentials.host,
                port=self.credentials.port,
                error=str(exc),
            )
            raise FHToolError(f"Telnet root command failed: {exc}") from exc


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
