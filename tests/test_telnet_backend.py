from __future__ import annotations

import unittest
from unittest.mock import patch

from fh_tool_cli.backends.telnet import TelnetCredentials, TelnetShell


class FakeSocket:
    def __init__(self, reads: list[bytes]):
        self.reads = reads
        self.sent: list[bytes] = []
        self.timeout: float | None = None

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        if self.reads:
            return self.reads.pop(0)
        return b""

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


class TelnetBackendTests(unittest.TestCase):
    def test_run_as_root_sends_su_sequence(self) -> None:
        fake_socket = FakeSocket(
            [
                b"login:",
                b"Password:",
                b"Password:",
                b"# id\nuid=0(root)\n",
                b"",
            ]
        )
        shell = TelnetShell(
            TelnetCredentials(
                host="192.168.1.1",
                username="telnetadmin",
                password="telnet-secret",
                timeout=3,
            )
        )

        with patch("socket.create_connection", return_value=fake_socket) as create_connection:
            output = shell.run_as_root("id", su_password="su-secret")

        create_connection.assert_called_once_with(("192.168.1.1", 23), timeout=3)
        self.assertEqual(
            fake_socket.sent,
            [
                b"telnetadmin\n",
                b"telnet-secret\n",
                b"su root\n",
                b"su-secret\n",
                b"id\n",
                b"exit\n",
                b"exit\n",
            ],
        )
        self.assertIn("uid=0(root)", output)


if __name__ == "__main__":
    unittest.main()
