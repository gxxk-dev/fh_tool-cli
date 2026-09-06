from __future__ import annotations

import unittest
from unittest.mock import patch

from fh_tool_cli.backends.telnet import TelnetCredentials, TelnetShell
from fh_tool_cli.errors import FHToolError


class FakeSocket:
    def __init__(self, reads: list[bytes], *, timeouts_after: bool = False):
        self.reads = reads
        self.sent: list[bytes] = []
        self.timeout: float | None = None
        self.timeouts_after = timeouts_after

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        if self.reads:
            return self.reads.pop(0)
        if self.timeouts_after:
            raise TimeoutError("timed out")
        return b""

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


def _credentials(**overrides: object) -> TelnetCredentials:
    values: dict = {
        "host": "192.168.1.1",
        "username": "telnetadmin",
        "password": "telnet-secret",
        "timeout": 3,
    }
    values.update(overrides)
    return TelnetCredentials(**values)


def _connect(fake_socket: FakeSocket):
    return patch("socket.create_connection", return_value=fake_socket)


class TelnetBackendTests(unittest.TestCase):
    def test_run_as_root_sends_su_sequence(self) -> None:
        fake_socket = FakeSocket(
            [
                b"login:",
                b"Password:",
                b"# ",
                b"Password: ",
                b"# ",
                b"uid=0(root)\n",
                b"",
            ]
        )
        shell = TelnetShell(_credentials())

        with _connect(fake_socket) as create_connection:
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

    def test_hg6142a3_uppercase_prompts_and_iac_negotiation(self) -> None:
        fake_socket = FakeSocket(
            [
                b"\xff\xfd\x18",
                b"Login: ",
                b"Password: ",
                b"~ # ",
                b"Password: ",
                b"# ",
                b"uid=0(root)\n",
                b"",
            ]
        )
        shell = TelnetShell(_credentials())

        with _connect(fake_socket):
            output = shell.run_as_root("id", su_password="su-secret")

        # IAC DO 被回应 WONT，且不干扰后续大小写不敏感的 Login:/Password: 匹配。
        self.assertEqual(
            fake_socket.sent,
            [
                b"\xff\xfc\x18",
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

    def test_run_with_uppercase_login_prompt(self) -> None:
        fake_socket = FakeSocket(
            [
                b"Login: ",
                b"Password: ",
                b"~ # ",
                b"uid=100(fiberhome)\n",
                b"",
            ]
        )
        shell = TelnetShell(_credentials(username="fiberhome", password="fh-secret"))

        with _connect(fake_socket):
            output = shell.run("id")

        self.assertEqual(
            fake_socket.sent,
            [
                b"fiberhome\n",
                b"fh-secret\n",
                b"id\n",
                b"exit\n",
            ],
        )
        self.assertIn("uid=100(fiberhome)", output)

    def test_iac_inside_prompt_does_not_break_matching(self) -> None:
        fake_socket = FakeSocket(
            [
                b"Log\xff\xfd\x18in: ",
                b"Password: ",
                b"# ",
                b"ok\n",
                b"",
            ]
        )
        shell = TelnetShell(_credentials())

        with _connect(fake_socket):
            output = shell.run("id")

        self.assertIn(b"\xff\xfc\x18", fake_socket.sent)
        self.assertEqual(fake_socket.sent[1:], [b"telnetadmin\n", b"telnet-secret\n", b"id\n", b"exit\n"])
        self.assertEqual(output, "ok\n")

    def test_login_failure_is_explicit_error(self) -> None:
        fake_socket = FakeSocket(
            [
                b"Login: ",
                b"Password: ",
                b"Login incorrect\r\nLogin: ",
                b"",
            ]
        )
        shell = TelnetShell(_credentials())

        with _connect(fake_socket):
            with self.assertRaises(FHToolError) as ctx:
                shell.run("id")

        message = str(ctx.exception)
        self.assertIn("Telnet login failed", message)
        self.assertIn("incorrect", message)
        # 认证失败时命令不应被盲发。
        self.assertNotIn(b"id\n", fake_socket.sent)

    def test_connection_closed_before_login_prompt(self) -> None:
        fake_socket = FakeSocket([b""])
        shell = TelnetShell(_credentials())

        with _connect(fake_socket):
            with self.assertRaises(FHToolError) as ctx:
                shell.run("id")

        self.assertIn("connection closed during login", str(ctx.exception))

    def test_su_reprompt_is_auth_failure(self) -> None:
        fake_socket = FakeSocket(
            [
                b"Login: ",
                b"Password: ",
                b"~ # ",
                b"Password: ",
                b"Password: ",
                b"",
            ]
        )
        shell = TelnetShell(_credentials())

        with _connect(fake_socket):
            with self.assertRaises(FHToolError) as ctx:
                shell.run_as_root("id", su_password="wrong-su")

        self.assertIn("Telnet su failed", str(ctx.exception))
        self.assertNotIn(b"id\n", fake_socket.sent)

    def test_no_credentials_sends_command_directly(self) -> None:
        fake_socket = FakeSocket([b"uid=0(root)\n", b""])
        shell = TelnetShell(_credentials(username=None, password=None))

        with _connect(fake_socket):
            output = shell.run("id")

        self.assertEqual(fake_socket.sent, [b"id\n", b"exit\n"])
        self.assertIn("uid=0(root)", output)

    def test_username_only_password_prompt_is_auth_failure(self) -> None:
        fake_socket = FakeSocket([b"Login: ", b"Password: ", b""])
        shell = TelnetShell(_credentials(password=None))

        with _connect(fake_socket):
            with self.assertRaises(FHToolError) as ctx:
                shell.run("id")

        self.assertIn("Telnet login failed", str(ctx.exception))

    def test_shell_prompt_timeout_degrades_to_send(self) -> None:
        fake_socket = FakeSocket([b"Login: ", b"Password: "], timeouts_after=True)
        shell = TelnetShell(_credentials())

        with _connect(fake_socket):
            output = shell.run("id")

        # prompt 未确认时降级为继续发送命令，不抛错。
        self.assertIn(b"id\n", fake_socket.sent)
        self.assertIn(b"exit\n", fake_socket.sent)
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
