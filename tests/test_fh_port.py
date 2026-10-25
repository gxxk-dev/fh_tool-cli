from __future__ import annotations

import argparse
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import requests

from fh_tool_cli import cli
from fh_tool_cli.argparse_utils import normalize_port
from fh_tool_cli.backends.fh_tool import (
    api_payload,
    call_method,
    check_fh_tool_port,
    classify_response_body,
    fh_tool_call,
    probe_fh_port_candidates,
    resolve_fh_port,
)
from fh_tool_cli.client import make_download_url
from fh_tool_cli.crypto import derive_crypto, encrypt_payload
from fh_tool_cli.errors import FHToolError, FHToolHttpError, FHToolResponseError

TEST_IP = "192.168.1.1"
TEST_MAC = "AABBCCDDEEFF"


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


def _encrypted_ok_response(result: int = 0) -> _FakeResponse:
    crypto = derive_crypto(TEST_MAC)
    return _FakeResponse(status_code=200, text=encrypt_payload({"result": result}, crypto))


def _args(**overrides) -> argparse.Namespace:
    values: dict = {
        "ip": TEST_IP,
        "mac": TEST_MAC,
        "timeout": 1.0,
        "fh_port": None,
        "config": "/nonexistent/fh-tool-test.json",
        "ask_mac": False,
        "json": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class NormalizePortTests(unittest.TestCase):
    def test_accepts_valid_port(self) -> None:
        self.assertEqual(normalize_port("80"), 80)
        self.assertEqual(normalize_port("65535"), 65535)

    def test_rejects_zero(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_port("0")

    def test_rejects_out_of_range(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_port("70000")

    def test_rejects_non_numeric(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_port("abc")


class ResolveFhPortTests(unittest.TestCase):
    def test_explicit_argument_skips_probing(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=AssertionError("should not probe")):
            self.assertEqual(
                resolve_fh_port(_args(fh_port=80), TEST_IP, mac=TEST_MAC, timeout=1.0),
                (80, "argument"),
            )

    def test_default_8080_when_tcp_open(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True) as tcp_mock,
            patch(
                "fh_tool_cli.backends.fh_tool.check_fh_tool_port",
                return_value=(True, False),
            ) as check_mock,
        ):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0),
                (8080, "default"),
            )
        tcp_mock.assert_called_once_with(TEST_IP, 8080, 1.0)
        check_mock.assert_called_once_with(TEST_IP, 8080, TEST_MAC, 1.0, path="/fh_tool/api")

    def test_8080_wrong_service_switches_to_verified_candidate(self) -> None:
        # 8080 是 Web UI（200 但响应体不是密文）、fh_tool API 在 80：必须自动换端口。
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[True, True]),
            patch(
                "fh_tool_cli.backends.fh_tool.check_fh_tool_port",
                side_effect=[(False, True), (True, False)],
            ),
        ):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0),
                (80, "auto_detected"),
            )

    def test_8080_api_error_keeps_default_port(self) -> None:
        # HTTP 500 等 API 自身错误说明端口选对了，不应触发换端口。
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True) as tcp_mock,
            patch(
                "fh_tool_cli.backends.fh_tool.check_fh_tool_port",
                return_value=(False, False),
            ),
        ):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0),
                (8080, "default"),
            )
        tcp_mock.assert_called_once_with(TEST_IP, 8080, 1.0)

    def test_fallback_detected_by_getdevinfo(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch(
                "fh_tool_cli.backends.fh_tool.check_fh_tool_port",
                return_value=(True, False),
            ) as check_mock,
        ):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0),
                (80, "auto_detected"),
            )
        check_mock.assert_called_once_with(TEST_IP, 80, TEST_MAC, 1.0, path="/fh_tool/api")

    def test_fallback_requires_getdevinfo_when_mac_known(self) -> None:
        # 有 MAC 时不再用“任意 HTTP 响应”兜底，避免选中 80 上的 Web UI。
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch(
                "fh_tool_cli.backends.fh_tool.check_fh_tool_port",
                return_value=(False, True),
            ),
            patch("fh_tool_cli.backends.fh_tool.requests.get") as get_mock,
        ):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0),
                (8080, "default_unverified"),
            )
        get_mock.assert_not_called()

    def test_fallback_uses_surface_without_mac(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch("fh_tool_cli.backends.fh_tool.requests.get", return_value=_FakeResponse(404)),
        ):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=None, timeout=1.0),
                (80, "auto_detected"),
            )

    def test_fallback_skips_candidate_when_surface_unreachable(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch(
                "fh_tool_cli.backends.fh_tool.requests.get",
                side_effect=requests.ConnectionError("refused"),
            ),
        ):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=None, timeout=1.0),
                (8080, "default_unverified"),
            )

    def test_all_closed_falls_back_to_default_unverified(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=False):
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0),
                (8080, "default_unverified"),
            )

    def test_default_port_candidates_are_skipped(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=False) as tcp_mock:
            self.assertEqual(
                resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0, candidates=(8080,)),
                (8080, "default_unverified"),
            )
        tcp_mock.assert_called_once_with(TEST_IP, 8080, 1.0)

    def test_missing_fh_port_attr_is_tolerated(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True):
            self.assertEqual(
                resolve_fh_port(argparse.Namespace(ip=TEST_IP), TEST_IP, timeout=1.0),
                (8080, "default"),
            )


class FhToolCallUrlTests(unittest.TestCase):
    def test_uses_explicit_port_in_url(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()) as post_mock:
            result = fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0, port=80)
        self.assertEqual(result, {"result": 0})
        self.assertEqual(post_mock.call_args.args[0], "http://192.168.1.1:80/fh_tool/api")

    def test_default_port_is_8080(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()) as post_mock:
            fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0)
        self.assertEqual(post_mock.call_args.args[0], "http://192.168.1.1:8080/fh_tool/api")


class MakeDownloadUrlTests(unittest.TestCase):
    def test_default_port(self) -> None:
        self.assertEqual(make_download_url(TEST_IP, "/fh_tool/tool_download?a=b"), "http://192.168.1.1:8080/fh_tool/tool_download?a=b")

    def test_explicit_port(self) -> None:
        self.assertEqual(make_download_url(TEST_IP, "/fh_tool/tool_download", port=80), "http://192.168.1.1:80/fh_tool/tool_download")

    def test_absolute_url_is_untouched(self) -> None:
        self.assertEqual(make_download_url(TEST_IP, "http://example.com/file.bin", port=80), "http://example.com/file.bin")


class CheckFhToolPortTests(unittest.TestCase):
    def test_ok_when_getdevinfo_succeeds(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()):
            self.assertEqual(check_fh_tool_port(TEST_IP, 8080, TEST_MAC, 1.0), (True, False))

    def test_html_200_marks_wrong_service(self) -> None:
        response = _FakeResponse(200, "<html>web ui</html>", {"Content-Type": "text/html"})
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            self.assertEqual(check_fh_tool_port(TEST_IP, 8080, TEST_MAC, 1.0), (False, True))

    def test_http_404_marks_wrong_service(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_FakeResponse(404)):
            self.assertEqual(check_fh_tool_port(TEST_IP, 8080, TEST_MAC, 1.0), (False, True))

    def test_http_500_keeps_port(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_FakeResponse(500)):
            self.assertEqual(check_fh_tool_port(TEST_IP, 8080, TEST_MAC, 1.0), (False, False))

    def test_connection_error_keeps_port(self) -> None:
        with patch(
            "fh_tool_cli.backends.fh_tool.requests.post",
            side_effect=requests.ConnectionError("refused"),
        ):
            self.assertEqual(check_fh_tool_port(TEST_IP, 8080, TEST_MAC, 1.0), (False, False))


class ClassifyResponseBodyTests(unittest.TestCase):
    def test_empty_body(self) -> None:
        self.assertEqual(classify_response_body("  \r\n"), "empty")

    def test_html_body(self) -> None:
        self.assertEqual(classify_response_body("<!DOCTYPE html><html>login</html>"), "html")

    def test_plaintext_json_body(self) -> None:
        self.assertEqual(classify_response_body('{"result":0}'), "json")

    def test_base64_ciphertext_body(self) -> None:
        self.assertEqual(classify_response_body(encrypt_payload({"result": 0}, derive_crypto(TEST_MAC))), "base64")

    def test_short_base64_is_text(self) -> None:
        # 不是 AES 块长度的 base64 不是 fh_tool 密文,归入普通文本。
        self.assertEqual(classify_response_body("QUJD"), "text")

    def test_plain_text_body(self) -> None:
        self.assertEqual(classify_response_body("400 Bad Request"), "text")


class FhToolErrorDetailTests(unittest.TestCase):
    def test_http_error_carries_status_code(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_FakeResponse(500)):
            with self.assertRaises(FHToolHttpError) as ctx:
                fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0)
        self.assertEqual(ctx.exception.status_code, 500)

    def test_decrypt_error_classifies_html_body(self) -> None:
        response = _FakeResponse(
            status_code=200,
            text="<html><body>web ui</body></html>",
            headers={"Content-Type": "text/html"},
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertRaises(FHToolResponseError) as ctx:
                fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0)
        error = ctx.exception
        self.assertEqual(error.body_kind, "html")
        self.assertEqual(error.content_type, "text/html")
        self.assertIn("HTML", str(error))
        self.assertIn("fh_tool API", str(error))
        self.assertIn("HTTP 400", str(error))

    def test_decrypt_error_classifies_empty_body(self) -> None:
        response = _FakeResponse(status_code=200, text="")
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertRaises(FHToolResponseError) as ctx:
                fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetAdminAccount"), 1.0)
        self.assertEqual(ctx.exception.body_kind, "empty")
        self.assertIn("疑似空响应", str(ctx.exception))


class CallMethodTests(unittest.TestCase):
    def test_result_contains_default_port_fields(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True),
            patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()),
        ):
            result = call_method(_args(), "GetDevInfo")
        self.assertEqual(result["fh_port"], 8080)
        self.assertEqual(result["fh_port_source"], "default")

    def test_result_uses_explicit_port_end_to_end(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=AssertionError("should not probe")),
            patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()) as post_mock,
        ):
            result = call_method(_args(fh_port=80), "GetDevInfo")
        self.assertEqual(result["fh_port"], 80)
        self.assertEqual(result["fh_port_source"], "argument")
        self.assertEqual(post_mock.call_args.args[0], "http://192.168.1.1:80/fh_tool/api")

    def test_unverified_port_appends_hint(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=False),
            patch(
                "fh_tool_cli.backends.fh_tool.requests.post",
                side_effect=requests.ConnectionError("connection refused"),
            ),
        ):
            with self.assertRaises(FHToolError) as ctx:
                call_method(_args(), "GetDevInfo")
        message = str(ctx.exception)
        self.assertIn("--fh-port", message)
        self.assertIn("fh-tool probe", message)
        self.assertIn("HG6142A3", message)

    def test_http_error_on_default_port_does_not_append_hint(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True),
            patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_FakeResponse(500)),
        ):
            with self.assertRaises(FHToolError) as ctx:
                call_method(_args(), "GetDevInfo")
        self.assertNotIn("--fh-port", str(ctx.exception))


class ProbeFhPortCandidatesTests(unittest.TestCase):
    def test_reports_per_port_surface_without_mac(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch("fh_tool_cli.backends.fh_tool.requests.get", return_value=_FakeResponse(404, headers={"Content-Type": "text/html"})),
        ):
            report = probe_fh_port_candidates(TEST_IP, None, 1.0)
        self.assertEqual(set(report), {"8080", "80"})
        self.assertFalse(report["8080"]["tcp"])
        self.assertTrue(report["80"]["tcp"])
        self.assertEqual(report["80"]["surface"]["/fh_tool/api"]["status_code"], 404)
        self.assertIsNone(report["80"]["getdevinfo"])

    def test_getdevinfo_verified_with_mac(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch("fh_tool_cli.backends.fh_tool.fh_tool_call", return_value={"result": 0}),
        ):
            report = probe_fh_port_candidates(TEST_IP, TEST_MAC, 1.0)
        self.assertTrue(report["80"]["getdevinfo"]["ok"])
        self.assertTrue(report["8080"]["getdevinfo"] is None)


class CliEndToEndTests(unittest.TestCase):
    def test_call_with_fh_port_80_sends_to_port_80(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()) as post_mock,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = cli.main(
                [
                    "call",
                    "--func",
                    "GetDevInfo",
                    "--fh-port",
                    "80",
                    "--ip",
                    TEST_IP,
                    "--mac",
                    TEST_MAC,
                    "--timeout",
                    "1",
                    "--json",
                ]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["fh_port"], 80)
        self.assertEqual(payload["fh_port_source"], "argument")
        self.assertTrue(post_mock.call_args.args[0].startswith("http://192.168.1.1:80/"))


if __name__ == "__main__":
    unittest.main()
