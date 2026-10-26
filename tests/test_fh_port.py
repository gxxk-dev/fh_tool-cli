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
    http_get_surface,
    probe_fh_port_candidates,
    resolve_fh_port,
    response_body_preview,
    response_header_summary,
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


class ResponseHeaderSummaryTests(unittest.TestCase):
    def test_keeps_only_safe_headers(self) -> None:
        summary = response_header_summary(
            {
                "Server": "nginx",
                "Content-Type": "text/html",
                "Location": "/login",
                "Set-Cookie": "sessionid=secret",
                "Authorization": "Bearer secret",
            }
        )
        self.assertEqual(
            summary,
            {
                "Server": "nginx",
                "Content-Type": "text/html",
                "Location": "/login",
            },
        )

    def test_matches_header_names_case_insensitively(self) -> None:
        self.assertEqual(response_header_summary({"server": "thttpd"}), {"Server": "thttpd"})

    def test_location_query_and_fragment_are_stripped(self) -> None:
        summary = response_header_summary(
            {"Location": "https://192.168.1.1/login?token=secret#section"}
        )
        self.assertEqual(summary["Location"], "https://192.168.1.1/login")


class HttpGetSurfaceTests(unittest.TestCase):
    def test_connection_error_is_reported_without_raising(self) -> None:
        with patch(
            "fh_tool_cli.backends.fh_tool.requests.get",
            side_effect=requests.ConnectionError("refused"),
        ):
            self.assertEqual(
                http_get_surface(TEST_IP, 8080, "/fh_tool/api", 1.0),
                {"error": "refused"},
            )

    def test_default_surface_keeps_legacy_fields(self) -> None:
        response = _FakeResponse(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Length": "123",
                "Server": "nginx",
                "Set-Cookie": "sid=secret",
            },
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.get", return_value=response):
            surface = http_get_surface(TEST_IP, 8080, "/", 1.0)
        self.assertEqual(surface, {"status_code": 200, "content_type": "text/html"})

    def test_returns_header_fingerprint_without_body(self) -> None:
        response = _FakeResponse(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Length": "123",
                "Set-Cookie": "sid=secret",
            },
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.get", return_value=response) as get_mock:
            surface = http_get_surface(TEST_IP, 8080, "/", 1.0, diagnose=True)
        self.assertEqual(surface["status_code"], 200)
        self.assertEqual(surface["content_type"], "text/html")
        self.assertEqual(surface["content_length"], "123")
        self.assertEqual(surface["header_names"], ["content-length", "content-type", "set-cookie"])
        self.assertNotIn("Set-Cookie", surface)
        self.assertTrue(get_mock.call_args.kwargs["stream"])


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


class ResponseBodyPreviewTests(unittest.TestCase):
    def test_empty_body_has_empty_preview(self) -> None:
        self.assertEqual(response_body_preview("", "empty"), "")

    def test_html_preview_is_truncated_but_readable(self) -> None:
        preview = response_body_preview("<html><title>403 Forbidden</title></html>", "html")
        self.assertIn("403 Forbidden", preview)

    def test_json_preview_redacts_sensitive_keys(self) -> None:
        preview = response_body_preview('{"adminpwd": "secret", "result": 0}', "json")
        self.assertIn("[REDACTED]", preview)
        self.assertNotIn("secret", preview)

    def test_text_with_assignment_is_hidden(self) -> None:
        self.assertEqual(response_body_preview("adminpwd=secret", "text"), "[文本内容已隐藏]")

    def test_safe_text_is_shown(self) -> None:
        self.assertEqual(response_body_preview("400 Bad Request", "text"), "400 Bad Request")

    def test_long_preview_is_truncated(self) -> None:
        preview = response_body_preview("x" * 400, "base64")
        self.assertLess(len(preview), 400)
        self.assertIn("chars", preview)


class FhToolLogTests(unittest.TestCase):
    def _records(self, captured) -> list:
        return captured.records

    def _fields(self, record) -> dict:
        return getattr(record, "structured_fields", {})

    def test_decrypt_error_logs_body_preview(self) -> None:
        response = _FakeResponse(
            status_code=200,
            text="<html><title>login</title></html>",
            headers={"Content-Type": "text/html", "Server": "nginx", "Set-Cookie": "sid=secret"},
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertLogs("fh_tool_cli", level="INFO") as captured:
                with self.assertRaises(FHToolResponseError):
                    fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0, diagnose=True)
        decrypt_events = [
            self._fields(item)
            for item in self._records(captured)
            if getattr(item, "event", None) == "fh_tool.api.decrypt_error"
        ]
        self.assertEqual(len(decrypt_events), 1)
        self.assertEqual(decrypt_events[0]["body_kind"], "html")
        self.assertIn("login", decrypt_events[0]["body_preview"])
        self.assertIn("elapsed_ms", decrypt_events[0])
        self.assertEqual(decrypt_events[0]["server"], "nginx")
        self.assertEqual(decrypt_events[0]["response_headers"]["Server"], "nginx")
        self.assertNotIn("Set-Cookie", decrypt_events[0]["response_headers"])
        self.assertIn("set-cookie", decrypt_events[0]["header_names"])

    def test_decrypt_error_default_log_omits_header_fingerprint(self) -> None:
        response = _FakeResponse(
            status_code=200,
            text="<html><title>login</title></html>",
            headers={"Content-Type": "text/html", "Server": "nginx"},
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertLogs("fh_tool_cli", level="INFO") as captured:
                with self.assertRaises(FHToolResponseError):
                    fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0)
        decrypt_events = [
            self._fields(item)
            for item in self._records(captured)
            if getattr(item, "event", None) == "fh_tool.api.decrypt_error"
        ]
        self.assertEqual(len(decrypt_events), 1)
        self.assertNotIn("server", decrypt_events[0])
        self.assertNotIn("response_headers", decrypt_events[0])
        self.assertNotIn("header_names", decrypt_events[0])

    def test_debug_result_log_redacts_password(self) -> None:
        crypto = derive_crypto(TEST_MAC)
        response = _FakeResponse(
            status_code=200,
            text=encrypt_payload({"result": 0, "adminpwd": "secret"}, crypto),
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertLogs("fh_tool_cli", level="DEBUG") as captured:
                fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetAdminAccount"), 1.0)
        result_events = [
            self._fields(item)
            for item in self._records(captured)
            if getattr(item, "event", None) == "fh_tool.api.result"
        ]
        self.assertEqual(len(result_events), 1)
        self.assertEqual(result_events[0]["response"]["adminpwd"], "[REDACTED]")


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
            headers={"Content-Type": "text/html", "Server": "nginx/1.14.0"},
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertRaises(FHToolResponseError) as ctx:
                fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0, diagnose=True)
        error = ctx.exception
        self.assertEqual(error.body_kind, "html")
        self.assertEqual(error.content_type, "text/html")
        self.assertEqual(error.server, "nginx/1.14.0")
        self.assertIn("Server=nginx/1.14.0", str(error))
        self.assertIn("HTML", str(error))
        self.assertIn("fh_tool API", str(error))
        self.assertIn("HTTP 400", str(error))

    def test_decrypt_error_default_hides_server(self) -> None:
        response = _FakeResponse(
            status_code=200,
            text="<html><body>web ui</body></html>",
            headers={"Content-Type": "text/html", "Server": "nginx/1.14.0"},
        )
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertRaises(FHToolResponseError) as ctx:
                fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0)
        error = ctx.exception
        self.assertEqual(error.body_kind, "html")
        self.assertIsNone(error.server)
        self.assertNotIn("Server=", str(error))
        self.assertIn("--diagnose", str(error))

    def test_decrypt_error_classifies_empty_body(self) -> None:
        response = _FakeResponse(status_code=200, text="")
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=response):
            with self.assertRaises(FHToolResponseError) as ctx:
                fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetAdminAccount"), 1.0, diagnose=True)
        self.assertEqual(ctx.exception.body_kind, "empty")
        self.assertIsNone(ctx.exception.server)
        self.assertIn("Server=none", str(ctx.exception))
        self.assertIn("疑似空响应", str(ctx.exception))
        self.assertEqual(ctx.exception.header_names, [])


class CallMethodTests(unittest.TestCase):
    def test_result_contains_default_port_fields(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True),
            patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()),
        ):
            result = call_method(_args(), "GetDevInfo")
        self.assertEqual(result["fh_port"], 8080)
        self.assertEqual(result["fh_port_source"], "default")

    def test_call_method_forwards_diagnose(self) -> None:
        args = _args(diagnose=True, fh_port=80)
        with (
            patch("fh_tool_cli.backends.fh_tool.fh_tool_call", return_value={"result": 0}) as call_mock,
        ):
            call_method(args, "GetDevInfo")
        self.assertTrue(call_mock.call_args.kwargs["diagnose"])

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

    def test_reports_root_and_safe_headers_per_port(self) -> None:
        def fake_get(url: str, **kwargs) -> _FakeResponse:
            if url.endswith("/"):
                return _FakeResponse(
                    200,
                    headers={
                        "Server": "nginx",
                        "Content-Type": "text/html",
                        "Location": "/login",
                        "Set-Cookie": "sid=secret",
                    },
                )
            return _FakeResponse(400, headers={"Server": "nginx", "Content-Type": "text/plain"})

        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch("fh_tool_cli.backends.fh_tool.requests.get", side_effect=fake_get),
        ):
            report = probe_fh_port_candidates(TEST_IP, None, 1.0, diagnose=True)
        self.assertEqual(report["80"]["root"]["server"], "nginx")
        self.assertEqual(report["80"]["root"]["content_type"], "text/html")
        self.assertEqual(report["80"]["root"]["location"], "/login")
        self.assertIn("set-cookie", report["80"]["root"]["header_names"])
        self.assertEqual(report["80"]["surface"]["/fh_tool/api"]["server"], "nginx")
        # 安全头子集不应把会话 cookie 写进 probe 输出。
        self.assertNotIn("Set-Cookie", report["80"]["root"])

    def test_default_report_keeps_legacy_shape(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch(
                "fh_tool_cli.backends.fh_tool.requests.get",
                return_value=_FakeResponse(
                    404, headers={"Content-Type": "text/html", "Server": "nginx"}
                ),
            ),
        ):
            report = probe_fh_port_candidates(TEST_IP, None, 1.0)
        self.assertNotIn("root", report["80"])
        self.assertEqual(
            report["80"]["surface"]["/fh_tool/api"],
            {"status_code": 404, "content_type": "text/html"},
        )

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

    def _run_probe(self, *extra: str) -> dict:
        stdout = io.StringIO()
        with (
            patch("fh_tool_cli.cli.resolve_mac", return_value=(None, "missing")),
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=False),
            patch(
                "fh_tool_cli.backends.fh_tool.requests.get",
                return_value=_FakeResponse(
                    404, headers={"Content-Type": "text/html", "Server": "nginx"}
                ),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            exit_code = cli.main(
                [
                    "probe",
                    "--ip",
                    TEST_IP,
                    "--fh-port",
                    "80",
                    "--timeout",
                    "1",
                    "--json",
                    *extra,
                ]
            )
        self.assertEqual(exit_code, 0)
        return json.loads(stdout.getvalue())

    def test_probe_default_json_has_no_diagnostic_fields(self) -> None:
        payload = self._run_probe()
        self.assertNotIn("root", payload)
        self.assertEqual(
            payload["surface"]["/fh_tool/api"],
            {"status_code": 404, "content_type": "text/html"},
        )
        self.assertNotIn("root", payload["fh_ports"]["80"])
        self.assertEqual(
            payload["fh_ports"]["80"]["surface"]["/fh_tool/api"],
            {"status_code": 404, "content_type": "text/html"},
        )

    def test_probe_diagnose_json_adds_root_and_headers(self) -> None:
        payload = self._run_probe("--diagnose")
        self.assertEqual(payload["root"]["server"], "nginx")
        self.assertIn("server", payload["surface"]["/fh_tool/api"])
        self.assertEqual(payload["fh_ports"]["80"]["root"]["server"], "nginx")
        self.assertIn("header_names", payload["fh_ports"]["80"]["surface"]["/fh_tool/api"])


if __name__ == "__main__":
    unittest.main()
