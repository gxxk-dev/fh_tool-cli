from __future__ import annotations

import argparse
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import requests

from fh_tool_cli import cli
from fh_tool_cli.argparse_utils import normalize_path
from fh_tool_cli.backends.fh_tool import (
    FH_TOOL_API_PATH,
    FhPaths,
    api_payload,
    call_method,
    fh_paths_from_args,
    fh_tool_call,
    probe_fh_port_candidates,
    resolve_fh_port,
)
from fh_tool_cli.crypto import derive_crypto, encrypt_payload

TEST_IP = "192.168.1.1"
TEST_MAC = "AABBCCDDEEFF"
CUSTOM_PATHS = FhPaths(api="/custom/api", upload="/custom/upload", download="/custom/dl")


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
        "fh_api_path": None,
        "fh_upload_path": None,
        "fh_download_path": None,
        "config": "/nonexistent/fh-tool-test.json",
        "ask_mac": False,
        "json": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class NormalizePathTests(unittest.TestCase):
    def test_accepts_valid_path(self) -> None:
        self.assertEqual(normalize_path("/fh_tool/api"), "/fh_tool/api")
        self.assertEqual(normalize_path("/custom/api"), "/custom/api")

    def test_rejects_missing_leading_slash(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_path("fh_tool/api")

    def test_rejects_query_or_fragment(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_path("/api?x=1")
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_path("/api#frag")

    def test_rejects_whitespace(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_path("/api path")


class FhPathsFromArgsTests(unittest.TestCase):
    def test_explicit_values_win(self) -> None:
        paths = fh_paths_from_args(_args(fh_api_path="/a", fh_upload_path="/b", fh_download_path="/c"))
        self.assertEqual(paths, FhPaths(api="/a", upload="/b", download="/c"))

    def test_none_falls_back_to_defaults(self) -> None:
        paths = fh_paths_from_args(_args())
        self.assertEqual(paths.api, FH_TOOL_API_PATH)
        self.assertEqual(paths.upload, "/fh_tool/upload")
        self.assertEqual(paths.download, "/fh_tool/tool_download")

    def test_missing_attrs_are_tolerated(self) -> None:
        paths = fh_paths_from_args(argparse.Namespace(ip=TEST_IP))
        self.assertEqual(paths.api, FH_TOOL_API_PATH)


class FhToolCallPathTests(unittest.TestCase):
    def test_uses_explicit_path_in_url(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()) as post_mock:
            result = fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0, path="/custom/api")
        self.assertEqual(result, {"result": 0})
        self.assertEqual(post_mock.call_args.args[0], "http://192.168.1.1:8080/custom/api")

    def test_default_path_is_fh_tool_api(self) -> None:
        with patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()) as post_mock:
            fh_tool_call(TEST_IP, TEST_MAC, api_payload("GetDevInfo"), 1.0)
        self.assertEqual(post_mock.call_args.args[0], "http://192.168.1.1:8080/fh_tool/api")


class ResolveFhPortPathTests(unittest.TestCase):
    def test_custom_path_is_passed_to_verification(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", side_effect=[False, True]),
            patch("fh_tool_cli.backends.fh_tool.verify_fh_tool_port", return_value=True) as verify_mock,
        ):
            resolve_fh_port(_args(), TEST_IP, mac=TEST_MAC, timeout=1.0, path="/custom/api")
        verify_mock.assert_called_once_with(TEST_IP, 80, TEST_MAC, 1.0, path="/custom/api")


class CallMethodPathTests(unittest.TestCase):
    def test_result_contains_default_api_path(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True),
            patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()),
        ):
            result = call_method(_args(), "GetDevInfo")
        self.assertEqual(result["fh_api_path"], FH_TOOL_API_PATH)

    def test_result_uses_custom_api_path_end_to_end(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True),
            patch("fh_tool_cli.backends.fh_tool.requests.post", return_value=_encrypted_ok_response()) as post_mock,
        ):
            result = call_method(_args(fh_api_path="/custom/api"), "GetDevInfo")
        self.assertEqual(result["fh_api_path"], "/custom/api")
        self.assertEqual(post_mock.call_args.args[0], "http://192.168.1.1:8080/custom/api")


class ProbeFhPortCandidatesPathTests(unittest.TestCase):
    def test_surface_keys_use_custom_paths(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True),
            patch("fh_tool_cli.backends.fh_tool.requests.get", return_value=_FakeResponse(404)),
        ):
            report = probe_fh_port_candidates(TEST_IP, None, 1.0, paths=CUSTOM_PATHS)
        for entry in report.values():
            self.assertEqual(set(entry["surface"]), {"/custom/api", "/custom/upload", "/custom/dl"})

    def test_getdevinfo_uses_custom_api_path(self) -> None:
        with (
            patch("fh_tool_cli.backends.fh_tool.tcp_open", return_value=True),
            patch("fh_tool_cli.backends.fh_tool.fh_tool_call", return_value={"result": 0}) as call_mock,
        ):
            report = probe_fh_port_candidates(TEST_IP, TEST_MAC, 1.0, paths=CUSTOM_PATHS)
        self.assertTrue(report["8080"]["getdevinfo"]["ok"])
        self.assertEqual(call_mock.call_args.kwargs["path"], "/custom/api")


class CliEndToEndPathTests(unittest.TestCase):
    def test_call_with_custom_api_path_sends_to_custom_url(self) -> None:
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
                    "--fh-api-path",
                    "/custom/api",
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
        self.assertEqual(payload["fh_api_path"], "/custom/api")
        self.assertEqual(post_mock.call_args.args[0], "http://192.168.1.1:8080/custom/api")


if __name__ == "__main__":
    unittest.main()
