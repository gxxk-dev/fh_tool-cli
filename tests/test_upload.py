from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import requests

from fh_tool_cli.upload import redact_upload_prepare_result, upload_file, upload_workflow_plan


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        text: str,
        *,
        content_type: str = "text/plain",
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = {"Content-Type": content_type}


class UploadTests(unittest.TestCase):
    def test_upload_dry_run_validates_and_does_not_call_http(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "preconfig.bin"
            file_path.write_bytes(b"data")
            calls: list[str] = []

            result = upload_file(
                ip="192.168.1.1",
                action="preconfig",
                file_path=file_path,
                sessionid="secret-token",
                timeout=5.0,
                dry_run=True,
                post=lambda *args, **kwargs: calls.append("called"),
            )

            self.assertTrue(result["ok"])
            self.assertTrue(result["dry_run"])
            self.assertEqual(calls, [])
            self.assertEqual(result["risk"], "extreme")
            self.assertFalse(result["side_effects"]["upload"])
            self.assertEqual(result["file"]["sha256"], "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7")
            self.assertEqual(result["workflow"]["stage"], "planned")
            self.assertFalse(result["workflow"]["automatic_actions"]["preconfig_switch"])
            self.assertNotIn("secret-token", str(result))

    def test_upload_success_uses_token_header_without_leaking_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "firmware.bin"
            file_path.write_bytes(b"firmware")
            calls: list[dict[str, object]] = []

            def post(url: str, **kwargs: object) -> FakeResponse:
                calls.append({"url": url, **kwargs})
                return FakeResponse(200, "upload ok")

            result = upload_file(
                ip="192.168.1.1",
                action="upgradeimage",
                file_path=file_path,
                sessionid="secret-token",
                timeout=5.0,
                post=post,
            )

            self.assertTrue(result["ok"])
            self.assertEqual(calls[0]["headers"], {"fh_upgrade_api_token": "secret-token"})
            self.assertEqual(result["status_code"], 200)
            self.assertEqual(result["workflow"]["stage"], "uploaded_to_staging")
            self.assertEqual(result["workflow"]["verification"][0]["command"], "fh-tool dev-info")
            self.assertNotIn("secret-token", str(result))
            self.assertFalse(result["side_effects"]["reboot"])
            self.assertFalse(result["side_effects"]["restore"])
            self.assertFalse(result["side_effects"]["preconfig_switch"])

    def test_upload_custom_path_is_used_in_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "preconfig.bin"
            file_path.write_bytes(b"data")
            calls: list[dict[str, object]] = []

            def post(url: str, **kwargs: object) -> FakeResponse:
                calls.append({"url": url, **kwargs})
                return FakeResponse(200, "upload ok")

            result = upload_file(
                ip="192.168.1.1",
                action="preconfig",
                file_path=file_path,
                sessionid="secret-token",
                timeout=5.0,
                path="/custom/upload",
                post=post,
            )

            self.assertTrue(result["ok"])
            self.assertEqual(calls[0]["url"], "http://192.168.1.1:8080/custom/upload?action=preconfig")

    def test_upload_http_failure_is_structured_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "preconfig.bin"
            file_path.write_bytes(b"data")

            result = upload_file(
                ip="192.168.1.1",
                action="preconfig",
                file_path=file_path,
                sessionid="secret-token",
                timeout=5.0,
                post=lambda *args, **kwargs: FakeResponse(500, "bad secret-token"),
            )

            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["type"], "http_status")
            self.assertEqual(result["error"]["status_code"], 500)
            self.assertEqual(result["response"]["text"], "bad [REDACTED]")
            self.assertNotIn("secret-token", str(result))

    def test_upload_timeout_is_structured_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "preconfig.bin"
            file_path.write_bytes(b"data")

            def post(*args: object, **kwargs: object) -> FakeResponse:
                raise requests.Timeout("timeout for secret-token")

            result = upload_file(
                ip="192.168.1.1",
                action="preconfig",
                file_path=file_path,
                sessionid="secret-token",
                timeout=5.0,
                post=post,
            )

            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["type"], "timeout")
            self.assertEqual(result["error"]["message"], "timeout for [REDACTED]")
            self.assertNotIn("secret-token", str(result))

    def test_upload_prepare_redacts_session_tokens_by_default(self) -> None:
        result = redact_upload_prepare_result(
            {
                "request": {"func": "UploadPrepare"},
                "response": {"sessionid": "secret-token", "token": "other-token"},
            }
        )

        self.assertEqual(result["response"]["sessionid"], "[REDACTED]")
        self.assertEqual(result["response"]["token"], "[REDACTED]")
        self.assertNotIn("secret-token", str(result))
        self.assertNotIn("other-token", str(result))

    def test_upload_prepare_can_reveal_session_tokens_explicitly(self) -> None:
        result = redact_upload_prepare_result(
            {"response": {"sessionid": "secret-token"}},
            reveal_secrets=True,
        )

        self.assertEqual(result["response"]["sessionid"], "secret-token")
        self.assertFalse(result["redacted"])

    def test_upload_workflow_plan_documents_preconfig_manual_switch(self) -> None:
        result = upload_workflow_plan("preconfig")

        self.assertEqual(result["stage"], "planned")
        self.assertEqual(result["verification"][0]["command"], "fh-tool get-preconfig")
        self.assertFalse(result["automatic_actions"]["reboot"])
        self.assertFalse(result["automatic_actions"]["preconfig_switch"])


if __name__ == "__main__":
    unittest.main()
