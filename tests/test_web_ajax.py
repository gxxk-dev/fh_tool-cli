from __future__ import annotations

import unittest
from unittest.mock import patch

from fh_tool_cli.backends.web_ajax import (
    DEFAULT_AJAX_PATH,
    WebAjaxClient,
    web_login_key_from_brmad,
)
from fh_tool_cli.cli import command_web_diagnostics_show, parse_args
from fh_tool_cli.errors import FHToolError


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: object | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = {"Content-Type": "application/json" if payload is not None else "text/plain"}

    def json(self) -> object:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append(("GET", url, kwargs))
        params = kwargs.get("params")
        if params == {"ajaxmethod": "get_login_user"}:
            return FakeResponse(payload={"login_user": "1", "sessionid": "sid-login-user"})
        if params == {"ajaxmethod": "get_operator"}:
            return FakeResponse(payload={"operator": "telecom", "sessionid": "sid-operator"})
        if params == {"ajaxmethod": "web_get_brmad"}:
            return FakeResponse(payload={"brmad": "ABCDEFGHabcdefghijklZZZZZZZ"})
        if kwargs.get("params") == {"ajaxmethod": "get_base_info"}:
            return FakeResponse(payload={"model": "HG5143F"})
        if params == {"ajaxmethod": "get_base_info", "sessionid": "sid-login-user"}:
            return FakeResponse(payload={"model": "HG5143F"})
        if params == {"ajaxmethod": "get_allwan_info"}:
            return FakeResponse(payload={"wan": [{"Name": "internet"}], "sessionid": "sid-wan"})
        if params == {"ajaxmethod": "get_allwan_info", "sessionid": "sid-wan"}:
            return FakeResponse(payload={"wan": [{"Name": "internet2"}]})
        if params == {"ajaxmethod": "get_port_mapping_info"}:
            return FakeResponse(
                payload={
                    "portmapping": [{"ExternalPort": "80", "InternalClient": "192.168.1.2"}],
                    "sessionid": "sid-portmapping",
                }
            )
        if params == {"ajaxmethod": "get_port_mapping_info", "sessionid": "sid-explicit"}:
            return FakeResponse(
                payload={
                    "portmapping": [{"ExternalPort": "443", "InternalClient": "192.168.1.3"}],
                    "sessionid": "sid-portmapping",
                }
            )
        if params == {"ajaxmethod": "vlanbind"}:
            return FakeResponse(
                payload={
                    "lanVlanBindList": [{"IfName": "eth1", "X_CT_COM_VLAN": "100"}],
                    "wanConnList": [{"Name": "OTHER_B_VID_100"}],
                    "sessionid": "sid-vlanbind",
                }
            )
        return FakeResponse(text="ok")

    def post(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append(("POST", url, kwargs))
        data = kwargs.get("data")
        if isinstance(data, dict) and data.get("ajaxmethod") == "do_login":
            return FakeResponse(payload={"login_result": 0, "sessionid": "sid-after-login"})
        if isinstance(data, dict) and data.get("ajaxmethod") == "set_port_mapping_info":
            return FakeResponse(payload={"result": "ok", "sessionid": "sid-write"})
        if isinstance(data, dict) and data.get("ajaxmethod") == "setVlanBind":
            return FakeResponse(payload={"result": "ok", "token": "write-token"})
        if isinstance(data, dict) and data.get("ajaxmethod") == "set_firewall_info":
            return FakeResponse(payload={"result": "ok"})
        if isinstance(data, dict) and data.get("ajaxmethod") == "set_services":
            return FakeResponse(payload={"result": "ok"})
        return FakeResponse(text="ok")


class RecordingReadClient:
    def __init__(self, sessionid: str | None = None, login_error: Exception | None = None) -> None:
        self.sessionid = sessionid
        self.login_error = login_error
        self.calls: list[tuple[str, object]] = []

    def login(self, username: str, password: str, *, port: str) -> dict[str, object]:
        self.calls.append(("login", (username, password, port)))
        if self.login_error:
            raise self.login_error
        self.sessionid = "sid-after-login"
        return {
            "ok": True,
            "username": username,
            "login_result": 0,
            "sessionid_present": True,
        }

    def ajax_get(self, method: str) -> dict[str, object]:
        self.calls.append(("ajax_get", method))
        return {
            "method": method,
            "status_code": 200,
            "ok": True,
            "content_type": "application/json",
            "sessionid_present": bool(self.sessionid),
            "response": {"value": "ok"},
        }

    def typed(self, group: str, action: str) -> dict[str, object]:
        self.calls.append(("typed", (group, action)))
        return {
            "group": group,
            "action": action,
            "method": "get_allwan_info",
            "status_code": 200,
            "ok": True,
            "sessionid_present": bool(self.sessionid),
            "data": [],
            "raw": {},
        }


class WebAjaxTests(unittest.TestCase):
    def test_login_check_gets_base_url(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.login_check()

        self.assertTrue(result["ok"])
        self.assertEqual(session.calls[0][1], "http://192.168.1.1/")
        self.assertTrue(result["session"]["sessionid_present"])
        self.assertEqual(result["session"]["checks"][0]["response"]["sessionid"], "[REDACTED]")

    def test_ajax_get_uses_ajaxmethod_param(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.ajax_get("get_base_info")

        self.assertEqual(result["response"], {"model": "HG5143F"})
        self.assertEqual(session.calls[0][2]["params"], {"ajaxmethod": "get_base_info"})
        self.assertEqual(session.calls[0][1], "http://192.168.1.1/cgi-bin/ajax")

    def test_default_ajax_path_matches_vendor_stack(self) -> None:
        self.assertEqual(DEFAULT_AJAX_PATH, "/cgi-bin/ajax")

    def test_typed_wan_list_maps_to_known_method(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.typed("wan", "list")

        self.assertEqual(result["method"], "get_allwan_info")
        self.assertEqual(result["data"], [{"Name": "internet"}])
        self.assertEqual(result["raw"]["response"]["sessionid"], "[REDACTED]")

    def test_typed_port_mapping_maps_to_known_method(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.typed("port-mapping", "list")

        self.assertEqual(result["group"], "port-mapping")
        self.assertEqual(result["action"], "list")
        self.assertEqual(result["method"], "get_port_mapping_info")
        self.assertEqual(result["status_code"], 200)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"], [{"ExternalPort": "80", "InternalClient": "192.168.1.2"}])
        self.assertEqual(result["raw"]["response"]["sessionid"], "[REDACTED]")

    def test_typed_vlanbind_maps_to_known_method_and_redacts_session(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.typed("vlanbind", "show")

        self.assertEqual(result["group"], "vlanbind")
        self.assertEqual(result["action"], "show")
        self.assertEqual(result["method"], "vlanbind")
        self.assertEqual(result["data"]["lanVlanBindList"], [{"IfName": "eth1", "X_CT_COM_VLAN": "100"}])
        self.assertEqual(result["data"]["sessionid"], "[REDACTED]")
        self.assertEqual(result["raw"]["response"]["sessionid"], "[REDACTED]")

    def test_typed_views_inject_explicit_sessionid(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session, sessionid="sid-explicit")

        result = client.typed("port-mapping", "list")

        self.assertEqual(result["data"], [{"ExternalPort": "443", "InternalClient": "192.168.1.3"}])
        self.assertEqual(
            session.calls[-1][2]["params"],
            {"ajaxmethod": "get_port_mapping_info", "sessionid": "sid-explicit"},
        )

    def test_typed_write_dry_run_does_not_post_and_redacts_payload(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.typed_write(
            "port-mapping",
            "set",
            {"ExternalPort": "80", "Password": "secret"},
            dry_run=True,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "dry-run")
        self.assertEqual(result["method"], "set_port_mapping_info")
        self.assertEqual(result["request"]["Password"], "[REDACTED]")
        self.assertEqual([call for call in session.calls if call[0] == "POST"], [])

    def test_typed_write_dry_run_shows_planned_sessionid_redacted(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session, sessionid="sid-explicit")

        result = client.typed_write(
            "services",
            "set",
            {"action": "telnet", "telnet": "0"},
            dry_run=True,
        )

        self.assertEqual(result["request"]["sessionid"], "[REDACTED]")
        self.assertEqual([call for call in session.calls if call[0] == "POST"], [])

    def test_typed_write_execute_posts_with_session_and_redacts_response(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session, sessionid="sid-explicit")

        result = client.typed_write(
            "vlanbind",
            "set",
            {"IfName": "eth1", "vlanPart": "100/100"},
            dry_run=False,
        )

        self.assertEqual(result["status"], "executed")
        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "setVlanBind")
        post_call = [call for call in session.calls if call[0] == "POST"][-1]
        self.assertEqual(post_call[2]["data"]["sessionid"], "sid-explicit")
        self.assertEqual(result["raw"]["response"]["token"], "[REDACTED]")

    def test_generic_post_dry_run_does_not_send_request(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session, sessionid="sid-explicit")

        result = client.raw_post(
            "set_fake",
            {"Enable": "1", "Password": "secret"},
            dry_run=True,
        )

        self.assertEqual(result["status"], "dry-run")
        self.assertEqual(result["request"]["Password"], "[REDACTED]")
        self.assertEqual(result["request"]["sessionid"], "[REDACTED]")
        self.assertEqual(session.calls, [])

    def test_generic_post_execute_injects_session_and_redacts_response(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session, sessionid="sid-explicit")

        result = client.raw_post("setVlanBind", {"IfName": "eth1"}, dry_run=False)

        self.assertEqual(result["status"], "executed")
        post_call = [call for call in session.calls if call[0] == "POST"][-1]
        self.assertEqual(post_call[2]["data"]["ajaxmethod"], "setVlanBind")
        self.assertEqual(post_call[2]["data"]["sessionid"], "sid-explicit")
        self.assertEqual(result["raw"]["response"]["token"], "[REDACTED]")

    def test_sessionid_is_captured_and_added_to_later_requests(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        first = client.typed("wan", "list")
        second = client.typed("wan", "list")

        self.assertTrue(first["sessionid_present"])
        self.assertEqual(second["data"], [{"Name": "internet2"}])
        self.assertEqual(
            session.calls[-1][2]["params"],
            {"ajaxmethod": "get_allwan_info", "sessionid": "sid-wan"},
        )

    def test_login_posts_encrypted_password_without_leaking_plaintext(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.login("telecomadmin", "plain-secret")

        self.assertTrue(result["ok"])
        self.assertEqual(result["response"]["sessionid"], "[REDACTED]")
        post_call = [call for call in session.calls if call[0] == "POST"][0]
        posted = post_call[2]["data"]
        self.assertEqual(posted["username"], "telecomadmin")
        self.assertEqual(posted["sessionid"], "sid-operator")
        self.assertNotEqual(posted["loginpd"], "plain-secret")
        self.assertNotIn("plain-secret", str(result))

    def test_auto_login_result_does_not_leak_plain_password(self) -> None:
        session = FakeSession()
        client = WebAjaxClient("http://192.168.1.1/", session=session)

        result = client.login("useradmin", "auto-secret")

        self.assertNotIn("auto-secret", str(result))
        self.assertNotIn("auto-secret", str(session.calls))

    def test_web_login_key_matches_vendor_slice(self) -> None:
        self.assertEqual(
            web_login_key_from_brmad("ABCDEFGHabcdefghijklZZZZZZZ"),
            "*$abcdefghijkl#&",
        )

    def test_ajax_get_defaults_to_auto_login_and_attaches_summary(self) -> None:
        client = RecordingReadClient()
        args = parse_args(["web", "ajax", "get", "get_base_info", "--ip", "192.168.1.1"])

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch("fh_tool_cli.commands.web._web_password_from_args", return_value=("auto-secret", "cfg", [])),
        ):
            result = args.handler(args)

        self.assertEqual(
            client.calls,
            [
                ("login", ("useradmin", "auto-secret", "0")),
                ("ajax_get", "get_base_info"),
            ],
        )
        self.assertEqual(result["login"]["password_source"], "cfg")
        self.assertTrue(result["login"]["ok"])
        self.assertNotIn("auto-secret", str(result))

    def test_typed_read_defaults_to_auto_login(self) -> None:
        client = RecordingReadClient()
        args = parse_args(["web", "wan", "list", "--ip", "192.168.1.1"])

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch("fh_tool_cli.commands.web._web_password_from_args", return_value=("auto-secret", "admin-account", [])),
        ):
            result = args.handler(args)

        self.assertEqual(
            client.calls,
            [
                ("login", ("useradmin", "auto-secret", "0")),
                ("typed", ("wan", "list")),
            ],
        )
        self.assertEqual(result["login"]["password_source"], "admin-account")
        self.assertTrue(result["login"]["ok"])

    def test_ajax_get_auto_login_failure_does_not_block_read(self) -> None:
        client = RecordingReadClient()
        args = parse_args(["web", "ajax", "get", "get_base_info", "--ip", "192.168.1.1"])

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch(
                "fh_tool_cli.commands.web._web_password_from_args",
                return_value=(None, "auto", ["admin-account: missing"]),
            ),
        ):
            result = args.handler(args)

        self.assertEqual(client.calls, [("ajax_get", "get_base_info")])
        self.assertEqual(result["method"], "get_base_info")
        self.assertFalse(result["login"]["attempted"])
        self.assertIn("admin-account: missing", result["login"]["error"])

    def test_ajax_get_login_error_does_not_block_read(self) -> None:
        client = RecordingReadClient(login_error=FHToolError("login surface unavailable"))
        args = parse_args(["web", "ajax", "get", "get_base_info", "--ip", "192.168.1.1"])

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch("fh_tool_cli.commands.web._web_password_from_args", return_value=("auto-secret", "cfg", [])),
        ):
            result = args.handler(args)

        self.assertEqual(
            client.calls,
            [
                ("login", ("useradmin", "auto-secret", "0")),
                ("ajax_get", "get_base_info"),
            ],
        )
        self.assertFalse(result["login"]["ok"])
        self.assertIn("login surface unavailable", result["login"]["error"])

    def test_explicit_sessionid_skips_auto_login(self) -> None:
        client = RecordingReadClient(sessionid="sid-explicit")
        args = parse_args(
            [
                "web",
                "ajax",
                "get",
                "get_base_info",
                "--sessionid",
                "sid-explicit",
                "--ip",
                "192.168.1.1",
            ]
        )

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=client),
            patch("fh_tool_cli.commands.web._web_password_from_args", side_effect=AssertionError("password used")),
        ):
            result = args.handler(args)

        self.assertEqual(client.calls, [("ajax_get", "get_base_info")])
        self.assertFalse(result["login"]["attempted"])
        self.assertEqual(result["login"]["password_source"], "sessionid")
        self.assertTrue(result["login"]["sessionid_present"])

    def test_web_diagnostics_show_collects_views_and_partial_failures(self) -> None:
        fake_client = FakeDiagnosticsClient()
        args = parse_args(
            [
                "web",
                "diagnostics",
                "show",
                "--view",
                "wan",
                "--view",
                "firewall",
                "--ip",
                "192.168.1.1",
            ]
        )

        with (
            patch("fh_tool_cli.commands.web._web_client_from_args", return_value=fake_client),
            patch(
                "fh_tool_cli.commands.web._web_password_from_args",
                return_value=(None, "auto", ["admin-account: missing"]),
            ),
        ):
            result = command_web_diagnostics_show(args)

        diagnostics = result["web_diagnostics"]
        self.assertIn("wan", diagnostics["views"])
        self.assertEqual(diagnostics["errors"], {"firewall": "firewall unavailable"})
        self.assertTrue(diagnostics["partial_failure"])
        self.assertFalse(diagnostics["sessionid_present"])
        self.assertFalse(diagnostics["login"]["attempted"])
        self.assertIn("admin-account: missing", diagnostics["login"]["error"])


class FakeDiagnosticsClient:
    sessionid = None

    def typed(self, group: str, action: str) -> dict[str, object]:
        if group == "firewall":
            raise FHToolError("firewall unavailable")
        return {
            "group": group,
            "action": action,
            "method": "fake",
            "status_code": 200,
            "ok": True,
            "data": [],
            "raw": {},
        }


if __name__ == "__main__":
    unittest.main()
