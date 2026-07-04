from __future__ import annotations

import base64
import hashlib
import re
from typing import Any
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from ..errors import FHToolError

DEFAULT_AJAX_PATH = "/cgi-bin/ajax"
DEFAULT_WEB_LOGIN_PORT = "0"

WEB_TYPED_METHODS = {
    ("wan", "list"): "get_allwan_info",
    ("tr069", "show"): "get_tr69_info",
    ("services", "show"): "get_services",
    ("firewall", "show"): "get_firewall_info",
    ("port-mapping", "list"): "get_port_mapping_info",
    ("vlanbind", "show"): "vlanbind",
}

WEB_TYPED_PAYLOAD_KEYS = {
    ("wan", "list"): "wan",
    ("tr069", "show"): "tr69",
    ("services", "show"): "services",
    ("firewall", "show"): "firewall",
    ("port-mapping", "list"): "portmapping",
}

WEB_TYPED_WRITE_METHODS = {
    ("port-mapping", "set"): "set_port_mapping_info",
    ("vlanbind", "set"): "setVlanBind",
    ("services", "set"): "set_services",
    ("firewall", "set"): "set_firewall_info",
}

SENSITIVE_WEB_KEY_RE = re.compile(
    r"(sessionid|token|password|passwd|pwd|loginpd|loid|pppoe|acs|secret|psk|wepkey|wpakey)",
    re.IGNORECASE,
)


class WebAjaxClient:
    def __init__(
        self,
        base_url: str,
        *,
        ajax_path: str = DEFAULT_AJAX_PATH,
        timeout: float = 5.0,
        session: Any | None = None,
        sessionid: str | None = None,
        reveal_secrets: bool = False,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.ajax_path = ajax_path
        self.timeout = timeout
        self.session = session or requests.Session()
        self.sessionid = sessionid
        self.reveal_secrets = reveal_secrets

    def login_check(self) -> dict[str, Any]:
        url = self.base_url
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            raise FHToolError(f"Web login-check failed {url}: {exc}") from exc
        result = {
            "url": url,
            "status_code": response.status_code,
            "ok": response.status_code < 500,
            "content_type": response.headers.get("Content-Type"),
        }
        try:
            result["session"] = self.discover_session()
        except FHToolError as exc:
            result["session"] = {
                "ok": False,
                "sessionid_present": bool(self.sessionid),
                "error": str(exc),
            }
        return result

    def discover_session(self) -> dict[str, Any]:
        checks = []
        for method in ("get_login_user", "get_operator"):
            result = self.ajax_get(method, use_session=False)
            checks.append(
                {
                    "method": method,
                    "status_code": result["status_code"],
                    "ok": result["ok"],
                    "response": result.get("response"),
                }
            )
            if self.sessionid:
                break
        return {
            "ok": any(check["ok"] for check in checks),
            "sessionid_present": bool(self.sessionid),
            "checks": checks,
        }

    def login(
        self,
        username: str,
        password: str,
        *,
        port: str = DEFAULT_WEB_LOGIN_PORT,
    ) -> dict[str, Any]:
        brmad = self._fetch_brmad()
        self.ajax_get("get_operator", use_session=False)
        loginpd = fiberhome_web_encrypt(
            hashlib.sha256(password.encode("utf-8")).hexdigest(),
            brmad,
        )
        result = self.ajax_post(
            "do_login",
            {
                "username": username,
                "loginpd": loginpd,
                "port": port,
            },
        )
        response = result.get("response")
        login_result = response.get("login_result") if isinstance(response, dict) else None
        return {
            "method": "do_login",
            "status_code": result["status_code"],
            "ok": result["ok"] and str(login_result) == "0",
            "login_result": login_result,
            "username": username,
            "sessionid_present": bool(self.sessionid),
            "response": response,
        }

    def ajax_get(
        self,
        method: str,
        *,
        params: dict[str, Any] | None = None,
        use_session: bool = True,
    ) -> dict[str, Any]:
        url = urljoin(self.base_url, self.ajax_path.lstrip("/"))
        request_params = {"ajaxmethod": method}
        if params:
            request_params.update(params)
        if use_session and self.sessionid:
            request_params.setdefault("sessionid", self.sessionid)
        try:
            response = self.session.get(
                url,
                params=request_params,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise FHToolError(f"Web AJAX GET failed {url}: {exc}") from exc
        return self._response_result("GET", url, method, response)

    def ajax_post(self, method: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        url = urljoin(self.base_url, self.ajax_path.lstrip("/"))
        request_data = dict(data or {})
        request_data["ajaxmethod"] = method
        if self.sessionid:
            request_data.setdefault("sessionid", self.sessionid)
        try:
            response = self.session.post(
                url,
                data=request_data,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise FHToolError(f"Web AJAX POST failed {url}: {exc}") from exc
        return self._response_result("POST", url, method, response)

    def typed(self, group: str, action: str) -> dict[str, Any]:
        try:
            method = WEB_TYPED_METHODS[(group, action)]
        except KeyError as exc:
            raise FHToolError(f"unsupported Web AJAX typed command: {group} {action}") from exc
        raw = self.ajax_get(method)
        response = raw.get("response")
        data_key = WEB_TYPED_PAYLOAD_KEYS.get((group, action))
        return {
            "group": group,
            "action": action,
            "method": method,
            "status_code": raw["status_code"],
            "ok": raw["ok"],
            "sessionid_present": bool(self.sessionid),
            "data": _select_typed_payload(response, data_key),
            "raw": raw,
        }

    def typed_write(
        self,
        group: str,
        action: str,
        payload: dict[str, Any],
        *,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        try:
            method = WEB_TYPED_WRITE_METHODS[(group, action)]
        except KeyError as exc:
            raise FHToolError(f"unsupported Web AJAX typed write: {group} {action}") from exc

        request_payload = dict(payload)
        if self.sessionid:
            request_payload.setdefault("sessionid", self.sessionid)
        rendered_payload = _redact_web_payload(
            request_payload,
            reveal_secrets=self.reveal_secrets,
        )
        base = {
            "group": group,
            "action": action,
            "method": method,
            "status": "dry-run" if dry_run else "executed",
            "status_code": None,
            "ok": True,
            "risk": "danger",
            "sessionid_present": bool(self.sessionid),
            "request": rendered_payload,
            "data": None,
            "raw": None,
            "side_effects": {
                "post": not dry_run,
                "reboot": False,
                "restore": False,
                "factory_reset": False,
            },
        }
        if dry_run:
            return base

        raw = self.ajax_post(method, payload)
        response = raw.get("response")
        return {
            **base,
            "status_code": raw["status_code"],
            "ok": raw["ok"],
            "sessionid_present": bool(self.sessionid),
            "data": response,
            "raw": raw,
        }

    def _fetch_brmad(self) -> str:
        result = self.ajax_get("web_get_brmad", use_session=False)
        response = result.get("response")
        brmad = response.get("brmad") if isinstance(response, dict) else None
        if not isinstance(brmad, str) or not brmad:
            raise FHToolError("Web login failed: web_get_brmad did not return brmad")
        return brmad

    def _response_result(
        self,
        http_method: str,
        url: str,
        method: str,
        response: Any,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "http_method": http_method,
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "ok": response.status_code < 400,
            "content_type": response.headers.get("Content-Type"),
            "sessionid_present": bool(self.sessionid),
        }
        try:
            payload = response.json()
        except ValueError:
            result["response_text"] = response.text
            return result

        self._capture_sessionid(payload)
        result["sessionid_present"] = bool(self.sessionid)
        result["response"] = _redact_web_payload(payload, reveal_secrets=self.reveal_secrets)
        return result

    def _capture_sessionid(self, payload: Any) -> None:
        if isinstance(payload, dict):
            sessionid = payload.get("sessionid")
            if isinstance(sessionid, str) and sessionid:
                self.sessionid = sessionid


def web_login_key_from_brmad(brmad: str) -> str:
    key = f"*${brmad[8:-7]}#&"
    if len(key.encode("utf-8")) != 16:
        raise FHToolError("Web login failed: brmad-derived AES key is not 16 bytes")
    return key


def fiberhome_web_encrypt(value: str, brmad: str) -> str:
    key = web_login_key_from_brmad(brmad).encode("utf-8")
    padder = PKCS7(128).padder()
    plaintext = padder.update(value.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def _select_typed_payload(response: Any, data_key: str | None) -> Any:
    if not isinstance(response, dict):
        return response
    if data_key and data_key in response:
        return response[data_key]
    return response


def _redact_web_payload(value: Any, *, reveal_secrets: bool) -> Any:
    if reveal_secrets:
        return value
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if SENSITIVE_WEB_KEY_RE.search(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_web_payload(item, reveal_secrets=False)
        return redacted
    if isinstance(value, list):
        return [_redact_web_payload(item, reveal_secrets=False) for item in value]
    return value
