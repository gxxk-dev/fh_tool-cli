from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests

from .backends.fh_tool import FH_TOOL_UPLOAD_PATH
from .errors import CliError
from .fh_endpoints import DEFAULT_FH_TOOL_PORT

UPLOAD_ACTIONS = {"upgradeimage", "preconfig"}
REDACTED = "[REDACTED]"
SENSITIVE_UPLOAD_KEY_RE = re.compile(
    r"(sessionid|session_id|token|password|passwd|pwd|secret)",
    re.IGNORECASE,
)


def redact_upload_prepare_result(
    result: dict[str, Any],
    *,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    rendered = _redact_value(result, reveal_secrets=reveal_secrets)
    assert isinstance(rendered, dict)
    rendered["redacted"] = not reveal_secrets
    return rendered


def upload_file(
    *,
    ip: str,
    action: str,
    file_path: Path,
    sessionid: str,
    timeout: float,
    port: int = DEFAULT_FH_TOOL_PORT,
    dry_run: bool = False,
    post: Callable[..., Any] = requests.post,
) -> dict[str, Any]:
    file_info = _validate_upload_inputs(action, file_path, sessionid)
    url = f"http://{ip}:{port}{FH_TOOL_UPLOAD_PATH}?action={action}"
    base = _upload_result_base(
        ip=ip,
        url=url,
        action=action,
        file_info=file_info,
        sessionid=sessionid,
        dry_run=dry_run,
    )
    if dry_run:
        return {
            **base,
            "ok": True,
            "workflow": upload_workflow_plan(action, file_info=file_info, uploaded=False),
        }

    try:
        with file_path.open("rb") as file:
            response = post(
                url,
                headers={"fh_upgrade_api_token": sessionid},
                files={"file": (file_path.name, file)},
                timeout=timeout,
                allow_redirects=False,
            )
    except requests.Timeout as exc:
        return {
            **base,
            "ok": False,
            "error": _upload_error("timeout", str(exc), sessionid),
            "workflow": upload_workflow_plan(action, file_info=file_info, uploaded=False),
        }
    except requests.RequestException as exc:
        return {
            **base,
            "ok": False,
            "error": _upload_error("request", str(exc), sessionid),
            "workflow": upload_workflow_plan(action, file_info=file_info, uploaded=False),
        }

    status_code = int(getattr(response, "status_code", 0))
    text = str(getattr(response, "text", ""))
    content_type = getattr(response, "headers", {}).get("Content-Type")
    result = {
        **base,
        "status_code": status_code,
        "response": {
            "content_type": content_type,
            "text": _redact_string(text[:1000], sessionid),
        },
    }
    if 200 <= status_code < 300:
        return {
            **result,
            "ok": True,
            "workflow": upload_workflow_plan(action, file_info=file_info, uploaded=True),
        }
    return {
        **result,
        "ok": False,
        "error": _upload_error(
            "http_status",
            f"HTTP {status_code}",
            sessionid,
            status_code=status_code,
        ),
        "workflow": upload_workflow_plan(action, file_info=file_info, uploaded=False),
    }


def upload_workflow_plan(
    action: str,
    *,
    file_info: dict[str, Any] | None = None,
    uploaded: bool = False,
) -> dict[str, Any]:
    if action not in UPLOAD_ACTIONS:
        raise CliError(f"upload action 不支持: {action}")
    if action == "preconfig":
        manual_actions = [
            "Run fh-tool get-preconfig to confirm the uploaded preconfig is visible.",
            "Only after manual review, run fh-tool set-preconfig --fullname ... --confirm.",
            "Do not reboot automatically; decide separately after configuration review.",
        ]
        verification = [
            {
                "command": "fh-tool get-preconfig",
                "purpose": "Read back available preconfig entries before any switch.",
            }
        ]
    else:
        manual_actions = [
            "Confirm the firmware image matches the target model and version policy.",
            "Do not reboot automatically from upload workflow.",
            "After any separately approved reboot, run fh-tool dev-info to compare SWVersion.",
        ]
        verification = [
            {
                "command": "fh-tool dev-info",
                "purpose": "Read current model/version before and after any separately approved reboot.",
            }
        ]
    return {
        "action": action,
        "stage": "uploaded_to_staging" if uploaded else "planned",
        "file": file_info,
        "manual_actions": manual_actions,
        "verification": verification,
        "automatic_actions": {
            "reboot": False,
            "restore": False,
            "preconfig_switch": False,
        },
    }


def upload_file_info(file_path: Path) -> dict[str, Any]:
    if not file_path.is_file():
        raise CliError(f"上传文件不存在: {file_path}")
    size = file_path.stat().st_size
    if size <= 0:
        raise CliError(f"上传文件为空: {file_path}")
    return {
        "path": str(file_path),
        "name": file_path.name,
        "size": size,
        "sha256": _sha256_file(file_path),
    }


def _validate_upload_inputs(action: str, file_path: Path, sessionid: str) -> dict[str, Any]:
    if action not in UPLOAD_ACTIONS:
        raise CliError(f"upload action 不支持: {action}")
    if not sessionid or not sessionid.strip():
        raise CliError("upload 需要非空 --sessionid token")
    return upload_file_info(file_path)


def _upload_result_base(
    *,
    ip: str,
    url: str,
    action: str,
    file_info: dict[str, Any],
    sessionid: str,
    dry_run: bool,
) -> dict[str, Any]:
    return {
        "mode": "upload",
        "risk": "extreme",
        "ip": ip,
        "url": url,
        "action": action,
        "file": file_info,
        "dry_run": dry_run,
        "sessionid_present": bool(sessionid),
        "sessionid": REDACTED,
        "side_effects": {
            "upload": not dry_run,
            "reboot": False,
            "restore": False,
            "preconfig_switch": False,
        },
    }


def _upload_error(
    error_type: str,
    message: str,
    sessionid: str,
    *,
    status_code: int | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "type": error_type,
        "message": _redact_string(message, sessionid),
    }
    if status_code is not None:
        error["status_code"] = status_code
    return error


def _redact_value(value: Any, *, reveal_secrets: bool) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                REDACTED
                if SENSITIVE_UPLOAD_KEY_RE.search(str(key)) and not reveal_secrets
                else _redact_value(item, reveal_secrets=reveal_secrets)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item, reveal_secrets=reveal_secrets) for item in value]
    return value


def _redact_string(value: str, sessionid: str) -> str:
    if not sessionid:
        return value
    return value.replace(sessionid, REDACTED)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
