from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

SENSITIVE_LOG_KEY_RE = re.compile(
    r"(sessionid|token|password|passwd|pwd|loginpd|loid|pppoe|acs|secret|psk|wepkey|wpakey|regpwd)",
    re.IGNORECASE,
)


class StructuredLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", None)
        fields = getattr(record, "structured_fields", None)
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if event:
            payload["event"] = event
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def configure_logging(*, verbose: int = 0, quiet: int = 0, log_file: str | None = None) -> None:
    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        path = Path(log_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(path, encoding="utf-8"))

    formatter = StructuredLogFormatter()
    for handler in handlers:
        handler.setFormatter(formatter)

    logging.basicConfig(
        level=level,
        handlers=handlers,
        force=True,
    )


def log_event(level: int, event: str, **fields: Any) -> None:
    logging.getLogger("fh_tool_cli").log(
        level,
        event,
        extra={
            "event": event,
            "structured_fields": redact_log_fields(fields),
        },
    )


def redact_log_fields(value: Any, *, key: str | None = None) -> Any:
    if key is not None and SENSITIVE_LOG_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): redact_log_fields(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [redact_log_fields(item) for item in value]
    if isinstance(value, tuple):
        return [redact_log_fields(item) for item in value]
    return value


def emit(data: Any, json_mode: bool) -> None:
    if json_mode or isinstance(data, dict):
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        return

    sys.stdout.write(str(data) + "\n")


def emit_error(message: str) -> None:
    Console(file=sys.stderr).print(f"[bold red]错误:[/bold red] {message}")


def emit_cancelled() -> None:
    Console(file=sys.stderr).print("[yellow]已取消[/yellow]")
