from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from rich.console import Console


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

    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def emit(data: Any, json_mode: bool) -> None:
    if json_mode or isinstance(data, dict):
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        return

    sys.stdout.write(str(data) + "\n")


def emit_error(message: str) -> None:
    Console(file=sys.stderr).print(f"[bold red]错误:[/bold red] {message}")


def emit_cancelled() -> None:
    Console(file=sys.stderr).print("[yellow]已取消[/yellow]")
