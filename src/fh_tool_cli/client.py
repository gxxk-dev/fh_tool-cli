from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from .errors import FHToolError
from .output import log_event


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    log_event(logging.DEBUG, "tcp.probe.start", ip=ip, port=port)
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            log_event(logging.DEBUG, "tcp.probe.result", ip=ip, port=port, open=True)
            return True
    except OSError:
        log_event(logging.DEBUG, "tcp.probe.result", ip=ip, port=port, open=False)
        return False


def make_download_url(ip: str, value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return urljoin(f"http://{ip}:8080", value)


def download_to_file(ip: str, url_value: str, output: Path, timeout: float) -> dict[str, Any]:
    url = make_download_url(ip, url_value)
    log_event(logging.INFO, "download.start", url=url, output=str(output))
    try:
        response = requests.get(url, timeout=timeout, stream=True)
    except requests.RequestException as exc:
        log_event(logging.INFO, "download.error", url=url, output=str(output), error=str(exc))
        raise FHToolError(f"下载失败 {url}: {exc}") from exc
    if response.status_code != 200:
        log_event(logging.INFO, "download.http_error", url=url, output=str(output), status_code=response.status_code)
        raise FHToolError(f"下载失败 {url}: HTTP {response.status_code}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as file:
        for chunk in response.iter_content(chunk_size=1024 * 128):
            if chunk:
                file.write(chunk)
    bytes_written = output.stat().st_size
    log_event(
        logging.INFO,
        "download.success",
        url=url,
        output=str(output),
        bytes=bytes_written,
        content_type=response.headers.get("Content-Type"),
    )
    return {
        "url": url,
        "output": str(output),
        "bytes": bytes_written,
        "content_type": response.headers.get("Content-Type"),
    }
