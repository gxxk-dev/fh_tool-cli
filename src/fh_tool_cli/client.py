from __future__ import annotations

import socket
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from .errors import FHToolError


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def make_download_url(ip: str, value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return urljoin(f"http://{ip}:8080", value)


def download_to_file(ip: str, url_value: str, output: Path, timeout: float) -> dict[str, Any]:
    url = make_download_url(ip, url_value)
    try:
        response = requests.get(url, timeout=timeout, stream=True)
    except requests.RequestException as exc:
        raise FHToolError(f"下载失败 {url}: {exc}") from exc
    if response.status_code != 200:
        raise FHToolError(f"下载失败 {url}: HTTP {response.status_code}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as file:
        for chunk in response.iter_content(chunk_size=1024 * 128):
            if chunk:
                file.write(chunk)
    return {
        "url": url,
        "output": str(output),
        "bytes": output.stat().st_size,
        "content_type": response.headers.get("Content-Type"),
    }
