from __future__ import annotations

# fh_tool 后端端点常量与 URL 构造。
# 独立成模块以避免 client.py 与 backends.fh_tool 之间的循环导入：
# backends.fh_tool 导入 client.tcp_open，而 client.py 需要这里的默认端口。

DEFAULT_FH_TOOL_PORT = 8080
# 8080 TCP 不可达时依次尝试的候选端口；HG6142A3 V03.00.M0000 实测 fh_tool API 在 80 端口。
FALLBACK_FH_TOOL_PORTS = (80,)
# TCP 探测超时上限（秒），控制候选端口全部不可达时的最坏延迟。
PORT_PROBE_TCP_TIMEOUT = 2.0


def fh_tool_base_url(ip: str, port: int) -> str:
    return f"http://{ip}:{port}"


def fh_tool_url(ip: str, port: int, path: str) -> str:
    return f"{fh_tool_base_url(ip, port)}{path}"
