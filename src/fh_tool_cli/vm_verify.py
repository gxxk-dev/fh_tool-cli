from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from .config_store import decode_text
from .vm_common import VM_SCHEMA_VERSION, collect_host_tools, utc_now, write_json


VERIFY_TOOLS = [
    "qemu-arm-static",
    "proot",
    "ubireader_extract_images",
    "ubireader_extract_files",
    "unsquashfs",
    "jefferson",
]


def verify_vm(*, vm_root: Path, with_fhapi: bool, with_http: bool) -> dict[str, Any]:
    vm_root = vm_root.resolve()
    checks: list[dict[str, Any]] = []
    warnings: list[str] = []
    limitations = [
        "The VM verifies userspace runtime behavior only; hardware, sysmgr, and full AJAX state remain incomplete.",
        "Full /etc/rc.d/rcS is intentionally not started.",
    ]
    host_tools = collect_host_tools(VERIFY_TOOLS)
    for name, info in host_tools.items():
        _record(checks, f"host tool: {name}", bool(info["path"]), details=info)

    required_files = [
        "bin/qemu-exec",
        "bin/proot-shell",
        "bin/prepare-runtime",
        "bin/start-fhapi-proot",
        "bin/stop-fhapi-proot",
        "bin/start-http-stack-proot",
        "bin/verify",
        "rootfs-vm/bin/busybox",
        "rootfs-vm/sbin/uci",
        "rootfs-vm/lib/ld-linux.so.3",
        "rootfs-vm/fhrom/bin/cfg_cmd",
        "rootfs-vm/fhconf/sysinfo_conf",
        "rootfs-vm/fhconf/usrconfig_conf",
        "rootfs-vm/fhconf/attrconfig_conf",
        "rootfs-vm/opt/upt/apps",
        "rootfs-vm/fhdata/factory_conf",
        "rootfs-vm/fhdata/pre_usrconfig_conf",
        "rootfs-vm/fhdata/pre_attrconfig_conf",
    ]
    for relative in required_files:
        path = vm_root / relative
        _record(checks, f"required path: {relative}", path.exists(), details={"path": str(path)})

    for relative in (
        "bin/qemu-exec",
        "bin/proot-shell",
        "bin/prepare-runtime",
        "bin/start-fhapi-proot",
        "bin/stop-fhapi-proot",
        "bin/start-http-stack-proot",
        "bin/verify",
        "rootfs-vm/bin/busybox",
        "rootfs-vm/fhrom/bin/cfg_cmd",
    ):
        path = vm_root / relative
        _record(checks, f"executable: {relative}", path.exists() and path.stat().st_mode & 0o111 != 0)

    _record_process(checks, "qemu busybox executes", [str(vm_root / "bin" / "qemu-exec"), "/bin/busybox", "--help"], timeout=15)
    _record_process(
        checks,
        "proot root identity",
        [str(vm_root / "bin" / "proot-shell"), "-c", '/bin/busybox test "$(id -u)" = "0"'],
        timeout=20,
    )
    _record_process(
        checks,
        "uci read /fhconf",
        [str(vm_root / "bin" / "proot-shell"), "-c", "/sbin/uci -c /fhconf get sysinfo_conf.area_code.value >/dev/null"],
        timeout=20,
    )
    _record_process(
        checks,
        "uci read /fhdata",
        [str(vm_root / "bin" / "proot-shell"), "-c", "/sbin/uci -c /fhdata get factory_conf.SerialNumber.value >/dev/null"],
        timeout=20,
    )
    _record_cfg_cmd_load(checks, vm_root)

    if with_fhapi:
        _verify_fhapi(checks, vm_root)
    else:
        warnings.append("FHAPI probe skipped; pass --with-fhapi to start ubusd + cfgmgr and run cfg_cmd get.")

    if with_http:
        _verify_http(checks, vm_root)
    else:
        warnings.append("HTTP probe skipped; pass --with-http to start/probe nginx and thttpd.")

    ok = all(check["ok"] for check in checks)
    result: dict[str, Any] = {
        "schema_version": VM_SCHEMA_VERSION,
        "command": "vm verify",
        "created_at": utc_now(),
        "ok": ok,
        "vm_root": str(vm_root),
        "host_tools": host_tools,
        "checks": checks,
        "warnings": warnings,
        "limitations": limitations,
    }
    try:
        write_json(vm_root / "verify-manifest.json", result)
    except OSError as exc:
        warnings.append(f"could not write verify-manifest.json: {exc}")
    return result


def _record(checks: list[dict[str, Any]], name: str, ok: bool, *, details: dict[str, Any] | None = None) -> None:
    item: dict[str, Any] = {"name": name, "ok": bool(ok)}
    if details is not None:
        item["details"] = details
    checks.append(item)


def _record_process(checks: list[dict[str, Any]], name: str, argv: list[str], *, timeout: float) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        ok = completed.returncode == 0
        details = {
            "returncode": completed.returncode,
            "stdout_tail": decode_text(completed.stdout)[-1000:],
            "stderr_tail": decode_text(completed.stderr)[-1000:],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        ok = False
        details = {"error": str(exc)}
    _record(checks, name, ok, details=details)
    return checks[-1]


def _record_cfg_cmd_load(checks: list[dict[str, Any]], vm_root: Path) -> None:
    item = _record_process(
        checks,
        "cfg_cmd binary loads",
        [str(vm_root / "bin" / "qemu-exec"), "/fhrom/bin/cfg_cmd", "get", "InternetGatewayDevice.DeviceInfo.Manufacturer"],
        timeout=20,
    )
    if item["ok"]:
        return
    details = item.get("details", {})
    output = f"{details.get('stdout_tail', '')}\n{details.get('stderr_tail', '')}"
    if "FHAPI_INIT Error" in output or "ubus" in output.lower():
        item["ok"] = True
        item["details"]["accepted_without_runtime"] = True


def _verify_fhapi(checks: list[dict[str, Any]], vm_root: Path) -> None:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [str(vm_root / "bin" / "start-fhapi-proot")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(5)
        _record_process(
            checks,
            "FHAPI cfg_cmd get Manufacturer",
            [
                str(vm_root / "bin" / "proot-shell"),
                "-c",
                "cfg_cmd get InternetGatewayDevice.DeviceInfo.Manufacturer | grep -E 'FiberHome|get success'",
            ],
            timeout=25,
        )
    except OSError as exc:
        _record(checks, "FHAPI runtime starts", False, details={"error": str(exc)})
    finally:
        subprocess.run([str(vm_root / "bin" / "stop-fhapi-proot")], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        _kill_patterns(
            [
                "[q]emu-arm-static .* /fhrom/bin/cfgmgr",
                "[q]emu-arm-static .* /fhrom/bin/ubusd",
                "[q]emu-arm-static .* sleep /bin/sleep 3600",
            ]
        )


def _verify_http(checks: list[dict[str, Any]], vm_root: Path) -> None:
    if not _port_free(8080) or not _port_free(8840):
        _record(checks, "HTTP ports free", False, details={"ports": [8080, 8840]})
        return
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [str(vm_root / "bin" / "start-http-stack-proot")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(4)
        _record_process(checks, "HTTP GET /", ["curl", "-fsS", "--max-time", "5", "http://127.0.0.1:8080/"], timeout=10)
    except OSError as exc:
        _record(checks, "HTTP stack starts", False, details={"error": str(exc)})
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        _kill_patterns(
            [
                "[q]emu-arm-static .* /fhrom/bin/nginx",
                "[q]emu-arm-static .* /fhrom/bin/thttpd",
            ]
        )


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _kill_patterns(patterns: list[str]) -> None:
    for pattern in patterns:
        try:
            found = subprocess.run(
                ["pgrep", "-f", pattern],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        pids = [pid for pid in decode_text(found.stdout).split() if pid.isdigit()]
        if not pids:
            continue
        subprocess.run(["kill", *pids], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        time.sleep(1)
        alive = subprocess.run(
            ["pgrep", "-f", pattern],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        alive_pids = [pid for pid in decode_text(alive.stdout).split() if pid.isdigit()]
        if alive_pids:
            subprocess.run(["kill", "-9", *alive_pids], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
