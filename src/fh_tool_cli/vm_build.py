from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .errors import FHToolError
from .vm_common import (
    VM_SCHEMA_VERSION,
    append_event,
    copy_tree_contents,
    require_empty_or_force,
    require_host_tools,
    run_command,
    sha256_file,
    utc_now,
    write_json,
)


BUILD_TOOLS = [
    "ubireader_extract_images",
    "ubireader_extract_files",
    "unsquashfs",
    "jefferson",
    "qemu-arm-static",
    "proot",
]

FACTORY_JFFS2_OFFSET = 0x380000


def build_vm(
    *,
    dump_dir: Path,
    output_dir: Path,
    rootfs_slot: str,
    force: bool,
) -> dict[str, Any]:
    dump_dir = dump_dir.resolve()
    if not dump_dir.is_dir():
        raise FHToolError(f"dump dir is not a directory: {dump_dir}")
    if rootfs_slot not in {"active", "A", "B"}:
        raise FHToolError("--rootfs-slot must be active, A, or B")
    require_empty_or_force(output_dir, force=force)
    output_dir.mkdir(parents=True, exist_ok=True)
    rootfs_dir = output_dir / "rootfs-vm"
    source_dir = output_dir / "source"
    logs_dir = output_dir / "logs"
    bin_dir = output_dir / "bin"
    for directory in (rootfs_dir, source_dir, logs_dir, bin_dir):
        directory.mkdir(parents=True, exist_ok=True)

    events_path = output_dir / "events.ndjson"
    append_event(events_path, "build.start", dump_dir=str(dump_dir), output_dir=str(output_dir))
    tools = require_host_tools(BUILD_TOOLS)

    manifest = _load_dump_manifest(dump_dir)
    selected_slot, slot_warning = select_rootfs_slot(rootfs_slot, manifest=manifest)
    warnings: list[str] = []
    if slot_warning:
        warnings.append(slot_warning)
    rootfs_dump = find_dump(dump_dir, index=0 if selected_slot == "A" else 1, name_contains=f"rootfs{selected_slot}")
    data_dump = find_dump(dump_dir, index=2, name_contains="data", prefer_contains="padbad")
    factory_dump = find_dump(dump_dir, index=6, name_contains="factory")
    append_event(
        events_path,
        "build.dumps.selected",
        rootfs=str(rootfs_dump),
        data=str(data_dump),
        factory=str(factory_dump),
        slot=selected_slot,
    )

    rootfs_image = _extract_rootfs_image(rootfs_dump, logs_dir, events_path)
    _extract_squashfs_root(rootfs_image, rootfs_dir, logs_dir, events_path)
    _extract_data_volumes(data_dump, rootfs_dir, logs_dir, events_path)
    _extract_factory(factory_dump, source_dir, rootfs_dir, logs_dir, events_path)
    _normalize_runtime(rootfs_dir)
    _write_scripts(bin_dir)
    _write_workspace_readme(output_dir)

    outputs = {
        "rootfs": str(rootfs_dir),
        "source": str(source_dir),
        "logs": str(logs_dir),
        "bin": str(bin_dir),
        "manifest": str(output_dir / "build-manifest.json"),
        "events": str(events_path),
    }
    source_sha = {
        "rootfs": sha256_file(rootfs_dump),
        "data": sha256_file(data_dump),
        "factory": sha256_file(factory_dump),
    }
    result: dict[str, Any] = {
        "schema_version": VM_SCHEMA_VERSION,
        "command": "vm build",
        "created_at": utc_now(),
        "ok": True,
        "dump_dir": str(dump_dir),
        "output_dir": str(output_dir),
        "rootfs_slot": selected_slot,
        "host_tools": tools,
        "source_dumps": {
            "rootfs": str(rootfs_dump),
            "data": str(data_dump),
            "factory": str(factory_dump),
        },
        "source_sha256": source_sha,
        "outputs": outputs,
        "warnings": warnings,
        "limitations": [
            "This is a userspace proot/qemu-arm-static VM, not a full board-level QEMU boot.",
            "Full /etc/rc.d/rcS is intentionally not used by default.",
            "mtd3 nvram is not merged into the VM rootfs.",
        ],
    }
    write_json(output_dir / "build-manifest.json", result)
    append_event(events_path, "build.done", ok=True)
    return result


def select_rootfs_slot(rootfs_slot: str, *, manifest: dict[str, Any] | None = None) -> tuple[str, str | None]:
    if rootfs_slot in {"A", "B"}:
        return rootfs_slot, None
    text = json.dumps(manifest or {}, ensure_ascii=False)
    lowered = text.lower()
    if "rootfsb" in lowered or "rootfs_b" in lowered or "active_flag=b" in lowered or '"active_flag": "b"' in lowered:
        return "B", None
    if "rootfsa" in lowered or "rootfs_a" in lowered or "active_flag=a" in lowered or '"active_flag": "a"' in lowered:
        return "A", None
    return "A", "active rootfs slot was not found in dump metadata; defaulting to rootfsA"


def find_dump(dump_dir: Path, *, index: int, name_contains: str, prefer_contains: str | None = None) -> Path:
    candidates = [
        path
        for path in dump_dir.rglob("*.bin")
        if path.is_file()
        and (path.name.startswith(f"mtd{index}_") or path.name.startswith(f"mtd{index:02d}_"))
        and name_contains.lower() in path.name.lower()
    ]
    if not candidates:
        raise FHToolError(f"missing mtd{index} {name_contains} dump in {dump_dir}")
    if prefer_contains:
        preferred = [path for path in candidates if prefer_contains.lower() in path.name.lower()]
        if preferred:
            return sorted(preferred, key=lambda item: (len(str(item)), str(item)))[0]
    return sorted(candidates, key=lambda item: (len(str(item)), str(item)))[0]


def _load_dump_manifest(dump_dir: Path) -> dict[str, Any] | None:
    for name in ("dump-manifest.json", "manifest.json"):
        path = dump_dir / name
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
    return None


def _extract_rootfs_image(rootfs_dump: Path, logs_dir: Path, events_path: Path) -> Path:
    output = logs_dir / "rootfs_ubi_images"
    output.mkdir(parents=True, exist_ok=True)
    run_command(
        ["ubireader_extract_images", "-o", str(output), str(rootfs_dump)],
        log_path=logs_dir / "ubireader-rootfs-images.log",
    )
    images = sorted(output.rglob("*vol-rootfs_ubifs*.ubifs"))
    if not images:
        raise FHToolError("rootfs_ubifs volume image was not extracted")
    append_event(events_path, "build.rootfs_image.extracted", image=str(images[0]))
    return images[0]


def _extract_squashfs_root(rootfs_image: Path, rootfs_dir: Path, logs_dir: Path, events_path: Path) -> None:
    run_command(
        ["unsquashfs", "-f", "-d", str(rootfs_dir), str(rootfs_image)],
        log_path=logs_dir / "unsquashfs-rootfs.log",
    )
    append_event(events_path, "build.rootfs.extracted", rootfs=str(rootfs_dir))


def _extract_data_volumes(data_dump: Path, rootfs_dir: Path, logs_dir: Path, events_path: Path) -> None:
    output = logs_dir / "data_ubi_files"
    output.mkdir(parents=True, exist_ok=True)
    run_command(
        ["ubireader_extract_files", "-o", str(output), str(data_dump)],
        log_path=logs_dir / "ubireader-data-files.log",
    )
    apps = _find_extracted_volume(output, "apps")
    userdata = _find_extracted_volume(output, "userdata")
    copy_tree_contents(apps, rootfs_dir / "opt" / "upt" / "apps")
    copy_tree_contents(userdata, rootfs_dir / "fhconf")
    append_event(events_path, "build.data.extracted", apps=str(apps), userdata=str(userdata))


def _extract_factory(factory_dump: Path, source_dir: Path, rootfs_dir: Path, logs_dir: Path, events_path: Path) -> None:
    factory_jffs2 = source_dir / "mtd6_factory_0x380000.jffs2"
    with factory_dump.open("rb") as source, factory_jffs2.open("wb") as target:
        source.seek(FACTORY_JFFS2_OFFSET)
        shutil.copyfileobj(source, target)
    factory_out = source_dir / "factory_jffs2"
    run_command(
        ["jefferson", "-f", "-d", str(factory_out), str(factory_jffs2)],
        log_path=logs_dir / "jefferson-factory.log",
    )
    copy_tree_contents(factory_out, rootfs_dir / "fhdata")
    append_event(events_path, "build.factory.extracted", factory=str(factory_out))


def _find_extracted_volume(root: Path, name: str) -> Path:
    matches = sorted(path for path in root.rglob(name) if path.is_dir() and path.name == name)
    if not matches:
        raise FHToolError(f"UBI volume was not extracted: {name}")
    return matches[0]


def _normalize_runtime(rootfs_dir: Path) -> None:
    for directory in (
        rootfs_dir / "tmp",
        rootfs_dir / "var" / "run",
        rootfs_dir / "var" / "log",
        rootfs_dir / "opt" / "upt" / "apps",
        rootfs_dir / "fhconf",
        rootfs_dir / "fhdata",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    busybox = rootfs_dir / "bin" / "busybox"
    if busybox.exists():
        for relative in (
            "bin/sh",
            "bin/ash",
            "bin/cat",
            "bin/chmod",
            "bin/cp",
            "bin/grep",
            "bin/ln",
            "bin/ls",
            "bin/mkdir",
            "bin/mount",
            "bin/rm",
            "bin/sleep",
            "bin/test",
            "usr/bin/env",
            "usr/bin/awk",
            "usr/bin/head",
            "sbin/ifconfig",
        ):
            path = rootfs_dir / relative
            if path.exists() and (path.is_symlink() or path.stat().st_size > 0):
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                path.unlink()
            target = os.path.relpath(busybox, start=path.parent)
            path.symlink_to(target)
    for preserved in ("passwd_old", "shadow_old", "group_old"):
        path = rootfs_dir / "etc" / preserved
        if not path.exists() and (rootfs_dir / "etc" / preserved.removesuffix("_old")).exists():
            shutil.copy2(rootfs_dir / "etc" / preserved.removesuffix("_old"), path)


def _write_scripts(bin_dir: Path) -> None:
    scripts = {
        "qemu-exec": QEMU_EXEC_SCRIPT,
        "prepare-runtime": PREPARE_RUNTIME_SCRIPT,
        "proot-shell": PROOT_SHELL_SCRIPT,
        "start-fhapi-proot": START_FHAPI_SCRIPT,
        "stop-fhapi-proot": STOP_FHAPI_SCRIPT,
        "start-http-stack-proot": START_HTTP_SCRIPT,
        "verify": VERIFY_SCRIPT,
    }
    for name, content in scripts.items():
        path = bin_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)


def _write_workspace_readme(output_dir: Path) -> None:
    (output_dir / "README.md").write_text(
        "# HG5143F userspace VM\n\n"
        "Run `./bin/verify` for local checks. Use `./bin/proot-shell` for a root shell in the extracted firmware.\n"
        "This workspace is a proot/qemu-arm-static userspace VM, not a full board-level QEMU boot.\n",
        encoding="utf-8",
    )


QEMU_EXEC_SCRIPT = """#!/usr/bin/env sh
set -eu
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOTFS="$BASE_DIR/rootfs-vm"
QEMU=${QEMU:-qemu-arm-static}
command -v "$QEMU" >/dev/null 2>&1 || { echo "missing $QEMU" >&2; exit 127; }
[ "$#" -gt 0 ] || set -- /bin/busybox --help
case "$1" in /*) guest_path=$1 ;; *) guest_path="/$1" ;; esac
shift
exec "$QEMU" -L "$ROOTFS" \
  -E PATH=/fhrom/fhshell:/usr/bin:/usr/sbin:/bin:/sbin:/fhrom/bin \
  -E LD_LIBRARY_PATH=/lib:/usr/lib:/fhrom/lib:/usr/lib/glib-2.0:/opt/upt/apps/lib:/opt/upt/apps/usr/lib \
  "$ROOTFS$guest_path" "$@"
"""

PREPARE_RUNTIME_SCRIPT = """#!/usr/bin/env sh
set -eu
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOTFS="$BASE_DIR/rootfs-vm"
mkdir -p "$ROOTFS/tmp" "$ROOTFS/var/run" "$ROOTFS/var/log"
[ ! -f "$ROOTFS/etc/passwd_old" ] || cp -f "$ROOTFS/etc/passwd_old" "$ROOTFS/tmp/passwd"
[ ! -f "$ROOTFS/etc/shadow_old" ] || cp -f "$ROOTFS/etc/shadow_old" "$ROOTFS/tmp/shadow"
[ ! -f "$ROOTFS/etc/group_old" ] || cp -f "$ROOTFS/etc/group_old" "$ROOTFS/tmp/group"
if [ ! -f "$ROOTFS/tmp/InternetGatewayDevice/DeviceInfo/property.conf" ] && [ -x "$ROOTFS/fhrom/bin/cfg_tool" ]; then
  proot -0 -q "${QEMU:-qemu-arm-static}" -r "$ROOTFS" -w / \
    -b /dev/null:/dev/null -b /dev/zero:/dev/zero -b /dev/random:/dev/random -b /dev/urandom:/dev/urandom \
    /usr/bin/env PATH=/fhrom/fhshell:/usr/bin:/usr/sbin:/bin:/sbin:/fhrom/bin \
    LD_LIBRARY_PATH=/lib:/usr/lib:/fhrom/lib:/usr/lib/glib-2.0:/opt/upt/apps/lib:/opt/upt/apps/usr/lib \
    /fhrom/bin/cfg_tool /fhrom/fhconf/param.tar.gz.enc >/dev/null 2>&1 || true
fi
"""

PROOT_SHELL_SCRIPT = """#!/usr/bin/env sh
set -eu
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOTFS="$BASE_DIR/rootfs-vm"
QEMU=${QEMU:-qemu-arm-static}
command -v proot >/dev/null 2>&1 || { echo "missing proot" >&2; exit 127; }
command -v "$QEMU" >/dev/null 2>&1 || { echo "missing $QEMU" >&2; exit 127; }
"$BASE_DIR/bin/prepare-runtime"
exec proot -0 -q "$QEMU" -r "$ROOTFS" -w / \
  -b /dev/null:/dev/null -b /dev/zero:/dev/zero -b /dev/random:/dev/random -b /dev/urandom:/dev/urandom \
  -b /proc:/proc -b /sys:/sys /bin/busybox sh -l "$@"
"""

START_FHAPI_SCRIPT = """#!/usr/bin/env sh
set -eu
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOG_DIR="$BASE_DIR/logs"
mkdir -p "$LOG_DIR"
"$BASE_DIR/bin/prepare-runtime"
if pgrep -f 'qemu-arm-static .* /fhrom/bin/cfgmgr' >/dev/null 2>&1; then
  echo "cfgmgr already appears to be running"
  exit 0
fi
exec "$BASE_DIR/bin/proot-shell" -c '
set -eu
export PATH=/fhrom/fhshell:/usr/bin:/usr/sbin:/bin:/sbin:/fhrom/bin
export LD_LIBRARY_PATH=/lib:/usr/lib:/fhrom/lib:/usr/lib/glib-2.0:/opt/upt/apps/lib:/opt/upt/apps/usr/lib
mkdir -p /var/run /var/log /tmp
rm -f /var/run/ubus.sock
/fhrom/bin/ubusd >/tmp/ubusd.log 2>&1 &
sleep 1
/fhrom/bin/cfgmgr >/tmp/cfgmgr.log 2>&1 &
sleep 3
echo "FHAPI runtime started: ubusd + cfgmgr"
while :; do sleep 3600; done
'
"""

STOP_FHAPI_SCRIPT = """#!/usr/bin/env sh
set -eu
FOUND=0
stop_pattern() {
  pids=$(pgrep -f "$1" || true)
  [ -n "$pids" ] || return 0
  FOUND=1
  kill $pids 2>/dev/null || true
}
stop_pattern 'qemu-arm-static .* /fhrom/bin/cfgmgr'
stop_pattern 'qemu-arm-static .* /fhrom/bin/ubusd'
stop_pattern 'qemu-arm-static .* sleep /bin/sleep 3600'
sleep 1
if [ "$FOUND" = 1 ]; then echo "FHAPI runtime stopped"; else echo "FHAPI runtime was not running"; fi
"""

START_HTTP_SCRIPT = """#!/usr/bin/env sh
set -eu
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if command -v ss >/dev/null 2>&1; then
  ss -ltn '( sport = :8840 )' | grep -q ':8840' && { echo "port 8840 is already in use" >&2; exit 1; }
  ss -ltn '( sport = :8080 )' | grep -q ':8080' && { echo "port 8080 is already in use" >&2; exit 1; }
fi
exec "$BASE_DIR/bin/proot-shell" -c '
set -eu
export PATH=/fhrom/fhshell:/usr/bin:/usr/sbin:/bin:/sbin:/fhrom/bin
export LD_LIBRARY_PATH=/lib:/usr/lib:/fhrom/lib:/usr/lib/glib-2.0:/opt/upt/apps/lib:/opt/upt/apps/usr/lib
mkdir -p /var/run /tmp /var/log
/fhrom/bin/thttpd -C /fhrom/fhconf/thttpd_nginx.conf
sleep 1
exec /fhrom/bin/nginx -c /fhconf/nginx.conf
'
"""

VERIFY_SCRIPT = """#!/usr/bin/env sh
set -eu
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOTFS="$BASE_DIR/rootfs-vm"

echo "[1/7] host tools"
command -v qemu-arm-static >/dev/null
command -v unsquashfs >/dev/null
command -v ubireader_extract_images >/dev/null
command -v proot >/dev/null
command -v jefferson >/dev/null

echo "[2/7] rootfs files"
test -x "$ROOTFS/bin/busybox"
test -x "$ROOTFS/sbin/uci"
test -f "$ROOTFS/lib/ld-linux.so.3"
test -x "$ROOTFS/fhrom/bin/cfg_cmd"
test -f "$ROOTFS/fhconf/sysinfo_conf"
test -f "$ROOTFS/fhconf/usrconfig_conf"
test -f "$ROOTFS/fhconf/attrconfig_conf"
test -d "$ROOTFS/opt/upt/apps"
test -f "$ROOTFS/fhdata/factory_conf"
test -f "$ROOTFS/fhdata/pre_usrconfig_conf"
test -f "$ROOTFS/fhdata/pre_attrconfig_conf"

echo "[3/7] ARM busybox executes"
"$BASE_DIR/bin/qemu-exec" /bin/busybox --help >/dev/null

echo "[4/7] proot runtime paths work"
"$BASE_DIR/bin/prepare-runtime"
"$BASE_DIR/bin/proot-shell" -c '/bin/busybox test "$(id -u)" = "0"'
"$BASE_DIR/bin/proot-shell" -c '/sbin/uci -c /fhconf get sysinfo_conf.area_code.value >/dev/null'
"$BASE_DIR/bin/proot-shell" -c '/sbin/uci -c /fhdata get factory_conf.SerialNumber.value >/dev/null'

echo "[5/7] vendor cfg_cmd status"
if pgrep -f 'qemu-arm-static .* /fhrom/bin/cfgmgr' >/dev/null 2>&1; then
  "$BASE_DIR/bin/proot-shell" -c 'cfg_cmd get InternetGatewayDevice.DeviceInfo.Manufacturer' >/tmp/hg5143f-cfg_cmd.out
  grep -Eq 'FiberHome|get success' /tmp/hg5143f-cfg_cmd.out
else
  if "$BASE_DIR/bin/qemu-exec" /fhrom/bin/cfg_cmd get InternetGatewayDevice.DeviceInfo.Manufacturer >/tmp/hg5143f-cfg_cmd.out 2>/tmp/hg5143f-cfg_cmd.err; then
    echo "cfg_cmd returned successfully without a detected cfgmgr runtime"
  elif grep -q 'FHAPI_INIT Error' /tmp/hg5143f-cfg_cmd.err /tmp/hg5143f-cfg_cmd.out; then
    echo "cfg_cmd binary loads; start FHAPI with ./bin/start-fhapi-proot for live cfg_cmd reads"
  else
    cat /tmp/hg5143f-cfg_cmd.out >&2
    cat /tmp/hg5143f-cfg_cmd.err >&2
    exit 1
  fi
fi

echo "[6/7] nginx config parses under proot"
"$BASE_DIR/bin/proot-shell" -c '/fhrom/bin/nginx -t -c /fhconf/nginx.conf >/dev/null'

echo "[7/7] optional HTTP stack probe"
if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 http://127.0.0.1:8080/ >/dev/null 2>&1; then
  echo "HTTP stack is running at http://127.0.0.1:8080/"
else
  echo "HTTP stack is not running; start it with ./bin/start-http-stack-proot"
fi

echo "verify ok"
"""
