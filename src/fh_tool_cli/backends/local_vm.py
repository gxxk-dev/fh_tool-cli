from __future__ import annotations

import subprocess
from pathlib import Path

from ..config_store import decode_text
from ..errors import FHToolError

DEFAULT_VM_ROOT = Path("/mnt/dev-cold/HG5143F-ONU-vm")


class LocalVmShell:
    def __init__(self, vm_root: Path = DEFAULT_VM_ROOT, *, timeout: float = 5.0):
        self.vm_root = vm_root
        self.timeout = timeout

    def run(self, command: str) -> str:
        self._validate_vm_root()
        proot_shell = self.vm_root / "bin" / "proot-shell"
        env_command = (
            "export PATH=/fhrom/fhshell:/usr/bin:/usr/sbin:/bin:/sbin:/fhrom/bin; "
            "export LD_LIBRARY_PATH=/lib:/usr/lib:/fhrom/lib:/usr/lib/glib-2.0:"
            "/opt/upt/apps/lib:/opt/upt/apps/usr/lib; "
            f"{command}"
        )
        try:
            completed = subprocess.run(
                [str(proot_shell), "-c", env_command],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FHToolError(f"local VM command failed: {exc}") from exc
        output = decode_text(completed.stdout)
        error = decode_text(completed.stderr)
        if completed.returncode != 0:
            detail = error.strip() or output.strip() or f"exit {completed.returncode}"
            raise FHToolError(f"local VM command failed: {detail}")
        return output

    def _validate_vm_root(self) -> None:
        proot_shell = self.vm_root / "bin" / "proot-shell"
        cfg_cmd = self.vm_root / "rootfs-vm" / "fhrom" / "bin" / "cfg_cmd"
        if not self.vm_root.is_dir():
            raise FHToolError(f"local VM root is not a directory: {self.vm_root}")
        if not proot_shell.is_file():
            if (self.vm_root / "fhrom" / "bin" / "cfg_cmd").is_file():
                raise FHToolError(
                    "local VM root must be the VM workspace directory, not rootfs-vm; "
                    f"got {self.vm_root}"
                )
            raise FHToolError(
                "local VM root must contain bin/proot-shell; "
                f"not found: {proot_shell}"
            )
        if not cfg_cmd.is_file():
            raise FHToolError(
                "local VM root must contain rootfs-vm/fhrom/bin/cfg_cmd; "
                f"not found: {cfg_cmd}"
            )
