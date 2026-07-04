from __future__ import annotations

import argparse

from .errors import CliError


DRY_RUN_HINT = "未传 --confirm，默认 dry-run；未执行写入。确认要写入设备时请重新运行并加 --confirm。"


DEPRECATED_CONFIRMATION_FLAGS = {
    "deprecated_yes": "--yes",
    "deprecated_danger": "--danger",
    "deprecated_extreme": "--i-know-this-can-break-my-device",
    "deprecated_backup_confirmed": "--backup-confirmed",
    "deprecated_execute": "--execute",
    "deprecated_dry_run": "--dry-run",
    "deprecated_allow_risky": "--allow-risky",
}


def reject_deprecated_confirmation_args(args: argparse.Namespace) -> None:
    used = [
        flag
        for attr, flag in DEPRECATED_CONFIRMATION_FLAGS.items()
        if getattr(args, attr, False)
    ]
    if used:
        raise CliError(
            f"{', '.join(used)} 已弃用。写入型命令默认 dry-run，确认执行请只加 --confirm"
        )


def is_confirmed(args: argparse.Namespace) -> bool:
    reject_deprecated_confirmation_args(args)
    return bool(getattr(args, "confirm", False))


def dry_run_notice() -> dict[str, object]:
    return {
        "dry_run": True,
        "executed": False,
        "hint": DRY_RUN_HINT,
        "confirm_requires": ["--confirm"],
    }
