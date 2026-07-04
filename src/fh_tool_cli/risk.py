from __future__ import annotations

import argparse

from .errors import CliError


def require_yes(args: argparse.Namespace, message: str) -> None:
    if not getattr(args, "yes", False):
        raise CliError(f"{message}。如确认执行，请加 --yes")


def require_danger(args: argparse.Namespace, message: str) -> None:
    require_yes(args, message)
    if not getattr(args, "danger", False):
        raise CliError(f"{message}。如确认危险动作，请加 --danger")


def require_extreme(args: argparse.Namespace, message: str) -> None:
    require_danger(args, message)
    if not getattr(args, "i_know_this_can_break_my_device", False):
        raise CliError(
            f"{message}。最后确认参数是 --i-know-this-can-break-my-device"
        )
