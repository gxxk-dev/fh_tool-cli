"""检查 pyproject.toml / __init__.py / uv.lock 三处版本的一致性。

发版需要同步修改三处版本(0.2.9 曾漏改 __init__.py 造成漂移),本脚本把
"发版三处同步"从纪律变成可校验的机器检查:

    uv run python scripts/check_version.py           # 三处一致 exit 0,否则列出差异 exit 1
    uv run python scripts/check_version.py --fix     # 把 __init__.py 修正为 pyproject 版本

--fix 不代改 uv.lock:uv.lock 里的项目条目版本由 `uv lock` 刷新。
仅使用标准库。
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
INIT_PATH = REPO_ROOT / "src" / "fh_tool_cli" / "__init__.py"
UV_LOCK_PATH = REPO_ROOT / "uv.lock"

INIT_VERSION_RE = re.compile(r'(?m)^__version__ = "(?P<version>[^"]+)"$')
UV_LOCK_ENTRY_RE = re.compile(
    r'\[\[package\]\]\nname = "fh-tool-cli"\nversion = "(?P<version>[^"]+)"'
)


def read_pyproject_version() -> str:
    with PYPROJECT_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    version = data.get("project", {}).get("version")
    if not version:
        raise SystemExit(f"{PYPROJECT_PATH} 缺少 project.version")
    return str(version)


def read_init_version() -> str:
    text = INIT_PATH.read_text(encoding="utf-8")
    match = INIT_VERSION_RE.search(text)
    if match is None:
        raise SystemExit(f"{INIT_PATH} 中找不到 __version__ 赋值")
    return match.group("version")


def read_uv_lock_version() -> str:
    text = UV_LOCK_PATH.read_text(encoding="utf-8")
    match = UV_LOCK_ENTRY_RE.search(text)
    if match is None:
        raise SystemExit(f"{UV_LOCK_PATH} 中找不到 fh-tool-cli 条目")
    return match.group("version")


def fix_init_version(target: str) -> bool:
    text = INIT_PATH.read_text(encoding="utf-8")
    new_text = INIT_VERSION_RE.sub(f'__version__ = "{target}"', text, count=1)
    if new_text == text:
        return False
    diff = difflib.unified_diff(
        text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=str(INIT_PATH),
        tofile=f"{INIT_PATH} (--fix)",
    )
    sys.stdout.writelines(diff)
    INIT_PATH.write_text(new_text, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="检查 pyproject/__init__/uv.lock 版本一致性")
    parser.add_argument(
        "--fix",
        action="store_true",
        help="把 __init__.py 的 __version__ 修正为 pyproject 版本(打印 diff;uv.lock 请用 uv lock 刷新)",
    )
    args = parser.parse_args(argv)

    if args.fix:
        target = read_pyproject_version()
        if fix_init_version(target):
            print(f"已把 {INIT_PATH} 的 __version__ 修正为 {target}")
            print("uv.lock 未改动;如需刷新请运行: uv lock")
            return 0
        print(f"{INIT_PATH} 的 __version__ 已是 {target},无需修改")
        return 0

    versions = {
        f"pyproject.toml ({PYPROJECT_PATH.name})": read_pyproject_version(),
        f"src/fh_tool_cli/__init__.py": read_init_version(),
        f"uv.lock (fh-tool-cli 条目)": read_uv_lock_version(),
    }
    distinct = sorted(set(versions.values()))
    if len(distinct) == 1:
        print(f"版本一致: {distinct[0]}")
        return 0

    print("版本不一致:")
    for label, version in versions.items():
        print(f"  {label}: {version}")
    print("修复: 统一三处版本(__init__.py 可用 --fix;uv.lock 用 uv lock)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
