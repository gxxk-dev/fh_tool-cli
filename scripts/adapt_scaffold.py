#!/usr/bin/env python3
"""设备适配脚手架：把新型号的凭据派生公式接入 fh_tool-cli 注册表。

面向"AI agent / 维护者"的机械臂（流程见仓库根 ADAPT.md）。对
src/fh_tool_cli/credentials.py 的注册表锚点与 tests/ 的联动断言做注入：

  - 默认 dry-run：打印每个文件的 unified diff，不落盘
  - --write：全部编辑在内存完成后一次性写入（任一锚点失败则整体 abort、零写入），
    随后自动运行 test_credentials.py 自检（--skip-self-check 可跳过）
  - 条件触点（telnet.py 提示文案、fh_tool 端口、hash 格式、su 写入格式等）只打印
    决策清单，不做改写——那些是需要人工/agent 语义判断的部分

仅使用标准库；一律通过 `uv run python scripts/adapt_scaffold.py ...` 运行。
"""

from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CREDENTIALS_PATH = REPO_ROOT / "src" / "fh_tool_cli" / "credentials.py"
TEST_CREDENTIALS_PATH = REPO_ROOT / "tests" / "test_credentials.py"
TEST_PARSER_PATH = REPO_ROOT / "tests" / "test_parser_registration.py"
TEST_SU_VERIFY_PATH = REPO_ROOT / "tests" / "test_cli_su_verify.py"

MAC_TEST_VECTOR = "D8F50736BC10"
MAC_TEST_SUFFIX = "36BC10"

ADAPT_GUIDE_URL = "https://github.com/gxxk-dev/fh_tool-cli/blob/main/ADAPT.md"

CONDITIONAL_TOUCHPOINTS = [
    (
        "src/fh_tool_cli/backends/telnet.py:179-181",
        "登录候选耗尽的硬编码提示文案（新增 telnet 候选时必须更新型号列举）",
    ),
    (
        "src/fh_tool_cli/fh_endpoints.py:8-9",
        "FALLBACK_FH_TOOL_PORTS（该型号 fh_tool API 不在 80/8080 时扩展候选端口）",
    ),
    (
        "src/fh_tool_cli/crypt_unix.py:17-19,35-38",
        "hash MAGIC 与 _CRYPT_HASH_PATTERN（su hash 非 $1$/$5$ 时需新增 crypt 实现、正则与测试向量）",
    ),
    (
        "src/fh_tool_cli/account.py:84-95",
        "set_su_runtime_password 写入格式（新型号 runtime 文件非 md5-crypt 时分型号分支）",
    ),
    (
        "README.md / ROADMAP.md",
        "补充新型号适配说明（公式、固件、验证结论）",
    ),
    (
        "confidence/note",
        "实机验证通过后把默认的 pending-live-verify 文案回填为实测结论",
    ),
]


class ScaffoldError(Exception):
    """锚点未命中、参数不合法或型号已存在；整体 abort、零写入。"""


def escape_literal(value: str) -> str:
    """把公式前缀转成可嵌入 Python 双引号字符串字面量的形式。"""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def segment_between(content: str, *, start_marker: str, end_marker: str, label: str) -> str:
    """取 content 中 start_marker 起首次出现 end_marker 止的片段（含两端）。

    用于"往容器末尾追加"类编辑：锚点是容器形状而非当前末项内容，从而对
    连续追加多个型号保持幂等。
    """
    start = content.find(start_marker)
    if start == -1:
        raise ScaffoldError(f"锚点 {label!r} 起点未命中；文件结构可能已变化，请人工对照 ADAPT.md 触点索引表")
    end = content.find(end_marker, start)
    if end == -1:
        raise ScaffoldError(f"锚点 {label!r} 终点未命中；文件结构可能已变化，请人工对照 ADAPT.md 触点索引表")
    return content[start : end + len(end_marker)]


def append_inside(segment: str, *, end_marker: str, lines: list[str]) -> str:
    """把若干行插入容器片段的收尾标记之前（segment 以 end_marker 收尾）。"""
    body = segment[: -len(end_marker)]
    return body + "\n" + "\n".join(lines) + end_marker


def normalize_model(model: str) -> tuple[str, str]:
    """返回 (slug, const)：HG9999A -> ("hg9999a", "HG9999A")。"""
    cleaned = model.strip()
    slug = re.sub(r"[^a-z0-9]+", "", cleaned.lower())
    const = re.sub(r"[^A-Z0-9]+", "", cleaned.upper())
    if not slug or not const:
        raise ScaffoldError(f"无法从型号名 {model!r} 解析出 slug/常量前缀")
    return slug, const


# ---------------------------------------------------------------------------
# credentials.py 编辑
# ---------------------------------------------------------------------------


def credentials_edits(
    *,
    content: str,
    slug: str,
    const: str,
    telnet_username: str | None,
    telnet_prefix: str | None,
    su_prefix: str | None,
    su_kind_suffix: str,
    confidence: str,
    source: str,
    note: str,
) -> list[tuple[str, str, str]]:
    """返回 (label, old, new) 列表；按文件中出现顺序应用。

    容器类锚点（kind 元组、候选列表等）用 segment_between 动态定位收尾，
    对连续追加多个型号保持幂等；其余锚点是稳定文本。
    """
    edits: list[tuple[str, str, str]] = []
    su_kind = f"{slug}-{su_kind_suffix}"
    derive_name_su = f"derive_{slug}_{su_kind_suffix}"

    comment = f"# {const}: 待实机验证的派生公式（来源见 derive 函数 source/note）。"

    # 1) kind 注册表（动态定位元组收尾，不依赖当前末项）
    kinds_segment = segment_between(
        content,
        start_marker="DERIVED_CREDENTIAL_KINDS = (",
        end_marker="\n)",
        label="DERIVED_CREDENTIAL_KINDS",
    )
    new_kinds = []
    if telnet_username is not None:
        new_kinds.append(f'    "{slug}-telnet",')
    new_kinds.append(f'    "{su_kind}",')
    edits.append(("DERIVED_CREDENTIAL_KINDS", kinds_segment, append_inside(kinds_segment, end_marker="\n)", lines=new_kinds)))

    # 2) 常量块（插在 HG6142A3_SU_PASSWORD_PREFIX 之后、注释块之前）
    constants = comment + "\n"
    if telnet_username is not None:
        constants += (
            f'{const}_TELNET_USERNAME = "{escape_literal(telnet_username)}"\n'
            f'{const}_TELNET_PASSWORD_PREFIX = "{escape_literal(telnet_prefix)}"\n'
        )
    if su_prefix is not None:
        constants += f'{const}_SU_PASSWORD_PREFIX = "{escape_literal(su_prefix)}"\n'
    edits.append(
        (
            "型号常量",
            'HG6142A3_SU_PASSWORD_PREFIX = "hg2x0"\n',
            f'HG6142A3_SU_PASSWORD_PREFIX = "hg2x0"\n{constants}',
        )
    )

    # 3) automatic fallback 可补齐密码的用户名集合（仅 telnet 候选；行级动态定位）
    if telnet_username is not None:
        frozenset_marker = "DERIVED_TELNET_USERNAMES = frozenset({"
        frozenset_index = content.find(frozenset_marker)
        if frozenset_index == -1:
            raise ScaffoldError("锚点 'DERIVED_TELNET_USERNAMES' 未命中；文件结构可能已变化")
        frozenset_line_end = content.index("\n", frozenset_index)
        frozenset_line = content[frozenset_index:frozenset_line_end]
        edits.append(
            (
                "DERIVED_TELNET_USERNAMES",
                frozenset_line,
                frozenset_line.replace("})", f", {const}_TELNET_USERNAME}})", 1),
            )
        )

    # 4) derive 函数（插在 derive_credentials 之前）
    funcs: list[str] = []
    if telnet_username is not None:
        funcs.append(
            f"def derive_{slug}_telnet(mac: str) -> DerivedCredential:\n"
            "    normalized = normalize_mac(mac)\n"
            "    suffix = mac_suffix(normalized)\n"
            "    return DerivedCredential(\n"
            f'        kind="{slug}-telnet",\n'
            f"        username={const}_TELNET_USERNAME,\n"
            f'        password=f"{{{const}_TELNET_PASSWORD_PREFIX}}{{suffix}}",\n'
            f"        source={source!r},\n"
            "        mac=normalized,\n"
            "        mac_suffix=suffix,\n"
            "        persistent=True,\n"
            '        target="telnet-login",\n'
            f"        confidence={confidence!r},\n"
            '        integration_level="automatic-telnet-fallback",\n'
            f"        note={note!r},\n"
            "    )"
        )
    if su_prefix is not None:
        funcs.append(
            f"def {derive_name_su}(mac: str) -> DerivedCredential:\n"
            "    normalized = normalize_mac(mac)\n"
            "    suffix = mac_suffix(normalized)\n"
            "    return DerivedCredential(\n"
            f'        kind="{su_kind}",\n'
            '        username="root",\n'
            f'        password=f"{{{const}_SU_PASSWORD_PREFIX}}{{suffix}}",\n'
            f"        source={source!r},\n"
            "        mac=normalized,\n"
            "        mac_suffix=suffix,\n"
            "        persistent=False,\n"
            '        target="su-root-runtime",\n'
            f"        confidence={confidence!r},\n"
            '        integration_level="derive-display-only",\n'
            f"        note={note!r},\n"
            "    )"
        )
    edits.append(
        (
            "derive 函数",
            "\n\ndef derive_credentials(mac: str, kind: str) -> list[DerivedCredential]:",
            "\n\n" + "\n\n\n".join(funcs) + "\n\n\ndef derive_credentials(mac: str, kind: str) -> list[DerivedCredential]:",
        )
    )

    # 5) "all" 分支列表（动态定位列表收尾）
    all_segment = segment_between(
        content,
        start_marker='    if kind == "all":',
        end_marker="\n        ]",
        label='"all" 分支列表',
    )
    all_lines = []
    if telnet_username is not None:
        all_lines.append(f"            derive_{slug}_telnet(mac),")
    if su_prefix is not None:
        all_lines.append(f"            {derive_name_su}(mac),")
    edits.append(('"all" 分支列表', all_segment, append_inside(all_segment, end_marker="\n        ]", lines=all_lines)))

    # 6) kind 分发分支（插在 raise ValueError 之前）
    branches = ""
    if telnet_username is not None:
        branches += (
            f'    if kind == "{slug}-telnet":\n        return [derive_{slug}_telnet(mac)]\n'
        )
    if su_prefix is not None:
        branches += f'    if kind == "{su_kind}":\n        return [{derive_name_su}(mac)]\n'
    edits.append(
        (
            "kind 分发分支",
            '    raise ValueError(f"unsupported credential kind: {kind}")',
            branches + '    raise ValueError(f"unsupported credential kind: {kind}")',
        )
    )

    # 7) 候选列表（顺序 = 登录/验证尝试顺序，新候选追加在尾部；动态定位函数体收尾）
    if telnet_username is not None:
        telnet_segment = segment_between(
            content,
            start_marker="def telnet_login_candidates(",
            end_marker="\n    ]",
            label="telnet_login_candidates",
        )
        edits.append(
            (
                "telnet_login_candidates",
                telnet_segment,
                append_inside(
                    telnet_segment,
                    end_marker="\n    ]",
                    lines=[f'        ("{slug}-telnet", {const}_TELNET_USERNAME, f"{{{const}_TELNET_PASSWORD_PREFIX}}{{suffix}}"),'],
                ),
            )
        )
    if su_prefix is not None:
        su_segment = segment_between(
            content,
            start_marker="def su_password_candidates(",
            end_marker="\n    ]",
            label="su_password_candidates",
        )
        edits.append(
            (
                "su_password_candidates",
                su_segment,
                append_inside(
                    su_segment,
                    end_marker="\n    ]",
                    lines=[f'        ("{su_kind}", f"{{{const}_SU_PASSWORD_PREFIX}}{{suffix}}"),'],
                ),
            )
        )
    return edits


# ---------------------------------------------------------------------------
# tests 编辑
# ---------------------------------------------------------------------------


def test_credentials_edits(
    *,
    content: str,
    slug: str,
    const: str,
    telnet_username: str | None,
    telnet_prefix: str | None,
    su_prefix: str | None,
    su_kind_suffix: str,
) -> list[tuple[str, str, str]]:
    edits: list[tuple[str, str, str]] = []
    su_kind = f"{slug}-{su_kind_suffix}"
    derive_name_su = f"derive_{slug}_{su_kind_suffix}"
    telnet_password_literal = f"{escape_literal(telnet_prefix or '')}{MAC_TEST_SUFFIX}"
    su_password_literal = f"{escape_literal(su_prefix or '')}{MAC_TEST_SUFFIX}"

    # 1) import 块：整体重排（加入新名字后按字母序），对连续追加保持幂等
    import_match = re.search(r"from fh_tool_cli\.credentials import \(\n(.*?)\n\)", content, re.DOTALL)
    if import_match is None:
        raise ScaffoldError("test import 块锚点未命中；文件结构可能已变化")
    names = [line.strip().rstrip(",") for line in import_match.group(1).splitlines() if line.strip()]
    new_names = []
    if su_prefix is not None:
        new_names.append(f"{const}_SU_PASSWORD_PREFIX")
    if telnet_username is not None:
        new_names.append(f"{const}_TELNET_PASSWORD_PREFIX")
    if telnet_username is not None:
        new_names.append(f"derive_{slug}_telnet")
    if su_prefix is not None:
        new_names.append(derive_name_su)
    merged = sorted(set(names) | set(new_names))
    import_block_old = import_match.group(0)
    import_block_new = "from fh_tool_cli.credentials import (\n" + "".join(f"    {name},\n" for name in merged) + ")"
    edits.append(("test import 块", import_block_old, import_block_new))

    # 2) "all" 顺序断言（按行动态定位，不依赖当前列表内容）
    all_line_marker = '["hg5143f-telnet", "hg6142a3-telnet", "hg5143f-su", "hg6142a3-root"'
    all_line_index = content.find(all_line_marker)
    if all_line_index == -1:
        raise ScaffoldError('"all" 顺序断言锚点未命中；文件结构可能已变化')
    line_start = content.rindex("\n", 0, all_line_index) + 1
    line_end = content.index("\n", all_line_index)
    all_line = content[line_start:line_end]
    new_kinds = ""
    if telnet_username is not None:
        new_kinds += f', "{slug}-telnet"'
    if su_prefix is not None:
        new_kinds += f', "{su_kind}"'
    edits.append(('"all" 顺序断言', all_line, all_line[:-2] + new_kinds + all_line[-2:]))

    # 3) telnet 候选精确列表断言（动态定位测试函数内列表收尾）
    if telnet_username is not None:
        telnet_segment = segment_between(
            content,
            start_marker="def test_telnet_login_candidates_are_ordered",
            end_marker="\n            ],",
            label="telnet candidates 断言",
        )
        edits.append(
            (
                "telnet candidates 断言",
                telnet_segment,
                append_inside(
                    telnet_segment,
                    end_marker="\n            ],",
                    lines=[f'                ("{slug}-telnet", "{escape_literal(telnet_username)}", "{telnet_password_literal}"),'],
                ),
            )
        )

    # 4) su 候选精确列表断言（单行列表，在 `],` 前插入）
    if su_prefix is not None:
        su_segment = segment_between(
            content,
            start_marker="def test_su_password_candidates_are_ordered",
            end_marker="],",
            label="su candidates 断言",
        )
        edits.append(
            (
                "su candidates 断言",
                su_segment,
                su_segment[: -len("],")] + f', ("{su_kind}", "{su_password_literal}")],',
            )
        )

    # 5) fallback 计数断言（动态提取当前候选数 +1，对连续追加幂等）
    if telnet_username is not None:
        fallback_match = re.search(
            r"(self\.assertEqual\(len\(credentials\.fallback_credentials\), )(\d+)(\))",
            content,
        )
        if fallback_match is None:
            raise ScaffoldError("fallback 计数断言锚点未命中；文件结构可能已变化")
        current_count = int(fallback_match.group(2))
        edits.append(
            (
                "fallback 计数断言",
                fallback_match.group(0),
                f"{fallback_match.group(1)}{current_count + 1}{fallback_match.group(3)}",
            )
        )

    # 6) 新增派生函数测试（文件尾 if __name__ 之前）
    tests = ""
    if telnet_username is not None:
        tests += (
            f"    def test_{slug}_telnet_derivation_uses_derived_prefix(self) -> None:\n"
            f'        credential = derive_{slug}_telnet("{MAC_TEST_VECTOR}")\n'
            "\n"
            f'        self.assertEqual(credential.kind, "{slug}-telnet")\n'
            f'        self.assertEqual(credential.username, "{escape_literal(telnet_username)}")\n'
            f"        self.assertTrue(credential.password.startswith({const}_TELNET_PASSWORD_PREFIX))\n"
            f'        self.assertTrue(credential.password.endswith("{MAC_TEST_SUFFIX}"))\n'
            '        self.assertEqual(credential.integration_level, "automatic-telnet-fallback")\n'
            "\n"
        )
    if su_prefix is not None:
        tests += (
            f"    def test_{slug}_{su_kind_suffix}_derivation_is_display_only(self) -> None:\n"
            f'        credential = {derive_name_su}("{MAC_TEST_VECTOR}")\n'
            "\n"
            f'        self.assertEqual(credential.kind, "{su_kind}")\n'
            f"        self.assertTrue(credential.password.startswith({const}_SU_PASSWORD_PREFIX))\n"
            f'        self.assertTrue(credential.password.endswith("{MAC_TEST_SUFFIX}"))\n'
            "        self.assertFalse(credential.persistent)\n"
            '        self.assertEqual(credential.integration_level, "derive-display-only")\n'
        )
    edits.append(
        (
            "新增派生函数测试",
            '\n\nif __name__ == "__main__":',
            "\n\n" + tests.rstrip("\n") + '\n\n\nif __name__ == "__main__":',
        )
    )
    return edits


def test_parser_registration_edit(
    *, slug: str, su_kind_suffix: str, telnet_username: str | None
) -> tuple[str, str, str]:
    # 优先测 telnet kind（存在时），否则测 su kind，保证测的是本次实际注册的 kind。
    registered_kind = f"{slug}-telnet" if telnet_username is not None else f"{slug}-{su_kind_suffix}"
    method = (
        f"    def test_kind_{slug}_is_registered(self) -> None:\n"
        "        args = cli.parse_args(\n"
        "            [\n"
        '                "credentials",\n'
        '                "derive",\n'
        '                "--kind",\n'
        f'                "{registered_kind}",\n'
        '                "--ip",\n'
        '                "192.0.2.1",\n'
        '                "--mac",\n'
        f'                "{MAC_TEST_VECTOR}",\n'
        "            ]\n"
        "        )\n"
        "\n"
        "        self.assertIs(args.handler, cli.command_credentials_derive)\n"
        f'        self.assertEqual(args.kind, "{registered_kind}")\n'
    )
    return (
        "parser 注册用例",
        '\n\nif __name__ == "__main__":',
        "\n" + method + '\n\nif __name__ == "__main__":',
    )


def build_su_verify_edit(*, slug: str, su_kind_suffix: str, oracle: str) -> tuple[str, str, str]:
    """往 ResolveSuPasswordTests 追加实机 hash oracle 用例。

    oracle 必须是能被新候选公式命中的真实 /var/telsu hash（crypt_verify 可验证），
    否则 --write 后的全量自检会失败——这是故意的防呆。
    """
    su_kind = f"{slug}-{su_kind_suffix}"
    oracle_literal = escape_literal(oracle)
    method = (
        f"    def test_verified_{slug}_{su_kind_suffix}_hash(self) -> None:\n"
        f'        shell = FakeShell("root:{oracle_literal}:0:0:Telnet user:/:/bin/ash\\r\\n# ")\n'
        "        args = _derive_args()\n"
        "\n"
        "        password, source = resolve_su_password_from_shell(args, ip=UNREACHABLE_IP, shell=shell)\n"
        "\n"
        f'        self.assertEqual(source, "verified-telsu:{su_kind}")\n'
    )
    return (
        "su hash oracle 用例",
        "    def test_explicit_password_skips_probe(self) -> None:",
        method + "\n    def test_explicit_password_skips_probe(self) -> None:",
    )


# ---------------------------------------------------------------------------
# 应用与输出
# ---------------------------------------------------------------------------


def apply_edits(content: str, edits: list[tuple[str, str, str]]) -> str:
    for label, old, new in edits:
        count = content.count(old)
        if count != 1:
            raise ScaffoldError(f"锚点 {label!r} 未命中或不唯一（count={count}）；文件结构可能已变化，请人工对照 ADAPT.md 触点索引表")
        content = content.replace(old, new, 1)
    return content


def render_diff(path: Path, before: str, after: str) -> str:
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=str(path),
        tofile=str(path),
    )
    return "".join(diff)


def run_self_check() -> int:
    # 全量测试：除了注册表本身，也覆盖 hash oracle 等联动用例，防止假 oracle 留坑。
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
    print(f"自检：{' '.join(command)}")
    completed = subprocess.run(command, cwd=REPO_ROOT, check=False)
    return completed.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="把新型号凭据派生公式接入注册表（默认 dry-run，--write 落盘；流程见 ADAPT.md）",
    )
    parser.add_argument("model", help="型号名，如 HG9999A")
    parser.add_argument("--telnet-username", help="Telnet 派生账号用户名（与 --telnet-prefix 成对给出）")
    parser.add_argument("--telnet-prefix", help="Telnet 密码公式固定前缀（与 --telnet-username 成对给出）")
    parser.add_argument("--su-prefix", help="su root 密码公式固定前缀")
    parser.add_argument("--su-kind-suffix", choices=["su", "root"], default="su", help="su 派生 kind 后缀，默认 su（HG6142A3 风格用 root）")
    parser.add_argument("--confidence", default=None, help="DerivedCredential.confidence，默认标注 pending-live-verify")
    parser.add_argument("--source", default=None, help="公式来源描述")
    parser.add_argument("--note", default=None, help="DerivedCredential.note 附加说明")
    parser.add_argument("--su-hash-oracle", help="可选：/var/telsu 实机 hash 原文，生成 hash oracle 测试向量（需 $1$/$5$ 格式）")
    parser.add_argument("--write", action="store_true", help="实际写入（默认 dry-run 打印 diff）")
    parser.add_argument("--no-tests", action="store_true", help="跳过测试文件改动")
    parser.add_argument("--skip-self-check", action="store_true", help="--write 后跳过自动 unittest")
    args = parser.parse_args(argv)

    slug, const = normalize_model(args.model)
    su_kind = f"{slug}-{args.su_kind_suffix}"

    telnet_username = args.telnet_username
    telnet_prefix = args.telnet_prefix
    if (telnet_username is None) != (telnet_prefix is None):
        parser.error("--telnet-username 与 --telnet-prefix 必须成对给出")
    if args.su_prefix is None and args.su_hash_oracle is not None:
        parser.error("--su-hash-oracle 需要同时提供 --su-prefix")
    if telnet_username is None and args.su_prefix is None:
        parser.error("至少提供一组公式参数（--telnet-username/--telnet-prefix 或 --su-prefix）")

    if args.su_hash_oracle is not None and not args.su_hash_oracle.startswith(("$1$", "$5$")):
        print(
            f"警告：--su-hash-oracle 不是 $1$/$5$ 格式（实际开头 {args.su_hash_oracle[:3]!r}），"
            "已跳过 oracle 用例；请先按条件触点扩展 crypt_unix.py",
            file=sys.stderr,
        )
        oracle = None
    else:
        oracle = args.su_hash_oracle

    confidence = args.confidence or f"medium-{slug}-formula-pending-live-verify"
    source = args.source or f"{args.model.strip().upper()} formula: fixed prefix + MAC suffix (uppercase); pending live verification"
    note = args.note or "Pending live verification; update confidence/note after on-device confirmation."

    if not CREDENTIALS_PATH.exists():
        raise SystemExit(f"找不到 {CREDENTIALS_PATH}；请在仓库根目录结构下运行")

    credentials_before = CREDENTIALS_PATH.read_text(encoding="utf-8")
    for existing_kind in (f"{slug}-telnet", su_kind):
        if f'"{existing_kind}"' in credentials_before:
            raise ScaffoldError(f"型号 {existing_kind} 已存在于 DERIVED_CREDENTIAL_KINDS，拒绝重复接入")

    test_credentials_before = "" if args.no_tests else TEST_CREDENTIALS_PATH.read_text(encoding="utf-8")
    targets: list[tuple[Path, list[tuple[str, str, str]]]] = [
        (CREDENTIALS_PATH, credentials_edits(
            content=credentials_before,
            slug=slug,
            const=const,
            telnet_username=telnet_username,
            telnet_prefix=telnet_prefix,
            su_prefix=args.su_prefix,
            su_kind_suffix=args.su_kind_suffix,
            confidence=confidence,
            source=source,
            note=note,
        )),
    ]
    if not args.no_tests:
        targets.append((TEST_CREDENTIALS_PATH, test_credentials_edits(
            content=test_credentials_before,
            slug=slug,
            const=const,
            telnet_username=telnet_username,
            telnet_prefix=telnet_prefix,
            su_prefix=args.su_prefix,
            su_kind_suffix=args.su_kind_suffix,
        )))
        targets.append((TEST_PARSER_PATH, [test_parser_registration_edit(
            slug=slug,
            su_kind_suffix=args.su_kind_suffix,
            telnet_username=telnet_username,
        )]))
        if oracle is not None:
            targets.append((TEST_SU_VERIFY_PATH, [build_su_verify_edit(slug=slug, su_kind_suffix=args.su_kind_suffix, oracle=oracle)]))

    results: list[tuple[Path, str, str]] = []
    try:
        for path, edits in targets:
            before = path.read_text(encoding="utf-8")
            results.append((path, before, apply_edits(before, edits)))
    except ScaffoldError as exc:
        print(f"中止（零写入）：{exc}", file=sys.stderr)
        return 1

    print(f"型号 {args.model.strip().upper()}（slug={slug}）")
    print(f"confidence: {confidence}")
    if oracle is None and args.su_hash_oracle is None and args.su_prefix is not None:
        print("提醒：未提供 --su-hash-oracle，test_cli_su_verify.py 需在实机调研后补 hash oracle 用例")
    print()
    for path, before, after in results:
        print(f"=== {path} ===")
        if args.write:
            path.write_text(after, encoding="utf-8")
            print("已写入")
        else:
            diff = render_diff(path, before, after)
            print(diff, end="" if diff.endswith("\n") else "\n")
        print()

    print("=== 条件触点决策清单（脚手架不改写，需逐项人工/agent 决策）===")
    for location, description in CONDITIONAL_TOUCHPOINTS:
        print(f"  - {location}：{description}")
    print(f"\n后续流程（实机调研 → 测试 → issue/PR）见 {ADAPT_GUIDE_URL}")

    if args.write:
        if args.skip_self_check:
            print("\n已跳过自检")
            return 0
        print()
        return run_self_check()
    print("\n（dry-run，未写入任何文件；确认 diff 后加 --write 落盘）")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScaffoldError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
