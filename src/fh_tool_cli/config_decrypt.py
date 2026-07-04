from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import decrypt_config_encrymode2
from .errors import CliError

REDACTED = "[REDACTED]"
ENCRYPTED_REDACTED = "[ENCRYPTED]"


@dataclass
class UciSection:
    type: str
    name: str | None = None
    options: dict[str, str] = field(default_factory=dict)
    lists: dict[str, list[str]] = field(default_factory=dict)
    line: int = 0


@dataclass(frozen=True)
class AttributePolicy:
    encrypted_mode: str | None = None
    sensitive: bool = False


def parse_uci_like(text: str) -> list[UciSection]:
    sections: list[UciSection] = []
    current: UciSection | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        try:
            parts = shlex.split(stripped, comments=True, posix=True)
        except ValueError as exc:
            raise CliError(f"配置解析失败: line {line_number}: {exc}") from exc
        if not parts:
            continue

        directive = parts[0]
        if directive == "config":
            if len(parts) not in (2, 3):
                raise CliError(f"config 需要 type 和可选 name: line {line_number}")
            current = UciSection(
                type=parts[1],
                name=parts[2] if len(parts) == 3 else None,
                line=line_number,
            )
            sections.append(current)
            continue

        if current is None:
            current = UciSection(type="global", name=None, line=line_number)
            sections.append(current)

        if directive == "option":
            if len(parts) < 3:
                raise CliError(f"option 需要 key 和 value: line {line_number}")
            current.options[parts[1]] = " ".join(parts[2:])
            continue

        if directive == "list":
            if len(parts) < 3:
                raise CliError(f"list 需要 key 和 value: line {line_number}")
            current.lists.setdefault(parts[1], []).append(" ".join(parts[2:]))
            continue

        if len(parts) == 1 and "=" in parts[0]:
            key, value = parts[0].split("=", 1)
            if not key:
                raise CliError(f"key 不能为空: line {line_number}")
            current.options[key] = value
            continue

        raise CliError(f"不支持的配置行: line {line_number}: {raw_line}")

    return sections


def _section_id(section: UciSection) -> tuple[str, str | None]:
    return section.type, section.name


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on", "sensitive"}


def _base_key_for_suffix(key: str, suffix: str) -> str | None:
    lowered = key.lower()
    if lowered.endswith(suffix):
        return key[: -len(suffix)]
    return None


def build_attr_policies(attr_sections: list[UciSection]) -> dict[tuple[str, str | None], dict[str, AttributePolicy]]:
    policies: dict[tuple[str, str | None], dict[str, AttributePolicy]] = {}

    for section in attr_sections:
        section_policies = policies.setdefault(_section_id(section), {})
        for key, value in section.options.items():
            lowered_value = value.strip().lower()
            encrypted_mode: str | None = None
            sensitive = False
            target_key = key

            encrymode_target = _base_key_for_suffix(key, "_encrymode")
            sensitive_target = _base_key_for_suffix(key, "_sensitive")
            if encrymode_target:
                target_key = encrymode_target
                encrypted_mode = value.strip()
            elif sensitive_target:
                target_key = sensitive_target
                sensitive = _truthy(value)
            elif lowered_value in {"2", "encrymode=2", "encrypt=2"}:
                encrypted_mode = "2"
                sensitive = True
            elif "encrymode=2" in lowered_value or "encrypt=2" in lowered_value:
                encrypted_mode = "2"
                sensitive = True
            elif _truthy(value):
                sensitive = True

            existing = section_policies.get(target_key, AttributePolicy())
            section_policies[target_key] = AttributePolicy(
                encrypted_mode=encrypted_mode or existing.encrypted_mode,
                sensitive=sensitive or existing.sensitive,
            )

    return policies


def looks_sensitive(section: UciSection, key: str) -> bool:
    key_l = key.lower()
    path_l = ".".join(part for part in [section.type, section.name or "", key]).lower()

    if any(term in path_l for term in ("loid", "token", "password", "passwd", "pwd", "secret")):
        return True
    if any(term in path_l for term in ("pppoe", "acs", "tr069")):
        return True
    if any(term in key_l for term in ("passphrase", "psk", "wepkey", "wpakey")):
        return True
    if "wifi" in path_l and any(term in key_l for term in ("key", "pass", "psk")):
        return True
    return False


def _decode_key(key: str | None, key_hex: str | None) -> bytes | None:
    if key and key_hex:
        raise CliError("--key 和 --key-hex 只能选择一个")
    if key_hex:
        try:
            decoded = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise CliError("--key-hex 不是合法 hex") from exc
    elif key:
        decoded = key.encode("utf-8")
    else:
        return None

    if len(decoded) != 16:
        raise CliError("config AES key 必须是 16 bytes")
    return decoded


def _render_option(
    section: UciSection,
    key: str,
    value: str,
    policy: AttributePolicy,
    *,
    reveal_secrets: bool,
    aes_key: bytes | None,
) -> dict[str, Any]:
    sensitive = policy.sensitive or looks_sensitive(section, key)
    encrypted = policy.encrypted_mode == "2"
    decrypted = False
    output_value = value

    if encrypted and aes_key:
        try:
            output_value = decrypt_config_encrymode2(value, aes_key)
            decrypted = True
        except ValueError as exc:
            raise CliError(f"{section.type}.{section.name or ''}.{key} 解密失败: {exc}") from exc
    elif encrypted and reveal_secrets:
        raise CliError(f"{section.type}.{section.name or ''}.{key} 已加密，需要 --key 或 --key-hex")

    if sensitive and not reveal_secrets:
        output_value = REDACTED if decrypted or not encrypted else ENCRYPTED_REDACTED

    return {
        "value": output_value,
        "sensitive": sensitive,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "redacted": sensitive and not reveal_secrets,
    }


def decrypt_config_document(
    config_text: str,
    *,
    attr_text: str | None = None,
    reveal_secrets: bool = False,
    key: str | None = None,
    key_hex: str | None = None,
) -> dict[str, Any]:
    sections = parse_uci_like(config_text)
    attr_sections = parse_uci_like(attr_text) if attr_text is not None else []
    policies = build_attr_policies(attr_sections)
    aes_key = _decode_key(key, key_hex)

    rendered_sections: list[dict[str, Any]] = []
    for section in sections:
        section_policies = policies.get(_section_id(section), {})
        rendered_sections.append(
            {
                "type": section.type,
                "name": section.name,
                "line": section.line,
                "options": {
                    option_key: _render_option(
                        section,
                        option_key,
                        option_value,
                        section_policies.get(option_key, AttributePolicy()),
                        reveal_secrets=reveal_secrets,
                        aes_key=aes_key,
                    )
                    for option_key, option_value in section.options.items()
                },
                "lists": section.lists,
            }
        )

    return {
        "format": "uci-like",
        "sections": rendered_sections,
        "section_count": len(rendered_sections),
        "attr_section_count": len(attr_sections),
        "redacted": not reveal_secrets,
    }


def decrypt_config_file(
    input_path: Path,
    *,
    attr_path: Path | None = None,
    output_path: Path | None = None,
    reveal_secrets: bool = False,
    key: str | None = None,
    key_hex: str | None = None,
) -> dict[str, Any]:
    try:
        config_text = input_path.read_text(encoding="utf-8")
        attr_text = attr_path.read_text(encoding="utf-8") if attr_path else None
    except OSError as exc:
        raise CliError(f"配置文件读取失败: {exc}") from exc

    document = decrypt_config_document(
        config_text,
        attr_text=attr_text,
        reveal_secrets=reveal_secrets,
        key=key,
        key_hex=key_hex,
    )
    document["input"] = str(input_path)
    if attr_path:
        document["attr"] = str(attr_path)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return {
            "input": str(input_path),
            "attr": str(attr_path) if attr_path else None,
            "output": str(output_path),
            "section_count": document["section_count"],
            "redacted": document["redacted"],
        }

    return document
