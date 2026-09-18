"""Unix crypt(3) 纯 Python 实现,用于 /var/telsu 密码 hash 的本地验证。

覆盖:
- md5-crypt($1$,HG5143F 一系固件的 su runtime 密码格式)
- sha256-crypt($5$,HG6142A3 一系固件的 su runtime 密码格式)

不引入第三方依赖(passlib 等)与已废弃的 stdlib crypt 模块(3.13 起移除)。
md5-crypt 迁自 account.py,曾用于 set-su-runtime-password 写入路径。
"""

from __future__ import annotations

import hmac
import re
from hashlib import md5, sha256

MD5_CRYPT_MAGIC = "$1$"
SHA256_CRYPT_MAGIC = "$5$"
SHA256_CRYPT_DEFAULT_ROUNDS = 5000
SHA256_CRYPT_MIN_ROUNDS = 1000

_CRYPT_B64_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_MD5_CRYPT_MAGIC_BYTES = b"$1$"

# sha256-crypt 输出编码的字节重排表(10 组,每组 3 字节出 4 字符,末 2 字节单独 3 字符)
_SHA256_OUTPUT_ORDER = (
    (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23),
    (24, 4, 14), (15, 25, 5), (6, 16, 26), (27, 7, 17),
    (18, 28, 8), (9, 19, 29),
)

# /var/telsu 内容形如 `root:$5$fh$...:0:0:Telnet user:/:/bin/ash`,
# 外层 telnet 输出还会混入命令回显、banner、\r 与 prompt 尾巴。
_CRYPT_HASH_PATTERN = re.compile(
    r"\$(?P<magic>[15])\$(?:rounds=(?P<rounds>\d+)\$)?"
    r"(?P<salt>[./0-9A-Za-z]{0,16})\$(?P<digest>[./0-9A-Za-z]+)"
)


def _as_bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode()


def _crypt_base64(byte2: int, byte1: int, byte0: int, length: int) -> str:
    value = (byte2 << 16) | (byte1 << 8) | byte0
    encoded = []
    for _ in range(length):
        encoded.append(_CRYPT_B64_ALPHABET[value & 0x3F])
        value >>= 6
    return "".join(encoded)


def md5_crypt(password: str | bytes, salt: str | bytes) -> str:
    password_bytes = _as_bytes(password)
    salt_bytes = _as_bytes(salt)
    if len(salt_bytes) > 8:
        salt_bytes = salt_bytes[:8]

    digest = md5(password_bytes + _MD5_CRYPT_MAGIC_BYTES + salt_bytes)
    alternate = md5(password_bytes + salt_bytes + password_bytes).digest()
    password_len = len(password_bytes)

    remaining = password_len
    while remaining > 0:
        digest.update(alternate[: min(16, remaining)])
        remaining -= 16

    remaining = password_len
    while remaining > 0:
        if remaining & 1:
            digest.update(b"\x00")
        else:
            digest.update(password_bytes[:1])
        remaining >>= 1

    final = digest.digest()
    for index in range(1000):
        digest = md5()
        digest.update(password_bytes if index & 1 else final)
        if index % 3:
            digest.update(salt_bytes)
        if index % 7:
            digest.update(password_bytes)
        digest.update(final if index & 1 else password_bytes)
        final = digest.digest()

    encoded = (
        _crypt_base64(final[0], final[6], final[12], 4)
        + _crypt_base64(final[1], final[7], final[13], 4)
        + _crypt_base64(final[2], final[8], final[14], 4)
        + _crypt_base64(final[3], final[9], final[15], 4)
        + _crypt_base64(final[4], final[10], final[5], 4)
        + _crypt_base64(0, 0, final[11], 2)
    )
    return f"$1${salt_bytes.decode()}${encoded}"


def sha256_crypt(password: str | bytes, salt: str | bytes, *, rounds: int = SHA256_CRYPT_DEFAULT_ROUNDS) -> str:
    password_bytes = _as_bytes(password)
    salt_bytes = _as_bytes(salt)[:16]
    if rounds < SHA256_CRYPT_MIN_ROUNDS:
        rounds = SHA256_CRYPT_MIN_ROUNDS

    # digest A: password + salt,再按口令长度混入 digest B(password+salt+password)
    digest_a = sha256(password_bytes + salt_bytes)
    digest_b = sha256(password_bytes + salt_bytes + password_bytes).digest()
    for _ in range(len(password_bytes) // 32):
        digest_a.update(digest_b)
    digest_a.update(digest_b[: len(password_bytes) % 32])

    # 位步骤:等价于对 password 做逐位选择混入
    bits = len(password_bytes)
    while bits > 0:
        digest_a.update(digest_b if bits & 1 else password_bytes)
        bits >>= 1

    final = digest_a.digest()

    # digest P:SHA256(password 重复自身长度次);digest S:SHA256(salt 重复 16+final[0] 次)。
    # 轮循环混入的是这两个 digest 的字节流(按 pwd/salt 长度重复或截断),不是原文。
    p_stream = sha256(password_bytes * len(password_bytes)).digest()
    dp = (p_stream * (len(password_bytes) // 32 + 1))[: len(password_bytes)]
    s_stream = sha256(salt_bytes * (16 + final[0])).digest()
    ds = s_stream[: len(salt_bytes)]

    for index in range(rounds):
        digest_c = sha256(dp if index & 1 else final)
        if index % 3:
            digest_c.update(ds)
        if index % 7:
            digest_c.update(dp)
        digest_c.update(final if index & 1 else dp)
        final = digest_c.digest()

    encoded = "".join(
        _crypt_base64(final[i2], final[i1], final[i0], 4)
        for i2, i1, i0 in _SHA256_OUTPUT_ORDER
    ) + _crypt_base64(0, final[31], final[30], 3)

    rounds_prefix = ""
    if rounds != SHA256_CRYPT_DEFAULT_ROUNDS:
        rounds_prefix = f"rounds={rounds}$"
    return f"$5${rounds_prefix}{salt_bytes.decode()}${encoded}"


def crypt_kind(hashed: str) -> str | None:
    if hashed.startswith(MD5_CRYPT_MAGIC):
        return MD5_CRYPT_MAGIC
    if hashed.startswith(SHA256_CRYPT_MAGIC):
        return SHA256_CRYPT_MAGIC
    return None


def crypt_verify(password: str, hashed: str) -> bool:
    parsed = _parse_crypt_hash(hashed)
    if parsed is None:
        return False
    magic, rounds, salt, expected_digest = parsed
    if magic == MD5_CRYPT_MAGIC:
        computed = md5_crypt(password, salt)
    else:
        computed = sha256_crypt(password, salt, rounds=rounds)
    computed_digest = computed.rsplit("$", 1)[-1]
    return hmac.compare_digest(computed_digest.encode(), expected_digest.encode())


def extract_crypt_hash(raw: str) -> str | None:
    """从 cat /var/telsu 的原始 telnet 输出中提取第一条 crypt hash。"""
    for match in _CRYPT_HASH_PATTERN.finditer(raw):
        magic = match.group("magic")
        rounds = match.group("rounds")
        salt = match.group("salt")
        digest = match.group("digest")
        if magic == MD5_CRYPT_MAGIC and rounds is not None:
            continue
        rounds_part = f"rounds={rounds}$" if rounds is not None else ""
        return f"${magic}${rounds_part}{salt}${digest}"
    return None


def _parse_crypt_hash(
    hashed: str,
) -> tuple[str, int, str, str] | None:
    match = _CRYPT_HASH_PATTERN.fullmatch(hashed.strip())
    if match is None:
        return None
    magic = f"${match.group('magic')}$"
    rounds = int(match.group("rounds")) if match.group("rounds") is not None else SHA256_CRYPT_DEFAULT_ROUNDS
    if magic == MD5_CRYPT_MAGIC and match.group("rounds") is not None:
        return None
    return magic, rounds, match.group("salt"), match.group("digest")
