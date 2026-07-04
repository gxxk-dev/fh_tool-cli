from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


@dataclass(frozen=True)
class FHToolCrypto:
    key: bytes
    iv: bytes
    digest: str


def derive_crypto(mac: str) -> FHToolCrypto:
    digest = hashlib.sha256(mac.encode("ascii")).hexdigest()
    key = "".join(digest[2 * i + 2] for i in range(16)).encode("ascii")
    iv = "".join(digest[3 * i + 3] for i in range(16)).encode("ascii")
    return FHToolCrypto(key=key, iv=iv, digest=digest)


def pkcs7_pad(data: bytes) -> bytes:
    padder = PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt_payload(payload: dict[str, Any], crypto: FHToolCrypto) -> str:
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    encryptor = Cipher(algorithms.AES(crypto.key), modes.CBC(crypto.iv)).encryptor()
    ciphertext = encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_payload(body: str, crypto: FHToolCrypto) -> dict[str, Any]:
    raw = base64.b64decode(body.strip())
    decryptor = Cipher(algorithms.AES(crypto.key), modes.CBC(crypto.iv)).decryptor()
    plaintext = pkcs7_unpad(decryptor.update(raw) + decryptor.finalize())
    return json.loads(plaintext.decode("utf-8"))


def decrypt_config_encrymode2(value: str, key: bytes) -> str:
    if len(key) != 16:
        raise ValueError("config AES key must be 16 bytes")
    ciphertext = bytes.fromhex(value.strip().upper())
    if len(ciphertext) % 16 != 0:
        raise ValueError("encrypted config value is not a full AES block")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.rstrip(b"\x00").decode("utf-8")
