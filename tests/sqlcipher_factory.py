"""Build synthetic SQLCipher4-style DB headers so HMAC verification is tested offline."""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from pathlib import Path

from Cryptodome.Cipher import AES

PAGE = 4096
KDF_ITER = 256_000
HMAC_ITER = 2


def make_encrypted_db(path: Path, password: bytes, pages: int = 2, salt: bytes | None = None) -> bytes:
    """Write a synthetic SQLCipher4 (reserve 80, HMAC-SHA512, LE page no.) file."""
    salt = salt or os.urandom(16)
    enc_key = hashlib.pbkdf2_hmac("sha512", password, salt, KDF_ITER, dklen=32)
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, HMAC_ITER, dklen=32)

    def page_blob(page_no: int, size: int, leading_salt: bool) -> bytes:
        content = os.urandom(size)  # page1: 4000; others: 4016
        iv = os.urandom(16)
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        padded = content  # AES-CBC needs multiple of 16: 4000/4016 both are
        enc = cipher.encrypt(padded)
        body = enc + iv
        calc = hmac.new(mac_key, body, hashlib.sha512)
        calc.update(struct.pack("<I", page_no))
        return body + calc.digest()

    with open(path, "wb") as fp:
        fp.write(salt)
        fp.write(page_blob(1, 4000, True))
        for idx in range(2, pages + 1):
            fp.write(page_blob(idx, 4016, False))
    return salt
