"""Decrypt WeChat 4.1.12.55 DBs with the captured password (each DB derives its own
enc_key from its file-header salt via PBKDF2-HMAC-SHA512 256000). Mirrors the layout
verified by HMAC checks. Outputs to the chatlog-studio cache layout."""
import hashlib
import os
import sqlite3
import sys
import time
from pathlib import Path

from Cryptodome.Cipher import AES

ACCOUNT = "wxid_demo0000_1234"
SRC = Path(r"D:\Users\demo\Documents\xwechat_files") / ACCOUNT / "db_storage"
OUT = Path(os.environ["TEMP"]) / "chatlog-verify-out" / ACCOUNT / "decrypted"
PAGE = 4096
RESERVE = 80

PASSWORD = Path(os.environ["TEMP"] / Path("wx_password.bin")).read_bytes()
print(f"password={PASSWORD.hex()} len={len(PASSWORD)}")

REQUIRED = [
    ("contact", "contact.db"),
    ("session", "session.db"),
    ("message", "message_0.db"),
    ("message", "message_1.db"),
    ("message", "message_2.db"),
    ("message", "message_3.db"),
    ("message", "message_resource.db"),
]


def enc_key_for(db_path: Path) -> bytes:
    with open(db_path, "rb") as fp:
        salt = fp.read(16)
    return hashlib.pbkdf2_hmac("sha512", PASSWORD, salt, 256000, dklen=32)


def decrypt_db(src: Path, dst: Path) -> None:
    key = enc_key_for(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as f_in, open(dst, "wb") as f_out:
        header = f_in.read(PAGE)
        if len(header) < PAGE:
            raise ValueError(f"too small: {src}")
        payload = header[16:]
        iv = payload[-RESERVE : -RESERVE + 16]
        f_out.write(b"SQLite format 3\x00")
        f_out.write(AES.new(key, AES.MODE_CBC, iv).decrypt(payload[:-RESERVE]))
        f_out.write(payload[-RESERVE:])
        while True:
            page = f_in.read(PAGE)
            if not page:
                break
            if len(page) != PAGE:
                raise ValueError(f"truncated page in {src}")
            iv = page[-RESERVE : -RESERVE + 16]
            f_out.write(AES.new(key, AES.MODE_CBC, iv).decrypt(page[:-RESERVE]))
            f_out.write(page[-RESERVE:])


def smoke_test(dst: Path) -> int:
    try:
        con = sqlite3.connect(str(dst))
        rows = con.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
        con.close()
        return int(rows[0])
    except Exception as exc:
        print(f"  !! sqlite open failed {dst.name}: {exc}")
        return -1


for sub, name in REQUIRED:
    src = SRC / sub / name
    dst = OUT / f"{sub}__{name}"
    if not src.exists():
        print(f"skip missing {src}")
        continue
    t0 = time.time()
    decrypt_db(src, dst)
    n = smoke_test(dst)
    print(f"{name:24s} {src.stat().st_size/1e6:7.1f}MB -> {n:6d} objects  ({time.time()-t0:.1f}s)")

print("done ->", OUT)
