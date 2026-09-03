"""DecryptService round-trip + smoke tests (offline, no real WeChat data).

We synthesize WeChat 4.x-layout cipher files: page = AES-CBC(key, iv=page[-80:-64])
over page[16:-80] (first page, after 16-byte salt) or page[:-80] (other pages),
keeping the trailing 80-byte reserve. decrypt_file() must restore the original sqlite.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from Cryptodome.Cipher import AES

from chattrace.service.decryptor import (
    DecryptService,
    decrypt_file,
    discover_source_dbs,
    smoke_test,
)

PAGE = 4096
RESERVE = 80
MASTER = bytes(range(32))
SALT = bytes(range(16, 32))


def encrypt_pages(pages: list[bytes]) -> bytes:
    """WeChat 4.x layout encryption (inverse of decrypt_file).

    AES key = PBKDF2-HMAC-SHA512(master, salt=file header, 256000) — mirrors the
    real per-DB derivation that decrypt_file performs via enc_key_for().
    """
    import hashlib

    key = hashlib.pbkdf2_hmac("sha512", MASTER, SALT, 256000, dklen=32)
    out = bytearray()
    for idx, plain in enumerate(pages, start=1):
        assert len(plain) == PAGE
        iv = plain[-RESERVE : -RESERVE + 16]
        if idx == 1:
            body = plain[16:-RESERVE]
            out += SALT
            out += AES.new(key, AES.MODE_CBC, iv).encrypt(body)
        else:
            body = plain[:-RESERVE]
            out += AES.new(key, AES.MODE_CBC, iv).encrypt(body)
        out += plain[-RESERVE:]
    return bytes(out)


def _pages_of(db_path: Path) -> list[bytes]:
    plain = db_path.read_bytes()
    n = (len(plain) + PAGE - 1) // PAGE
    padded = plain.ljust(n * PAGE, b"\x00")
    return [padded[i : i + PAGE] for i in range(0, len(padded), PAGE)]


def _tiny_db(tmp_path: Path, name: str) -> Path:
    db = tmp_path / name
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
    con.execute("INSERT INTO items VALUES (1, 'alpha'), (2, 'beta')")
    con.commit()
    con.close()
    return db


def test_roundtrip_restores_sqlite(tmp_path: Path) -> None:
    src_db = _tiny_db(tmp_path, "plain.db")
    enc = tmp_path / "encrypted.db"
    enc.write_bytes(encrypt_pages(_pages_of(src_db)))

    out = tmp_path / "out.db"
    decrypt_file(enc, out, MASTER)
    con = sqlite3.connect(out)
    rows = con.execute("SELECT name FROM items ORDER BY id").fetchall()
    con.close()
    assert rows == [("alpha",), ("beta",)]


def test_service_run_incremental_and_force(tmp_path: Path) -> None:
    src_db = _tiny_db(tmp_path, "plain.db")
    db_storage = tmp_path / "db_storage" / "message"
    db_storage.mkdir(parents=True)
    (db_storage / "message_0.db").write_bytes(encrypt_pages(_pages_of(src_db)))

    found = discover_source_dbs(db_storage.parent)
    assert [p.name for p in found] == ["message_0.db"]

    out_root = tmp_path / "decrypted"
    svc = DecryptService(db_storage.parent, MASTER, out_root)
    report = svc.run()
    assert report.decrypted == 1 and not report.failed
    assert smoke_test(out_root / "message" / "message_0.db") >= 1

    # incremental second run skips fresh outputs
    report2 = svc.run()
    assert report2.decrypted == 0 and report2.skipped == 1

    # forcing re-decrypts
    report3 = svc.run(incremental=False)
    assert report3.decrypted == 1


def test_wrong_key_yields_garbage(tmp_path: Path) -> None:
    src_db = _tiny_db(tmp_path, "plain.db")
    enc = tmp_path / "enc.db"
    enc.write_bytes(encrypt_pages(_pages_of(src_db)))

    out = tmp_path / "out.db"
    decrypt_file(enc, out, bytes(32))  # wrong master key; length-preserving write succeeds
    with pytest.raises(Exception):
        smoke_test(out)
