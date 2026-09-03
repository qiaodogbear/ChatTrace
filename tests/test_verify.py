import os
from pathlib import Path

from chattrace.keyagent.verify import read_db_header, verify_hmac, verify_hmac_sweep
from chattrace.keyagent.verify import test_key_against_db as db_key_check

from sqlcipher_factory import make_encrypted_db


def test_hmac_ok_wrong_password(tmp_path: Path):
    pwd = os.urandom(32)
    db = tmp_path / "message_0.db"
    make_encrypted_db(db, pwd)
    header = read_db_header(db)
    assert verify_hmac(pwd, header) is True
    assert verify_hmac(os.urandom(32), header) is False


def test_sweep_reports_endian(tmp_path: Path):
    pwd = os.urandom(32)
    db = tmp_path / "message_0.db"
    make_encrypted_db(db, pwd)
    header = read_db_header(db)
    ok, endian = verify_hmac_sweep(pwd, header)
    assert ok and endian == "le"


def test_db_key_check(tmp_path: Path):
    pwd = os.urandom(32)
    db = tmp_path / "message_0.db"
    make_encrypted_db(db, pwd)
    ok, detail = db_key_check(pwd.hex(), db)
    assert ok
    ok2, _ = db_key_check(os.urandom(32).hex(), db)
    assert not ok2


def test_bad_hex(tmp_path: Path):
    db = tmp_path / "x.db"
    ok, detail = db_key_check("zz-not-hex", db)
    assert not ok and "invalid hex" in detail


def test_wrong_length(tmp_path: Path):
    db = tmp_path / "x.db"
    ok, detail = db_key_check("00" * 31, db)
    assert not ok and "32 bytes" in detail
