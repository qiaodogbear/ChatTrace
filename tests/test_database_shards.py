"""Cross-shard sender resolution tests (M4).

Name2Id rowids are per shard: the same rowid maps to different people in different
message_*.db files.  These tests pin the regression where a merged map made
senders and message bodies mismatch.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
import zstandard as zstd

from chattrace.service.database import DatabaseService

ACCOUNT_ID = "wxid_alice_100"
CHAT = "room@chatroom"
_Z = zstd.ZstdCompressor()


def _table(username: str) -> str:
    return f"Msg_{hashlib.md5(username.encode('utf-8')).hexdigest()}"


def _shard(path: Path, rows: list[tuple], name2id: list[tuple]) -> None:
    con = sqlite3.connect(path)
    t = _table(CHAT)
    con.execute(
        f"CREATE TABLE [{t}] (local_id INTEGER PRIMARY KEY, local_type INT, create_time INT, status INT, "
        "real_sender_id INT, message_content BLOB, compress_content BLOB, packed_info_data BLOB, source BLOB)"
    )
    con.execute("CREATE TABLE Name2Id (user_name TEXT, is_session INT)")
    for user in name2id:
        con.execute("INSERT INTO Name2Id VALUES (?, 0)", (user,))
    for row in rows:
        con.execute(f"INSERT INTO [{t}] VALUES (?,?,?,?,?,?,?,?,?)", row)
    con.commit()
    con.close()


@pytest.fixture()
def sharded(tmp_path: Path) -> Path:
    dec = tmp_path / "decrypted"
    (dec / "message").mkdir(parents=True)
    (dec / "contact").mkdir(parents=True)
    (dec / "session").mkdir(parents=True)

    contact = sqlite3.connect(dec / "contact" / "contact.db")
    contact.execute("CREATE TABLE contact (id INTEGER PRIMARY KEY, username TEXT, delete_flag INT, "
                    "remark TEXT, nick_name TEXT, alias TEXT)")
    for i, (user, nick) in enumerate(
        [("wxid_bob", "老鲍勃"), ("wxid_dave", "戴夫"), ("wxid_alice", "我自己"), ("wxid_carol", "卡罗尔")], start=1
    ):
        contact.execute("INSERT INTO contact VALUES (?,?,0,'',?,'')", (i, user, nick))
    contact.commit()
    contact.close()

    body_bob = _Z.compress("wxid_bob:\n第一条".encode())
    body_dave = _Z.compress("第二条（无前缀）".encode())
    # shard 0: rowid 1 = alice(me), 2 = bob          -> real_sender_id 2 means bob here
    _shard(
        dec / "message" / "message_0.db",
        [(1, 1, 100, 3, 2, body_bob, b"", None, b"")],
        ["wxid_alice", "wxid_bob"],
    )
    # shard 1: rowid 1 = carol, 2 = dave            -> the same rowid 2 means dave here
    _shard(
        dec / "message" / "message_1.db",
        [(1, 1, 200, 3, 2, body_dave, b"", None, b"")],
        ["wxid_carol", "wxid_dave"],
    )
    return dec


def test_senders_resolved_per_shard(sharded: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, sharded)
    page = db.chat(CHAT, limit=10)
    by_time = {m.create_time: m for m in page.messages}
    assert len(by_time) == 2, "both shards' rows must be visible"

    first = by_time[100]      # group prefix wins: wxid_bob
    second = by_time[200]     # no prefix -> Name2Id of *its own* shard -> wxid_dave
    assert first.sender_wxid == "wxid_bob" and first.sender == "老鲍勃"
    assert second.sender_wxid == "wxid_dave" and second.sender == "戴夫"
    assert first.text == "第一条"
    assert second.text == "第二条（无前缀）"


def test_account_username_from_directory_name(sharded: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, sharded)
    # wxid_alice_100 -> wxid_alice without consulting any table
    assert db.account_username(CHAT) == "wxid_alice"


def test_raw_message_lookup_uses_create_time(sharded: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, sharded)
    raw = db.raw_message_by_id(CHAT, 1, 200)
    assert raw is not None and int(raw["create_time"]) == 200
    raw_old = db.raw_message_by_id(CHAT, 1, 100)
    assert raw_old is not None and int(raw_old["create_time"]) == 100
