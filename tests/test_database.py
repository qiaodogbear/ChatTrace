"""DatabaseService + ChatExportService tests over a synthetic decrypted tree."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from chattrace.service.database import DatabaseService
from chattrace.service.exporter import ChatExportService

ACCOUNT_ID = "wxid_alice_100"
CONTACT_USER = "wxid_bob"
GROUP_USER = "room@chatroom"


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    return _build_tree(tmp_path)


def _msg_table(username: str) -> str:
    return f"Msg_{hashlib.md5(username.encode('utf-8')).hexdigest()}"


def _build_tree(root: Path) -> Path:
    """contact + session + one message shard with Name2Id."""
    dec = root / "decrypted"
    (dec / "contact").mkdir(parents=True)
    (dec / "session").mkdir(parents=True)
    (dec / "message").mkdir(parents=True)

    con = sqlite3.connect(dec / "contact" / "contact.db")
    con.execute("CREATE TABLE contact (id INTEGER PRIMARY KEY, username TEXT, delete_flag INT, "
                "remark TEXT, nick_name TEXT, alias TEXT)")
    con.execute("INSERT INTO contact VALUES (1, ?, 0, ?, '', '')", (CONTACT_USER, "老鲍勃"))
    con.execute("INSERT INTO contact VALUES (2, ?, 0, '', '微信团队', '')", ("weixin",))
    con.execute("INSERT INTO contact VALUES (3, ?, 0, '我记', '我自己', '')", ("wxid_alice",))
    con.execute("INSERT INTO contact VALUES (4, ?, 1, '已删', '', '')", ("deleted_user",))
    con.commit()
    con.close()

    con = sqlite3.connect(dec / "session" / "session.db")
    con.execute("CREATE TABLE SessionTable (username TEXT PRIMARY KEY, is_hidden INT, sort_timestamp INT, "
                "last_timestamp INT, summary TEXT, unread_count INT, last_sender_display_name TEXT)")
    con.execute("INSERT INTO SessionTable VALUES (?, 0, 3000, 3000, '在吗？', 2, '老鲍勃')", (CONTACT_USER,))
    con.execute("INSERT INTO SessionTable VALUES (?, 0, 2000, 2000, '图片', 0, '')", (GROUP_USER,))
    con.execute("INSERT INTO SessionTable VALUES (?, 1, 1000, 1000, 'hidden', 0, '')", ("hidden_chat",))
    con.commit()
    con.close()

    con = sqlite3.connect(dec / "message" / "message_0.db")
    t = _msg_table(CONTACT_USER)
    con.execute(f"CREATE TABLE [{t}] (local_id INTEGER PRIMARY KEY, local_type INT, create_time INT, "
                "status INT, real_sender_id INT, message_content TEXT, compress_content TEXT, packed_info_data BLOB)")
    # Name2Id: rowid 1 = wxid_alice (self), rowid 2 = wxid_bob
    con.execute("CREATE TABLE Name2Id (user_name TEXT, is_session INT)")
    con.execute("INSERT INTO Name2Id VALUES ('wxid_alice', 0), ('wxid_bob', 0)")
    # incoming text from bob (rowid 2) at t=100
    con.execute(f"INSERT INTO [{t}] VALUES (1, 1, 100, 3, 2, '你好，在吗？', '', NULL)")
    # outgoing from alice (rowid 1) at t=200
    con.execute(f"INSERT INTO [{t}] VALUES (2, 1, 200, 2, 1, '在的呀', '', NULL)")
    # image message with byte-ish content
    con.execute(f"INSERT INTO [{t}] VALUES (3, 3, 300, 3, 2, '\\x00\\x01\\x02', '', NULL)")
    # voice message
    con.execute(f"INSERT INTO [{t}] VALUES (4, 34, 400, 3, 2, '', 'voice_data', NULL)")
    con.commit()
    con.close()
    return dec


def test_sessions_and_contacts(tree: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, tree)
    sessions = db.sessions()
    assert len(sessions) == 2  # hidden excluded
    top = sessions[0]
    assert top.username == CONTACT_USER and top.display_name == "老鲍勃"
    assert top.unread_count == 2 and top.summary == "在吗？"
    assert db.sessions(query="鲍勃")[0].username == CONTACT_USER

    contacts = db.contacts()
    assert len(contacts) == 3  # delete_flag=1 excluded
    assert db.contact(CONTACT_USER).display_name == "老鲍勃"
    assert db.contacts(query="微信")[0].username == "weixin"


def test_chat_direction_and_render(tree: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, tree)
    page = db.chat(CONTACT_USER, limit=10)
    msgs = page.messages  # newest first
    assert len(msgs) == 4 and not page.has_more
    by_id = {m.local_id: m for m in msgs}

    assert by_id[1].is_outgoing is False and by_id[1].sender == "老鲍勃"
    assert by_id[1].text == "你好，在吗？" and by_id[1].display_type == "text"
    assert by_id[2].is_outgoing is True and by_id[2].sender != "老鲍勃"
    assert by_id[3].display_type == "image" and by_id[3].text == "图片"
    assert by_id[4].display_type == "voice" and by_id[4].text == "语音"

    # account-username inference: account dir name starts with wxid_alice_
    assert db.account_username(CONTACT_USER) == "wxid_alice"
    # keyset pagination
    page2 = db.chat(CONTACT_USER, limit=2)
    assert len(page2.messages) == 2 and page2.has_more
    oldest = page2.messages[-1]
    page3 = db.chat(CONTACT_USER, limit=2, before=(oldest.create_time, oldest.local_id))
    assert len(page3.messages) == 2 and not page3.has_more


def test_export_formats(tree: Path, tmp_path: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, tree)
    out_dir = tmp_path / "exports"
    svc = ChatExportService(db, out_dir)

    out_txt = svc.export(CONTACT_USER, "txt")
    text = out_txt.output_path.read_text(encoding="utf-8")
    assert out_txt.message_count == 4
    assert "你好，在吗？" in text and "老鲍勃" in text

    out_json = svc.export(CONTACT_USER, "json")
    data = json.loads(out_json.output_path.read_text(encoding="utf-8"))
    assert data["meta"]["total"] == 4
    assert len(data["messages"]) == 4
    assert data["messages"][0]["text"] == "你好，在吗？"

    out_html = svc.export(CONTACT_USER, "html")
    html_text = out_html.output_path.read_text(encoding="utf-8")
    assert "<html" in html_text and "msg me" in html_text and "msg peer" in html_text
    assert "图片" in html_text
