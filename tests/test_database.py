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
    # rich messages render through the payload parser: "[图片]" / "[语音]" style labels
    assert by_id[3].display_type == "image" and by_id[3].kind == "image" and by_id[3].text == "[图片]"
    assert by_id[4].display_type == "voice" and by_id[4].kind == "voice" and by_id[4].text == "[语音]"

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


# ------------------------------------------------------- ordering & incremental

def _append_messages(tree: Path, count: int, start_time: int) -> None:
    """Append ``count`` text messages so the 2000-row page boundary is crossed."""
    con = sqlite3.connect(tree / "message" / "message_0.db")
    table = _msg_table(CONTACT_USER)
    con.executemany(
        f"INSERT INTO [{table}] VALUES (?, 1, ?, 3, 2, ?, '', NULL)",
        [(1000 + i, start_time + i, f"line {i}") for i in range(count)],
    )
    con.commit()
    con.close()


def test_iter_chat_all_is_strictly_ascending(tree: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, tree)
    assert [m.create_time for m in db.iter_chat_all(CONTACT_USER)] == [100, 200, 300, 400]


def test_iter_chat_all_is_ascending_across_page_boundary(tree: Path) -> None:
    """Regression: paging newest-first then reversing per page reordered the timeline."""
    _append_messages(tree, 2500, start_time=1000)
    db = DatabaseService(ACCOUNT_ID, tree)
    keys = [(m.create_time, m.local_id) for m in db.iter_chat_all(CONTACT_USER)]
    assert len(keys) == 2504
    assert keys == sorted(keys)
    assert keys == sorted(set(keys))          # nothing yielded twice
    assert keys[0] == (100, 1)
    assert keys[-1] == (1000 + 2499, 1000 + 2499)


def test_iter_chat_all_since_cursor_is_exclusive(tree: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, tree)
    assert [m.create_time for m in db.iter_chat_all(CONTACT_USER, (200, 2))] == [300, 400]
    assert list(db.iter_chat_all(CONTACT_USER, (400, 4))) == []
    # same create_time: the local_id half of the cursor breaks the tie
    assert [m.local_id for m in db.iter_chat_all(CONTACT_USER, (200, 1))] == [2, 3, 4]


def test_iter_chat_all_since_across_page_boundary(tree: Path) -> None:
    """A cursor read must also stay ordered when it spans more than one page."""
    _append_messages(tree, 2500, start_time=1000)
    db = DatabaseService(ACCOUNT_ID, tree)
    tail = [(m.create_time, m.local_id) for m in db.iter_chat_all(CONTACT_USER, (1200, 1200))]
    assert tail == sorted(tail)
    assert tail[0] == (1201, 1201)
    assert tail[-1] == (3499, 3499)
    assert len(tail) == 2299                      # > one 2000-row page


def test_export_since_emits_only_newer_messages(tree: Path, tmp_path: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, tree)
    svc = ChatExportService(db, tmp_path / "exports")

    full_path = tmp_path / "full.json"
    svc.export(CONTACT_USER, "json", output_path=full_path)
    full = json.loads(full_path.read_text(encoding="utf-8"))
    assert full["meta"]["incremental"] is False and full["meta"]["since"] is None
    assert full["exported"] == 4 and full["next_since"] == "400,4"

    inc_path = tmp_path / "inc.json"
    outcome = svc.export(CONTACT_USER, "json", output_path=inc_path, since=(200, 2))
    payload = json.loads(inc_path.read_text(encoding="utf-8"))
    assert outcome.message_count == 2
    assert payload["meta"]["incremental"] is True and payload["meta"]["since"] == "200,2"
    assert payload["exported"] == 2 and payload["next_since"] == "400,4"
    assert [m["create_time"] for m in payload["messages"]] == [300, 400]

    empty_path = tmp_path / "empty.json"
    svc.export(CONTACT_USER, "json", output_path=empty_path, since=(400, 4))
    tail = json.loads(empty_path.read_text(encoding="utf-8"))
    assert tail["exported"] == 0 and tail["messages"] == []
    assert tail["next_since"] == "400,4"      # a poller never loses its place


def test_export_since_txt_marks_the_cursor(tree: Path, tmp_path: Path) -> None:
    db = DatabaseService(ACCOUNT_ID, tree)
    svc = ChatExportService(db, tmp_path / "exports")
    out = svc.export(CONTACT_USER, "txt", since=(200, 2))
    text = out.output_path.read_text(encoding="utf-8")
    assert "Since: 200,2" in text
    assert out.message_count == 2
    assert "你好，在吗？" not in text