"""DatabaseService: read-only query layer over a decrypted db_storage tree.

Mirrors the WeChat 4.x layout:
  contact.db    -> contact(username, remark, nick_name, alias, delete_flag, …)
  session.db    -> SessionTable(username, summary, last_timestamp, unread_count, …)
  message/*.db  -> Msg_<md5(username)> tables + Name2Id(rowid, user_name)

Two WeChat 4.x quirks are handled explicitly (see also service/payload.py):
  * message bodies are Zstandard-compressed in most rows (WCDB_CT_*=4), so the raw
    column bytes must be decompressed before any text rendering;
  * Name2Id rowids are **per shard**: the same rowid means different people in
    different message_*.db files, so senders are resolved against the Name2Id of
    the shard the row came from (never from a merged map).

All queries are defensive: every SQL statement adapts to the columns actually present
in the file (message shards can differ across versions), and tables that do not exist
are simply skipped.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .payload import ParsedMessage, parse_payload

_CONTACT_DB_REL = Path("contact") / "contact.db"
_SESSION_DB_REL = Path("session") / "session.db"
_MESSAGE_DIR = Path("message")
_DISPLAY_FALLBACKS = ("remark", "nick_name", "alias")


class DatabaseError(RuntimeError):
    pass


# ------------------------------------------------------------------------- text


def _value_to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def normalize_text_content(content: str) -> str:
    normalized = unicodedata.normalize("NFC", content).replace("\ufeff", "")
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    cleaned: list[str] = []
    for character in normalized:
        if character in {"\n", "\t"}:
            cleaned.append(character)
            continue
        if unicodedata.category(character) == "Cc":
            continue
        cleaned.append(character)
    return "".join(cleaned).strip()


def _looks_binaryish(content: str) -> bool:
    if not content:
        return False
    suspicious = 0
    for character in content:
        codepoint = ord(character)
        if character in {"\x00", "\ufffd"}:
            suspicious += 3
        elif codepoint < 32 and character not in "\r\n\t":
            suspicious += 1
    return suspicious >= max(4, len(content) // 16)


URL_RE = re.compile(r"https?://[^\s<>'\"，。！？、）】》]+", re.IGNORECASE)

TYPE_PLACEHOLDER = {
    3: "图片",
    34: "语音",
    43: "视频",
    47: "表情",
    49: "链接/卡片",
    50: "语音",
    1048625: "位置",
}

TYPE_LABEL = {
    1: "text",
    3: "image",
    34: "voice",
    43: "video",
    47: "emoji",
    49: "link",
    50: "voice",
    1048625: "location",
}


def message_base_type(local_type: int) -> int:
    return int(local_type) & 0xFFFFFFFF


def _extract_links(*values: object) -> tuple[str, ...]:
    links: list[str] = []
    for value in values:
        text = _value_to_text(value)
        if not text:
            continue
        links.extend(m.group(0).rstrip(".,;:") for m in URL_RE.finditer(text))
    return tuple(dict.fromkeys(links))


def render_message(local_type: int, message_content: str, compress_content: str, packed_info_data: object = None) -> str:
    """Human-readable text for one message row (chatlog-compatible semantics)."""
    content = message_content or compress_content or ""
    base_type = message_base_type(local_type)
    content = _value_to_text(content)
    links = _extract_links(message_content, compress_content, packed_info_data)

    if content.startswith("b'(") or content.startswith('b"('):
        return links[0] if links else TYPE_PLACEHOLDER.get(base_type, f"类型 {base_type}")

    if base_type in TYPE_PLACEHOLDER:
        return TYPE_PLACEHOLDER[base_type]

    cleaned = normalize_text_content(content)
    if _looks_binaryish(cleaned):
        return links[0] if links else TYPE_PLACEHOLDER.get(base_type, f"类型 {base_type}")
    if cleaned:
        return cleaned
    return links[0] if links else f"类型 {base_type}"


# ------------------------------------------------------------------ dataclasses


@dataclass(frozen=True)
class ContactView:
    username: str
    display_name: str
    remark: str = ""
    nick_name: str = ""
    alias: str = ""

    @property
    def search_blob(self) -> str:
        return "\n".join(
            value.lower() for value in (self.username, self.display_name, self.remark, self.nick_name, self.alias) if value
        )

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "display_name": self.display_name,
            "remark": self.remark,
            "nick_name": self.nick_name,
            "alias": self.alias,
        }


@dataclass(frozen=True)
class SessionView:
    username: str
    display_name: str
    summary: str
    last_timestamp: int
    unread_count: int
    last_sender_display: str = ""

    @property
    def search_blob(self) -> str:
        return "\n".join(v.lower() for v in (self.username, self.display_name, self.summary) if v)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "display_name": self.display_name,
            "summary": self.summary,
            "last_timestamp": self.last_timestamp,
            "unread_count": self.unread_count,
            "last_sender_display": self.last_sender_display,
        }


@dataclass(frozen=True)
class MessageView:
    local_id: int
    local_type: int
    base_type: int
    create_time: int
    is_outgoing: bool
    sender: str            # display name of the sender
    text: str
    display_type: str      # text|image|voice|video|emoji|link|other
    links: tuple[str, ...] = ()
    raw_content: str = ""
    packed_info_data: object = None   # used by MediaService; not serialized
    sender_wxid: str = ""             # resolved sender username (empty when unknown)
    kind: str = "text"                # text|image|voice|video|emoji|location|call|card|file|link|quote|system|other
    media: dict = field(default_factory=dict)   # metadata extracted from the message XML

    def to_dict(self) -> dict:
        return {
            "local_id": self.local_id,
            "local_type": self.local_type,
            "base_type": self.base_type,
            "create_time": self.create_time,
            "is_outgoing": self.is_outgoing,
            "sender": self.sender,
            "sender_wxid": self.sender_wxid,
            "text": self.text,
            "display_type": self.display_type,
            "kind": self.kind,
            "meta": self.media or None,
            "links": list(self.links),
        }


@dataclass
class ChatPage:
    contact: ContactView
    messages: list[MessageView]
    total: int | None = None      # None unless cheap to compute
    has_more: bool = False        # older messages exist before this page


# -------------------------------------------------------------- service


class DatabaseService:
    """Read-only queries over one account's decrypted tree."""

    def __init__(self, account_id: str, decrypted_dir: Path) -> None:
        self.account_id = account_id
        self.decrypted_dir = Path(decrypted_dir)
        if not self.decrypted_dir.is_dir():
            raise DatabaseError(f"decrypted dir missing: {self.decrypted_dir} (run `data decrypt` first)")
        self._contacts: dict[str, ContactView] | None = None
        self._sender_map: dict[int, str] | None = None
        self._shard_sender_maps: dict[Path, dict[int, str]] = {}
        self._shard_cache: dict[str, list[Path]] = {}

    # ------------------------------------------------------------ connection
    def _connect(self, rel: Path):
        db = self.decrypted_dir / rel
        if not db.exists():
            return None
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.text_factory = lambda value: value.decode("utf-8", "replace")
        return con

    @staticmethod
    def _connect_raw(db: Path):
        """Connection that yields **bytes** for TEXT columns.

        Message payloads are zstd blobs stored in TEXT columns; decoding them as
        UTF-8 first (the default text_factory) irreversibly corrupts the data, so
        message reads always go through this raw connection.
        """
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.text_factory = bytes
        return con

    @staticmethod
    def _cols(con, table: str) -> set[str]:
        try:
            rows = con.execute(f"PRAGMA table_info([{table}])").fetchall()
        except sqlite3.Error:
            return set()
        # raw connections hand back bytes for TEXT columns, so normalise here
        return {_as_text(row[1]) for row in rows}

    @staticmethod
    def _has_table(con, table: str) -> bool:
        row = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ?",
            (table,),
        ).fetchone()
        return row is not None

    # --------------------------------------------------------------- contacts
    def load_contacts(self) -> dict[str, ContactView]:
        if self._contacts is not None:
            return self._contacts
        out: dict[str, ContactView] = {}
        con = self._connect(_CONTACT_DB_REL)
        if con is None:
            self._contacts = out
            return out
        try:
            cols = self._cols(con, "contact")
            needed = {"username", "delete_flag"}
            if not needed.issubset(cols):
                self._contacts = out
                return out
            select_extra = [c for c in ("remark", "nick_name", "alias") if c in cols]
            select = ", ".join(["username"] + select_extra)
            rows = con.execute(
                f"SELECT {select} FROM contact WHERE delete_flag = 0 ORDER BY id"
            ).fetchall()
        finally:
            con.close()
        for row in rows:
            values = dict(zip(["username", *select_extra], row))
            username = values["username"] or ""
            if not username:
                continue
            remark = str(values.get("remark") or "")
            nick = str(values.get("nick_name") or "")
            alias = str(values.get("alias") or "")
            display = next((v for v in (remark, nick, alias, username) if v), username)
            out[username] = ContactView(
                username=username,
                display_name=display,
                remark=remark,
                nick_name=nick,
                alias=alias,
            )
        self._contacts = out
        return out

    def contacts(self, query: str | None = None, limit: int = 200) -> list[ContactView]:
        all_contacts = list(self.load_contacts().values())
        if not query:
            return all_contacts[:limit]
        normalized = query.lower()
        return [c for c in all_contacts if normalized in c.search_blob][:limit]

    def contact(self, username: str) -> ContactView | None:
        return self.load_contacts().get(username)

    # --------------------------------------------------------------- sessions
    def sessions(self, query: str | None = None, limit: int = 500) -> list[SessionView]:
        contacts = self.load_contacts()
        con = self._connect(_SESSION_DB_REL)
        out: list[SessionView] = []
        if con is None:
            return out
        try:
            cols = self._cols(con, "SessionTable")
            if {"username", "summary"}.issubset(cols) and "last_timestamp" in cols:
                extra = [c for c in ("unread_count", "is_hidden", "sort_timestamp", "last_sender_display_name") if c in cols]
                order_col = "sort_timestamp" if "sort_timestamp" in cols else "last_timestamp"
                select = ", ".join(["username", "summary", "last_timestamp", *extra])
                where = "WHERE is_hidden = 0" if "is_hidden" in cols else ""
                sql = f"SELECT {select} FROM SessionTable {where} ORDER BY {order_col} DESC LIMIT ?"
                rows = con.execute(sql, (limit * 4,)).fetchall()
            else:
                rows = []
        finally:
            con.close()
        for row in rows:
            values = dict(zip(["username", "summary", "last_timestamp", *extra], row))
            username = values["username"] or ""
            if not username:
                continue
            contact = contacts.get(username)
            display = contact.display_name if contact else username
            out.append(
                SessionView(
                    username=username,
                    display_name=display,
                    summary=str(values.get("summary") or ""),
                    last_timestamp=int(values.get("last_timestamp") or 0),
                    unread_count=int(values.get("unread_count") or 0),
                    last_sender_display=str(values.get("last_sender_display_name") or ""),
                )
            )
        if query:
            normalized = query.lower()
            out = [s for s in out if normalized in s.search_blob]
        out.sort(key=lambda s: s.last_timestamp, reverse=True)
        return out[:limit]

    def session(self, username: str) -> SessionView | None:
        for s in self.sessions(limit=10_000):
            if s.username == username:
                return s
        return None

    # ------------------------------------------------------- message plumbing
    def _message_shard_dbs(self) -> list[Path]:
        msg_dir = self.decrypted_dir / _MESSAGE_DIR
        if not msg_dir.is_dir():
            return []
        return sorted(msg_dir.glob("*.db"))

    def _shards_with_table(self, table_name: str) -> list[Path]:
        if table_name in self._shard_cache:
            return self._shard_cache[table_name]
        hits: list[Path] = []
        for db in self._message_shard_dbs():
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                if self._has_table(con, table_name):
                    hits.append(db)
            finally:
                con.close()
        self._shard_cache[table_name] = hits
        return hits

    def sender_name_map(self) -> dict[int, str]:
        """rowid -> username from Name2Id, merged across shards (legacy helper).

        NOTE: rowids are per-shard, so this merged map is only safe for tasks that
        do not resolve a specific message's sender (e.g. guessing the account's own
        username).  Message rendering uses :meth:`sender_name_map_for_shard`.
        """
        if self._sender_map is not None:
            return self._sender_map
        mapping: dict[int, str] = {}
        for db in self._message_shard_dbs():
            mapping.update(self.sender_name_map_for_shard(db))
        self._sender_map = mapping
        return mapping

    def sender_name_map_for_shard(self, shard: Path) -> dict[int, str]:
        """rowid -> username using **this shard's** Name2Id table."""
        shard = Path(shard)
        cached = self._shard_sender_maps.get(shard)
        if cached is not None:
            return cached
        mapping: dict[int, str] = {}
        try:
            con = self._connect_raw(shard)
        except sqlite3.Error:
            self._shard_sender_maps[shard] = mapping
            return mapping
        try:
            if self._has_table(con, "Name2Id"):
                cols = self._cols(con, "Name2Id")
                if "user_name" in cols:
                    for rowid, user_name in con.execute("SELECT rowid, user_name FROM Name2Id"):
                        name = _as_text(user_name)
                        if name:
                            mapping[int(rowid)] = name
        except sqlite3.Error:
            pass
        finally:
            con.close()
        self._shard_sender_maps[shard] = mapping
        return mapping

    @staticmethod
    def message_table_name(username: str) -> str:
        return f"Msg_{hashlib.md5(username.encode('utf-8')).hexdigest()}"

    def account_username(self, contact_username: str) -> str:
        """Best-effort recovery of the local account's own username.

        The account directory is named ``<wxid>_<suffix>`` so dropping the final
        ``_<digits>`` segment is the most reliable signal; the Name2Id/user tables
        are used only as a fallback.
        """
        base_name, separator, suffix = self.account_id.rpartition("_")
        if separator and base_name.startswith("wxid_") and suffix.isdigit():
            return base_name
        usernames = set(self.sender_name_map().values())
        if self.account_id in usernames:
            return self.account_id
        candidates = sorted(
            (u for u in usernames if u != contact_username and self.account_id.startswith(f"{u}_")),
            key=len,
            reverse=True,
        )
        if candidates:
            return candidates[0]
        return base_name if separator and base_name else self.account_id

    def me_display_name(self, contact_username: str) -> str:
        account_username = self.account_username(contact_username)
        me = self.contact(account_username)
        return me.display_name if me else account_username

    # ------------------------------------------------------------------ messages
    _MSG_WANT = ("local_id", "local_type", "create_time", "status")
    _MSG_OPTIONAL = ("real_sender_id", "message_content", "compress_content", "packed_info_data", "source")

    def _chat_page_rows(
        self,
        username: str,
        limit: int,
        before: tuple[int, int] | None,
    ) -> tuple[list[dict], bool]:
        """Keyset-paginated raw rows across shards (newest-first by (create_time, local_id)).

        Returns dict rows aligned to the union of columns found on the shards; a shard
        missing one of the wanted columns is skipped, and cells missing on a shard are None.
        Every row carries ``_shard`` (the db file it came from) so senders can be resolved
        against that shard's own Name2Id table, and raw bytes for the payload columns.
        """
        table = self.message_table_name(username)
        shards = self._shards_with_table(table)
        # union of usable columns across shards
        union_cols: set[str] = set()
        per_shard: dict[Path, set[str]] = {}
        for db in shards:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                cols = self._cols(con, table)
            finally:
                con.close()
            per_shard[db] = cols
            union_cols |= cols
        columns = list(self._MSG_WANT) + [c for c in self._MSG_OPTIONAL if c in union_cols]
        if not set(self._MSG_WANT).issubset(union_cols):
            return [], False

        collected: list[dict] = []
        for db in shards:
            shard_cols = per_shard[db]
            if not set(self._MSG_WANT).issubset(shard_cols):
                continue  # incompatible shard layout: skip
            usable = [c for c in columns if c in shard_cols]
            select = ", ".join(f"[{c}]" for c in usable)
            where = ""
            params: list = []
            if before is not None:
                where = "WHERE (create_time < ?) OR (create_time = ? AND local_id < ?)"
                params = [before[0], before[0], before[1]]
            con = self._connect_raw(db)
            try:
                sql = f"SELECT {select} FROM [{table}] {where} ORDER BY create_time DESC, local_id DESC LIMIT ?"
                db_rows = con.execute(sql, [*params, limit + 1]).fetchall()
            finally:
                con.close()
            for row in db_rows:
                rec = dict(zip(usable, row))
                rec["_shard"] = db
                collected.append({c: rec.get(c) for c in columns} | {"_shard": db})
        collected.sort(key=lambda r: (int(r["create_time"]), int(r["local_id"])), reverse=True)
        has_more = len(collected) > limit
        return collected[:limit], has_more

    def chat(
        self,
        username: str,
        limit: int = 200,
        before: tuple[int, int] | None = None,
    ) -> ChatPage:
        """Newest page (or the page before `before`) for one chat; messages newest-first."""
        contact = self.contact(username)
        if contact is None:
            contact = ContactView(username=username, display_name=username)
        rows, has_more = self._chat_page_rows(username, limit, before)
        messages = _build_views(self, username, rows)
        return ChatPage(contact=contact, messages=messages, has_more=has_more)

    def count_messages(self, username: str) -> int | None:
        table = self.message_table_name(username)
        total = 0
        for db in self._shards_with_table(table):
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                row = con.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()
                total += int(row[0]) if row else 0
            finally:
                con.close()
        return total

    def raw_message_by_id(self, username: str, local_id: int, create_time: int | None = None) -> dict | None:
        """One raw row dict for a single (local_id[, create_time]).

        local_id is only unique within one shard, so callers that paginate across
        shards (the chat view) should also pass create_time to pick the same row
        that the merged view would keep.  Payload columns are returned as raw bytes.
        """
        table = self.message_table_name(username)
        for db in self._shards_with_table(table):
            con = self._connect_raw(db)
            try:
                cols = self._cols(con, table)
                if not set(self._MSG_WANT).issubset(cols):
                    continue
                usable = list(self._MSG_WANT) + [c for c in self._MSG_OPTIONAL if c in cols]
                select = ", ".join(f"[{c}]" for c in usable)
                where = "local_id = ?"
                params: list = [int(local_id)]
                if create_time is not None:
                    where += " AND create_time = ?"
                    params.append(int(create_time))
                row = con.execute(
                    f"SELECT {select} FROM [{table}] WHERE {where} LIMIT 1", params
                ).fetchone()
            finally:
                con.close()
            if row:
                rec = dict(zip(usable, row))
                rec["_shard"] = db
                return rec
        return None

    def iter_chat_all(self, username: str) -> Iterator[MessageView]:
        """All messages oldest-first (used by exporters)."""
        cursor: tuple[int, int] | None = None
        while True:
            rows, has_more = self._chat_page_rows(username, 2000, cursor)
            if not rows:
                break
            for msg in reversed(_build_views(self, username, rows)):
                yield msg
            if not has_more:
                break
            oldest = rows[-1]
            cursor = (int(oldest["create_time"]), int(oldest["local_id"]))


def _as_text(value: Any) -> str:
    """Decode a SQLite cell (bytes or str) into text without raising."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _build_views(db: DatabaseService, username: str, rows: list[dict]) -> list[MessageView]:
    """Shared raw-row -> MessageView builder (rows keep their given order).

    Sender resolution order (most reliable first):
      1. the ``<wxid>:\\n`` prefix that group-chat text messages carry;
      2. ``real_sender_id`` resolved against **the row's own shard** Name2Id;
      3. ``status == 2`` heuristic for outgoing messages with no sender column.
    """
    contact = db.contact(username)
    account_username = db.account_username(username)
    me_display = db.me_display_name(username)
    views: list[MessageView] = []
    for raw in rows:
        local_id = int(raw["local_id"])
        local_type = int(raw["local_type"])
        create_time = int(raw["create_time"])
        status = int(raw["status"])
        base_type = message_base_type(local_type)

        parsed: ParsedMessage = parse_payload(
            local_type,
            raw.get("message_content") or raw.get("compress_content"),
            raw.get("source"),
        )

        sender_wxid = parsed.sender_hint
        if not sender_wxid:
            sender_id_val = raw.get("real_sender_id")
            if sender_id_val is not None:
                if isinstance(sender_id_val, int) or str(sender_id_val).isdigit():
                    shard = raw.get("_shard")
                    smap = db.sender_name_map_for_shard(shard) if shard else {}
                    sender_wxid = smap.get(int(sender_id_val), "") or f"id:{sender_id_val}"
                else:
                    sender_wxid = _as_text(sender_id_val)

        outgoing = sender_wxid == account_username or (not sender_wxid and status == 2)
        if outgoing:
            sender_display = me_display
        elif sender_wxid:
            peer = db.contact(sender_wxid)
            sender_display = peer.display_name if peer else sender_wxid
        else:
            sender_display = username if contact is not None else "未知发送者"

        text = parsed.text or render_message(local_type, "", "", raw.get("packed_info_data"))
        links = _extract_links(parsed.text, parsed.raw_xml, raw.get("packed_info_data"))

        views.append(
            MessageView(
                local_id=local_id,
                local_type=local_type,
                base_type=base_type,
                create_time=create_time,
                is_outgoing=outgoing,
                sender=sender_display,
                sender_wxid=sender_wxid or "",
                text=text,
                display_type=TYPE_LABEL.get(base_type, parsed.kind or "other"),
                kind=parsed.kind or TYPE_LABEL.get(base_type, "other"),
                media=parsed.meta.to_dict() if parsed.meta else {},
                links=links,
                raw_content=parsed.plain[:20000],
                packed_info_data=raw.get("packed_info_data"),
            )
        )
    return views
