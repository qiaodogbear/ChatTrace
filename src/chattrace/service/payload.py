"""Message payload decoding for WeChat 4.x (M4).

Two facts drive this module (verified on a real 4.1.12.55 account):

1. WeChat stores most message bodies **Zstandard-compressed** inside the TEXT
   column ``message_content`` (``WCDB_CT_message_content = 4``; older rows use 0
   for plain UTF-8).  ``source`` is compressed almost always (``WCDB_CT_source = 4``).
   Treating the raw bytes as text is what produced the "garbled text" output.
2. Once decompressed, rich messages carry a small XML document that holds the
   real metadata: image ``md5``/``aeskey``/``length``, voice ``voicelength``,
   video ``playlength``/``md5``, appmsg ``title``/``type``/``url``, location
   coordinates, VoIP call duration, and so on.

Group text messages additionally start with ``<sender_wxid>:\\n`` which is a far
more reliable sender signal than the per-shard ``Name2Id`` rowid mapping.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

try:  # zstandard is a hard dependency, but keep the import defensive
    import zstandard as _zstd

    _ZSTD_DECOMPRESSOR = _zstd.ZstdDecompressor()
except Exception:  # pragma: no cover - only when the dependency is missing
    _ZSTD_DECOMPRESSOR = None

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

CT_PLAIN = 0
CT_ZSTD = 4

# message base types (local_type & 0xFFFFFFFF)
TEXT = 1
IMAGE = 3
VOICE = 34
CARD = 42
VIDEO = 43
EMOJI = 47
LOCATION = 48
APPMSG = 49
VOIP = 50
OPENIM_CARD = 66
SYSTEM = 10000

_ATTR_RE = re.compile(r'([A-Za-z_][\w:.-]*)\s*=\s*"([^"]*)"')
_TAG_RE = re.compile(r"<\s*([A-Za-z_][\w:.-]*)")
_GROUP_PREFIX_RE = re.compile(r"^(?P<who>[A-Za-z0-9_@.\-]{3,64}):\n(?P<rest>.*)$", re.DOTALL)

# appmsg <type> values worth naming (WeChat's own taxonomy)
APPMSG_LABELS = {
    3: ("music", "音乐"),
    4: ("link", "链接"),
    5: ("link", "链接"),
    6: ("file", "文件"),
    7: ("weapp", "小程序"),
    8: ("emoji", "表情"),
    17: ("real-time location", "实时位置"),
    19: ("chat record", "聊天记录"),
    24: ("note", "笔记"),
    33: ("weapp", "小程序"),
    36: ("weapp", "小程序"),
    44: ("weapp", "小程序"),
    48: ("weapp", "小程序"),
    51: ("video channel", "视频号"),
    53: ("video channel live", "视频号直播"),
    57: ("quote", "引用"),
    62: ("video channel", "视频号"),
    74: ("file", "文件"),
    87: ("weapp", "小程序"),
    2000: ("transfer", "转账"),
    2001: ("red packet", "红包"),
}


class PayloadError(RuntimeError):
    pass


def decompress(raw: bytes | bytearray | memoryview | None) -> bytes:
    """Return the plain payload for one stored message column.

    Handles zstd (magic-detected, so a wrong/absent CT flag is harmless) and
    returns the input untouched when it is already plain.
    """
    if raw is None:
        return b""
    data = bytes(raw)
    if not data:
        return b""
    if data[:4] == ZSTD_MAGIC:
        if _ZSTD_DECOMPRESSOR is None:
            raise PayloadError("zstandard is required to read compressed messages")
        try:
            return _ZSTD_DECOMPRESSOR.decompress(data, max_output_size=8 << 20)
        except Exception as exc:  # pragma: no cover - corrupt row
            raise PayloadError(f"zstd decompression failed: {exc}") from exc
    return data


def to_text(raw: bytes | bytearray | memoryview | str | None, *, decompress_first: bool = True) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):          # already-decoded payload (tests, callers)
        return raw
    data = bytes(raw)
    if not data:
        return ""
    if decompress_first:
        try:
            data = decompress(data)
        except PayloadError:
            return ""
    return data.decode("utf-8", "replace")


def _attrs(text: str) -> dict[str, str]:
    return {key.lower(): value for key, value in _ATTR_RE.findall(text)}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _root_tag(xml_text: str) -> str:
    for match in _TAG_RE.finditer(xml_text):
        tag = match.group(1).lower()
        if tag in ("xml", "msg", "msgsource"):
            continue
        return tag
    return ""


def _inner(xml_text: str, tag: str) -> str:
    """Text content of the first <tag>…</tag> (or attribute-style self-closing tag)."""
    match = re.search(rf"<\s*{tag}\s*>(.*?)<\s*/\s*{tag}\s*>", xml_text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _unescape(text: str) -> str:
    try:
        return (
            text.replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&")
        )
    except Exception:  # pragma: no cover
        return text


def _unescape_rounds(text: str, rounds: int = 2) -> str:
    for _ in range(rounds):
        new = _unescape(text)
        if new == text:
            break
        text = new
    return text


@dataclass
class MediaMeta:
    """Metadata extracted from one rich message payload."""

    kind: str = "other"          # image|voice|video|emoji|file|link|quote|location|call|card|system|text|other
    label: str = ""              # short human label, e.g. 文件 / 链接 / 引用
    md5: str = ""
    aeskey: str = ""
    length: int = 0              # payload size in bytes (plaintext when known)
    duration_ms: int = 0
    width: int = 0
    height: int = 0
    title: str = ""
    desc: str = ""
    url: str = ""
    thumb_url: str = ""
    subtype: int = 0
    nickname: str = ""
    username: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    poi: str = ""
    city: str = ""
    call_duration_s: int = 0
    call_text: str = ""
    quoted: dict = field(default_factory=dict)   # refermsg: {kind,title,content,from}
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {
            "kind": self.kind,
            "label": self.label,
        }
        for key in ("md5", "length", "duration_ms", "width", "height", "title", "desc",
                    "url", "subtype", "nickname", "username", "poi", "city",
                    "call_duration_s", "call_text"):
            value = getattr(self, key)
            if value:
                out[key] = value
        if self.latitude or self.longitude:
            out["latitude"] = self.latitude
            out["longitude"] = self.longitude
        if self.quoted:
            out["quoted"] = self.quoted
        return out


@dataclass
class ParsedMessage:
    kind: str = "other"
    text: str = ""                    # display text (clean, human readable)
    meta: MediaMeta | None = None
    sender_hint: str = ""             # wxid from the group-chat "sender:\n" prefix
    raw_xml: str = ""
    plain: str = ""                   # decompressed payload (text form)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "text": self.text,
            "sender_hint": self.sender_hint,
            "meta": self.meta.to_dict() if self.meta else None,
        }


def _clean_text(value: str) -> str:
    """Drop control chars that would otherwise render as乱码 in the bubble."""
    out = []
    for ch in value:
        if ch in "\n\t":
            out.append(ch)
            continue
        if ord(ch) < 32:
            continue
        out.append(ch)
    return "".join(out).strip()


def _appmsg_kind(subtype: int) -> tuple[str, str]:
    return APPMSG_LABELS.get(subtype, ("link", "卡片"))


def parse_payload(local_type: int, message_content: Any, source: Any = None) -> ParsedMessage:
    """Decode one message row into display text + media metadata."""
    base_type = int(local_type) & 0xFFFFFFFF
    plain = to_text(message_content)
    parsed = ParsedMessage(plain=plain)

    if base_type == TEXT:
        parsed.kind = "text"
        text = plain
        match = _GROUP_PREFIX_RE.match(text)
        if match:
            parsed.sender_hint = match.group("who")
            text = match.group("rest")
        parsed.text = _clean_text(text)
        return parsed

    if base_type == SYSTEM:
        parsed.kind = "system"
        parsed.text = _clean_text(plain)
        return parsed

    if base_type in (IMAGE, VOICE, VIDEO, EMOJI, LOCATION, APPMSG, VOIP, CARD, OPENIM_CARD) or plain.lstrip().startswith("<"):
        xml_text = plain
        # some bodies carry a "sender:\n" prefix before the XML (group chats)
        match = _GROUP_PREFIX_RE.match(xml_text)
        if match and match.group("rest").lstrip().startswith("<"):
            parsed.sender_hint = match.group("who")
            xml_text = match.group("rest")
        parsed.raw_xml = xml_text
        meta = _parse_rich(base_type, xml_text)
        parsed.kind = meta.kind
        parsed.meta = meta
        parsed.text = _meta_to_text(meta)
        return parsed

    # unknown type: show readable text when it looks like text, else a generic label
    cleaned = _clean_text(plain)
    parsed.kind = "other"
    parsed.text = cleaned if cleaned and not _looks_binary(plain) else f"类型 {base_type}"
    return parsed


def _looks_binary(text: str) -> bool:
    if not text:
        return False
    bad = sum(1 for ch in text if ch == "\ufffd" or ord(ch) < 9)
    return bad >= max(3, len(text) // 10)


def _parse_rich(base_type: int, xml_text: str) -> MediaMeta:
    tag = _root_tag(xml_text)
    attrs = _attrs(xml_text)
    meta = MediaMeta()

    if base_type == IMAGE or tag == "img":
        meta.kind = "image"
        meta.label = "图片"
        meta.md5 = attrs.get("md5", "")
        meta.aeskey = attrs.get("aeskey", "")
        meta.length = _int(attrs.get("length"))
        meta.thumb_url = attrs.get("cdnthumburl", "")
        for key in ("cdnthumbwidth", "width", "cdnmidwidth"):
            if _int(attrs.get(key)):
                meta.width = _int(attrs.get(key))
                break
        for key in ("cdnthumbheight", "height", "cdnmidheight"):
            if _int(attrs.get(key)):
                meta.height = _int(attrs.get(key))
                break
        meta.extra["encryver"] = attrs.get("encryver", "")
        return meta

    if base_type == VOICE or tag == "voicemsg":
        meta.kind = "voice"
        meta.label = "语音"
        meta.duration_ms = _int(attrs.get("voicelength"))
        meta.length = _int(attrs.get("length"))
        meta.aeskey = attrs.get("aeskey", "")
        meta.extra["voiceformat"] = attrs.get("voiceformat", "")
        return meta

    if base_type == VIDEO or tag == "videomsg":
        meta.kind = "video"
        meta.label = "视频"
        meta.md5 = attrs.get("md5", "")
        meta.aeskey = attrs.get("aeskey", "")
        meta.length = _int(attrs.get("length"))
        meta.duration_ms = _int(attrs.get("playlength")) * 1000
        meta.width = _int(attrs.get("cdnthumbwidth"))
        meta.height = _int(attrs.get("cdnthumbheight"))
        meta.thumb_url = attrs.get("cdnthumburl", "")
        return meta

    if base_type == EMOJI or tag == "emoji":
        meta.kind = "emoji"
        meta.label = "表情"
        meta.md5 = attrs.get("md5", "")
        meta.length = _int(attrs.get("len"))
        meta.url = _unescape(attrs.get("cdnurl", ""))
        meta.extra["productid"] = attrs.get("productid", "")
        return meta

    if base_type == LOCATION or tag == "location":
        meta.kind = "location"
        meta.label = "位置"
        meta.latitude = _float(attrs.get("x"))
        meta.longitude = _float(attrs.get("y"))
        meta.poi = attrs.get("poiname", "")
        meta.city = attrs.get("cityname", "")
        meta.desc = attrs.get("label", "")
        return meta

    if base_type == VOIP or "voip" in tag or "voipinvitemsg" in xml_text:
        meta.kind = "call"
        meta.label = "语音通话"
        text = _inner(xml_text, "diaplay_content") or _inner(xml_text, "display_content")
        meta.call_text = _unescape_rounds(text)
        match = re.search(r"(\d+):(\d{2})", meta.call_text)
        if match:
            meta.call_duration_s = int(match.group(1)) * 60 + int(match.group(2))
        meta.extra["status"] = _inner(xml_text, "status")
        return meta

    if base_type == APPMSG or "<appmsg" in xml_text:
        subtype = _int(_inner(xml_text, "type"))
        kind, label = _appmsg_kind(subtype)
        meta.kind = kind
        meta.label = label
        meta.subtype = subtype
        meta.title = _unescape_rounds(_inner(xml_text, "title"))
        meta.desc = _unescape_rounds(_inner(xml_text, "des"))
        meta.url = _unescape(_inner(xml_text, "url"))
        meta.md5 = _inner(xml_text, "md5")
        if kind == "file":
            fileext = _inner(xml_text, "fileext")
            meta.extra["fileext"] = fileext
        refer = _inner(xml_text, "refermsg")
        if refer:
            refer_attrs = _attrs(refer)

            def pick(name: str) -> str:
                # real payloads carry these as child elements; older ones as attributes
                return refer_attrs.get(name) or _inner(refer, name)

            meta.quoted = {
                "kind": _int(_inner(refer, "type")),
                "title": _unescape_rounds(_inner(refer, "title")),
                "content": _unescape_rounds(_inner(refer, "content")) or _unescape_rounds(_inner(refer, "svrid")),
                "from": pick("fromusr"),
                "chat": pick("chatusr"),
            }
        return meta

    if base_type in (CARD, OPENIM_CARD) or ("nickname" in attrs and "username" in attrs):
        meta.kind = "card"
        meta.label = "名片"
        meta.nickname = _unescape_rounds(attrs.get("nickname", ""))
        meta.username = attrs.get("username", "")
        meta.desc = attrs.get("alias", "") or attrs.get("province", "")
        meta.extra["openim"] = base_type == OPENIM_CARD or attrs.get("openimappid", "") != ""
        return meta

    if "sysmsg" in xml_text:
        meta.kind = "system"
        meta.label = "系统"
        return meta

    meta.kind = "other"
    meta.label = f"类型 {base_type}"
    meta.extra["root"] = tag
    return meta


def _format_duration(ms: int) -> str:
    if ms <= 0:
        return ""
    seconds = round(ms / 1000)
    if seconds < 60:
        return f"{seconds}″"
    return f"{seconds // 60}′{seconds % 60:02d}″"


def _format_size(size: int) -> str:
    if size <= 0:
        return ""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.1f} MB"


def _meta_to_text(meta: MediaMeta) -> str:
    """A concise human-readable fallback line for each rich message kind."""
    if meta.kind == "image":
        parts = ["[图片]"]
        if meta.width and meta.height:
            parts.append(f"{meta.width}×{meta.height}")
        if meta.length:
            parts.append(_format_size(meta.length))
        return " ".join(parts)
    if meta.kind == "voice":
        duration = _format_duration(meta.duration_ms)
        return f"[语音 {duration}]" if duration else "[语音]"
    if meta.kind == "video":
        duration = _format_duration(meta.duration_ms)
        return f"[视频 {duration}]" if duration else "[视频]"
    if meta.kind == "emoji":
        return "[表情]"
    if meta.kind == "location":
        place = " ".join(x for x in (meta.poi, meta.city) if x)
        return f"[位置] {place}" if place else "[位置]"
    if meta.kind == "call":
        if meta.call_text:
            return f"[语音通话] {meta.call_text}"
        if meta.call_duration_s:
            return f"[语音通话] {_format_duration(meta.call_duration_s * 1000)}"
        return "[语音通话]"
    if meta.kind == "file":
        return f"[文件] {meta.title}" if meta.title else "[文件]"
    if meta.kind == "quote":
        quoted = meta.quoted.get("content") or meta.quoted.get("title") or ""
        head = f"[引用] {meta.title}" if meta.title else "[引用]"
        return f"{head} ⟵ {quoted}" if quoted else head
    if meta.kind == "link":
        if meta.title:
            return f"[链接] {meta.title}"
        return f"[链接] {meta.url}" if meta.url else "[链接]"
    if meta.kind == "music":
        return f"[音乐] {meta.title}" if meta.title else "[音乐]"
    if meta.kind in ("weapp",):
        return f"[小程序] {meta.title}" if meta.title else "[小程序]"
    if meta.kind == "transfer":
        return "[转账]"
    if meta.kind == "red packet":
        return "[红包]"
    if meta.kind == "card":
        name = meta.nickname or meta.username
        return f"[名片] {name}" if name else "[名片]"
    if meta.kind == "system":
        return "[系统消息]"
    return meta.title or meta.label or "[消息]"


def is_playable_voice(text: str) -> bool:
    return "语音" in text or "通话" in text
