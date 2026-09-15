"""M3 MediaService: locate & decrypt WeChat 4.x chat media files.

Decoding knowledge (empirically verified against a real 4.1.12.55 account):
  * msg/attach/<md5(username)>/<yyyy-MM>/Img/<md5>_*.dat  -- chat images.
    Three generations share this location:
      - legacy: whole-file single-byte XOR.  On the verified account the key is
        0xA4 for every file regardless of image format (JPEG JFIF, JPEG Exif,
        PNG) -> key is derived per magic; we auto-derive from the first bytes.
      - V1 (magic b"\\x07\\x08\\x56\\x31\\x08\\x07"): AES-128-ECB with the fixed
        key md5(b"0") (16 raw bytes) mixed with trailing XOR.
      - V2 (magic b"\\x07\\x08\\x56\\x32\\x08\\x07"): AES-128-ECB over the first
        ``aes_size`` bytes (PKCS7 padded to a block boundary) followed by a
        single-byte-XOR trailer.  Both keys are derived *offline* from the
        kvcomm code and the account wxid -- see .image_key -- so these images
        decode without touching the running client.  Payloads that turn out to
        be WxAM ("wxgf") still need a HEVC decoder and stay "unsupported".
  * msg/video/<yyyy-MM>/<md5>.mp4 + <md5>_thumb.jpg -- plaintext (no decryption).
  * decrypted/message/media_*.db  VoiceInfo(chat_name_id, create_time, local_id,
    svr_id, voice_data, data_index) -- voice payloads (SILK v3) stored in the
    decrypted database itself, keyed by (Name2Id rowid == chat_name_id, local_id).
  * The <md5> links come from Msg_* rows: packed_info_data embeds the disk file
    md5 as 32 lowercase hex ascii inside protobuf-ish string fields.

All file access is read-only on the source account dir; decoded images are
cached under the per-account media cache dir (atomic writes).
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from .database import DatabaseService, message_base_type
from .image_key import (
    V2_HEADER_SIZE,
    V2_MAGIC,
    ImageKeyResolver,
    ImageKeys,
    decode_v2,
    image_format_of,
)
from .payload import parse_payload

V1_MAGIC = bytes.fromhex("070856310807")
_V1_AES_KEY_CANDIDATES = (
    hashlib.md5(b"0").digest(),              # 16 raw bytes
    hashlib.md5(b"0").hexdigest()[:16].encode("ascii"),  # 'cfcd208495d565ef'
)

_IMAGE_MAGICS = {
    "jpg": (b"\xff\xd8\xff", 0xFF),   # expect out[0:3]; xor key = magic[0]^data[0]
    "png": (b"\x89PNG", 0x89),
    "gif": (b"GIF8", 0x47),
}
_HEX32_RE = re.compile(rb"[0-9a-f]{32}(?![0-9a-f])")
_IMAGE_KIND = ("image", 3)
_VIDEO_KIND = ("video", 43)
_VOICE_KIND = ("voice", 34)
_VOICE_KIND_ALT = ("voice", 50)

#: JPEG Start-Of-Frame markers carry the real pixel dimensions.
_SOF_MARKERS = frozenset((0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB))
#: Enough plaintext to walk past a typical Exif/APP1 segment and reach the SOF.
#: Phone photos can stack Exif + ICC + APP3 segments; retry with a wider window
#: instead of paying the larger read for every image.
_DIMENSION_PROBE_LIMITS = (64 * 1024, 512 * 1024)


def _jpeg_dimensions(buf: bytes) -> tuple[int, int] | None:
    """Walk JPEG segments to the Start-Of-Frame marker."""
    index = 2
    end = len(buf) - 9
    while index < end:
        if buf[index] != 0xFF:
            index += 1
            continue
        marker = buf[index + 1]
        if marker in _SOF_MARKERS:
            height = (buf[index + 5] << 8) | buf[index + 6]
            width = (buf[index + 7] << 8) | buf[index + 8]
            return (width, height) if width and height else None
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            index += 2
            continue
        if index + 4 > len(buf):
            break
        segment = (buf[index + 2] << 8) | buf[index + 3]
        if segment < 2:
            return None
        index += 2 + segment
    return None


def image_dimensions(blob: bytes) -> tuple[int, int] | None:
    """Pixel size of a *decoded* image payload (jpg / png / gif)."""
    if blob[:3] == b"\xff\xd8\xff":
        return _jpeg_dimensions(blob)
    if blob[:8] == b"\x89PNG\r\n\x1a\n" and len(blob) >= 24:
        width = int.from_bytes(blob[16:20], "big")
        height = int.from_bytes(blob[20:24], "big")
        return (width, height) if width and height else None
    if blob[:6] in (b"GIF87a", b"GIF89a") and len(blob) >= 10:
        width = int.from_bytes(blob[6:8], "little")
        height = int.from_bytes(blob[8:10], "little")
        return (width, height) if width and height else None
    return None


class MediaError(RuntimeError):
    pass


class MediaUnsupported(MediaError):
    """Media exists on disk but uses an encryption we cannot decode offline."""


@dataclass(frozen=True)
class MediaItem:
    kind: str                 # image | voice | video | file
    status: str               # ok | missing | unsupported | no-md5 | skipped
    ref: str = ""             # short human reference (md5 / file name)
    disk_path: Path | None = None
    detail: str = ""
    size: int = 0
    is_thumbnail: bool = False
    alternates: tuple[Path, ...] = ()   # lower-priority dat candidates (e.g. thumbnail)
    dimensions: tuple[int, int] | None = None   # real pixel size of the chosen file


# ------------------------------------------------------------------ helpers

def md5_hex32(packed: object) -> str | None:
    """Extract the 32-lowercase-hex disk md5 embedded in packed_info_data."""
    if packed is None:
        return None
    if isinstance(packed, str):
        try:
            packed = packed.encode("latin-1")
        except Exception:
            return None
    if not isinstance(packed, (bytes, bytearray)):
        return None
    packed = bytes(packed)
    match = _HEX32_RE.search(packed)
    return match.group(0).decode("ascii") if match else None


def data_key_for(data: bytes) -> int | None:
    """Single-byte XOR key implied by the leading image magic, if any."""
    for _fmt, (magic, first) in _IMAGE_MAGICS.items():
        if len(magic) > len(data):
            continue
        key = data[0] ^ first
        if all((data[i] ^ key) == magic[i] for i in range(len(magic))):
            return key
    return None


def classify_dat(data: bytes) -> str:
    """'xor' | 'v1' | 'v2' | 'unknown'"""
    head = data[:6]
    if head == V2_MAGIC:
        return "v2"
    if head == V1_MAGIC:
        return "v1"
    if len(data) < 4:
        return "unknown"
    return "xor" if data_key_for(data) is not None else "unknown"


def decode_dat(data: bytes, keys: ImageKeys | None = None) -> tuple[str, bytes]:
    """Decode one .dat payload -> (extension, image bytes).

    ``keys`` carries the kvcomm-derived V2 key set; without it V2 payloads stay
    unsupported.  Raises MediaUnsupported for layouts we cannot decode and
    MediaError for corrupt data.
    """
    cls = classify_dat(data)
    if cls == "xor":
        key = data_key_for(data)
        if key is None:
            raise MediaError("legacy dat xor decode produced no known image magic")
        plain = bytes(b ^ key for b in data)
        return image_format_of(plain) or "jpg", plain
    if cls == "v1":
        from Cryptodome.Cipher import AES

        last_error: Exception | None = None
        for key in _V1_AES_KEY_CANDIDATES:
            try:
                dec = AES.new(key, AES.MODE_ECB).decrypt(data[6:])
            except Exception as exc:  # pragma: no cover
                last_error = exc
                continue
            # trailing xor tweak + optional jpeg header area
            probe = dec[:16]
            if probe[:2] == b"\xff\xd8" or b"\xff\xd8" in dec[:64] or b"JFIF" in dec[:64]:
                return "jpg", dec
            if probe[:4] == b"\x89PNG":
                return "png", dec
        raise MediaUnsupported(f"v1 image needs key validation (raw error: {last_error})")
    if cls == "v2":
        if keys is None:
            raise MediaUnsupported("V2 加密图片需要 kvcomm 派生的密钥（本机未解析到）")
        try:
            plain = decode_v2(data, keys)
        except ValueError as exc:
            raise MediaError(f"V2 解密失败: {exc}") from exc
        kind = image_format_of(plain)
        if kind is None:
            raise MediaUnsupported("V2 解密结果不是已知图片格式")
        if kind == "wxgf":
            raise MediaUnsupported("WxAM 压缩图片（需要 HEVC 解码器）")
        return kind, plain
    raise MediaUnsupported("unknown .dat layout (not xor / v1 / v2)")


def _month_of(create_time: int) -> str:
    try:
        return datetime.fromtimestamp(int(create_time)).strftime("%Y-%m")
    except Exception:
        return ""


# ------------------------------------------------------------------ service

class MediaService:
    """Resolve message rows to concrete media files under one WeChat account."""

    def __init__(
        self,
        account_id: str,
        account_dir: Path,
        decrypted_dir: Path,
        cache_dir: Path | None = None,
        image_key_resolver: ImageKeyResolver | None = None,
    ) -> None:
        self.account_id = account_id
        self.account_dir = Path(account_dir)      # xwechat_files/<account>
        self.decrypted_dir = Path(decrypted_dir)
        self.cache_dir = Path(cache_dir) if cache_dir else Path(decrypted_dir) / ".." / "media_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._media_name2id: dict[Path, dict[str, int]] | None = None
        self._locate_stats: dict[str, int] = {}
        self._image_key_resolver = image_key_resolver

    # ------------------------------------------------------------ image path
    def _attach_root(self, username: str) -> Path:
        digest = hashlib.md5(username.encode("utf-8")).hexdigest()
        return self.account_dir / "msg" / "attach" / digest

    def image_dat_candidates(self, username: str, md5: str, create_time: int) -> list[Path]:
        """Files named <md5>* under the chat's Img dir(s); best first.

        Original (non-thumbnail) files are preferred, then thumbnails; a plain
        <md5>.dat scores equal to <md5>_W.dat because both are full-size forms.
        """
        root = self._attach_root(username)
        month = _month_of(create_time)
        hits: list[Path] = []
        for month_dir in ([month] if month else []) + ([p.name for p in root.iterdir() if p.is_dir()] if root.is_dir() else []):
            img_dir = root / month_dir / "Img"
            if not img_dir.is_dir():
                continue
            for candidate in img_dir.glob(f"{md5}*.dat"):
                if candidate not in hits:
                    hits.append(candidate)
        if not hits and root.is_dir():  # fallback: full scan (slow path)
            for candidate in root.rglob(f"{md5}*.dat"):
                if candidate not in hits:
                    hits.append(candidate)
        rank = {False: 0, True: 1}
        hits.sort(
            key=lambda p: (
                rank["_t" in p.stem or "_s" in p.stem],   # thumbnails last
                -p.stat().st_size,
            )
        )
        return hits

    # ----------------------------------------------------------- image keys
    def image_keys(self) -> ImageKeys | None:
        """kvcomm-derived V2 key set for this account (cached; may be None)."""
        if self._image_key_resolver is None:
            self._image_key_resolver = ImageKeyResolver(self.account_dir, self.account_id)
        return self._image_key_resolver.keys()

    def image_key_status(self) -> dict[str, object]:
        """Diagnostics for /api/state: whether V2 images can be decoded."""
        if self._image_key_resolver is None:
            self._image_key_resolver = ImageKeyResolver(self.account_dir, self.account_id)
        return self._image_key_resolver.describe()

    def _plaintext_head(self, path: Path, keys: ImageKeys | None, limit: int) -> bytes:
        """First ~``limit`` plaintext bytes of one dat candidate.

        Only the needed prefix is read, so a 9 MB original costs one 64 KB read:
        V2 keeps its ciphertext in the first ``aes_size`` bytes and the rest of
        the file is already plaintext.
        """
        import struct

        try:
            with open(path, "rb") as handle:
                blob = handle.read(limit + V2_HEADER_SIZE + 1088)
        except OSError:
            return b""
        cls = classify_dat(blob)
        if cls == "v2":
            if keys is None or len(blob) < V2_HEADER_SIZE + 16:
                return b""
            try:
                _, aes_size, _xor_size = struct.unpack_from("<6sLL", blob)
            except struct.error:  # pragma: no cover - guarded by the length check
                return b""
            if aes_size <= 0:
                return b""
            aligned = aes_size + 16 - (aes_size % 16)
            if V2_HEADER_SIZE + aligned > len(blob):
                return b""
            from Cryptodome.Cipher import AES
            from Cryptodome.Util import Padding

            head = AES.new(keys.aes_key[:16], AES.MODE_ECB).decrypt(
                blob[V2_HEADER_SIZE : V2_HEADER_SIZE + aligned]
            )
            # The AES segment is PKCS7 padded, so it must be stripped before the
            # plaintext middle section is appended -- otherwise everything after
            # the first block boundary shifts by the padding length.
            try:
                head = Padding.unpad(head, 16)
            except ValueError:
                pass
            return head + blob[V2_HEADER_SIZE + aligned : limit]
        if cls == "xor":
            key = data_key_for(blob)
            return bytes(b ^ key for b in blob[:limit]) if key is not None else b""
        return b""

    def _probe_image_dat(self, path: Path, keys: ImageKeys | None) -> tuple[str, str]:
        """Read only the header block of one dat candidate -> (status, kind).

        status: ``ok`` | ``locked`` | ``wxam`` | ``missing`` | ``unknown``
        """
        try:
            with open(path, "rb") as handle:
                head = handle.read(V2_HEADER_SIZE + 32)
        except OSError:
            return "missing", ""
        cls = classify_dat(head)
        if cls == "v2":
            if keys is None:
                return "locked", ""
            from Cryptodome.Cipher import AES

            block = head[V2_HEADER_SIZE : V2_HEADER_SIZE + 16]
            if len(block) < 16:
                return "unknown", ""
            try:
                plain = AES.new(keys.aes_key[:16], AES.MODE_ECB).decrypt(block)
            except (ValueError, TypeError):  # pragma: no cover
                return "unknown", ""
            kind = image_format_of(plain)
            if kind is None:
                return "unknown", ""
            return ("wxam", "wxgf") if kind == "wxgf" else ("ok", kind)
        if cls == "xor":
            return "ok", "jpg"
        if cls == "v1":
            return "locked", ""
        return "unknown", ""

    _IMAGE_FALLBACK_DETAIL = {
        "locked": "新版加密图片（V2），本机未解析到 kvcomm 密钥",
        "wxam": "WxAM 压缩图片，需要 HEVC 解码器",
        "missing": "图片文件已被微信清理",
    }

    def image_item(self, username: str, md5: str, create_time: int) -> MediaItem:
        if not md5:
            return MediaItem(kind="image", status="no-md5", ref="", detail="消息未携带图片指纹")
        cands = self.image_dat_candidates(username, md5, create_time)
        if not cands:
            return MediaItem(
                kind="image", status="missing", ref=md5,
                detail="磁盘上不存在该图片（可能已被微信清理）",
            )

        keys = self.image_keys()
        chosen: Path | None = None
        fallback = ("unsupported", "unknown")
        alternates: list[Path] = []
        for path in cands:
            status, kind = self._probe_image_dat(path, keys)
            if status == "ok" and chosen is None:
                chosen = path
                continue
            alternates.append(path)
            if fallback[0] == "unsupported" and status != "ok":
                fallback = (status, kind)

        if chosen is None:
            detail = self._IMAGE_FALLBACK_DETAIL.get(fallback[0], "未知图片格式")
            return MediaItem(
                kind="image", status="unsupported", ref=md5,
                disk_path=cands[0], detail=detail,
            )
        try:
            size = chosen.stat().st_size
        except OSError:
            size = 0
        # Report the size of the file we actually picked: WeChat keeps several
        # renditions under one md5 (``_h`` original, plain mid-size, ``_t``
        # thumbnail) and the message XML only describes one of them.
        dimensions = None
        for probe_limit in _DIMENSION_PROBE_LIMITS:
            dimensions = image_dimensions(self._plaintext_head(chosen, keys, probe_limit))
            if dimensions:
                break
        return MediaItem(
            kind="image", status="ok", ref=md5, disk_path=chosen,
            detail=chosen.name, size=size,
            is_thumbnail="_t" in chosen.stem or "_s" in chosen.stem,
            alternates=tuple(alternates),
            dimensions=dimensions,
        )

    # -------------------------------------------------------------- voice
    def _voice_name2id(self) -> dict[Path, dict[str, int]]:
        if self._media_name2id is not None:
            return self._media_name2id
        mapping: dict[Path, dict[str, int]] = {}
        for db in sorted((self.decrypted_dir / "message").glob("media_*.db")):
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
                try:
                    rows = con.execute("SELECT rowid, user_name FROM Name2Id WHERE user_name IS NOT NULL").fetchall()
                finally:
                    con.close()
            except sqlite3.Error:
                continue
            mapping[db] = {str(user): int(rowid) for rowid, user in rows}
        self._media_name2id = mapping
        return mapping

    def _voice_row(self, username: str, local_id: int, create_time: int):
        """(db, chat_name_id, voice_data|None)."""
        for db, name2id in self._voice_name2id().items():
            chat_name_id = name2id.get(username)
            if chat_name_id is None:
                continue
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
                try:
                    rows = con.execute(
                        "SELECT voice_data, create_time FROM VoiceInfo "
                        "WHERE chat_name_id = ? AND local_id = ?",
                        (chat_name_id, int(local_id)),
                    ).fetchall()
                finally:
                    con.close()
            except sqlite3.Error:
                continue
            if rows:
                data = rows[0][0]
                return data if isinstance(data, (bytes, bytearray)) else None
        return None

    def voice_item(self, username: str, local_id: int, create_time: int) -> MediaItem:
        blob = self._voice_row(username, local_id, create_time)
        if blob is None or len(blob) == 0:
            return MediaItem(kind="voice", status="missing", ref=str(local_id),
                             detail="语音缓存不存在（可能已过期清理）")
        if blob[:8] == b"\x02#!SILK_V3" or b"SILK" in blob[:16]:
            ext = "silk"
        else:
            ext = "bin"
        return MediaItem(
            kind="voice", status="ok", ref=str(local_id),
            detail=f"语音 {len(blob) / 1024:.1f} KB",
            size=len(blob), disk_path=None,
        )

    def voice_blob(self, username: str, local_id: int, create_time: int) -> bytes | None:
        blob = self._voice_row(username, local_id, create_time)
        return bytes(blob) if blob else None

    def voice_wav(self, username: str, local_id: int, create_time: int = 0) -> bytes | None:
        """Decode the voice for in-UI playback, caching the WAV next to other media.

        Returns ``None`` when the payload is missing (WeChat cleaned it up) or no
        SILK decoder is installed — callers then render a placeholder instead.
        """
        from . import voice as voice_mod

        chat_key = hashlib.md5(username.encode("utf-8")).hexdigest()
        cached = voice_mod.cached_wav_path(self.cache_dir, chat_key, int(local_id))
        if cached.is_file() and cached.stat().st_size > 44:
            return cached.read_bytes()
        blob = self.voice_blob(username, local_id, create_time)
        if not blob:
            return None
        wav = voice_mod.silk_to_wav(blob)
        if wav is None:
            return None
        try:
            voice_mod.write_cached_wav(cached, wav)
        except OSError:
            pass
        return wav

    # -------------------------------------------------------------- video
    def video_file(self, username: str, md5: str, create_time: int) -> tuple[Path | None, Path | None]:
        """(mp4, thumb) plaintext under msg/video/<yyyy-MM>/."""
        if not md5:
            return None, None
        month = _month_of(create_time)
        base = self.account_dir / "msg" / "video" / month if month else self.account_dir / "msg" / "video"
        mp4 = thumb = None
        if base.is_dir():
            for p in base.glob(f"{md5}*.mp4"):
                if mp4 is None or p.stat().st_size > mp4.stat().st_size:
                    mp4 = p
            for p in base.glob(f"{md5}*thumb*.jpg"):
                thumb = p
            if mp4 is None and thumb is None:
                for p in base.glob(f"{md5}*"):
                    if p.suffix.lower() == ".mp4":
                        mp4 = p
        # the video may be in a different month dir than the message timestamp
        if mp4 is None or thumb is None:
            vroot = self.account_dir / "msg" / "video"
            if vroot.is_dir():
                for month_dir in vroot.iterdir():
                    if month_dir.is_dir():
                        if mp4 is None:
                            for p in month_dir.glob(f"{md5}*.mp4"):
                                mp4 = p
                                break
                        if thumb is None:
                            for p in month_dir.glob(f"{md5}*thumb*.jpg"):
                                thumb = p
                                break
                        if mp4 and thumb:
                            break
        return mp4, thumb

    def video_item(self, username: str, md5: str, create_time: int) -> MediaItem:
        if not md5:
            return MediaItem(kind="video", status="no-md5", detail="消息未携带视频指纹")
        mp4, thumb = self.video_file(username, md5, create_time)
        if mp4 is not None:
            return MediaItem(kind="video", status="ok", ref=md5, disk_path=mp4,
                             detail=f"mp4 {mp4.stat().st_size / 1024 / 1024:.1f} MB",
                             size=mp4.stat().st_size)
        if thumb is not None:
            return MediaItem(kind="video", status="ok", ref=md5, disk_path=thumb,
                             detail="仅剩缩略图（原视频已被微信清理）", is_thumbnail=True,
                             size=thumb.stat().st_size)
        return MediaItem(kind="video", status="missing", ref=md5,
                         detail="原视频已被微信清理（仅消息记录）")

    # --------------------------------------------------------- message-level
    def item_for_message(self, db: DatabaseService, username: str, msg) -> MediaItem:
        """Resolve a rendered MessageView (or dict with the same keys).

        Message-declared metadata (size, dimensions, duration from the message XML)
        is used to enrich the item so the UI can render informative cards even when
        the payload itself is missing or encrypted.
        """
        meta: dict = {}
        if hasattr(msg, "base_type"):
            base_type = int(msg.base_type)
            local_id = int(msg.local_id)
            create_time = int(msg.create_time)
            packed = getattr(msg, "packed_info_data", None)
            meta = getattr(msg, "media", None) or {}
            if packed is None:
                packed = _packed_from_raw(db, username, local_id)
        else:
            base_type = message_base_type(int(msg.get("local_type", 0)))
            local_id = int(msg.get("local_id", 0))
            create_time = int(msg.get("create_time", 0))
            packed = msg.get("packed_info_data")
            meta = msg.get("media") or {}
            if not meta:  # raw row (API path): decode the payload for its metadata
                try:
                    parsed = parse_payload(int(msg.get("local_type", 0)), msg.get("message_content"), msg.get("source"))
                    meta = parsed.meta.to_dict() if parsed.meta else {}
                except Exception:
                    meta = {}
        md5 = md5_hex32(packed)
        if base_type == 3:
            item = self.image_item(username, md5 or "", create_time)
        elif base_type in (34, 50):
            item = self.voice_item(username, local_id, create_time)
        elif base_type == 43:
            item = self.video_item(username, md5 or "", create_time)
        else:
            return MediaItem(kind="other", status="skipped", ref="", detail="该消息类型不包含可导出媒体")
        return _enrich(item, meta)

    def decode_image(self, item: MediaItem) -> tuple[str, bytes] | None:
        """Decode an ok image_item to (ext, image bytes); None when undecodable.

        Candidates are tried best-first, so an original that only holds a WxAM
        payload silently falls back to the still-displayable thumbnail.
        """
        if item.status != "ok" or item.disk_path is None:
            return None
        keys = self.image_keys()
        for path in (item.disk_path, *item.alternates):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            try:
                return decode_dat(data, keys)
            except MediaError:
                continue
            except Exception:  # pragma: no cover - defensive
                continue
        return None


def _packed_from_raw(db: DatabaseService, username: str, local_id: int):
    """Fetch packed_info_data for one row across shards (best-effort)."""
    import sqlite3 as _s

    table = db.message_table_name(username)
    for shard in db._shards_with_table(table):  # noqa: SLF001 (service-internal)
        try:
            con = _s.connect(f"file:{shard}?mode=ro", uri=True)
            try:
                row = con.execute(
                    f"SELECT packed_info_data FROM [{table}] WHERE local_id = ? LIMIT 1",
                    (int(local_id),),
                ).fetchone()
            finally:
                con.close()
        except _s.Error:
            continue
        if row and row[0] is not None:
            return row[0]
    return None


def _fmt_size(size: int) -> str:
    if size <= 0:
        return ""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.1f} MB"


def _fmt_duration(ms: int) -> str:
    if ms <= 0:
        return ""
    seconds = round(ms / 1000)
    if seconds < 60:
        return f"{seconds}″"
    return f"{seconds // 60}′{seconds % 60:02d}″"


def _enrich(item: MediaItem, meta: dict) -> MediaItem:
    """Fold message-XML metadata into the human-readable detail line."""
    if not meta:
        return item
    duration = int(meta.get("duration_ms") or 0)
    length = int(meta.get("length") or 0)
    width = int(meta.get("width") or 0)
    height = int(meta.get("height") or 0)
    dims = f"{width}×{height}" if width and height else ""
    size = _fmt_size(length)
    label = _fmt_duration(duration)
    detail = item.detail

    if item.kind == "voice":
        if item.status == "ok":
            detail = f"语音 {label} · 点击播放" if label else "语音 · 点击播放"
        elif item.status == "missing":
            detail = f"语音 {label}（本机缓存已过期，无法播放）" if label else "语音缓存已过期"
    elif item.kind == "image":
        # Prefer the measured file over the message XML: the XML describes
        # whichever rendition the sender uploaded, not the one on this disk.
        real_dims = f"{item.dimensions[0]}×{item.dimensions[1]}" if item.dimensions else dims
        real_size = _fmt_size(item.size) or size
        extra = " · ".join(x for x in (real_dims, real_size) if x)
        if item.status == "unsupported":
            detail = f"{item.detail} · {extra}" if extra else item.detail
        elif item.status == "missing":
            detail = f"{extra}（原文件已被微信清理）" if extra else item.detail
        elif item.status == "ok" and extra:
            detail = extra
    elif item.kind == "video":
        extra = " · ".join(x for x in (label, size, dims) if x)
        if item.status == "ok" and not item.is_thumbnail:
            detail = f"视频 {label} · {size}" if label and size else (item.detail or extra)
        elif item.is_thumbnail:
            detail = f"仅剩缩略图 · {extra}" if extra else item.detail
        elif item.status == "missing":
            detail = f"视频 {label}（原文件已被微信清理）" if label else item.detail
    if detail and detail != item.detail:
        return replace(item, detail=detail)
    return item
