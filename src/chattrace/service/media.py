"""M3 MediaService: locate & decrypt WeChat 4.x chat media files.

Decoding knowledge (empirically verified against a real 4.1.12.55 account):
  * msg/attach/<md5(username)>/<yyyy-MM>/Img/<md5>_*.dat  -- chat images.
    Three generations share this location:
      - legacy: whole-file single-byte XOR.  On the verified account the key is
        0xA4 for every file regardless of image format (JPEG JFIF, JPEG Exif,
        PNG) -> key is derived per magic; we auto-derive from the first bytes.
      - V1 (magic b"\\x07\\x08\\x56\\x31\\x08\\x07"): AES-128-ECB with the fixed
        key md5(b"0") (16 raw bytes) mixed with trailing XOR.
      - V2 (magic b"\\x07\\x08\\x56\\x32\\x08\\x07"): AES-128-ECB with one
        per-account key that only exists in the running WeChat process memory
        (not derivable offline) -> surfaced as "unsupported".
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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from .database import DatabaseService, message_base_type

V1_MAGIC = bytes.fromhex("070856310807")
V2_MAGIC = bytes.fromhex("070856320807")
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


def classify_dat(data: bytes) -> str:
    """'xor' | 'v1' | 'v2' | 'unknown'"""
    head = data[:6]
    if head == V2_MAGIC:
        return "v2"
    if head == V1_MAGIC:
        return "v1"
    if len(data) < 4:
        return "unknown"
    # legacy xor: derive key from the magic we expect afterwards
    for _fmt, (magic, first) in _IMAGE_MAGICS.items():
        if len(magic) > len(data):
            continue
        key = data[0] ^ first
        if all((data[i] ^ key) == magic[i] for i in range(len(magic))):
            return "xor"
    return "unknown"


def decode_dat(data: bytes) -> tuple[str, bytes]:
    """Decode one .dat payload -> (extension, image bytes).

    Raises MediaUnsupported for V2 (runtime key only) and unknown layouts,
    MediaError for corrupt data.
    """
    cls = classify_dat(data)
    if cls == "xor":
        # derive the single-byte key from each plausible image magic and verify
        for fmt, (magic, first) in _IMAGE_MAGICS.items():
            key = data[0] ^ first
            if len(magic) > len(data):
                continue
            if all((data[i] ^ key) == magic[i] for i in range(len(magic))):
                out = bytes(b ^ key for b in data)
                return fmt, out
        raise MediaError("legacy dat xor decode produced no known image magic")
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
        raise MediaUnsupported(
            "v2 加密图片需要微信运行时密钥（暂不支持离线导出）"
        )
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
    ) -> None:
        self.account_id = account_id
        self.account_dir = Path(account_dir)      # xwechat_files/<account>
        self.decrypted_dir = Path(decrypted_dir)
        self.cache_dir = Path(cache_dir) if cache_dir else Path(decrypted_dir) / ".." / "media_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._media_name2id: dict[Path, dict[str, int]] | None = None
        self._locate_stats: dict[str, int] = {}

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

    def image_item(self, username: str, md5: str, create_time: int) -> MediaItem:
        if not md5:
            return MediaItem(kind="image", status="no-md5", ref="", detail="消息未携带图片指纹")
        cands = self.image_dat_candidates(username, md5, create_time)
        if not cands:
            return MediaItem(
                kind="image", status="missing", ref=md5,
                detail="磁盘上不存在该图片（可能已被微信清理）",
            )
        path = cands[0]
        try:
            head = path.read_bytes()[:6]
        except OSError:
            return MediaItem(kind="image", status="missing", ref=md5, detail="文件不可读")
        cls = classify_dat(head + b"\x00" * (6 - len(head))) if len(head) < 6 else classify_dat(head)
        if cls == "v2":
            return MediaItem(
                kind="image", status="unsupported", ref=md5, disk_path=path,
                detail="2025-08 之后的新版加密图片（V2），离线无法解密",
            )
        if cls == "v1":
            return MediaItem(
                kind="image", status="unsupported", ref=md5, disk_path=path,
                detail="V1 加密图片（需在线提取密钥）",
            )
        if cls == "unknown":
            return MediaItem(kind="image", status="unsupported", ref=md5, disk_path=path, detail="未知图片格式")
        return MediaItem(
            kind="image", status="ok", ref=md5, disk_path=path,
            detail=path.name, size=path.stat().st_size,
            is_thumbnail="_t" in path.stem,
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
        """Resolve a rendered MessageView (or dict with the same keys)."""
        if hasattr(msg, "base_type"):
            base_type = int(msg.base_type)
            local_id = int(msg.local_id)
            create_time = int(msg.create_time)
            local_type = int(msg.local_type)
            packed = getattr(msg, "packed_info_data", None)
            if packed is None:
                packed = _packed_from_raw(db, username, local_id)
        else:
            base_type = message_base_type(int(msg.get("local_type", 0)))
            local_id = int(msg.get("local_id", 0))
            create_time = int(msg.get("create_time", 0))
            packed = msg.get("packed_info_data")
            local_type = int(msg.get("local_type", 0))
        md5 = md5_hex32(packed)
        if base_type == 3:
            return self.image_item(username, md5 or "", create_time)
        if base_type in (34, 50):
            return self.voice_item(username, local_id, create_time)
        if base_type == 43:
            return self.video_item(username, md5 or "", create_time)
        return MediaItem(kind="other", status="skipped", ref="", detail="该消息类型不包含可导出媒体")

    def decode_image(self, item: MediaItem) -> tuple[str, bytes] | None:
        """Decode an ok image_item to (ext, image bytes); raises on corrupt."""
        if item.status != "ok" or item.disk_path is None:
            return None
        data = item.disk_path.read_bytes()
        return decode_dat(data)


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
