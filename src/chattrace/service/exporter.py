"""M2 ChatExportService: export one chat to .txt / .json / .html.

All outputs are written to the account exports directory. HTML is a fully
self-contained dark-themed page (inline CSS, no external assets).
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .database import DatabaseService

ProgressCallback = Callable[[int, int], None]  # (processed, total) total may be None


class ExportError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExportOutcome:
    username: str
    display_name: str
    output_path: Path
    message_count: int
    fmt: str


def _safe_component(value: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in value).strip("._")
    return cleaned[:80] or "chat"


def _ts(epoch: int) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def _file_stem(display_name: str, username: str, stamp: str) -> str:
    return f"{stamp}__{_safe_component(display_name)}__{_safe_component(username)}"


class ChatExportService:
    def __init__(self, db: DatabaseService, out_dir: Path) -> None:
        self.db = db
        self.out_dir = Path(out_dir)

    def _total_for(self, username: str) -> int | None:
        try:
            return self.db.count_messages(username)
        except Exception:
            return None

    def export(
        self,
        username: str,
        fmt: str,
        progress: ProgressCallback | None = None,
        output_path: Path | None = None,
        include_media: bool = False,
        media=None,  # Optional[MediaService]
        since: tuple[int, int] | None = None,
    ) -> ExportOutcome:
        """Export one chat.  ``since`` is an exclusive ``(create_time, local_id)``
        cursor, so passing the newest cursor of a previous run yields only the
        messages that arrived afterwards (incremental export)."""
        if fmt not in ("txt", "json", "html"):
            raise ExportError(f"unsupported format: {fmt}")
        contact = self.db.contact(username)
        display = contact.display_name if contact else username
        self.out_dir.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_path = self.out_dir / f"{_file_stem(display, username, stamp)}.{fmt}"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if media is not None:
            from .media import MediaService

            if not isinstance(media, MediaService):
                raise ExportError("media must be a MediaService instance")
        self._media = media

        count = 0
        with open(output_path, "w", encoding="utf-8", newline="") as fh:
            if fmt == "txt":
                count = self._write_txt(fh, username, display, progress, include_media, media, since)
            elif fmt == "json":
                count = self._write_json(fh, username, display, progress, include_media, media, since)
            else:
                count = self._write_html(fh, username, display, progress, include_media, media, output_path, since)
        return ExportOutcome(
            username=username,
            display_name=display,
            output_path=output_path,
            message_count=count,
            fmt=fmt,
        )

    # ------------------------------------------------------ media helpers
    @staticmethod
    def _media_note(item, fmt_hint: str = "txt") -> str:
        """Short textual representation of one media item for txt/json outputs."""
        if item.status == "ok":
            return f"[{item.kind} {item.ref[:12]}{'…' if len(item.ref) > 12 else ''}]"
        if item.status == "unsupported":
            return f"[{item.kind} 加密格式未导出]"
        if item.status == "missing":
            return f"[{item.kind} 原文件已被清理]"
        if item.status == "no-md5":
            return f"[{item.kind} 无指纹]"
        return ""

    def _media_assets_dir(self, output_path: Path) -> Path:
        return output_path.parent / (output_path.stem + "_assets")

    # ---------------------------------------------------------------- writers
    def _write_txt(self, fh, username: str, display: str, progress: ProgressCallback | None,
                   include_media: bool = False, media=None, since: tuple[int, int] | None = None) -> int:
        exported_at = datetime.now()
        fh.write(f"Chat: {display}\n")
        fh.write(f"Username: {username}\n")
        fh.write(f"Exported At: {exported_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
        if since is not None:
            fh.write(f"Since: {since[0]},{since[1]}\n")
        fh.write("-" * 60 + "\n")
        count = 0
        for msg in self.db.iter_chat_all(username, since):
            line = f"[{_ts(msg.create_time)}] {msg.sender}: {msg.text}"
            if msg.links:
                extras = [link for link in msg.links if link not in msg.text]
                if extras:
                    line += "  " + " ".join(extras)
            fh.write(line + "\n")
            count += 1
            if progress and count % 500 == 0:
                progress(count, None)
        if progress:
            progress(count, None)
        return count

    def _message_dicts(self, username: str, progress: ProgressCallback | None, include_media: bool = False,
                       media=None, since: tuple[int, int] | None = None):
        for msg in self.db.iter_chat_all(username, since):
            item = None
            if include_media and media is not None and msg.kind in ("image", "voice", "video"):
                try:
                    it = media.item_for_message(self.db, username, msg)
                    item = {"kind": it.kind, "status": it.status, "detail": it.detail, "size": it.size}
                except Exception:
                    item = None
            yield {
                "local_id": msg.local_id,
                "create_time": msg.create_time,
                "time": _ts(msg.create_time),
                "sender": msg.sender,
                "sender_wxid": msg.sender_wxid,
                "is_outgoing": msg.is_outgoing,
                "kind": msg.kind,
                "type": msg.display_type,
                "local_type": msg.local_type,
                "text": msg.text,
                "meta": msg.media or None,
                "links": list(msg.links),
                **({"media": item} if item is not None else {}),
            }

    def _write_json(self, fh, username: str, display: str, progress: ProgressCallback | None,
                    include_media: bool = False, media=None, since: tuple[int, int] | None = None) -> int:
        exported_at = datetime.now()
        count = 0
        fh.write('{"meta":')
        json.dump(
            {
                "username": username,
                "display_name": display,
                "exported_at": exported_at.strftime("%Y-%m-%d %H:%M:%S"),
                "total": self._total_for(username),
                "incremental": since is not None,
                "since": f"{since[0]},{since[1]}" if since is not None else None,
                "media": bool(include_media),
            },
            fh,
            ensure_ascii=False,
        )
        fh.write(',"messages":[')
        first = True
        cursor: tuple[int, int] | None = None
        for item in self._message_dicts(username, progress, include_media, media, since):
            if not first:
                fh.write(",")
            json.dump(item, fh, ensure_ascii=False)
            first = False
            count += 1
            cursor = (int(item["create_time"]), int(item["local_id"]))
            if progress and count % 500 == 0:
                progress(count, None)
        # ``next_since`` is the cursor to hand back on the following run; it is
        # echoed even for an empty result so a poller never loses its place.
        next_cursor = cursor if cursor is not None else since
        fh.write("]")
        fh.write(',"next_since":')
        json.dump(
            f"{next_cursor[0]},{next_cursor[1]}" if next_cursor is not None else None,
            fh,
            ensure_ascii=False,
        )
        fh.write(',"exported":')
        fh.write(str(count))
        fh.write("}")
        if progress:
            progress(count, None)
        return count

    def _write_html(self, fh, username: str, display: str, progress: ProgressCallback | None,
                    include_media: bool = False, media=None, output_path: Path | None = None,
                    since: tuple[int, int] | None = None) -> int:
        escaped_display = html.escape(display)
        fh.write(_HTML_HEAD.format(title=escaped_display))
        fh.write(f"<h1>{escaped_display}</h1>\n")
        fh.write(f'<div class="meta">username: {html.escape(username)} · media: {"on" if include_media else "off"}</div>\n')
        fh.write('<div id="chat">\n')
        assets_dir = None
        if include_media and media is not None and output_path is not None:
            assets_dir = self._media_assets_dir(output_path)
            assets_dir.mkdir(parents=True, exist_ok=True)
        media_stats = {"image": 0, "voice": 0, "video": 0, "skipped": 0}
        count = 0
        for msg in self.db.iter_chat_all(username, since):
            bubble = "me" if msg.is_outgoing else "peer"
            name = "我" if msg.is_outgoing else html.escape(msg.sender)
            tag = ""
            body = ""
            extra = ""
            if msg.kind == "system":
                fh.write(
                    f'<div class="sysmsg"><div class="sysbody">{html.escape(msg.text)}</div>'
                    f'<div class="time">{_ts(msg.create_time)}</div></div>\n'
                )
                count += 1
                if progress and count % 500 == 0:
                    progress(count, None)
                continue
            if msg.kind == "text":
                body = html.escape(msg.text).replace("\n", "<br>")
            else:
                extra = self._html_card(msg, username, assets_dir, media_stats, include_media, media)
                if msg.kind in ("emoji", "other"):
                    body = html.escape(msg.text)
            fh.write(
                f'<div class="msg {bubble}"><div class="who">{name}</div>'
                f'<div class="bubble">{tag}{body}{extra}</div>'
                f'<div class="time">{_ts(msg.create_time)}</div></div>\n'
            )
            count += 1
            if progress and count % 500 == 0:
                progress(count, None)
        fh.write("</div>\n")
        if assets_dir is not None:
            fh.write(
                f'<div class="footer">{count} messages · 媒体附件目录: '
                f'{html.escape(assets_dir.name)}/（图片 {media_stats.get("image", 0)}，'
                f'语音 {media_stats.get("voice", 0)}，视频 {media_stats.get("video", 0)}）</div>\n'
            )
        else:
            fh.write(f'<div class="footer">{count} messages</div>\n')
        fh.write("</body></html>")
        if progress:
            progress(count, None)
        return count

    # ---------------------------------------------------------- html cards
    def _html_card(self, msg, username: str, assets_dir: Path | None, stats: dict,
                   include_media: bool, media) -> str:
        """Render one non-text message as a card (mirrors the Web UI rendering)."""
        meta = msg.media or {}
        kind = msg.kind

        def esc(value) -> str:
            return html.escape(str(value or ""))

        def fmt_size(n) -> str:
            n = int(n or 0)
            if n <= 0:
                return ""
            if n < 1024:
                return f"{n} B"
            if n < 1048576:
                return f"{n / 1024:.1f} KB"
            return f"{n / 1024 / 1024:.1f} MB"

        def fmt_dur(ms) -> str:
            ms = int(ms or 0)
            if ms <= 0:
                return ""
            seconds = round(ms / 1000)
            if seconds < 60:
                return f"{seconds}″"
            return f"{seconds // 60}′{seconds % 60:02d}″"

        info_bits = []
        if meta.get("width") and meta.get("height"):
            info_bits.append(f"{meta['width']}×{meta['height']}")
        if meta.get("duration_ms"):
            info_bits.append(fmt_dur(meta["duration_ms"]))
        elif meta.get("call_duration_s"):
            info_bits.append(fmt_dur(meta["call_duration_s"] * 1000))
        if meta.get("length"):
            info_bits.append(fmt_size(meta["length"]))
        info = " · ".join(info_bits)

        def stub(icon: str, title: str, sub: str, why: str = "") -> str:
            parts = [f'<div class="card stub"><span class="ic">{esc(icon)}</span><div class="cbody">',
                     f'<div class="ctitle">{esc(title)}</div>']
            if sub:
                parts.append(f'<div class="csub">{esc(sub)}</div>')
            if why:
                parts.append(f'<div class="cwhy">{esc(why)}</div>')
            parts.append("</div></div>")
            return "".join(parts)

        def app(icon: str, title: str, sub: str = "", url: str = "") -> str:
            parts = [f'<div class="card app"><span class="ic">{esc(icon)}</span><div class="cbody">',
                     f'<div class="ctitle">{esc(title)}</div>']
            if sub:
                parts.append(f'<div class="csub">{esc(sub)}</div>')
            if url:
                safe = esc(url) if url.startswith(("http://", "https://")) else ""
                if safe:
                    parts.append(f'<a class="curl" href="{safe}" target="_blank" rel="noreferrer">{esc(url[:68])}</a>')
                else:
                    parts.append(f'<div class="curl">{esc(url[:68])}</div>')
            parts.append("</div></div>")
            return "".join(parts)

        def quote_bar(quoted: dict) -> str:
            text = quoted.get("content") or quoted.get("title") or ""
            return f'<div class="quote">引用：{esc(text[:90])}</div>' if text else ""

        if kind == "image":
            item = media.item_for_message(self.db, username, msg) if media is not None else None
            if item is not None and item.status == "ok":
                asset = self._write_media_asset(item, msg, username, assets_dir) if assets_dir else None
                if asset is not None:
                    stats["image"] = stats.get("image", 0) + 1
                    rel = esc(asset.name)
                    badge = f'<div class="badge">{esc(info)}</div>' if info else ""
                    return (f'<div class="card media"><a href="{rel}" target="_blank">'
                            f'<img loading="lazy" src="{rel}" alt="图片"></a>{badge}</div>')
                return stub("🖼", "图片", info, "图片解码失败")
            why = item.detail if item is not None else "图片不可用"
            if item is None or item.status != "ok":
                stats["skipped"] = stats.get("skipped", 0) + 1
            return stub("🖼", "图片", info, why)

        if kind == "voice":
            item = media.item_for_message(self.db, username, msg) if media is not None else None
            duration = fmt_dur(meta.get("duration_ms"))
            if item is not None and item.status == "ok" and media is not None:
                wav = media.voice_wav(username, int(msg.local_id), int(msg.create_time))
                if wav is not None and assets_dir is not None:
                    target = assets_dir / f"{msg.local_id}.wav"
                    if not target.exists():
                        tmp = target.with_suffix(".wav.tmp")
                        tmp.write_bytes(wav)
                        tmp.replace(target)
                    stats["voice"] = stats.get("voice", 0) + 1
                    return (f'<div class="card voice"><audio controls preload="none" src="{esc(target.name)}"></audio>'
                            f'<span class="csub">{esc(duration or "语音")}</span></div>')
                why = "未安装 SILK 解码器，无法转码播放"
            else:
                why = (item.detail if item is not None else "") or "本机语音缓存已过期"
            stats["skipped"] = stats.get("skipped", 0) + 1
            return stub("🔊", f"语音 {duration}".strip(), "", why)

        if kind == "video":
            item = media.item_for_message(self.db, username, msg) if media is not None else None
            if item is not None and item.status == "ok":
                asset = self._write_media_asset(item, msg, username, assets_dir) if assets_dir else None
                if asset is not None:
                    stats["video"] = stats.get("video", 0) + 1
                    rel = esc(asset.name)
                    if item.is_thumbnail:
                        return (f'<div class="card media"><img loading="lazy" src="{rel}" alt="视频缩略图">'
                                f'<div class="csub">仅剩缩略图（原视频已被微信清理）{(" · " + esc(info)) if info else ""}</div></div>')
                    return (f'<div class="card media"><video controls preload="metadata" src="{rel}"></video>'
                            f'<div class="csub">{esc(info)}</div></div>')
            stats["skipped"] = stats.get("skipped", 0) + 1
            why = (item.detail if item is not None else "") or "原视频已被微信清理"
            return stub("🎬", "视频", info, why)

        if kind == "emoji":
            return stub("😀", "表情", info)
        if kind == "location":
            place = " · ".join(x for x in (meta.get("poi"), meta.get("city")) if x) or "位置"
            coords = ""
            if meta.get("latitude") and meta.get("longitude"):
                coords = f"{meta['latitude']:.5f}, {meta['longitude']:.5f}"
            return app("📍", place, coords)
        if kind == "call":
            title = meta.get("call_text") or f"通话 {fmt_dur((meta.get('call_duration_s') or 0) * 1000)}"
            return app("📞", title, "语音通话")
        if kind == "card":
            return app("👤", meta.get("nickname") or meta.get("username") or "名片", meta.get("username") or "")
        if kind == "file":
            ext = (meta.get("extra") or {}).get("fileext", "")
            return app("📄", meta.get("title") or "文件", (ext.upper() + " 文件") if ext else "文件")
        if kind == "quote":
            return quote_bar(meta.get("quoted") or {}) + app("💬", meta.get("title") or "引用消息")
        if kind in ("link", "music", "weapp", "transfer", "red packet"):
            icons = {"link": "🔗", "music": "🎵", "weapp": "🧩", "transfer": "💰", "red packet": "🧧"}
            return quote_bar(meta.get("quoted") or {}) + app(
                icons.get(kind, "🔗"), meta.get("title") or meta.get("label") or "卡片",
                meta.get("label") or "", meta.get("url") or "",
            )
        return f'<span>{esc(msg.text)}</span>'

    def _write_media_asset(self, item, msg, username: str, assets_dir: Path) -> Path | None:
        """Materialize the media payload next to the exported HTML; returns the file."""
        svc = self._media
        if svc is None:
            return None
        try:
            if item.kind == "image":
                result = svc.decode_image(item)
                if result is None:
                    return None
                ext, blob = result
                target = assets_dir / f"{msg.local_id}.{ext}"
            elif item.kind == "voice":
                blob = svc.voice_blob(username, int(msg.local_id), int(msg.create_time))
                if blob is None:
                    return None
                target = assets_dir / f"{msg.local_id}.silk"
            elif item.kind == "video":
                if item.disk_path is None or not item.disk_path.is_file():
                    return None
                suffix = item.disk_path.suffix or ".bin"
                target = assets_dir / f"{msg.local_id}{suffix}"
                blob = item.disk_path.read_bytes()
            else:
                return None
        except Exception:
            return None
        if not target.exists():
            tmp = target.with_suffix(target.suffix + ".tmp")
            tmp.write_bytes(blob)
            tmp.replace(target)
        return target


_HTML_HEAD = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: "Segoe UI", "Microsoft YaHei", system-ui, sans-serif; background:#121417; color:#e8eaed; margin:0; }}
  h1 {{ font-size: 20px; margin: 18px 16px 2px; }}
  .meta {{ color:#9aa0a6; font-size: 12px; margin: 0 16px 14px; }}
  #chat {{ display:flex; flex-direction:column; gap:10px; padding: 0 16px 20px; max-width: 860px; margin: 0 auto; }}
  .msg {{ display:flex; flex-direction:column; max-width: 72%; }}
  .msg.me {{ align-self: flex-end; align-items: flex-end; }}
  .msg.peer {{ align-self: flex-start; align-items: flex-start; }}
  .who {{ font-size: 12px; color:#9aa0a6; margin-bottom: 3px; padding: 0 4px; }}
  .bubble {{ background:#1e2329; border:1px solid #2b313a; border-radius: 12px; padding: 8px 12px;
            word-break: break-word; white-space: pre-wrap; line-height: 1.5; }}
  .msg.me .bubble {{ background:#1f4e36; border-color:#2c6b4c; }}
  .tag {{ color:#e8c76a; font-size: 11px; margin-right: 6px; }}
  .time {{ font-size: 11px; color:#6b7280; margin-top: 2px; padding: 0 4px; }}
  .footer {{ text-align:center; color:#6b7280; font-size: 12px; padding: 8px 0 24px; }}
  .media-img {{ display:block; max-width: 320px; max-height: 320px; border-radius: 8px; margin-top: 8px; border:1px solid #333a44; }}
  /* ---- cards (M4) ---- */
  .card {{ margin-top: 6px; }}
  .card.media {{ position: relative; }}
  .card.media img {{ display:block; max-width: 320px; max-height: 320px; border-radius: 8px; border:1px solid #333a44; }}
  .card.media img.thumb {{ max-width: 160px; max-height: 160px; }}
  .card.media video {{ display:block; max-width: 360px; border-radius: 8px; background:#000; }}
  .badge {{ position:absolute; right:6px; bottom:6px; background: rgba(0,0,0,.62); color:#dfe5ea; font-size:10px; padding:2px 6px; border-radius:5px; }}
  .card.stub, .card.app {{ display:flex; gap:9px; align-items:flex-start; background:#171c22; border:1px solid #2b333d;
                           border-radius:10px; padding:8px 10px; min-width:190px; max-width:340px; }}
  .msg.me .card.stub, .msg.me .card.app {{ background:#1b3a2c; border-color:#2c6b4c; }}
  .card .ic {{ font-size:19px; line-height:1.1; }}
  .card .cbody {{ min-width:0; }}
  .card .ctitle {{ font-size:13px; font-weight:600; }}
  .card .csub {{ font-size:11px; color:#98a1ab; margin-top:2px; }}
  .card .cwhy {{ font-size:11px; color:#d9a05b; margin-top:3px; }}
  .card .curl {{ display:block; font-size:11px; color:#78c8a4; margin-top:3px; word-break:break-all; }}
  .card.voice {{ display:flex; align-items:center; gap:8px; }}
  .card.voice audio {{ height:34px; max-width:250px; }}
  .quote {{ font-size:11px; color:#9aa0a6; border-left:2px solid #4a5462; padding:2px 0 2px 7px; margin-top:4px; word-break:break-word; }}
  .sysmsg {{ align-self:center; max-width:82%; text-align:center; margin:6px 0; }}
  .sysbody {{ display:inline-block; background:#1a1e24; border:1px solid #262d36; color:#98a1ab; font-size:11.5px; padding:4px 10px; border-radius:10px; line-height:1.5; }}
  .sysmsg .time {{ font-size:10px; color:#5d6570; }}
  .media-img.thumb {{ max-width: 160px; max-height: 160px; }}
  .media-video {{ display:block; max-width: 380px; margin-top: 8px; border-radius: 8px; background:#000; }}
  .voice {{ color:#7fd0a0; font-weight:600; text-decoration:none; }}
  .media-note {{ font-size: 11px; color:#9aa0a6; margin-top: 4px; }}
  .media-note a, .voice a {{ color:#7fd0a0; }}
  .media-warn {{ color:#d9a05b; font-size: 12px; }}
</style>
</head>
<body>
"""
