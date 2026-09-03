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
    ) -> ExportOutcome:
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
                count = self._write_txt(fh, username, display, progress, include_media, media)
            elif fmt == "json":
                count = self._write_json(fh, username, display, progress, include_media, media)
            else:
                count = self._write_html(fh, username, display, progress, include_media, media, output_path)
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
                   include_media: bool = False, media=None) -> int:
        exported_at = datetime.now()
        fh.write(f"Chat: {display}\n")
        fh.write(f"Username: {username}\n")
        fh.write(f"Exported At: {exported_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write("-" * 60 + "\n")
        count = 0
        for msg in self.db.iter_chat_all(username):
            line = f"[{_ts(msg.create_time)}] {msg.sender}: {msg.text}"
            if msg.links:
                extras = [link for link in msg.links if link not in msg.text]
                if extras:
                    line += "  " + " ".join(extras)
            if include_media and media is not None and msg.display_type in ("image", "voice", "video"):
                item = media.item_for_message(self.db, username, msg)
                note = self._media_note(item)
                if note:
                    line += "  " + note
            fh.write(line + "\n")
            count += 1
            if progress and count % 500 == 0:
                progress(count, None)
        if progress:
            progress(count, None)
        return count

    def _message_dicts(self, username: str, progress: ProgressCallback | None, include_media: bool = False, media=None):
        for msg in self.db.iter_chat_all(username):
            item = None
            if include_media and media is not None and msg.display_type in ("image", "voice", "video"):
                it = media.item_for_message(self.db, username, msg)
                item = {
                    "kind": it.kind, "status": it.status, "ref": it.ref,
                    "detail": it.detail, "size": it.size,
                }
            yield {
                "local_id": msg.local_id,
                "create_time": msg.create_time,
                "time": _ts(msg.create_time),
                "sender": msg.sender,
                "is_outgoing": msg.is_outgoing,
                "type": msg.display_type,
                "local_type": msg.local_type,
                "text": msg.text,
                "links": list(msg.links),
                **({"media": item} if item is not None else {}),
            }

    def _write_json(self, fh, username: str, display: str, progress: ProgressCallback | None,
                    include_media: bool = False, media=None) -> int:
        exported_at = datetime.now()
        count = 0
        fh.write('{"meta":')
        json.dump(
            {
                "username": username,
                "display_name": display,
                "exported_at": exported_at.strftime("%Y-%m-%d %H:%M:%S"),
                "total": self._total_for(username),
                "media": bool(include_media),
            },
            fh,
            ensure_ascii=False,
        )
        fh.write(',"messages":[')
        first = True
        for item in self._message_dicts(username, progress, include_media, media):
            if not first:
                fh.write(",")
            json.dump(item, fh, ensure_ascii=False)
            first = False
            count += 1
            if progress and count % 500 == 0:
                progress(count, None)
        fh.write("]}")
        if progress:
            progress(count, None)
        return count

    def _write_html(self, fh, username: str, display: str, progress: ProgressCallback | None,
                    include_media: bool = False, media=None, output_path: Path | None = None) -> int:
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
        for msg in self.db.iter_chat_all(username):
            bubble = "me" if msg.is_outgoing else "peer"
            name = "我" if msg.is_outgoing else html.escape(msg.sender)
            tag = ""
            if msg.display_type != "text":
                tag = f'<span class="tag">{html.escape(msg.display_type)}</span> '
            body = html.escape(msg.text).replace("\n", "<br>")
            extra = ""
            if include_media and media is not None and msg.display_type in ("image", "voice", "video"):
                item = media.item_for_message(self.db, username, msg)
                extra = self._html_media_block(item, msg, username, assets_dir, media_stats)
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
            total = sum(v for k, v in media_stats.items() if k != "skipped")
            fh.write(
                f'<div class="footer">{count} messages · 媒体附件目录: '
                f'{html.escape(assets_dir.name)}/（图片 {media_stats["image"]}，'
                f'语音 {media_stats["voice"]}，视频 {media_stats["video"]}）</div>\n'
            )
        else:
            fh.write(f'<div class="footer">{count} messages</div>\n')
        fh.write("</body></html>")
        if progress:
            progress(count, None)
        return count

    def _html_media_block(self, item, msg, username: str, assets_dir: Path | None, stats: dict) -> str:
        """Render one media item inside the bubble; writes the asset when ok."""
        kind = item.kind
        stats.setdefault(kind, 0)
        if item.status == "ok":
            asset = None
            if assets_dir is not None:
                asset = self._write_media_asset(item, msg, username, assets_dir)
            stats[kind] += 1
            if kind == "image":
                if asset is not None:
                    rel = asset.name
                    return f'<br><a href="{html.escape(rel)}" target="_blank"><img class="media-img" loading="lazy" src="{html.escape(rel)}" alt="图片"></a>'
                return "<br><span class='media-warn'>⚠️ 图片（解码失败）</span>"
            if kind == "voice":
                if asset is not None:
                    return f'<br><a class="voice" href="{html.escape(asset.name)}">🎤 语音 {msg.text}</a>'
                return "<br><span class='media-warn'>⚠️ 语音不可用</span>"
            if kind == "video":
                if asset is not None and item.is_thumbnail:
                    return (f'<br><img class="media-img thumb" loading="lazy" src="{html.escape(asset.name)}" alt="视频缩略图">'
                            f'<div class="media-note">仅剩缩略图（原视频已被微信清理）· '
                            f'<a href="{html.escape(asset.name)}">下载缩略图</a></div>')
                if asset is not None:
                    return (f'<br><video class="media-video" controls preload="metadata" src="{html.escape(asset.name)}"></video>'
                            f'<div class="media-note"><a href="{html.escape(asset.name)}">下载视频（{item.detail}）</a></div>')
                return "<br><span class='media-warn'>⚠️ 视频不可用</span>"
        if item.status == "unsupported" or item.status == "missing" or item.status == "no-md5":
            stats["skipped"] += 1
            return f"<br><span class='media-warn'>⚠️ {html.escape(item.detail)}</span>"
        return ""

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
