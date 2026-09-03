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
    ) -> ExportOutcome:
        if fmt not in ("txt", "json", "html"):
            raise ExportError(f"unsupported format: {fmt}")
        contact = self.db.contact(username)
        display = contact.display_name if contact else username
        self.out_dir.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_path = self.out_dir / f"{_file_stem(display, username, stamp)}.{fmt}"

        count = 0
        with open(output_path, "w", encoding="utf-8", newline="") as fh:
            if fmt == "txt":
                count = self._write_txt(fh, username, display, progress)
            elif fmt == "json":
                count = self._write_json(fh, username, display, progress)
            else:
                count = self._write_html(fh, username, display, progress)
        return ExportOutcome(
            username=username,
            display_name=display,
            output_path=output_path,
            message_count=count,
            fmt=fmt,
        )

    # ---------------------------------------------------------------- writers
    def _write_txt(self, fh, username: str, display: str, progress: ProgressCallback | None) -> int:
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
            fh.write(line + "\n")
            count += 1
            if progress and count % 500 == 0:
                progress(count, None)
        if progress:
            progress(count, None)
        return count

    def _message_dicts(self, username: str, progress: ProgressCallback | None):
        for msg in self.db.iter_chat_all(username):
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
            }

    def _write_json(self, fh, username: str, display: str, progress: ProgressCallback | None) -> int:
        exported_at = datetime.now()
        count = 0
        fh.write('{"meta":')
        json.dump(
            {
                "username": username,
                "display_name": display,
                "exported_at": exported_at.strftime("%Y-%m-%d %H:%M:%S"),
                "total": self._total_for(username),
            },
            fh,
            ensure_ascii=False,
        )
        fh.write(',"messages":[')
        first = True
        for item in self._message_dicts(username, progress):
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

    def _write_html(self, fh, username: str, display: str, progress: ProgressCallback | None) -> int:
        escaped_display = html.escape(display)
        fh.write(_HTML_HEAD.format(title=escaped_display))
        fh.write(f"<h1>{escaped_display}</h1>\n")
        fh.write(f'<div class="meta">username: {html.escape(username)}</div>\n')
        fh.write('<div id="chat">\n')
        count = 0
        for msg in self.db.iter_chat_all(username):
            bubble = "me" if msg.is_outgoing else "peer"
            name = "我" if msg.is_outgoing else html.escape(msg.sender)
            body = html.escape(msg.text).replace("\n", "<br>")
            tag = ""
            if msg.display_type != "text":
                tag = f'<span class="tag">{html.escape(msg.display_type)}</span> '
            fh.write(
                f'<div class="msg {bubble}"><div class="who">{name}</div>'
                f'<div class="bubble">{tag}{body}</div>'
                f'<div class="time">{_ts(msg.create_time)}</div></div>\n'
            )
            count += 1
            if progress and count % 500 == 0:
                progress(count, None)
        fh.write("</div>\n")
        fh.write(f'<div class="footer">{count} messages</div>\n</body></html>')
        if progress:
            progress(count, None)
        return count


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
</style>
</head>
<body>
"""
