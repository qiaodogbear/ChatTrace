"""ChatTrace Web UI server: guided local-first flow over the service layer.

Endpoints (all under /api):
  GET  /api/state            overall status (account/key/decrypt/counts)
  GET  /api/accounts?root=   discover account dirs under an xwechat_files root
  GET  /api/settings         current persisted settings
  GET  /api/decrypt-status   per-DB decryption readiness
  GET  /api/sessions?q=&l=   session list (recent first)
  GET  /api/contacts?q=&l=   contact list
  GET  /api/chat/<user>      messages page (?limit&before=<ct>,<lid>)
  GET  /api/tasks/<id>       background task state/log
  GET  /api/download?name=   download an export file
  POST /api/select-account   {account_dir}
  POST /api/browse           pick a folder via native dialog (optional initial dir)
  POST /api/key/capture      start KeyAgent capture task {account_dir?}
  POST /api/key/manual       store a manually supplied 64-hex key
  POST /api/decrypt          start decrypt task {force?}
  POST /api/export           start export task {username, format}
  POST /api/open-exports     open exports folder in Explorer
  POST /api/open-file        {name} reveal one export file

Only binds to 127.0.0.1; no auth, no secrets in responses.
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .. import config
from ..config import account_exports_dir, account_work_dir, settings_file
from ..keyagent import keystore
from ..keyagent.account import Account, discover_accounts
from ..models import KeyInfo
from ..service import DecryptService
from ..service import voice as voice_service
from ..service.database import DatabaseService, message_base_type
from ..service.exporter import ChatExportService
from ..service.keycapture import CaptureService
from ..service.media import MediaService

STATIC_DIR = Path(__file__).parent / "static"
STATE_LOCK = threading.RLock()

_LAST_SETTINGS: dict = {}
_last_settings_mtime: float = 0.0


def load_settings() -> dict:
    global _LAST_SETTINGS, _last_settings_mtime
    path = settings_file()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        _LAST_SETTINGS = {}
        return _LAST_SETTINGS
    with STATE_LOCK:
        if mtime != _last_settings_mtime:
            try:
                _LAST_SETTINGS = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                _LAST_SETTINGS = {}
            _last_settings_mtime = mtime
    return _LAST_SETTINGS


def save_settings(patch: dict) -> dict:
    with STATE_LOCK:
        current = load_settings()
        current.update(patch)
        path = settings_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
        return current


# ------------------------------------------------------------------ tasks
class Task:
    def __init__(self, kind: str, title: str) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.title = title
        self.status = "running"  # running | done | failed | cancelled
        self.log: list[dict] = []
        self.result: dict | None = None
        self.error: str | None = None
        self.started_at = time.time()
        self.done_at: float | None = None

    def add_log(self, message: str, level: str = "info") -> None:
        entry = {"t": time.strftime("%H:%M:%S"), "level": level, "msg": message}
        with STATE_LOCK:
            self.log.append(entry)
            if len(self.log) > 2000:
                self.log = self.log[-2000:]

    def snapshot(self) -> dict:
        with STATE_LOCK:
            return {
                "id": self.id,
                "kind": self.kind,
                "title": self.title,
                "status": self.status,
                "log": list(self.log),
                "result": self.result,
                "error": self.error,
            }


class TaskManager:
    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._lock = threading.RLock()

    def start(self, kind: str, title: str, fn) -> str:
        task = Task(kind, title)
        with self._lock:
            self._tasks[task.id] = task

        def runner() -> None:
            try:
                result = fn(task)
                with self._lock:
                    task.result = result
                    task.status = "done"
            except Exception as exc:  # surface any failure into the task
                with self._lock:
                    task.error = f"{type(exc).__name__}: {exc}"
                    task.status = "failed"
                task.add_log(str(exc), "error")
            finally:
                task.done_at = time.time()

        threading.Thread(target=runner, name=f"task-{task.kind}-{task.id}", daemon=True).start()
        return task.id

    def get(self, task_id: str) -> Task | None:
        with self._lock:
            task = self._tasks.get(task_id)
            return task


TASKS = TaskManager()


# ------------------------------------------------------------ account helpers
def current_account() -> Account | None:
    """The account selected in settings, if still discoverable."""
    settings = load_settings()
    account_dir = settings.get("account_dir")
    if not account_dir:
        return None
    path = Path(account_dir)
    if path.is_dir():
        return Account(
            account_id=path.name,
            account_dir=path,
            message_db=path / "db_storage" / "message" / "message_0.db",
        )
    return None


def account_key_state(account: Account | None) -> dict:
    if account is None:
        return {"present": False}
    try:
        info = keystore.load_key(account.account_id)
        return {
            "present": True,
            "fingerprint": info.fingerprint,
            "wechat_version": info.wechat_version,
            "captured_at": info.captured_at,
            "source": info.source,
            "expired": keystore.is_expired(info),
        }
    except Exception:
        return {"present": False}


def account_decrypt_state(account: Account | None) -> dict:
    if account is None:
        return {"dbs": [], "ready": 0, "total": 0, "error": None}
    try:
        out = config.account_decrypted_dir(account.account_id)
        probe = DecryptService(account.account_dir / "db_storage", b"", out)
        return probe.status()
    except Exception as exc:
        return {"dbs": [], "ready": 0, "total": 0, "error": str(exc)}


def _db_for_account(account: Account) -> DatabaseService | None:
    out = config.account_decrypted_dir(account.account_id)
    if not any(out.rglob("*.db")):
        return None
    return DatabaseService(account.account_id, out)


_MEDIA_SVC_CACHE: dict[str, MediaService] = {}


def _media_for_account(account: Account) -> MediaService | None:
    db = _db_for_account(account)
    if db is None:
        return None
    key = account.account_id
    svc = _MEDIA_SVC_CACHE.get(key)
    if svc is None or svc.decrypted_dir != config.account_decrypted_dir(key):
        svc = MediaService(
            account.account_id,
            account.account_dir,
            config.account_decrypted_dir(key),
            account_work_dir(key) / "media_cache",
        )
        _MEDIA_SVC_CACHE[key] = svc
    return svc


# ------------------------------------------------------------------ request
class ChatTraceHandler(BaseHTTPRequestHandler):
    server_version = "ChatTrace/0.1"

    # ------------------------------------------------------------- helpers
    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json(self, payload, code: int = 200) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def send_static(self, rel: str) -> None:
        target = (STATIC_DIR / rel).resolve()
        if not target.is_file() or STATIC_DIR.resolve() not in target.parents:
            self.send_json({"error": "not found"}, 404)
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), f"{ctype}; charset=utf-8")

    def send_error_json(self, message: str, code: int = 400) -> None:
        self.send_json({"error": message}, code)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # -------------------------------------------------------------- routing
    def do_GET(self) -> None:  # noqa: N802
        self._route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")

    def log_message(self, fmt: str, *args) -> None:  # keep console quiet
        pass

    def _route(self, method: str) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if method == "GET" and (path == "/" or path == "/index.html"):
                return self.send_static("index.html")
            if method == "GET" and path.startswith("/assets/"):
                return self.send_static(path.removeprefix("/assets/"))
            if path.startswith("/api/"):
                return self._api(method, path.removeprefix("/api/"), query)
            return self.send_error_json("not found", 404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            try:
                self.send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)
            except Exception:
                pass

    # ----------------------------------------------------------------- API
    def _api(self, method: str, path: str, query: dict) -> None:
        segments = [urllib.parse.unquote(s) for s in path.rstrip("/").split("/") if s]

        if method == "GET" and segments == ["state"]:
            return self.send_json(self._api_state())
        if method == "GET" and segments == ["settings"]:
            return self.send_json(load_settings())
        if method == "GET" and segments == ["accounts"]:
            return self.send_json(self._api_accounts(query))
        if method == "GET" and segments == ["decrypt-status"]:
            return self.send_json(account_decrypt_state(current_account()))
        if method == "GET" and segments == ["sessions"]:
            return self.send_json(self._api_sessions(query))
        if method == "GET" and segments == ["contacts"]:
            return self.send_json(self._api_contacts(query))
        if method == "GET" and len(segments) == 2 and segments[0] == "chat":
            return self.send_json(self._api_chat(segments[1], query))
        if method == "GET" and segments == ["media", "file"]:
            return self._api_media_file(query)
        if method == "GET" and len(segments) == 2 and segments[0] == "tasks":
            task = TASKS.get(segments[1])
            if not task:
                return self.send_error_json("task not found", 404)
            return self.send_json(task.snapshot())
        if method == "GET" and segments == ["download"]:
            return self._api_download(query)

        body = self._read_body()
        if method == "POST" and segments == ["select-account"]:
            return self.send_json(self._api_select_account(body))
        if method == "POST" and segments == ["browse"]:
            return self.send_json(self._api_browse(body))
        if method == "POST" and segments == ["key", "capture"]:
            return self.send_json(self._api_key_capture(body))
        if method == "POST" and segments == ["key", "manual"]:
            return self.send_json(self._api_key_manual(body))
        if method == "POST" and segments == ["decrypt"]:
            return self.send_json(self._api_decrypt(body))
        if method == "POST" and segments == ["export"]:
            return self.send_json(self._api_export(body))
        if method == "POST" and segments == ["open-exports"]:
            return self.send_json(self._api_open_exports())
        if method == "POST" and segments == ["open-file"]:
            return self.send_json(self._api_open_file(body))
        return self.send_error_json("unknown endpoint", 404)

    # ------------------------------------------------------- api impl: GET
    def _api_state(self) -> dict:
        account = current_account()
        key = account_key_state(account)
        decrypt = account_decrypt_state(account)
        counts: dict = {"sessions": None, "contacts": None}
        if account and decrypt["ready"] == decrypt["total"] and decrypt["total"] > 0:
            db = _db_for_account(account)
            if db:
                try:
                    counts["sessions"] = len(db.sessions(limit=100_000))
                    counts["contacts"] = len(db.contacts())
                except Exception:
                    pass
        return {
            "settings": load_settings(),
            "account": None if account is None else {
                "account_id": account.account_id,
                "account_dir": str(account.account_dir),
            },
            "key": key,
            "decrypted": decrypt,
            "counts": counts,
            "app_dir": str(config.app_data_dir()),
            "capabilities": {
                "voice_playback": voice_service.decoder_available(),
            },
        }

    def _api_accounts(self, query: dict) -> dict:
        root = (query.get("root") or [""])[0] or None
        settings = load_settings()
        remembered = settings.get("wechat_root")
        roots: list[str] = []
        seen: set[str] = set()
        candidates = [root, remembered, str(Path.home() / "Documents" / "xwechat_files")]
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if Path(candidate).is_dir():
                roots.append(candidate)
        if not roots:
            roots = _probe_common_roots()
        results = []
        for r in roots:
            accounts = discover_accounts(Path(r))
            results.append(
                {
                    "root": r,
                    "accounts": [
                        {"account_id": a.account_id, "account_dir": str(a.account_dir),
                         "message_db": str(a.message_db)} for a in accounts
                    ],
                }
            )
        return {"roots": results}

    def _api_sessions(self, query: dict) -> dict:
        account = current_account()
        if account is None:
            return {"error": "no account selected"}
        db = _db_for_account(account)
        if db is None:
            return {"error": "databases not decrypted yet"}
        q = (query.get("q") or [""])[0] or None
        limit = int((query.get("limit") or [200])[0])
        sessions = db.sessions(query=q, limit=min(limit, 2000))
        return {"sessions": [s.to_dict() for s in sessions]}

    def _api_contacts(self, query: dict) -> dict:
        account = current_account()
        if account is None:
            return {"error": "no account selected"}
        db = _db_for_account(account)
        if db is None:
            return {"error": "databases not decrypted yet"}
        q = (query.get("q") or [""])[0] or None
        limit = int((query.get("limit") or [100])[0])
        contacts = db.contacts(query=q, limit=min(limit, 1000))
        return {"contacts": [c.to_dict() for c in contacts]}

    def _api_chat(self, username: str, query: dict) -> dict:
        account = current_account()
        if account is None:
            return {"error": "no account selected"}
        db = _db_for_account(account)
        if db is None:
            return {"error": "databases not decrypted yet"}
        limit = int((query.get("limit") or [200])[0])
        before = None
        raw_before = (query.get("before") or [""])[0]
        if raw_before:
            try:
                ct_s, lid_s = raw_before.split(",")
                before = (int(ct_s), int(lid_s))
            except ValueError:
                return {"error": "bad before cursor"}
        page = db.chat(username, limit=min(limit, 2000), before=before)
        total = db.count_messages(username)
        media_svc = _media_for_account(account)
        can_play_voice = voice_service.decoder_available()
        messages = []
        for m in page.messages:
            item = m.to_dict()
            if media_svc is not None and m.kind in ("image", "voice", "video"):
                try:
                    media_item = media_svc.item_for_message(db, username, m)
                except Exception:
                    media_item = None
                if media_item is not None:
                    payload = {
                        "kind": media_item.kind,
                        "status": media_item.status,
                        "detail": media_item.detail,
                        "size": media_item.size,
                        "is_thumbnail": media_item.is_thumbnail,
                    }
                    url = None
                    if media_item.status == "ok":
                        if media_item.kind == "voice":
                            if can_play_voice:
                                url = (
                                    f"/api/media/file?kind=voice"
                                    f"&username={urllib.parse.quote(username)}"
                                    f"&local_id={m.local_id}&ct={m.create_time}"
                                )
                        else:
                            url = (
                                f"/api/media/file?kind={media_item.kind}"
                                f"&username={urllib.parse.quote(username)}"
                                f"&local_id={m.local_id}&ct={m.create_time}"
                            )
                    if url:
                        payload["url"] = url
                    item["media"] = payload
            messages.append(item)
        return {
            "contact": page.contact.to_dict(),
            "messages": messages,
            "total": total,
            "has_more": page.has_more,
        }

    def _api_media_file(self, query: dict) -> None:
        """Serve one media payload (image bytes / .silk / video) for a message."""
        account = self._require_account()
        username = (query.get("username") or [""])[0]
        local_id_s = (query.get("local_id") or [""])[0]
        kind = (query.get("kind") or [""])[0]
        ct_s = (query.get("ct") or [""])[0]
        if not username or not local_id_s.isdigit():
            return self.send_error_json("username and numeric local_id required")
        db = _db_for_account(account)
        if db is None:
            return self.send_error_json("databases not decrypted yet", 409)
        media_svc = _media_for_account(account)
        if media_svc is None:
            return self.send_error_json("media service unavailable", 409)
        try:
            create_time = int(ct_s) if ct_s.isdigit() else None
        except ValueError:
            create_time = None
        raw = db.raw_message_by_id(username, int(local_id_s), create_time)
        if raw is None:
            return self.send_error_json("message not found", 404)
        try:
            item = media_svc.item_for_message(db, username, raw)
        except Exception as exc:
            return self.send_error_json(f"resolve failed: {exc}", 500)
        if item.status != "ok" or item.kind != kind:
            return self.send_error_json(f"media not available ({item.status})", 404)
        try:
            if kind == "image":
                result = media_svc.decode_image(item)
                if result is None:
                    return self.send_error_json("decode failed", 404)
                ext, blob = result
                ctype = "image/jpeg" if ext == "jpg" else ("image/png" if ext == "png" else "image/gif")
                return self._send(200, blob, ctype)
            if kind == "voice":
                # decoded WAV powers the inline <audio> player in the UI
                wav = media_svc.voice_wav(username, int(local_id_s), int(raw["create_time"]))
                if wav is None:
                    return self.send_error_json(
                        "voice cannot be played (missing payload or no SILK decoder)", 404
                    )
                return self._send_audio(wav)
            if kind == "video":
                if item.disk_path is None or not item.disk_path.is_file():
                    return self.send_error_json("video file missing", 404)
                ctype = mimetypes.guess_type(item.disk_path.name)[0] or "application/octet-stream"
                return self._send_file_stream(item.disk_path, ctype)
        except Exception as exc:
            return self.send_error_json(f"media read failed: {exc}", 500)
        return self.send_error_json("unsupported media kind", 400)

    def _send_audio(self, wav: bytes) -> None:
        """Serve a decoded voice WAV inline, honouring a simple Range request."""
        start, end = 0, len(wav) - 1
        range_header = self.headers.get("Range") or ""
        match = re.match(r"bytes=(\d*)-(\d*)$", range_header.strip())
        if match and (match.group(1) or match.group(2)):
            if match.group(1):
                start = int(match.group(1))
                if match.group(2):
                    end = int(match.group(2))
            else:  # suffix range: last N bytes
                start = max(0, len(wav) - int(match.group(2)))
            start = max(0, min(start, len(wav) - 1))
            end = max(start, min(end, len(wav) - 1))
            body = wav[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(wav)}")
        else:
            body = wav
            self.send_response(200)
        self.send_header("Content-Type", "audio/wav")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "private, max-age=3600")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_bytes_attachment(self, code: int, body: bytes, content_type: str, name: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", f'attachment; filename="{urllib.parse.quote(name)}"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_file_stream(self, path: Path, content_type: str, chunk: int = 64 * 1024) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", f'attachment; filename="{urllib.parse.quote(path.name)}"')
        self.end_headers()
        try:
            with open(path, "rb") as fh:
                while True:
                    data = fh.read(chunk)
                    if not data:
                        break
                    self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _api_download(self, query: dict) -> None:
        account = current_account()
        if account is None:
            return self.send_error_json("no account selected")
        name = (query.get("name") or [""])[0]
        if not name:
            return self.send_error_json("missing name")
        exports = account_exports_dir(account.account_id)
        target = (exports / name).resolve()
        try:
            target.relative_to(exports.resolve())
        except ValueError:
            return self.send_error_json("path outside exports", 403)
        if not target.is_file():
            return self.send_error_json("file not found", 404)
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{urllib.parse.quote(target.name)}"',
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ------------------------------------------------------ api impl: POST
    def _api_select_account(self, body: dict) -> dict:
        account_dir = (body.get("account_dir") or "").strip()
        if not account_dir or not Path(account_dir).is_dir():
            return {"error": "account_dir must be an existing directory"}
        settings = save_settings({"account_dir": account_dir})
        account = current_account()
        return {"ok": True, "account_id": account.account_id if account else None, "settings": settings}

    def _api_browse(self, body: dict) -> dict:
        initial = (body.get("initial") or "").strip() or str(Path.home())
        picked = _pick_folder_via_powershell(initial)
        if picked is None:
            return {"error": "dialog cancelled or unavailable"}
        return {"path": picked}

    def _require_account(self) -> Account | None:
        account = current_account()
        if account is None:
            raise ValueError("no account selected yet — choose one on the Account step")
        return account

    def _api_key_capture(self, body: dict) -> dict:
        account = self._require_account()
        observe_ms = int(body.get("observe_ms") or 150_000)

        def run(task: Task) -> dict:
            task.add_log("checking WeChat state…")
            try:
                key = CaptureService.run(
                    account,
                    weixin_exe=None,
                    observe_ms=observe_ms,
                    store=True,
                    progress=lambda stage, payload: task.add_log(f"[{stage}] {payload}"),
                )
            except Exception as exc:
                task.add_log(f"capture failed: {exc}", "error")
                raise
            return {"fingerprint": key.fingerprint, "wechat_version": key.wechat_version}

        task_id = TASKS.start("key-capture", f"自动获取密钥 · {account.account_id}", run)
        return {"task_id": task_id}

    def _api_key_manual(self, body: dict) -> dict:
        account = self._require_account()
        hex_password = (body.get("hex_password") or "").strip().lower()
        try:
            password = bytes.fromhex(hex_password)
        except ValueError:
            return {"error": "not valid hex"}
        if len(password) != 32:
            return {"error": "expected 32 bytes (64 hex chars)"}
        from ..keyagent.verify import test_key_against_db

        ok, detail = test_key_against_db(password, account.message_db)
        if not ok:
            return {"error": f"key does not validate: {detail}"}
        info = KeyInfo(
            account_id=account.account_id,
            wechat_version=(body.get("wechat_version") or "manual"),
            password=password,
            source="manual",
            verified=True,
        )
        keystore.store_key(info)
        return {"ok": True, "fingerprint": info.fingerprint}

    def _api_decrypt(self, body: dict) -> dict:
        account = self._require_account()
        force = bool(body.get("force"))

        def run(task: Task) -> dict:
            info = keystore.load_key(account.account_id)
            out = config.account_decrypted_dir(account.account_id)
            svc = DecryptService(account.account_dir / "db_storage", info.password, out)
            report = svc.run(
                incremental=not force,
                progress=lambda phase, name, detail: task.add_log(
                    {"decrypt": f"解密 {name} …", "ok": f"✓ {name} ({detail})",
                     "skip": f"= {name} 已就绪", "fail": f"✗ {name}: {detail}"}[phase]
                ),
            )
            task.add_log(f"完成：{report.decrypted} 解密 / {report.skipped} 已就绪 / "
                         f"{len(report.failed)} 失败（共 {report.discovered} 个库）")
            if report.failed:
                raise RuntimeError(f"{len(report.failed)} 个库解密失败")
            return {
                "decrypted": report.decrypted,
                "skipped": report.skipped,
                "failed": len(report.failed),
                "total": report.discovered,
                "out_root": str(out),
            }

        task_id = TASKS.start("decrypt", f"解密数据 · {account.account_id}", run)
        return {"task_id": task_id}

    def _api_export(self, body: dict) -> dict:
        account = self._require_account()
        username = (body.get("username") or "").strip()
        fmt = (body.get("format") or "txt").strip().lower()
        include_media = bool(body.get("include_media"))
        if not username:
            return {"error": "missing username"}
        if fmt not in ("txt", "json", "html"):
            return {"error": f"unsupported format {fmt}"}

        def run(task: Task) -> dict:
            db = DatabaseService(account.account_id, config.account_decrypted_dir(account.account_id))
            total = db.count_messages(username) or 0
            media_svc = None
            if include_media:
                media_svc = _media_for_account(account)
            task.add_log(f"开始导出 {username} · {fmt}（约 {total} 条，媒体{'开' if include_media else '关'}）")
            exporter = ChatExportService(db, account_exports_dir(account.account_id))
            outcome = exporter.export(
                username,
                fmt,
                progress=lambda done, _t: task.add_log(f"…{done}/{total}") if done % 2000 == 0 else None,
                include_media=include_media,
                media=media_svc,
            )
            payload = {
                "path": str(outcome.output_path),
                "name": outcome.output_path.name,
                "message_count": outcome.message_count,
                "format": fmt,
                "display_name": outcome.display_name,
            }
            if include_media and fmt == "html":
                assets = outcome.output_path.parent / (outcome.output_path.stem + "_assets")
                if assets.is_dir():
                    payload["assets_dir"] = str(assets)
                    payload["assets_name"] = assets.name
                    task.add_log(f"完成：{outcome.message_count} 条 -> {outcome.output_path.name}（含媒体目录 {assets.name}/）")
                    return payload
            task.add_log(f"完成：{outcome.message_count} 条 -> {outcome.output_path.name}")
            return payload

        task_id = TASKS.start("export", f"导出 · {fmt}", run)
        return {"task_id": task_id}

    def _api_open_exports(self) -> dict:
        account = self._require_account()
        exports = account_exports_dir(account.account_id)
        _open_in_explorer(exports)
        return {"ok": True, "path": str(exports)}

    def _api_open_file(self, body: dict) -> dict:
        account = self._require_account()
        name = (body.get("name") or "").strip()
        exports = account_exports_dir(account.account_id)
        target = (exports / name).resolve()
        try:
            target.relative_to(exports.resolve())
        except ValueError:
            return {"error": "outside exports"}
        if target.is_file():
            _open_in_explorer(target)
            return {"ok": True}
        return {"error": "file not found"}


# ------------------------------------------------------------ native helpers
def _probe_common_roots() -> list[str]:
    home = Path.home()
    candidates = [
        home / "Documents" / "xwechat_files",
        home / "xwechat_files",
        Path(os.environ.get("USERPROFILE", str(home))) / "Documents" / "xwechat_files",
    ]
    seen: set[str] = set()
    roots = []
    for c in candidates:
        key = str(c)
        if key in seen or not c.is_dir():
            continue
        seen.add(key)
        roots.append(key)
    return roots


def _pick_folder_via_powershell(initial: str) -> str | None:
    """Native folder picker (runs on the desktop session, so usable from the Web UI)."""
    ps = r"""
Add-Type -AssemblyName System.Windows.Forms
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = '选择微信数据根目录（xwechat_files 或账号目录）'
$d.SelectedPath = $args[0]
if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.SelectedPath }
"""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-STA", "-Command", ps, initial],
            capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
        )
    except Exception:
        return None
    out = (proc.stdout or "").strip().splitlines()
    return out[-1] if out else None


def _open_in_explorer(path: Path) -> None:
    try:
        subprocess.Popen(["explorer", str(path)], close_fds=True)
    except Exception:
        pass


# ------------------------------------------------------------------ server
def make_server(host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer((host, port), ChatTraceHandler)
    server.daemon_threads = True
    return server, int(server.server_address[1])


def build_parser() -> argparse.ArgumentParser:
    import argparse

    parser = argparse.ArgumentParser(prog="chattrace webui", description="ChatTrace guided Web UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8714)
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        server, port = make_server(args.host, args.port)
    except OSError:
        # preferred port busy -> pick a free one
        server, port = make_server(args.host, 0)
    url = f"http://{args.host}:{port}"
    print(f"ChatTrace Web UI -> {url}")
    print("(close this window to stop the server)")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
