#!/usr/bin/env python3
"""Poll one WeChat chat and append only what arrived since the previous run.

This is the one command an agent needs.  It wraps the three ChatTrace steps:

1. ``chattrace data decrypt``  -- incremental; brings brand-new WeChat messages
   into the local plaintext copy (skip with ``--no-decrypt``);
2. resolve the chat           -- ``--chat`` takes either a display name
   (substring, e.g. a group name) or an exact username;
3. ``chattrace export``       -- with ``--since`` set to the cursor stored by the
   previous run, so only newer messages are written.

State is kept in ``<out-dir>/.state/<slug>.json``.  The resolved ``username`` is
remembered there, so renaming the group later cannot silently retarget the poll
(a substring that stops matching would otherwise look like "no new messages").

Every run prints exactly one JSON object on stdout for the calling agent::

    {"chat": "...", "username": "...", "mode": "incremental", "exported": 5,
     "next_since": "1790005705,1236", "total": 10710, "output": "...",
     "decrypt": "3 decrypted, 22 fresh, 0 failed of 25 DBs", "ok": true}

Exit codes: 0 ok, 1 usage/environment problem, 2 the chat could not be resolved,
3 export failed, 4 the cursor could not be read back.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_SRC = Path(__file__).resolve().parents[1] / "src"
if REPO_SRC.is_dir():
    # run straight from a checkout (no ``pip install`` required)
    sys.path.insert(0, str(REPO_SRC))

DEFAULT_PORT_HINT = "chattrace"
_USERNAME_RE = re.compile(r"^(wxid_[A-Za-z0-9]+|gh_[A-Za-z0-9]+|\d+@chatroom|brandsessionholder)$")


class PollError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _slug(value: str) -> str:
    """Filesystem-safe component for a chat name (keeps CJK, strips separators)."""
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" .")
    return (cleaned or "chat")[:80]


def looks_like_username(value: str) -> bool:
    return bool(_USERNAME_RE.match(value.strip()))


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.run(
        [sys.executable, "-m", "chattrace.cli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def _load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _decrypt(account_dir: Path) -> str:
    proc = run_cli(["data", "decrypt", "--account-dir", str(account_dir)])
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode not in (0,):
        raise PollError(1, f"decrypt failed: {text.strip()[-400:]}")
    for line in reversed(text.splitlines()):
        if line.startswith("result:"):
            return line[len("result:"):].strip()
    return "decrypt finished"


def _export(account_dir: Path, target: dict, out_path: Path, *, fmt: str,
            since: str | None, media: bool) -> tuple[subprocess.CompletedProcess, dict | None]:
    args = ["export", "--account-dir", str(account_dir), "--format", fmt, "--out", str(out_path)]
    if target.get("username"):
        args += ["--user", target["username"]]
    else:
        args += ["--query", target["query"]]
    if since:
        args += ["--since", since]
    if media:
        args += ["--media"]
    proc = run_cli(args)
    payload = None
    if fmt == "json" and out_path.is_file():
        try:
            payload = json.loads(out_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise PollError(4, f"exported JSON is unreadable: {exc}") from exc
    return proc, payload


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="poll_chat.py",
        description="Incrementally fetch one WeChat chat into a JSON file.",
    )
    ap.add_argument("--account-dir", required=True,
                    help="WeChat account directory, e.g. <xwechat_files>\\wxid_xxx_1234")
    ap.add_argument("--chat", required=True,
                    help="Group/contact display name (substring) or an exact username")
    ap.add_argument("--out-dir", default=None,
                    help="Where exports and .state/ live "
                         "(default: %LOCALAPPDATA%\\ChatTrace\\accounts\\<account>\\poll)")
    ap.add_argument("--format", default="json", choices=("json", "txt", "html"),
                    help="Export format; incremental mode requires json (default)")
    ap.add_argument("--media", action="store_true", help="Annotate/emit media too")
    ap.add_argument("--no-decrypt", action="store_true",
                    help="Skip the incremental database decrypt step")
    ap.add_argument("--full", action="store_true",
                    help="Ignore the stored cursor and export the whole chat")
    ap.add_argument("--quiet", action="store_true", help="Do not print progress lines")
    args = ap.parse_args(argv)

    account_dir = Path(args.account_dir).expanduser()
    if not account_dir.is_dir():
        raise PollError(1, f"account dir not found: {account_dir}")
    account_id = account_dir.name

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr, flush=True)

    # Never default into the WeChat data tree: the whole toolchain promises to
    # leave <xwechat_files> strictly read-only.
    default_root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "ChatTrace"
    out_dir = (Path(args.out_dir).expanduser() if args.out_dir
               else default_root / "accounts" / account_id / "poll")
    state_path = out_dir / ".state" / f"{_slug(args.chat)}.json"
    state = _load_state(state_path)

    try:
        decrypt_summary = "skipped"
        if not args.no_decrypt:
            log(f"[1/3] decrypting {account_id} (incremental) ...")
            decrypt_summary = _decrypt(account_dir)
            log(f"      {decrypt_summary}")

        target: dict[str, str] = {}
        # An explicit username pinned earlier wins over the substring: group
        # names change, usernames do not.
        if state.get("username"):
            target["username"] = state["username"]
        elif looks_like_username(args.chat):
            target["username"] = args.chat.strip()
        else:
            target["query"] = args.chat

        since = None if args.full else state.get("next_since")
        if args.format != "json" and since:
            log("      note: --format other than json cannot track a cursor; exporting fully")
            since = None

        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        out_path = out_dir / f"{_slug(args.chat)}__{stamp}.{args.format}"

        log(f"[2/3] exporting ({'incremental since ' + since if since else 'full'}) ...")
        proc, payload = _export(account_dir, target, out_path, fmt=args.format,
                                since=since, media=args.media)
        if proc.returncode != 0:
            detail = ((proc.stdout or "") + (proc.stderr or "")).strip()
            if "no chat matched query" in detail or "ambiguous query" in detail:
                raise PollError(2, f"cannot resolve chat {args.chat!r}: {detail.splitlines()[-1]}")
            if state.get("username"):   # pinned username stopped working
                state.pop("username", None)
                _save_state(state_path, state)
                raise PollError(2, f"pinned username {target.get('username')!r} no longer works: "
                                   f"{detail.splitlines()[-1] if detail else 'unknown error'}")
            raise PollError(3, f"export failed: {detail.splitlines()[-1] if detail else proc.returncode}")

        if payload is None:
            summary = {
                "ok": True, "chat": args.chat, "username": state.get("username"),
                "mode": "full", "output": str(out_path), "decrypt": decrypt_summary,
                "note": "non-json format: no cursor tracked",
            }
            print(json.dumps(summary, ensure_ascii=False))
            return 0

        meta = payload.get("meta", {})
        exported = int(payload.get("exported", 0))
        next_since = payload.get("next_since") or since

        log(f"[3/3] {exported} new message(s) -> {out_path.name}")
        _save_state(state_path, {
            "chat": args.chat,
            "username": meta.get("username") or state.get("username"),
            "display_name": meta.get("display_name"),
            "next_since": next_since,
            "last_run": time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_exported": exported,
            "runs": int(state.get("runs", 0)) + 1,
        })

        print(json.dumps({
            "ok": True,
            "chat": meta.get("display_name") or args.chat,
            "username": meta.get("username") or state.get("username"),
            "mode": "incremental" if meta.get("incremental") else "full",
            "exported": exported,
            "next_since": next_since,
            "total": meta.get("total"),
            "output": str(out_path),
            "decrypt": decrypt_summary,
        }, ensure_ascii=False))
        return 0

    except PollError as exc:
        print(json.dumps({"ok": False, "chat": args.chat, "error": str(exc),
                          "code": exc.code}, ensure_ascii=False))
        return exc.code


if __name__ == "__main__":
    raise SystemExit(main())
