"""ChatTrace CLI (M1: KeyAgent workflows)."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, config
from .config import (
    ERR_OK,
    KeyagentError,
    account_decrypted_dir,
    account_exports_dir,
    keys_dir,
    logs_dir,
)
from .keyagent import keystore, wechat_state, version_map
from .keyagent.account import Account, discover_accounts, resolve_account
from .keyagent.agent import capture_key
from .keyagent.locate_anchors import LocateError, locate_anchors
from .keyagent.verify import test_key_against_db
from .models import AnchorSet
from .service import DecryptService
from .service.database import DatabaseService
from .service.exporter import ChatExportService

PROG = "chattrace"


def _e(code: int) -> int:
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description="ChatTrace: local WeChat 4.x data toolchain.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("doctor", help="Environment self-check (frida/weixin/anchors/keystore).")

    key = sub.add_parser("key", help="Manage stored keys (DPAPI-protected).")
    key_sub = key.add_subparsers(dest="key_command")
    key_sub.add_parser("status", help="List stored keys (fingerprints only).")
    p_store = key_sub.add_parser("store", help="Import a key manually (64 hex chars) and store it.")
    p_store.add_argument("hex_password")
    p_store.add_argument("--account-dir", required=True, help="Account dir or xwechat_files root.")
    p_store.add_argument("--version", default="", help="Optional WeChat version tag.")
    p_store.add_argument("--force", action="store_true", help="Overwrite existing key.")
    p_test = key_sub.add_parser("test", help="HMAC-check a key against the account DB.")
    p_test.add_argument("hex_password", nargs="?", help="64 hex chars; omit to test the stored key.")
    p_test.add_argument("--account-dir", required=True)
    p_forget = key_sub.add_parser("forget", help="Delete the stored key for an account.")
    p_forget.add_argument("--account-dir", required=True)

    ka = sub.add_parser("keyagent", help="Frida capture workflows.")
    ka_sub = ka.add_subparsers(dest="keyagent_command")
    p_run = ka_sub.add_parser("run", help="Spawn WeChat, hook codec, capture and store the key.")
    p_run.add_argument("--account-dir", required=True)
    p_run.add_argument("--weixin-exe", default=None, help="Path to Weixin.exe (auto-detected otherwise).")
    p_run.add_argument("--observe-ms", type=int, default=120_000, help="Observation window in ms.")
    p_run.add_argument("--store", action="store_true", help="Store the captured key (default: just report).")
    p_loc = ka_sub.add_parser("locate", help="Statically locate anchors in a Weixin.dll and cache them.")
    p_loc.add_argument("--weixin-dll", required=True)
    p_loc.add_argument("--version", default="", help="WeChat version tag; inferred from path if omitted.")

    data = sub.add_parser("data", help="Decrypt & prepare account databases (needs a stored key).")
    data_sub = data.add_subparsers(dest="data_command")
    p_dstat = data_sub.add_parser("status", help="Key + decryption readiness summary.")
    p_dstat.add_argument("--account-dir", required=True)
    p_dec = data_sub.add_parser("decrypt", help="Decrypt required DBs (incremental) into the account cache.")
    p_dec.add_argument("--account-dir", required=True)
    p_dec.add_argument("--force", action="store_true", help="Re-decrypt everything, ignoring freshness.")
    p_dec.add_argument("--root", default=None, help="Output root override (default: %%LOCALAPPDATA%%\\ChatTrace\\accounts\\<wxid>).")

    chat = sub.add_parser("chat", help="Browse decrypted chats.")
    chat_sub = chat.add_subparsers(dest="chat_command")
    p_sess = chat_sub.add_parser("list", help="List sessions (most recent first).")
    p_sess.add_argument("--account-dir", required=True)
    p_sess.add_argument("--query", default="", help="Filter by name / username / summary.")
    p_sess.add_argument("--limit", type=int, default=40)
    p_cons = chat_sub.add_parser("contacts", help="List contacts.")
    p_cons.add_argument("--account-dir", required=True)
    p_cons.add_argument("--query", default="")
    p_cons.add_argument("--limit", type=int, default=40)
    p_read = chat_sub.add_parser("read", help="Read the most recent messages of one chat.")
    p_read.add_argument("--account-dir", required=True)
    p_read.add_argument("username", help="Chat username (wxid_xxx / xxx@chatroom).")
    p_read.add_argument("--limit", type=int, default=30)
    p_read.add_argument("--before", default=None, help="Older page cursor as 'create_time,local_id'.")

    exp = sub.add_parser("export", help="Export one chat to txt/json/html.")
    exp.add_argument("--account-dir", required=True)
    exp.add_argument("--user", default=None, help="Exact chat username.")
    exp.add_argument("--query", default="", help="Resolve chat by name/username substring.")
    exp.add_argument("--format", choices=("txt", "json", "html"), default="txt")
    exp.add_argument("--out", default=None, help="Output file (default: <exports>/<stamp>__<name>.<fmt>).")
    exp.add_argument("--media", action="store_true",
                     help="Include media: HTML writes an <xxx>_assets folder with images/voices/videos; "
                          "txt/json annotate each media message with availability.")
    exp.add_argument("--since", default=None,
                     help="Incremental cursor 'create_time,local_id' (exclusive): export only messages "
                          "newer than it. JSON output echoes the next cursor as meta.next_since.")

    web = sub.add_parser("webui", help="Launch the guided Web UI (opens the browser).")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8714)
    web.add_argument("--no-browser", action="store_true", help="Do not auto-open a browser tab.")

    return parser


# ---------------------------------------------------------------- commands
def cmd_doctor(_args) -> int:
    print(f"{PROG} doctor")
    ok_all = True

    def check(name: str, ok: bool, detail: str) -> None:
        nonlocal ok_all
        ok_all = ok_all and ok
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: {detail}")

    try:
        import frida  # noqa: F401

        check("frida", True, f"frida {frida.__version__}")
    except Exception as exc:
        check("frida", False, f"not importable: {exc}")

    exe = wechat_state.find_weixin_exe()
    check("weixin-exe", exe is not None, str(exe) if exe else "not found (WeChat may not be installed)")
    versions = wechat_state.installed_wechat_versions() if exe else []
    check("weixin-versions", bool(versions), ", ".join(v for v, _ in versions) or "none")
    for ver, dll in versions[:3]:
        anchors = version_map.resolve_anchors(ver)
        check(
            f"anchors[{ver}]",
            anchors is not None,
            f"entry=0x{anchors.entry:X} mmv1=0x{anchors.mmv1_ref:X} magic=0x{anchors.magic_check:X}"
            if anchors
            else "not registered — run `keyagent locate`",
        )
    try:
        keys_dir().mkdir(parents=True, exist_ok=True)
        probe = keys_dir() / ".probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        check("keystore-dir", True, str(keys_dir()))
    except OSError as exc:
        check("keystore-dir", False, str(exc))
    print(f"\nsummary: {'ALL OK' if ok_all else 'ISSUES FOUND'}")
    return ERR_OK if ok_all else 1


def _resolve_account_id(account_dir: str) -> tuple[str, Path]:
    account = resolve_account(Path(account_dir))
    return account.account_id, account.message_db


def cmd_key_status(_args) -> int:
    rows = keystore.list_keys()
    if not rows:
        print("no stored keys")
        return ERR_OK
    print(f"{len(rows)} stored key(s) in {keys_dir()}:")
    for account_id, version, captured_at in rows:
        info = keystore.load_key(account_id, version)
        expired = keystore.is_expired(info)
        when = datetime.fromtimestamp(captured_at).strftime("%Y-%m-%d %H:%M")
        print(f"  {account_id:30s} v{version or '?':12s} fp={info.fingerprint}  source={info.source}  "
              f"captured={when}  {'EXPIRED' if expired else 'ok'}")
    return ERR_OK


def cmd_key_store(args) -> int:
    account_id, message_db = _resolve_account_id(args.account_dir)
    password = bytes.fromhex(args.hex_password)
    if len(password) != 32:
        print(f"error: expected 32 bytes (64 hex chars), got {len(password)}", file=sys.stderr)
        return 9
    ok, detail = test_key_against_db(password, message_db)
    if not ok:
        print(f"error: key does not validate against {message_db.name}: {detail}", file=sys.stderr)
        return 9
    from .models import KeyInfo

    info = KeyInfo(
        account_id=account_id,
        wechat_version=args.version or "manual",
        password=password,
        source="manual",
        verified=True,
    )
    target = keystore.key_file(info.account_id, info.wechat_version)
    if target.exists() and not args.force:
        print(f"error: key already stored for {account_id} (v{args.version or 'manual'}); use --force",
              file=sys.stderr)
        return 9
    keystore.store_key(info)
    print(f"stored key for {account_id} (fp={info.fingerprint}) -> {target}")
    return ERR_OK


def cmd_key_test(args) -> int:
    account_id, message_db = _resolve_account_id(args.account_dir)
    if args.hex_password:
        password = bytes.fromhex(args.hex_password)
        ok, detail = test_key_against_db(password, message_db)
    else:
        info = keystore.load_key(account_id)
        if keystore.is_expired(info):
            print(f"note: stored key is older than 24h; re-capture recommended", file=sys.stderr)
        ok, detail = test_key_against_db(info.password, message_db)
    print(f"account {account_id}: {'OK — ' + detail if ok else 'FAIL — ' + detail}")
    return ERR_OK if ok else 9


def cmd_key_forget(args) -> int:
    account_id, _ = _resolve_account_id(args.account_dir)
    removed = keystore.delete_key(account_id)
    print(f"{'removed' if removed else 'no key found'} for {account_id}")
    return ERR_OK


def _pick_weixin_exe(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    exe = wechat_state.find_weixin_exe()
    if exe is None:
        raise KeyagentError(4, "Weixin.exe not found; pass --weixin-exe explicitly")
    return exe


def cmd_keyagent_run(args) -> int:
    if wechat_state.is_weixin_running():
        print(
            "error: WeChat is currently running. For automatic capture it must be fully closed "
            "(a normal open/sign-in then tray-exit first keeps auto-login working). "
            "Alternatively import a known key with `key store`.",
            file=sys.stderr,
        )
        return 4
    account_id, message_db = _resolve_account_id(args.account_dir)
    exe = _pick_weixin_exe(args.weixin_exe)

    # resolve anchors: version registry or auto-locate on first use
    versions = wechat_state.installed_wechat_versions()
    if exe is not None:
        versions = [v for v in versions if v[1].parent.parent == exe.parent]
    anchors: AnchorSet | None = None
    dll_path: Path | None = None
    for ver, dll in versions:
        if dll.name == "Weixin.dll":
            anchors = version_map.resolve_anchors(ver)
            dll_path = dll
            if anchors:
                break
    if anchors is None and dll_path is None and args.weixin_exe:
        dll_path = args.weixin_exe.with_name("Weixin.dll")
        if not dll_path.exists():
            dll_path = Path(args.weixin_exe).parent.parent / "Weixin.dll"
    if anchors is None and dll_path is not None and dll_path.exists():
        print(f"locating anchors in {dll_path} ...", file=sys.stderr)
        try:
            anchors = locate_anchors(dll_path)
            version_map.save_anchor_cache([anchors])
        except LocateError as exc:
            raise KeyagentError(3, f"anchor auto-locate failed: {exc}") from exc
    if anchors is None:
        raise KeyagentError(3, "no registered anchors for installed WeChat version; run `keyagent locate`")

    def progress(stage: str, payload=None):
        if stage in ("spawned", "module-loaded"):
            print(f"[{stage}] {payload}")
        elif stage == "armed":
            print(f"[armed] {payload}")
        elif stage == "key-found":
            print(f"[key-found] {payload}")

    print(f"capturing key for account {account_id} (WeChat {anchors.wechat_version}) ...")
    outcome = capture_key(
        exe,
        anchors,
        message_db,
        account_id=account_id,
        observe_ms=args.observe_ms,
        progress=progress,
    )
    key = outcome.key
    assert key is not None
    print(f"captured key: fp={key.fingerprint}  variant={key.variant}")
    if args.store:
        target = keystore.store_key(key)
        print(f"stored -> {target}")
    else:
        print("(not stored; re-run with --store to keep it)")
    return ERR_OK


def cmd_keyagent_locate(args) -> int:
    version = args.version or Path(args.weixin_dll).parent.name
    try:
        anchors = locate_anchors(Path(args.weixin_dll), wechat_version=version)
    except LocateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    version_map.save_anchor_cache([anchors])
    print(f"located anchors for WeChat {version}:")
    print(f"  entry       = 0x{anchors.entry:X}")
    print(f"  mmv1_ref    = 0x{anchors.mmv1_ref:X}")
    print(f"  magic_check = 0x{anchors.magic_check:X}")
    print("cached to", version_map.anchor_cache_path())
    return ERR_OK


def _loaded_key_for(account: Account):
    """Stored key for an account (any version tag). Raises KeyagentError(9) when absent."""
    try:
        return keystore.load_key(account.account_id)
    except KeyagentError as exc:
        raise KeyagentError(
            9,
            f"no stored key for {account.account_id} — run `keyagent run --store` or `key store` first "
            f"({exc})",
        ) from exc


def _decrypted_root(account_id: str, override: str | None) -> Path:
    if override:
        return Path(override)
    return account_decrypted_dir(account_id)


def cmd_data_status(args) -> int:
    account = resolve_account(Path(args.account_dir))
    print(f"account: {account.account_id}")
    print(f"  dir : {account.account_dir}")
    try:
        info = keystore.load_key(account.account_id)
        when = datetime.fromtimestamp(info.captured_at).strftime("%Y-%m-%d %H:%M")
        expired = keystore.is_expired(info)
        print(f"  key : v{info.wechat_version or '?'} fp={info.fingerprint} captured={when} "
              f"{'EXPIRED (>24h)' if expired else 'ok'}")
    except KeyagentError as exc:
        print(f"  key : MISSING ({exc})")
        return 9
    svc = DecryptService(account.account_dir / "db_storage", info.password, _decrypted_root(account.account_id, None))
    status = svc.status()
    print(f"  dbs : {status['ready']}/{status['total']} decrypted")
    for row in status["dbs"]:
        mark = "ok " if row["ready"] else "-- "
        print(f"    {mark}{row['name']:<45s} {row['size'] / 1e6:7.1f}MB")
    return ERR_OK


def cmd_data_decrypt(args) -> int:
    account = resolve_account(Path(args.account_dir))
    info = _loaded_key_for(account)
    if keystore.is_expired(info):
        print(f"note: stored key is older than 24h; HMAC may still pass but re-capture is recommended",
              file=sys.stderr)
    out = _decrypted_root(account.account_id, args.root)
    svc = DecryptService(account.account_dir / "db_storage", info.password, out)

    def progress(phase: str, name: str, detail: str) -> None:
        if phase == "decrypt":
            print(f"  decrypt {name} ...", flush=True)
        elif phase == "ok":
            print(f"  ok      {name}  ({detail})", flush=True)
        elif phase == "skip":
            print(f"  skip    {name}  ({detail})", flush=True)
        elif phase == "fail":
            print(f"  FAIL    {name}: {detail}", file=sys.stderr)

    report = svc.run(progress=progress, incremental=not args.force)
    print(f"\nresult: {report.decrypted} decrypted, {report.skipped} fresh, "
          f"{len(report.failed)} failed of {report.discovered} DBs -> {out}")
    if report.failed:
        for name, detail in report.failed:
            print(f"  failed {name}: {detail}", file=sys.stderr)
        return 10
    return ERR_OK


def _ensure_decrypted(account: Account, out_root: str | None, quiet: bool = False) -> Path:
    """Decrypt incrementally when needed; returns the decrypted tree root."""
    out = _decrypted_root(account.account_id, out_root)
    probe = DecryptService(account.account_dir / "db_storage", b"", out)
    status = probe.status()
    if status["ready"] >= status["total"]:
        return out
    info = _loaded_key_for(account)
    report = DecryptService(account.account_dir / "db_storage", info.password, out).run(
        progress=None if quiet else (lambda phase, name, detail: None)
    )
    if report.failed:
        raise KeyagentError(10, f"{len(report.failed)} DB(s) failed to decrypt: "
                                f"{', '.join(n for n, _ in report.failed[:5])}")
    return out


def _open_db(args) -> tuple[Account, DatabaseService]:
    account = resolve_account(Path(args.account_dir))
    out = _ensure_decrypted(account, getattr(args, "root", None))
    return account, DatabaseService(account.account_id, out)


def cmd_chat_list(args) -> int:
    account, db = _open_db(args)
    sessions = db.sessions(query=args.query or None, limit=args.limit)
    print(f"{len(sessions)} session(s) for {account.account_id}:\n")
    for s in sessions:
        when = datetime.fromtimestamp(s.last_timestamp).strftime("%Y-%m-%d %H:%M") if s.last_timestamp else "-"
        summary = (s.summary or "").replace("\n", " ")[:60]
        print(f"{s.display_name[:22]:24s} {when:17s} u{s.unread_count:<3d} {summary}")
        print(f"    {s.username}")
    return ERR_OK


def cmd_chat_contacts(args) -> int:
    account, db = _open_db(args)
    contacts = db.contacts(query=args.query or None, limit=args.limit)
    print(f"{len(contacts)} contact(s) for {account.account_id}:")
    for c in contacts:
        print(f"  {c.display_name[:24]:26s} {c.username}")
    return ERR_OK


def cmd_chat_read(args) -> int:
    account, db = _open_db(args)
    before = None
    if args.before:
        try:
            ct_s, lid_s = args.before.split(",")
            before = (int(ct_s), int(lid_s))
        except ValueError:
            print("error: --before must look like '1720000000,123'", file=sys.stderr)
            return 9
    page = db.chat(args.username, limit=args.limit, before=before)
    if not page.messages:
        print(f"no messages for {args.username}")
        return ERR_OK
    print(f"{page.contact.display_name} ({args.username}) — newest {len(page.messages)}"
          f"{'+, older available' if page.has_more else ''}:")
    for m in reversed(page.messages):
        who = "me" if m.is_outgoing else m.sender
        when = datetime.fromtimestamp(m.create_time).strftime("%m-%d %H:%M")
        tag = f"[{m.display_type}] " if m.display_type != "text" else ""
        print(f"  {when} {who[:14]:16s} {tag}{m.text[:140]}")
    if page.has_more:
        oldest = page.messages[0]
        print(f"\nolder messages: chattrace chat read --account-dir \"{args.account_dir}\" "
              f"{args.username} --before {oldest.create_time},{oldest.local_id}")
    return ERR_OK


def _resolve_chat_username(db: DatabaseService, user: str | None, query: str) -> str:
    if user:
        if db.contact(user) is not None or db.session(user):
            return user
        raise KeyagentError(8, f"chat not found: {user}")
    if query:
        hits = [s for s in db.sessions(limit=400) if query.lower() in s.search_blob]
        if len(hits) == 1:
            return hits[0].username
        if len(hits) > 1:
            raise KeyagentError(8, f"ambiguous query {query!r}; pass --user with the exact username")
        c_hits = db.contacts(query=query, limit=2)
        if len(c_hits) == 1:
            return c_hits[0].username
        raise KeyagentError(8, f"no chat matched query {query!r}")
    raise KeyagentError(8, "need --user or --query")


def _parse_cursor(value: str | None, flag: str) -> tuple[int, int] | None:
    """Parse a 'create_time,local_id' keyset cursor from the CLI."""
    if not value:
        return None
    try:
        ct_s, lid_s = value.split(",")
        return (int(ct_s), int(lid_s))
    except ValueError:
        print(f"error: {flag} must look like '1720000000,123'", file=sys.stderr)
        raise SystemExit(9)


def cmd_export(args) -> int:
    account, db = _open_db(args)
    username = _resolve_chat_username(db, args.user, args.query)
    contact = db.contact(username)
    display = contact.display_name if contact else username
    since = _parse_cursor(args.since, "--since")
    print(f"exporting {display} ({username}) -> {args.format} "
          f"({'incremental since ' + args.since if since else 'full'}) ...")
    total = db.count_messages(username) or 0
    media_svc = None
    if args.media:
        from .service.media import MediaService

        dec_root = _decrypted_root(account.account_id, None)
        media_svc = MediaService(
            account.account_id, account.account_dir, dec_root,
            config.account_work_dir(account.account_id) / "media_cache",
        )

    def progress(done: int, _total: int | None) -> None:
        print(f"\r  {done}/{total}", end="", flush=True)

    try:
        outcome = ChatExportService(db, account_exports_dir(account.account_id)).export(
            username, args.format, progress=progress, output_path=Path(args.out) if args.out else None,
            include_media=args.media, media=media_svc, since=since,
        )
    except Exception as exc:
        raise KeyagentError(10, f"export failed: {exc}") from exc
    print()
    print(f"exported {outcome.message_count} messages -> {outcome.output_path}")
    if args.media and args.format == "html":
        assets = outcome.output_path.parent / (outcome.output_path.stem + "_assets")
        if assets.is_dir():
            print(f"media assets   -> {assets}/")
    return ERR_OK


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "key":
            if args.key_command == "status":
                return cmd_key_status(args)
            if args.key_command == "store":
                return cmd_key_store(args)
            if args.key_command == "test":
                return cmd_key_test(args)
            if args.key_command == "forget":
                return cmd_key_forget(args)
            parser.parse_args(["key", "--help"])
            return 1
        if args.command == "keyagent":
            if args.keyagent_command == "run":
                return cmd_keyagent_run(args)
            if args.keyagent_command == "locate":
                return cmd_keyagent_locate(args)
            parser.parse_args(["keyagent", "--help"])
            return 1
        if args.command == "data":
            if args.data_command == "status":
                return cmd_data_status(args)
            if args.data_command == "decrypt":
                return cmd_data_decrypt(args)
            parser.parse_args(["data", "--help"])
            return 1
        if args.command == "chat":
            if args.chat_command == "list":
                return cmd_chat_list(args)
            if args.chat_command == "contacts":
                return cmd_chat_contacts(args)
            if args.chat_command == "read":
                return cmd_chat_read(args)
            parser.parse_args(["chat", "--help"])
            return 1
        if args.command == "export":
            return cmd_export(args)
        if args.command == "webui":
            from .webui.server import main as webui_main

            return webui_main(
                ["--host", args.host, "--port", str(args.port)] + (["--no-browser"] if args.no_browser else [])
            )
        parser.print_help()
        return 1
    except (KeyagentError, FileNotFoundError, ValueError) as exc:
        code = exc.code if isinstance(exc, KeyagentError) else 8
        print(f"error: {exc}", file=sys.stderr)
        return code


if __name__ == "__main__":
    raise SystemExit(main())
