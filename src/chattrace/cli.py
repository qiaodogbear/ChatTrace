"""ChatTrace CLI (M1: KeyAgent workflows)."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .config import ERR_OK, KeyagentError, keys_dir, logs_dir
from .keyagent import keystore, wechat_state, version_map
from .keyagent.account import resolve_account
from .keyagent.agent import capture_key
from .keyagent.locate_anchors import LocateError, locate_anchors
from .keyagent.verify import test_key_against_db
from .models import AnchorSet

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


def main(argv: list[str] | None = None) -> int:
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
        parser.print_help()
        return 1
    except (KeyagentError, FileNotFoundError, ValueError) as exc:
        code = exc.code if isinstance(exc, KeyagentError) else 8
        print(f"error: {exc}", file=sys.stderr)
        return code


if __name__ == "__main__":
    raise SystemExit(main())
