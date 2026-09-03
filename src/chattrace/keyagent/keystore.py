"""DPAPI-protected persistence for validated keys (Windows CurrentUser scope)."""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import tempfile
import time
from pathlib import Path

from ..config import KeyagentError, ERR_KEY_STORE, keys_dir
from ..models import KeyInfo

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4


def _blob_to_bytes(data_in: bytes) -> bytes:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buffer_in = ctypes.create_string_buffer(data_in, len(data_in))
    blob_in = DATA_BLOB(len(data_in), ctypes.cast(buffer_in, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "ChatTraceKey",
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _bytes_from_blob(data: bytes) -> bytes:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buffer_in = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buffer_in, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def key_file(account_id: str, wechat_version: str = "") -> Path:
    tag = wechat_version if wechat_version else "unknown-version"
    safe_account = "".join(c if c.isalnum() or c in "-_" else "_" for c in account_id) or "account"
    return keys_dir() / f"{safe_account}@{tag}.keyinfo"


def _restrict_file_acls(path: Path) -> None:
    """Best-effort: restrict to current user via icacls; never fatal."""
    try:
        user = os.environ.get("USERNAME")
        if not user:
            return
        import subprocess

        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass


def store_key(info: KeyInfo) -> Path:
    target = key_file(info.account_id, info.wechat_version)
    payload = {
        "account_id": info.account_id,
        "wechat_version": info.wechat_version,
        "password_b64": __import__("base64").b64encode(info.password).decode("ascii"),
        "captured_at": info.captured_at,
        "source": info.source,
        "variant": info.variant,
        "verified": info.verified,
    }
    cipher = _blob_to_bytes(json.dumps(payload).encode("utf-8"))
    # atomic write
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".key-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(cipher)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    _restrict_file_acls(target)
    return target


def _find_any_for_account(account_id: str) -> Path | None:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in account_id)
    matches = sorted(keys_dir().glob(f"{safe}@*.keyinfo"), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def load_key(account_id: str, wechat_version: str = "") -> KeyInfo:
    target = key_file(account_id, wechat_version)
    if not target.exists():
        target = _find_any_for_account(account_id)
    if target is None:
        raise KeyagentError(ERR_KEY_STORE, f"no stored key for {account_id}")
    try:
        return load_key_from_file(target)
    except KeyagentError:
        raise
    except Exception as exc:
        raise KeyagentError(ERR_KEY_STORE, f"failed to decrypt key file {target}: {exc}") from exc


def list_keys() -> list[tuple[str, str, float]]:
    """Return (account_id, wechat_version, captured_at) for stored keys."""
    out: list[tuple[str, str, float]] = []
    for path in sorted(keys_dir().glob("*.keyinfo")):
        try:
            info = load_key_from_file(path)
        except Exception:
            continue
        out.append((info.account_id, info.wechat_version, info.captured_at))
    return out


def load_key_from_file(path: Path) -> KeyInfo:
    plain = _bytes_from_blob(Path(path).read_bytes())
    payload = json.loads(plain.decode("utf-8"))
    import base64

    return KeyInfo(
        account_id=payload["account_id"],
        wechat_version=payload.get("wechat_version", ""),
        password=base64.b64decode(payload["password_b64"]),
        captured_at=float(payload.get("captured_at", 0)),
        source=payload.get("source", "unknown"),
        variant=payload.get("variant", ""),
        verified=bool(payload.get("verified", True)),
    )


def delete_key(account_id: str, wechat_version: str = "") -> bool:
    target = key_file(account_id, wechat_version)
    if not target.exists():
        target = _find_any_for_account(account_id)
    if target is None:
        return False
    target.unlink()
    return True


def is_expired(info: KeyInfo, ttl: float = 24 * 3600) -> bool:
    return (time.time() - info.captured_at) > ttl
