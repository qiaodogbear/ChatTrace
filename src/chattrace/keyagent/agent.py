"""Frida spawn capture engine: hook codec anchors, validate candidates live, clean up.

Design notes (from 2026-09-03 end-to-end validation on WeChat 4.1.12.55):
- Weixin.dll is NOT a static import: poll module load after resume, then arm hooks.
- Interceptor.onEnter receives `args`; registers must be read via `this.context.rcx`.
- The codec-config entry receives a structure whose first 32 bytes are the master key.
- Every candidate is HMAC-checked against the *current* account DB header before
  acceptance (guards against transitional/stale keys). Observed working variant is
  PBKDF2-SHA512(db_salt, 256000) / little-endian page numbers.
- Only processes spawned by this engine are ever killed.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import frida

from ..config import (
    ERR_CLEANUP,
    ERR_FRIDA,
    ERR_LOGIN_TIMEOUT,
    ERR_NO_VALID_KEY,
    ERR_WECHAT_CRASH,
    ERR_NO_WEIXIN,
    KeyagentError,
)
from ..models import AnchorSet, KeyInfo
from . import verify

ProgressFn = Callable[[str, object], None]


def _noop_progress(stage: str, payload: object = None) -> None:
    pass


JS_TEMPLATE = r"""
function snapshot(label, ctx) {
  if ((fireCount[label] || 0) >= 10) return;
  fireCount[label] = (fireCount[label] || 0) + 1;
  var regs = { rcx: ctx.rcx, rdx: ctx.rdx, r8: ctx.r8, r9: ctx.r9 };
  var out = {t:'hit', label:label, n:fireCount[label], regs:{}};
  Object.keys(regs).forEach(function(r){ out.regs[r] = regs[r].toString(16); });
  [['rcx',0x100],['rdx',0x80],['r8',0x40],['r9',0x40]].forEach(function(p){
    var ptr = regs[p[0]];
    if (ptr.isNull()) return;
    try { out[p[0]] = Array.prototype.slice.call(new Uint8Array(ptr.readByteArray(p[1]))); } catch(e){}
  });
  send(out);
}
var fireCount = {}, armed = false, armedAll = false;
var offsets = { 'entry': 0x%X, 'mmv1_ref': 0x%X, 'magic_check': 0x%X };
function tryArm() {
  if (armed) return;
  var m = Process.findModuleByName('Weixin.dll');
  if (!m) return;
  send({t:'module', base: m.base.toString(), size: m.size.toString(16)});
  var ok = 0, fail = 0;
  Object.keys(offsets).forEach(function(label){
    try {
      Interceptor.attach(m.base.add(offsets[label]), { onEnter: function (a) { snapshot(label, this.context); } });
      ok++; send({t:'armed', label:label, at: m.base.add(offsets[label]).toString()});
    } catch(e){ fail++; send({t:'armfail', label:label, err:String(e)}); }
  });
  armed = true;
  armedAll = (fail === 0);
  send({t:'armdone', ok: ok, fail: fail});
}
var tries = 0;
setInterval(function(){ tryArm(); if (armed || (++tries > 60000)) clearInterval(); }, 1);
"""


@dataclass
class CaptureStats:
    hook_fires: dict[str, int] = field(default_factory=dict)
    dumps: int = 0
    candidates_tried: int = 0
    events: list[str] = field(default_factory=list)


@dataclass
class CaptureOutcome:
    key: KeyInfo | None
    stats: CaptureStats
    weixin_pid: int | None = None


def _fresh_header(db_path: Path):
    """Read DB header at check time (Weixin may be writing; shared read is fine)."""
    return verify.read_db_header(db_path)


def _verify_live(password: bytes, db_path: Path) -> bool:
    try:
        header = _fresh_header(db_path)
    except (OSError, ValueError):
        return False
    ok, _ = verify.verify_hmac_sweep(password, header)
    return ok


def _kill_tree(pid: int, progress: ProgressFn) -> None:
    """Kill a process tree by PID via taskkill /T /F. Only ever called on self-spawned pids."""
    if pid <= 0:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            timeout=20,
            check=False,
        )
        progress("cleanup", f"killed spawned tree root {pid}")
    except Exception as exc:
        progress("cleanup", f"taskkill failed: {exc}")


def capture_key(
    weixin_exe: Path,
    anchors: AnchorSet,
    account_db: Path,
    *,
    account_id: str,
    observe_ms: int = 120_000,
    progress: ProgressFn | None = None,
) -> CaptureOutcome:
    progress = progress or _noop_progress
    stats = CaptureStats()
    if not Path(weixin_exe).exists():
        raise KeyagentError(ERR_NO_WEIXIN, f"Weixin.exe not found: {weixin_exe}")
    if not Path(account_db).exists():
        raise KeyagentError(ERR_NO_WEIXIN, f"account database not found: {account_db}")

    pid: int | None = None
    session = None
    script = None
    try:
        try:
            pid = frida.spawn(str(weixin_exe))
        except Exception as exc:
            raise KeyagentError(ERR_FRIDA, f"frida.spawn failed: {exc}") from exc
        stats.weixin_pid = pid
        progress("spawned", pid)
        session = frida.attach(pid)

        found_key: KeyInfo | None = None
        started_at = time.time()

        def on_message(message, data):
            nonlocal found_key
            if message["type"] == "error":
                stats.events.append(f"js-error: {str(message.get('stack') or message.get('description'))[:300]}")
                return
            payload = message.get("payload")
            if not isinstance(payload, dict):
                return
            kind = payload.get("t")
            if kind == "module":
                progress("module-loaded", payload["base"])
            elif kind == "armed":
                progress("armed", payload["label"])
            elif kind == "armdone":
                progress("arm-done", payload)
            elif kind == "hit":
                label = payload["label"]
                stats.hook_fires[label] = stats.hook_fires.get(label, 0) + 1
                stats.dumps += 1
                blob = payload.get("rcx")
                if found_key is None and blob:
                    stats.candidates_tried += 1
                    candidates = [bytes(blob[:32])]
                    # sliding windows inside the rcx dump as fallback
                    for off in range(0, min(len(blob), 0x80) - 31, 8):
                        candidates.append(bytes(blob[off : off + 32]))
                    for idx, cand in enumerate(candidates):
                        if found_key is not None:
                            break
                        if _verify_live(cand, Path(account_db)):
                            found_key = KeyInfo(
                                account_id=account_id,
                                wechat_version=anchors.wechat_version,
                                password=cand,
                                source="frida-keyagent",
                                variant="pbkdf2-sha512-256000/dbsalt/le",
                                verified=True,
                            )
                            progress("key-found", f"validated key after {stats.candidates_tried} candidate(s)")
                            stats.candidates_tried += idx

        js = JS_TEMPLATE % (anchors.entry, anchors.mmv1_ref, anchors.magic_check)
        script = session.create_script(js)
        script.on("message", on_message)
        script.load()
        progress("resumed", "")
        frida.resume(pid)

        deadline = time.time() + observe_ms / 1000.0
        while time.time() < deadline:
            if found_key is not None:
                break
            time.sleep(0.25)

        if found_key is None:
            if stats.hook_fires:
                raise KeyagentError(
                    ERR_NO_VALID_KEY,
                    f"{len(stats.hook_fires)} hook points fired but no candidate passed HMAC "
                    f"(tried {stats.candidates_tried}); DB may be mid-migration — retry after a normal "
                    "WeChat sign-in/out cycle, or import the key manually with `key store`.",
                )
            raise KeyagentError(
                ERR_LOGIN_TIMEOUT,
                "no codec activity observed — spawned WeChat did not auto-login. "
                "Open WeChat normally, sign in, then exit from the tray, and retry.",
            )
        return CaptureOutcome(key=found_key, stats=stats, weixin_pid=pid)
    except KeyagentError:
        raise
    except frida.ProcessNotFoundError as exc:
        raise KeyagentError(ERR_WECHAT_CRASH, f"WeChat process disappeared during capture: {exc}") from exc
    except Exception as exc:
        # WeChat dying mid-capture surfaces as generic frida errors; keep diagnostics small.
        msg = str(exc)
        low = msg.lower()
        if "process" in low and ("terminated" in low or "gone" in low or "not found" in low):
            raise KeyagentError(ERR_WECHAT_CRASH, f"WeChat crashed during capture: {exc}") from exc
        raise
    finally:
        # ---- deterministic cleanup of ONLY our own spawn ----
        try:
            if script is not None:
                script.unload()
        except Exception:
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        if pid:
            try:
                frida.get_local_device().kill(pid)
            except Exception:
                pass
            time.sleep(1.5)
            _kill_tree(pid, progress)
