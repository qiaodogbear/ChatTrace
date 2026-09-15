"""Spawn capture v3: long window, full dumps to disk, verify password against DB header
snapshots taken (a) at hit time while Weixin runs, (b) after force-kill."""
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

import frida

WEIXIN_EXE = os.environ.get("CHATTRACE_WEIXIN_EXE", r"C:\Program Files\Weixin\Weixin.exe")
MSG0_DB = os.environ.get(
    "CHATTRACE_MSG0_DB",
    r"D:\Users\demo\Documents\xwechat_files\wxid_demo0000_1234\db_storage\message\message_0.db",
)
ENTRY_A = 0x353BC60
ANCHOR_A = 0x353BC99
ANCHOR_B = 0x7050502
PAGE = 4096
OUT = Path(os.environ["TEMP"]) / "wx_hits.jsonl"


def db_pages():
    with open(MSG0_DB, "rb") as fp:
        head = fp.read(16384)
    salt = head[:16]
    p1 = head[16:4096]
    p2 = head[4096:8192]
    return salt, [p1, p2], hashlib.sha256(head).hexdigest()


def verify(password, salt, pages):
    for little in (True, False):
        enc = hashlib.pbkdf2_hmac("sha512", password, salt, 256000, dklen=32)
        mac_key = hashlib.pbkdf2_hmac("sha512", enc, bytes(b ^ 0x3A for b in salt), 2, dklen=32)
        for idx, page in enumerate(pages, start=1):
            if len(page) <= 80 or len(page) != PAGE - (16 if idx == 1 else 0):
                break
            body, actual = page[:-64], page[-64:]
            calc = hmac.new(mac_key, body, hashlib.sha512)
            calc.update(idx.to_bytes(4, "little" if little else "big"))
            if not hmac.compare_digest(calc.digest(), actual):
                break
        else:
            return True, enc.hex(), "le" if little else "be"
    return False, "", ""


JS = r"""
function snapshot(label, ctx) {
  if ((fireCount[label] || 0) >= 8) return;
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
var fireCount = {}, armed = false;
var offsets = { 'entryA': 0x%X, 'anchorA': 0x%X, 'anchorB': 0x%X };
function tryArm() {
  if (armed) return;
  var m = Process.findModuleByName('Weixin.dll');
  if (!m) return;
  send({t:'module', base: m.base.toString()});
  Object.keys(offsets).forEach(function(label){
    try { Interceptor.attach(m.base.add(offsets[label]), { onEnter: function (a) { snapshot(label, this.context); } });
          send({t:'armed', label:label}); }
    catch(e){ send({t:'armfail', label:label, err:String(e)}); }
  });
  armed = true; send({t:'armdone'});
}
var tries = 0;
setInterval(function(){ tryArm(); if (armed || (++tries > 60000)) clearInterval(); }, 1);
"""


def main():
    salt, pages, before_hash = db_pages()
    print(f"[v3] before_hash={before_hash[:16]} salt={salt.hex()[:12]}", flush=True)
    dumps: list[dict] = []
    password_found = {"pw": None, "at": None, "hash": None}
    wl = open(OUT, "w", encoding="utf-8")

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict) and payload.get("t") == "hit":
                dumps.append(payload)
                wl.write(json.dumps(payload) + "\n")
                wl.flush()
                rc = payload.get("rcx")
                if rc and password_found["pw"] is None:
                    cand = bytes(rc[:32])
                    ok, enc, endian = verify(cand, salt, pages)  # header read at script start
                    if ok:
                        password_found["pw"] = cand.hex()
                        password_found["at"] = payload["label"]
                        password_found["hash"] = before_hash
                        print(f"[v3] >>> INLINE HIT pw={cand.hex()}", flush=True)
            elif isinstance(payload, dict):
                print("[js]", payload, flush=True)
        else:
            print("[js-err]", (message.get("stack") or message.get("description"))[:400], flush=True)

    print("[v3] spawning...", flush=True)
    pid = frida.spawn(WEIXIN_EXE)
    print(f"[v3] pid={pid}", flush=True)
    session = frida.attach(pid)
    script = session.create_script(JS % (ENTRY_A, ANCHOR_A, ANCHOR_B))
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    print("[v3] resumed; observing 130s", flush=True)
    deadline = time.time() + 130
    while time.time() < deadline:
        time.sleep(0.5)

    _, _, running_hash = db_pages()
    print(f"[v3] running_hash={running_hash[:16]} changed={running_hash != before_hash}", flush=True)
    print(f"[v3] dumps={len(dumps)} inline={password_found['pw'] is not None}", flush=True)

    # offline sweep candidates from rcx windows against BEFORE-state pages
    tried = set()
    offline_hit = None
    if password_found["pw"] is None:
        for d in dumps:
            blob = d.get("rcx")
            if not blob:
                continue
            for off in range(0, min(len(blob), 0x100) - 31, 4):
                cand = bytes(blob[off : off + 32])
                if cand in tried:
                    continue
                tried.add(cand)
                ok, enc, endian = verify(cand, salt, pages)
                if ok:
                    offline_hit = (d["label"], off, cand.hex())
                    break
            if offline_hit:
                break
    if offline_hit:
        label, off, hexpw = offline_hit
        password_found["pw"] = hexpw
        password_found["at"] = f"{label}+{off:#x}"
        password_found["hash"] = before_hash
        print(f"[v3] >>> OFFLINE HIT {label} off={off:#x} pw={hexpw}", flush=True)
    print(f"[v3] swept {len(tried)} candidates", flush=True)

    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass
    try:
        frida.get_local_device().kill(pid)
    except Exception as exc:
        print("[v3] kill:", exc, flush=True)
    time.sleep(3)

    # post-kill verification
    _, _, killed_hash = db_pages()
    print(f"[v3] killed_hash={killed_hash[:16]} changed_vs_before={killed_hash != before_hash}", flush=True)
    if password_found["pw"]:
        pw = bytes.fromhex(password_found["pw"])
        salt_k, pages_k, _ = db_pages()
        ok, enc, endian = verify(pw, salt_k, pages_k)
        print(f"[v3] post-kill verify pw: {ok} ({endian})", flush=True)
        if ok:
            Path(os.environ["TEMP"] + "\\wx_password.bin").write_bytes(pw)
            print(f"[v3] >>> CONFIRMED post-kill; saved", flush=True)
    wl.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
