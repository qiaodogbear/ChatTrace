"""Phase A: read-only frida attach probe against running Weixin.exe main process.
Checks: attach works (anti-debug), Weixin.dll base, anchor bytes match static analysis,
hooks at the two MMV1 anchors fire within a short observation window (likely not for an
already-initialized process, but zero-risk to check)."""
import sys
import time

import frida

ANCHOR_A = 0x353BC99  # lea rcx,[MMV1 str]
ANCHOR_B = 0x7050502  # cmp dword ptr [rcx], 'MMV1'

JS = r"""
function dumpRegs(ctx) {
  return {
    rcx: ctx.rcx.toString(16),
    rdx: ctx.rdx.toString(16),
    r8:  ctx.r8.toString(16),
    r9:  ctx.r9.toString(16),
    r10: ctx.r10.toString(16),
    r11: ctx.r11.toString(16),
    r15: ctx.r15.toString(16),
  };
}
function tryDumpMem(addr, n, label) {
  try {
    const bytes = addr.readByteArray(n);
    send(label + ' mem@' + addr + ': ' + hexdump(bytes, {length: n, ansi: false}));
  } catch (e) { send(label + ' read fail: ' + e); }
}
rpc.exports = {};
"""


def main():
    target = None
    # find main Weixin.exe: executable path == install dir, no --type in cmdline
    devices = frida.enumerate_devices()
    dev = frida.get_local_device()
    procs = dev.enumerate_processes()
    for p in procs:
        if p.name.lower() == "weixin.exe":
            target = p.pid
            break
    if not target:
        print("no running Weixin.exe found")
        return 1
    print(f"attaching to pid {target}")
    try:
        session = dev.attach(target)
    except Exception as exc:
        print(f"ATTACH FAILED: {exc}")
        return 2

    script = session.create_script(
        JS
        + r"""
var m = Process.getModuleByName('Weixin.dll');
send('module base=' + m.base + ' size=0x' + m.size.toString(16));
var aA = m.base.add(0x%X);
var aB = m.base.add(0x%X);
send('A @ ' + aA);
send('B @ ' + aB);
try {
  send('A bytes: ' + aA.readByteArray(16).then ? '' : hexdump(aA.readByteArray(16), {length:16, ansi:false}));
} catch (e) { send('A read fail: ' + e); }
try {
  send('B bytes: ' + hexdump(aB.readByteArray(16), {length:16, ansi:false}));
} catch (e) { send('B read fail: ' + e); }
var fired = 0;
function arm(addr, label) {
  try {
    Interceptor.attach(addr, {
      onEnter: function (ctx) {
        fired++;
        send('HIT ' + label + ' ' + JSON.stringify(dumpRegs(ctx)));
        tryDumpMem(ctx.rcx, 0x100, label + ' [rcx]');
        tryDumpMem(ctx.rdx, 0x40, label + ' [rdx]');
      }
    });
    send('armed ' + label);
  } catch (e) { send('arm ' + label + ' failed: ' + e); }
}
arm(aA, 'A');
arm(aB, 'B');
"""
        % (ANCHOR_A, ANCHOR_B)
    )
    script.on("message", lambda message, data: print("[JS]", message.get("payload", message)))
    script.load()
    print("waiting 15s for hook fires (already-initialized process usually stays quiet)...")
    time.sleep(15)
    try:
        script.post({})
    except Exception:
        pass
    session.detach()
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
