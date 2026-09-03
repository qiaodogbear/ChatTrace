"""Minimal probe: which CpuContext register accesses are legal in this frida build (Windows x64)."""
import sys
import time

import frida

JS = r"""
var names = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15'];
function hookExport(mod, exp) {
  try {
    var m = Process.getModuleByName(mod);
    var a = m.getExportByName(exp);
    Interceptor.attach(a, {
      onEnter: function (args) {
        var ctx = this.context;
        var report = {at: mod + '!' + exp};
        names.forEach(function (n) {
          try { var v = ctx[n]; report[n] = 'ok:' + v.toString(16); }
          catch (e) { report[n] = 'ERR:' + e; }
        });
        send(report);
      }
    });
    send('armed ' + mod + '!' + exp);
  } catch (e) { send('armfail ' + mod + '!' + exp + ': ' + e); }
}
hookExport('kernel32.dll', 'GetTickCount');
hookExport('kernel32.dll', 'LoadLibraryW');
hookExport('ntdll.dll', 'NtDelayExecution');
hookExport('ntdll.dll', 'RtlUserThreadStart');
"""


def main():
    pid = frida.spawn(r"C:\Windows\System32\notepad.exe")
    session = frida.attach(pid)
    script = session.create_script(JS)
    fired = {"n": 0}

    def on_message(message, data):
        if message["type"] == "send":
            fired["n"] += 1
            print("regs:", message["payload"])
        else:
            print("ERR", message)

    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    deadline = time.time() + 6
    while time.time() < deadline and fired["n"] < 2:
        time.sleep(0.1)
    print("fires:", fired["n"])
    try:
        frida.get_local_device().kill(pid)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
