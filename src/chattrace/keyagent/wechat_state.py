"""WeChat process / install / login-state probes (read-only)."""
from __future__ import annotations

import os
import re
from pathlib import Path

import frida

WEIXIN_PROCESS = "Weixin.exe"


def weixin_pids() -> list[int]:
    try:
        procs = frida.get_local_device().enumerate_processes()
    except Exception:
        return []
    return [p.pid for p in procs if p.name.lower() == WEIXIN_PROCESS.lower()]


def is_weixin_running() -> bool:
    return bool(weixin_pids())


def running_weixin_paths() -> list[Path]:
    """Executable paths of running Weixin.exe processes (main + helpers)."""
    out: list[Path] = []
    for pid in weixin_pids():
        try:
            import ctypes
            import ctypes.wintypes as wt

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                continue
            try:
                size = wt.DWORD(1024)
                buf = ctypes.create_unicode_buffer(size.value)
                ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
                out.append(Path(buf.value))
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            continue
    return out


def find_weixin_exe() -> Path | None:
    """Locate Weixin.exe: prefer a running instance, then registry, then common roots."""
    for path in running_weixin_paths():
        if path.name.lower() == WEIXIN_PROCESS.lower():
            return path
    try:
        import winreg

        for sub in (r"Software\Tencent\Weixin", r"Software\Tencent\xwechat"):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub) as key:
                    value, _ = winreg.QueryValueEx(key, "InstallPath")
                    cand = Path(value) / WEIXIN_PROCESS
                    if cand.exists():
                        return cand
            except OSError:
                continue
    except Exception:
        pass
    for root in (Path("C:/Program Files/Weixin"), Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Tencent"):
        if root.exists():
            versioned = sorted(root.glob("*/Weixin.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
            if versioned:
                return versioned[0]
            direct = root / WEIXIN_PROCESS
            if direct.exists():
                return direct
    return None


def installed_wechat_versions() -> list[tuple[str, Path]]:
    """Return (version, Weixin.dll path) for each version dir under the install root."""
    exe = find_weixin_exe()
    if exe is None:
        return []
    # WeChat install root: sibling dirs of Weixin.exe hold versioned Weixin.dlls,
    # e.g. C:\Program Files\Weixin\4.1.12.55\Weixin.dll
    root = exe.parent
    out: list[tuple[str, Path]] = []
    for dll in sorted(root.glob("*/Weixin.dll"), key=lambda p: p.stat().st_mtime, reverse=True):
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)", dll.parent.name)
        out.append((m.group(1) if m else dll.parent.name, dll))
    direct = root / "Weixin.dll"
    if direct.exists():
        out.append(("embedded", direct))
    return out


def account_dir_name(account_dir: Path) -> str:
    return Path(account_dir).name
