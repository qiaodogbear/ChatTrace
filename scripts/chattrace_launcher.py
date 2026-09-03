"""Packaged-app launcher: starts the guided Web UI and opens the browser.

Double-click target for the PyInstaller build (chattrace.exe).
"""
from __future__ import annotations

import sys
import threading

from chattrace.webui.server import main

if __name__ == "__main__":
    # keep a console open so the URL stays visible and the user can close it
    argv = [] if len(sys.argv) <= 1 else sys.argv[1:]
    sys.exit(main(argv))
