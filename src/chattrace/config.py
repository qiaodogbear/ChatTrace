"""Central configuration: paths, error codes, constants."""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "ChatTrace"
APP_DIR_NAME = "ChatTrace"
DEFAULT_ACCOUNT_DB_REL = Path("db_storage") / "message" / "message_0.db"
KEY_TTL_SECONDS = 24 * 3600

# --- error codes (surfaced to CLI/UI guides) ---
ERR_OK = 0
ERR_NO_WEIXIN = 1            # no Weixin / Weixin.dll found
ERR_LOGIN_TIMEOUT = 2        # spawned Weixin never auto-logged-in (no codec fire)
ERR_UNSUPPORTED_VERSION = 3  # version not registered and auto-locate failed
ERR_NO_VALID_KEY = 4         # candidates failed HMAC after retries
ERR_WECHAT_CRASH = 5         # Weixin crashed during capture (possible anti-hook)
ERR_FRIDA = 6                # frida missing / unusable
ERR_CLEANUP = 7              # failed to clean up spawned instance
ERR_ACCOUNT = 8              # account dir / db not found or ambiguous
ERR_KEY_STORE = 9            # keystore read/write failure


class KeyagentError(RuntimeError):
    """Raised with an error code from the table above."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def app_data_dir() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / APP_DIR_NAME
    root.mkdir(parents=True, exist_ok=True)
    return root


def keys_dir() -> Path:
    d = app_data_dir() / "keys"
    d.mkdir(parents=True, exist_ok=True)
    return d


def logs_dir() -> Path:
    d = app_data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def default_account_db(account_dir: Path) -> Path:
    return Path(account_dir) / DEFAULT_ACCOUNT_DB_REL
