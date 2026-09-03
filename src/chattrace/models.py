"""Shared data models."""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class KeyInfo:
    """A validated WeChat DB master key for one account."""

    account_id: str            # wxid_xxx (account directory name)
    wechat_version: str        # e.g. "4.1.12.55" ("" when unknown/manual)
    password: bytes            # 32-byte master key
    captured_at: float = field(default_factory=time.time)
    source: str = "frida-keyagent"  # frida-keyagent | memory-scan | manual
    variant: str = "pbkdf2-sha512-256000/dbsalt/le"
    verified: bool = True      # HMAC self-check passed at capture/import time

    @property
    def hex_password(self) -> str:
        return self.password.hex()

    @property
    def fingerprint(self) -> str:
        return self.password.hex()[:8]


@dataclass(frozen=True)
class AnchorSet:
    """Three Weixin.dll hook anchors as RVAs."""

    wechat_version: str
    entry: int                 # codec-config function entry (rcx[0:32] = password)
    mmv1_ref: int              # lea rcx,[MMV1 string]
    magic_check: int           # cmp dword ptr [rcx], 'MMV1'
    located_at: float = field(default_factory=time.time)
