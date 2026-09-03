import os
import sys
from pathlib import Path

import pytest

from chattrace.keyagent import keystore
from chattrace.models import KeyInfo

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")


def test_store_load_delete_roundtrip(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    info = KeyInfo(
        account_id="wxid_test_0001",
        wechat_version="4.1.12.55",
        password=os.urandom(32),
        source="manual",
    )
    target = keystore.store_key(info)
    assert target.exists()
    loaded = keystore.load_key(info.account_id, info.wechat_version)
    assert loaded.password == info.password
    assert loaded.fingerprint == info.fingerprint
    assert keystore.delete_key(info.account_id, info.wechat_version)
    assert not target.exists()
