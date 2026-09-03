from pathlib import Path

from chattrace.keyagent import version_map
from chattrace.models import AnchorSet


def test_registered_anchor_exists():
    anchors = version_map.resolve_anchors("4.1.12.55")
    assert anchors is not None
    assert anchors.entry == 0x353BC60


def test_cache_roundtrip(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "la"))
    anchors = AnchorSet(wechat_version="9.9.9.9", entry=0x1000, mmv1_ref=0x2000, magic_check=0x3000)
    version_map.save_anchor_cache([anchors])
    resolved = version_map.resolve_anchors("9.9.9.9")
    assert resolved is not None
    assert resolved.entry == 0x1000
    # registry still resolves too
    assert version_map.resolve_anchors("4.1.12.55") is not None
