"""Known WeChat 4.x codec anchor registry + file-based cache of located anchors."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..config import app_data_dir
from ..models import AnchorSet

#: Hand-located anchor sets by WeChat version (RVA). 4.1.12.55 values were
#: verified end-to-end on 2026-09-03 (see docs/evidence/README.md).
KNOWN_ANCHORS: dict[str, AnchorSet] = {
    "4.1.12.55": AnchorSet(
        wechat_version="4.1.12.55",
        entry=0x353BC60,
        mmv1_ref=0x353BC99,
        magic_check=0x7050502,
    ),
}


def anchor_cache_path() -> Path:
    return app_data_dir() / "anchor_cache.json"


def save_anchor_cache(anchors: list[AnchorSet]) -> None:
    payload = {
        "anchors": [
            {
                "wechat_version": a.wechat_version,
                "entry": a.entry,
                "mmv1_ref": a.mmv1_ref,
                "magic_check": a.magic_check,
                "located_at": a.located_at,
            }
            for a in anchors
        ]
    }
    path = anchor_cache_path()
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".anchor-", suffix=".tmp")
    try:
        with open(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        import os

        os.replace(tmp, path)
    finally:
        if Path(tmp).exists():
            try:
                Path(tmp).unlink()
            except OSError:
                pass


def load_anchor_cache() -> dict[str, AnchorSet]:
    path = anchor_cache_path()
    if not path.exists():
        return dict(KNOWN_ANCHORS)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(KNOWN_ANCHORS)
    out = dict(KNOWN_ANCHORS)
    for item in payload.get("anchors", []):
        try:
            out[item["wechat_version"]] = AnchorSet(
                wechat_version=item["wechat_version"],
                entry=int(item["entry"]),
                mmv1_ref=int(item["mmv1_ref"]),
                magic_check=int(item["magic_check"]),
                located_at=float(item.get("located_at", 0)),
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def resolve_anchors(wechat_version: str) -> AnchorSet | None:
    return load_anchor_cache().get(wechat_version)
