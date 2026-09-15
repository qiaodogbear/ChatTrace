"""Tests for media.py dimension probing and dat classification regressions."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

from chattrace.service.image_key import ImageKeys
from chattrace.service.media import (
    MediaService,
    classify_dat,
    data_key_for,
    image_dimensions,
)

AES_KEY = b"7afad634d235415a"
V2_MAGIC = bytes.fromhex("070856320807")
XOR_KEY = 0xA4
MONTH_CT = 1767225600  # 2026-01-01


# ---------------------------------------------------------------- fixtures

def _jpeg(width: int, height: int, sof_offset: int) -> bytes:
    """Build a JPEG whose SOF marker sits at ``sof_offset``.

    Real phone photos stack several APP segments (Exif, ICC, APP3) before the
    frame header; a single segment caps at 64 KiB, so fill with as many as needed.
    """
    assert sof_offset >= 8
    out = bytearray(b"\xff\xd8")
    while len(out) < sof_offset:
        remaining = sof_offset - len(out)
        if remaining <= 4:
            out += b"\x00" * remaining          # filler the walker skips over
            break
        seg_field = min(0xFFFF, remaining - 2)
        out += b"\xff\xe1" + struct.pack(">H", seg_field) + b"\x00" * (seg_field - 2)
    assert len(out) == sof_offset, (len(out), sof_offset)
    out += b"\xff\xc0" + struct.pack(">H", 17) + b"\x08"
    out += struct.pack(">HH", height, width) + b"\x00" * 6
    return bytes(out)


def _png(width: int, height: int) -> bytes:
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    out += struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", width, height)
    out += b"\x08\x06\x00\x00\x00"
    return bytes(out)


def _v2_payload(plaintext: bytes, *, xor_tail: bytes = b"") -> bytes:
    """Wrap plaintext in a V2 container with a 1024-byte AES head."""
    head = plaintext[:1024]
    head = head + bytes(1024 - len(head))
    rest = bytes(plaintext[1024:])
    cipher = AES.new(AES_KEY, AES.MODE_ECB).encrypt(Padding.pad(head, 16))
    assert len(cipher) == 1040
    trailer = bytes(b ^ XOR_KEY for b in xor_tail)
    header = V2_MAGIC + struct.pack("<LL", 1024, len(xor_tail)) + b"\x01"
    return header + cipher + rest + trailer


class _StubResolver:
    def __init__(self, keys: ImageKeys | None) -> None:
        self._keys = keys

    def keys(self) -> ImageKeys | None:
        return self._keys

    def describe(self) -> dict:
        return {"status": "ok" if self._keys else "unavailable", "reason": ""}


def _service(tmp_path: Path, keys: ImageKeys | None, account_id: str = "wxid_demo_0001") -> MediaService:
    account = tmp_path / account_id
    return MediaService(
        account_id,
        account,
        tmp_path / "decrypted",
        tmp_path / "cache",
        image_key_resolver=_StubResolver(keys) if keys is not None else _StubResolver(None),
    )


def _place(svc: MediaService, md5: str, blob: bytes, suffix: str = "_h") -> Path:
    username = "someone@chatroom"
    img_dir = svc._attach_root(username) / "2026-01" / "Img"
    img_dir.mkdir(parents=True, exist_ok=True)
    path = img_dir / f"{md5}{suffix}.dat"
    path.write_bytes(blob)
    return path


# ------------------------------------------------------- image_dimensions

def test_image_dimensions_jpeg():
    blob = _jpeg(1920, 1080, sof_offset=64)
    assert image_dimensions(blob) == (1920, 1080)


def test_image_dimensions_jpeg_far_sof():
    blob = _jpeg(4096, 3072, sof_offset=100_000)
    assert image_dimensions(blob) == (4096, 3072)


def test_image_dimensions_png():
    assert image_dimensions(_png(800, 600)) == (800, 600)


def test_image_dimensions_gif():
    blob = b"GIF89a" + struct.pack("<HH", 320, 240) + b"\x00" * 4
    assert image_dimensions(blob) == (320, 240)


@pytest.mark.parametrize("blob", [b"", b"nope", b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n short"])
def test_image_dimensions_unknown(blob):
    assert image_dimensions(blob) is None


def test_image_dimensions_rejects_zero_sized_sof():
    blob = _jpeg(0, 0, sof_offset=32)
    assert image_dimensions(blob) is None


# ------------------------------------------------------------- dat classes

def test_data_key_for_legacy_magics():
    assert data_key_for(bytes(b ^ XOR_KEY for b in b"\xff\xd8\xff\xe0")) == XOR_KEY
    assert data_key_for(bytes(b ^ 0x2D for b in b"\x89PNG\r\n\x1a\n")) == 0x2D
    assert data_key_for(b"\x01\x02\x03\x04") is None


def test_classify_dat_dispatch():
    assert classify_dat(V2_MAGIC + b"\x00" * 20) == "v2"
    assert classify_dat(bytes.fromhex("070856310807") + b"\x00" * 20) == "v1"
    assert classify_dat(bytes(b ^ XOR_KEY for b in b"\xff\xd8\xff\xe0") + b"\x00") == "xor"
    assert classify_dat(b"\x00\x01\x02\x03") == "unknown"


# ----------------------------------------------------- plaintext head / item

def test_plaintext_head_v2_stitches_middle_section(tmp_path):
    plain = _jpeg(4096, 3072, sof_offset=100_000) + bytes(4096)
    svc = _service(tmp_path, ImageKeys(1, AES_KEY, XOR_KEY, "wxid_demo"))
    path = _place(svc, "a" * 32, _v2_payload(plain, xor_tail=b"\x00" * 16))

    head = svc._plaintext_head(path, svc.image_keys(), 128 * 1024)
    assert head[: len(plain)] == plain          # padding stripped, no 16-byte shift
    assert image_dimensions(head) == (4096, 3072)


def test_plaintext_head_legacy_xor(tmp_path):
    plain = _jpeg(640, 480, sof_offset=48) + bytes(64)
    svc = _service(tmp_path, ImageKeys(1, AES_KEY, XOR_KEY, "wxid_demo"))
    path = _place(svc, "b" * 32, bytes(b ^ XOR_KEY for b in plain), suffix="")

    head = svc._plaintext_head(path, svc.image_keys(), 4096)
    assert head == plain
    assert image_dimensions(head) == (640, 480)


def test_image_item_reports_real_dimensions_for_v2(tmp_path):
    """The card must describe the file we picked, not the message XML."""
    plain = _jpeg(4096, 3072, sof_offset=100_000)
    md5 = "c" * 32
    keys = ImageKeys(1, AES_KEY, XOR_KEY, "wxid_demo")
    svc = _service(tmp_path, keys)
    _place(svc, md5, _v2_payload(plain))

    item = svc.image_item("someone@chatroom", md5, MONTH_CT)
    assert item.status == "ok"
    assert item.is_thumbnail is False
    assert item.dimensions == (4096, 3072)
    assert item.size == len(_v2_payload(plain))


def test_image_item_prefers_original_and_keeps_thumbnail_as_alternate(tmp_path):
    md5 = "d" * 32
    keys = ImageKeys(1, AES_KEY, XOR_KEY, "wxid_demo")
    svc = _service(tmp_path, keys)
    _place(svc, md5, _v2_payload(_jpeg(1600, 1200, 64)), suffix="_h")
    _place(svc, md5, _v2_payload(_jpeg(160, 120, 64)), suffix="_t")

    item = svc.image_item("someone@chatroom", md5, MONTH_CT)
    assert item.dimensions == (1600, 1200)
    assert item.is_thumbnail is False
    assert [p.name for p in item.alternates] == [f"{md5}_t.dat"]
    assert svc.decode_image(item) is not None


def test_image_item_without_keys_reports_locked(tmp_path):
    md5 = "e" * 32
    svc = _service(tmp_path, None)
    _place(svc, md5, _v2_payload(_jpeg(100, 100, 32)))

    item = svc.image_item("someone@chatroom", md5, MONTH_CT)
    assert item.status == "unsupported"
    assert "kvcomm" in item.detail


def test_image_item_legacy_xor_is_ok_and_measured(tmp_path):
    md5 = "f" * 32
    plain = _jpeg(800, 600, sof_offset=64)
    svc = _service(tmp_path, ImageKeys(1, AES_KEY, XOR_KEY, "wxid_demo"))
    _place(svc, md5, bytes(b ^ XOR_KEY for b in plain), suffix="")

    item = svc.image_item("someone@chatroom", md5, MONTH_CT)
    assert item.status == "ok"
    assert item.dimensions == (800, 600)
    ext, blob = svc.decode_image(item)
    assert ext == "jpg"
    assert blob == plain


def test_attach_root_uses_md5_of_username(tmp_path):
    svc = _service(tmp_path, None, account_id="wxid_x_1")
    expected = svc.account_dir / "msg" / "attach" / hashlib.md5(b"someone@chatroom").hexdigest()
    assert svc._attach_root("someone@chatroom") == expected
