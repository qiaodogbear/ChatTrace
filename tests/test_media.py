"""MediaService pure-function tests: dat decode, classify, md5 extraction."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from chattrace.service import media as media_mod
from chattrace.service.media import (
    MediaUnsupported,
    classify_dat,
    decode_dat,
    md5_hex32,
    _IMAGE_MAGICS,
)

JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


class TestClassifyAndDecode:
    def test_legacy_xor_jpeg(self):
        dat = _xor(JPEG, 0xA4)
        assert dat[:4] == bytes.fromhex("5b7c5b44")
        assert classify_dat(dat) == "xor"
        ext, out = decode_dat(dat)
        assert ext == "jpg" and out == JPEG

    def test_legacy_xor_png_same_key(self):
        dat = _xor(PNG, 0xA4)
        assert dat[:4] == bytes.fromhex("2df4eae3")
        assert classify_dat(dat) == "xor"
        ext, out = decode_dat(dat)
        assert ext == "png" and out == PNG

    def test_legacy_other_xor_key_derived(self):
        # a different single-byte key must still be auto-derived from the magic
        dat = _xor(JPEG, 0x7C)
        assert classify_dat(dat) == "xor"
        ext, out = decode_dat(dat)
        assert ext == "jpg" and out == JPEG

    def test_v2_unsupported(self):
        dat = bytes.fromhex("070856320807") + b"\x00" * 32
        assert classify_dat(dat) == "v2"
        with pytest.raises(MediaUnsupported):
            decode_dat(dat)

    def test_v1_container_recognized(self):
        dat = bytes.fromhex("070856310807") + b"\x00" * 32
        assert classify_dat(dat) == "v1"

    def test_unknown_garbage(self):
        assert classify_dat(b"\xde\xad\xbe\xef" + b"\x00" * 10) == "unknown"


class TestMd5Extraction:
    def test_simple_40b_shape(self):
        # protobuf-ish: 08 01 10 02 1a 22 [22 20 <32 hex ascii>]
        md5 = "c0cfd3149f2dafc17c806ca3ba7e9cef"
        packed = bytes.fromhex("080110021a22") + bytes.fromhex("2220") + md5.encode("ascii")
        assert md5_hex32(packed) == md5

    def test_longer_shape(self):
        md5 = "4e973b6bb314606571cc92faa6349462"
        packed = bytes.fromhex("080510022222") + bytes.fromhex("4220") + md5.encode("ascii")
        assert md5_hex32(packed) == md5

    def test_empty_and_junk(self):
        assert md5_hex32(None) is None
        assert md5_hex32(b"") is None
        assert md5_hex32(b"\x08\x01") is None


class TestLocator:
    def test_image_dat_candidates_prefer_original(self, tmp_path: Path):
        account = tmp_path / "account"
        username = "wxid_bob"
        digest = hashlib.md5(username.encode()).hexdigest()
        img = account / "msg" / "attach" / digest / "2024-08" / "Img"
        img.mkdir(parents=True)
        md5 = "c0cfd3149f2dafc17c806ca3ba7e9cef"
        (img / f"{md5}_t_W.dat").write_bytes(_xor(JPEG, 0xA4))            # 26 B thumb
        (img / f"{md5}_W.dat").write_bytes(_xor(JPEG * 3, 0xA4))          # larger original
        svc = media_mod.MediaService("a", account, tmp_path / "decrypted", tmp_path / "cache")
        cands = svc.image_dat_candidates(username, md5, 1723000000)  # 2024-08
        assert len(cands) == 2
        # the original (non-thumbnail, larger) must rank first
        assert cands[0].name == f"{md5}_W.dat"

    def test_item_missing(self, tmp_path: Path):
        account = tmp_path / "account"
        svc = media_mod.MediaService("a", account, tmp_path / "decrypted", tmp_path / "cache")
        item = svc.image_item("wxid_bob", "0" * 32, 1723000000)
        assert item.status == "missing"

    def test_voice_row_from_media_db(self, tmp_path: Path):
        import sqlite3

        account = tmp_path / "account"
        dec = tmp_path / "decrypted"
        (dec / "message").mkdir(parents=True)
        dbp = dec / "message" / "media_0.db"
        con = sqlite3.connect(dbp)
        con.execute("CREATE TABLE Name2Id (user_name TEXT)")
        con.execute("INSERT INTO Name2Id VALUES (?)", ("wxid_bob",))
        con.execute("CREATE TABLE VoiceInfo (chat_name_id INT, create_time INT, local_id INT, "
                    "voice_data BLOB, data_index TEXT)")
        silk = b"\x02#!SILK_V3\x00\x01\x02payload"
        con.execute("INSERT INTO VoiceInfo VALUES (1, 1700000000, 42, ?, '0')", (silk,))
        con.commit()
        con.close()
        svc = media_mod.MediaService("a", account, dec, tmp_path / "cache")
        item = svc.voice_item("wxid_bob", 42, 1700000000)
        assert item.status == "ok" and item.detail
        blob = svc.voice_blob("wxid_bob", 42, 1700000000)
        assert blob == silk
        missing = svc.voice_item("wxid_bob", 999, 1700000000)
        assert missing.status == "missing"

    def test_video_plaintext_locator(self, tmp_path: Path):
        account = tmp_path / "account"
        md5 = "4e973b6bb314606571cc92faa6349462"
        month = account / "msg" / "video" / "2025-08"
        month.mkdir(parents=True)
        (month / f"{md5}.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42")
        (month / f"{md5}_thumb.jpg").write_bytes(JPEG)
        svc = media_mod.MediaService("a", account, tmp_path / "decrypted", tmp_path / "cache")
        mp4, thumb = svc.video_file("wxid_bob", md5, 1754000000)
        assert mp4 is not None and mp4.suffix == ".mp4"
        assert thumb is not None and thumb.name.endswith("_thumb.jpg")
