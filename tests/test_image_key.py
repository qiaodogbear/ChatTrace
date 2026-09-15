"""Tests for offline V2 image key derivation and decode (service/image_key.py)."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

from chattrace.service.image_key import (
    V2_HEADER_SIZE,
    V2_MAGIC,
    ImageKeyResolver,
    ImageKeys,
    clean_wxid,
    decode_v2,
    derive_image_keys,
    find_kvcomm_codes,
    image_format_of,
    infer_xor_key_from_tail,
    probe_image_keys,
    v2_template_blocks,
)

# Real pair captured from a WeChat 4.1.13 account: the kvcomm code and the
# derived 16-ASCII-byte key that decrypts that account's V2 image blocks.
REAL_CODE = 1234567
REAL_WXID = "wxid_demo0000"
REAL_AES_KEY = b"7afad634d235415a"
# First AES block of any V2 image from that account (plaintext = JPEG JFIF head).
REAL_CIPHER_BLOCK = bytes.fromhex("036151a320f5496ba355e2c3534c6b0d")


# ------------------------------------------------------------------- deriving

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("wxid_demo0000_1234", "wxid_demo0000"),
        ("wxid_demo0000", "wxid_demo0000"),
        ("somebody", "somebody"),
        ("", ""),
        (None, ""),
    ],
)
def test_clean_wxid(raw, expected):
    assert clean_wxid(raw) == expected


def test_derive_image_keys_matches_captured_account():
    keys = derive_image_keys(REAL_CODE, REAL_WXID)
    assert keys.aes_key == REAL_AES_KEY
    assert keys.aes_key_ascii == REAL_AES_KEY.decode("ascii")
    assert keys.xor_key == REAL_CODE & 0xFF == 0xA4
    assert keys.wxid == REAL_WXID


def test_derive_image_keys_accepts_data_dir_name():
    """The `_8146` disambiguator must not change the derivation."""
    assert derive_image_keys(REAL_CODE, REAL_WXID + "_8146").aes_key == REAL_AES_KEY


def test_derive_image_keys_rejects_bad_input():
    for code in (0, -1, 0x1_0000_0000, True):
        with pytest.raises(ValueError):
            derive_image_keys(code, REAL_WXID)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        derive_image_keys(REAL_CODE, "")


def test_aes_key_is_md5_prefix_of_code_plus_wxid():
    expected = hashlib.md5(f"{REAL_CODE}{REAL_WXID}".encode()).hexdigest()[:16]
    assert derive_image_keys(REAL_CODE, REAL_WXID).aes_key == expected.encode("ascii")


def test_as_dict_never_leaks_the_raw_key():
    payload = derive_image_keys(REAL_CODE, REAL_WXID, source="k.statistic").as_dict()
    assert "aes_key" not in payload
    assert REAL_AES_KEY.decode() not in str(payload)
    assert payload["xor_key"] == "0xA4"
    assert payload["code"] == REAL_CODE
    assert payload["aes_key_fingerprint"] == hashlib.sha256(REAL_AES_KEY).hexdigest()[:8]


# --------------------------------------------------------------------- probing

def test_probe_accepts_real_cipher_block():
    keys = derive_image_keys(REAL_CODE, REAL_WXID)
    assert probe_image_keys(keys, [REAL_CIPHER_BLOCK]) == "jpg"


def test_probe_rejects_wrong_key():
    wrong = ImageKeys(code=1, aes_key=b"0123456789abcdef", xor_key=1, wxid=REAL_WXID)
    assert probe_image_keys(wrong, [REAL_CIPHER_BLOCK]) is None


def test_probe_ignores_short_blocks():
    keys = derive_image_keys(REAL_CODE, REAL_WXID)
    assert probe_image_keys(keys, [b"\x00" * 8]) is None


@pytest.mark.parametrize(
    "head,expected",
    [
        (b"\xff\xd8\xff\xe0", "jpg"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"GIF89a", "gif"),
        (b"wxgf\x00\x00", "wxgf"),
        (b"nope", None),
        (b"", None),
    ],
)
def test_image_format_of(head, expected):
    assert image_format_of(head) == expected


def test_infer_xor_key_from_tail():
    # a JPEG end-of-image marker XORed with 0xA4
    assert infer_xor_key_from_tail(b"....\x5b\x7d") == 0xA4
    assert infer_xor_key_from_tail(b"\x00\x00") is None
    assert infer_xor_key_from_tail(b"\x00") is None


# --------------------------------------------------------------------- decode

def _build_v2(plain_aes: bytes, plain_tail: bytes, *, aes_size: int, xor_key: int) -> bytes:
    """Assemble a synthetic V2 payload the way WeChat lays it out."""
    blocks = aes_size + 16 - (aes_size % 16)
    padded = Padding.pad(plain_aes, 16)
    assert len(padded) == blocks, "test fixture must fill the declared aes_size"
    cipher = AES.new(REAL_AES_KEY, AES.MODE_ECB).encrypt(padded)
    trailer = bytes(b ^ xor_key for b in plain_tail)
    header = V2_MAGIC + struct.pack("<LL", aes_size, len(plain_tail)) + b"\x01"
    assert len(header) == V2_HEADER_SIZE
    return header + cipher + trailer


def test_decode_v2_roundtrip():
    head = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    body = (head + bytes(range(256)) * 4)[:1024]
    assert len(body) == 1024
    plain = _build_v2(body, b"tail-bytes" * 4, aes_size=1024, xor_key=0xA4)

    keys = derive_image_keys(REAL_CODE, REAL_WXID)
    out = decode_v2(plain, keys)
    assert out == body + b"tail-bytes" * 4
    assert image_format_of(out) == "jpg"


def test_decode_v2_handles_non_multiple_aes_size():
    body = (b"\x89PNG\r\n\x1a\n" + bytes(1000))[:1000]
    payload = _build_v2(body, b"", aes_size=1000, xor_key=0x5C)
    keys = ImageKeys(code=92, aes_key=REAL_AES_KEY, xor_key=0x5C, wxid=REAL_WXID)
    assert decode_v2(payload, keys) == body


def test_decode_v2_rejects_non_v2():
    keys = derive_image_keys(REAL_CODE, REAL_WXID)
    with pytest.raises(ValueError):
        decode_v2(b"not-a-v2-file" * 8, keys)


def test_decode_v2_rejects_short_payload():
    keys = derive_image_keys(REAL_CODE, REAL_WXID)
    header = V2_MAGIC + struct.pack("<LL", 4096, 0) + b"\x01"
    with pytest.raises(ValueError):
        decode_v2(header + b"\x00" * 32, keys)


# -------------------------------------------------------------------- kvcomm

def _write_kvcomm(root: Path, entries: dict[str, list[str]]) -> None:
    for sub, names in entries.items():
        kv = root / sub / "kvcomm"
        kv.mkdir(parents=True, exist_ok=True)
        for name in names:
            (kv / name).write_bytes(b"")


def test_find_kvcomm_codes(tmp_path: Path):
    _write_kvcomm(
        tmp_path,
        {
            "net": ["key_1234567_1_2_3600_input.statistic", "unrelated.txt"],
            "net_1": ["key_0_9_9_3600_ready.statistic", "key_reportnow_0_1.monitor"],
            "radium/ilink/abc": ["key_4242_1_1_600_input.statistic"],
        },
    )
    found = find_kvcomm_codes([tmp_path])
    assert [code for code, _ in found] == [4242, 1234567]
    assert all(Path(path).is_file() for _, path in found)


def test_find_kvcomm_codes_empty(tmp_path: Path):
    assert find_kvcomm_codes([tmp_path]) == []
    assert find_kvcomm_codes([tmp_path / "missing"]) == []


# ------------------------------------------------------------------ resolver

def _make_v2_file(path: Path, *, aes_size: int = 1024) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    head = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    body = (head + bytes(1024))[:1024]
    path.write_bytes(_build_v2(body, b"\x00" * 32, aes_size=aes_size, xor_key=0xA4))


def test_v2_template_blocks_reads_headers_only(tmp_path: Path):
    account = tmp_path / "wxid_demo0000"
    _make_v2_file(account / "msg" / "attach" / "deadbeef" / "2026-01" / "Img" / "aaaa_t.dat")
    (account / "msg" / "attach" / "deadbeef" / "2026-01" / "Img" / "plain.txt").write_text("x")

    blocks = v2_template_blocks(account)
    assert len(blocks) == 1
    assert len(blocks[0]) == 16
    assert AES.new(REAL_AES_KEY, AES.MODE_ECB).decrypt(blocks[0]).startswith(b"\xff\xd8\xff")


def test_v2_template_blocks_absent(tmp_path: Path):
    assert v2_template_blocks(tmp_path / "nope") == []


def test_resolver_selects_code_that_decrypts_locally(tmp_path: Path):
    account = tmp_path / "wxid_demo0000_1234"
    _make_v2_file(account / "msg" / "attach" / "ab" / "2026-01" / "Img" / "x_t.dat")
    config = tmp_path / "config"
    # a decoy code that derives a wrong key, plus the real one
    _write_kvcomm(config, {"net": ["key_1_1_1_3600_input.statistic"]})
    real_name = "key_%d_1_1_3600_input.statistic" % REAL_CODE
    _write_kvcomm(config, {"net_1": [real_name]})

    resolver = ImageKeyResolver(account, "wxid_demo0000_1234", config_roots=[config])
    keys = resolver.keys()
    assert keys is not None
    assert keys.code == REAL_CODE
    assert keys.aes_key == REAL_AES_KEY
    assert resolver.describe()["status"] == "ok"


def test_resolver_reports_reason_without_codes(tmp_path: Path):
    account = tmp_path / "wxid_demo0000"
    _make_v2_file(account / "msg" / "attach" / "ab" / "2026-01" / "Img" / "x_t.dat")
    resolver = ImageKeyResolver(account, "wxid_demo0000", config_roots=[tmp_path / "empty"])
    assert resolver.keys() is None
    assert "kvcomm" in resolver.reason
    assert resolver.describe() == {"status": "unavailable", "reason": resolver.reason}


def test_resolver_reports_reason_without_templates(tmp_path: Path):
    config = tmp_path / "config"
    _write_kvcomm(config, {"net": ["key_%d_1_1_3600_input.statistic" % REAL_CODE]})
    resolver = ImageKeyResolver(tmp_path / "no-account", "wxid_demo0000", config_roots=[config])
    assert resolver.keys() is None
    assert "V2 图片" in resolver.reason


def test_resolver_caches_and_invalidates(tmp_path: Path):
    account = tmp_path / "wxid_demo0000"
    _make_v2_file(account / "msg" / "attach" / "ab" / "2026-01" / "Img" / "x_t.dat")
    config = tmp_path / "config"
    _write_kvcomm(config, {"net": ["key_%d_1_1_3600_input.statistic" % REAL_CODE]})
    resolver = ImageKeyResolver(account, "wxid_demo0000", config_roots=[config])
    first = resolver.keys()
    assert resolver.keys() is first          # cached
    resolver.invalidate()
    assert resolver.keys() is not first
