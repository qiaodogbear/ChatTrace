"""Payload decoding tests (M4): zstd bodies, XML metadata, group sender prefix."""
from __future__ import annotations

import pytest
import zstandard as zstd

from chattrace.service.payload import (
    ParsedMessage,
    decompress,
    parse_payload,
    to_text,
)

_Z = zstd.ZstdCompressor()


def zc(text: str) -> bytes:
    return _Z.compress(text.encode("utf-8"))


IMAGE_XML = (
    '<?xml version="1.0"?><msg><img aeskey="4d839c5cafcbf41de4bab626647df3df" encryver="1" '
    'cdnthumburl="30570201" cdnthumblength="14791" cdnthumbwidth="201" cdnthumbheight="432" '
    'length="506768" md5="8ecb83c641ff47037d2744260b371b0e" /></msg>'
)
VOICE_XML = (
    '<msg><voicemsg endflag="1" voiceformat="4" voicelength="27547" length="48655" '
    'aeskey="ab3ce514013d5c428c084dd067f4b31f" fromusername="wxid_alice" /></msg>'
)
VIDEO_XML = (
    '<?xml version="1.0"?><msg><videomsg aeskey="5a11" length="3585019" playlength="27" '
    'cdnthumbwidth="360" cdnthumbheight="640" md5="a63a2e4dc35950d9ebb12fcc06839af5" /></msg>'
)
LOCATION_XML = (
    '<?xml version="1.0"?><msg><location x="33.741640" y="112.927086" scale="20" '
    'poiname="程庄东265米" cityname="平顶山市" /></msg>'
)
CALL_XML = '<voipinvitemsg><roomid>0</roomid></voipinvitemsg><voiplocalinfo><diaplay_content>通话时长 01:20</diaplay_content></voiplocalinfo>'
FILE_XML = (
    '<?xml version="1.0"?><msg><appmsg appid="" sdkver="0"><title>清单.pdf</title><des />'
    '<type>6</type><fileext>pdf</fileext><md5>abc123</md5></appmsg></msg>'
)
QUOTE_XML = (
    '<?xml version="1.0"?><msg><appmsg><title>同意</title><type>57</type>'
    '<refermsg><type>1</type><svrid>123</svrid><chatusr>wxid_bob</chatusr>'
    '<content>我也愿意吹风</content></refermsg></appmsg></msg>'
)
EMOJI_XML = '<msg><emoji fromusername = "wxid_alice" type="2" md5="60228b8f953b59256551093e65eeafbd" len = "104204" /></msg>'
CARD_XML = (
    '<?xml version="1.0"?><msg bigheadimgurl="http://x/0" username="wxid_demo_peer01" '
    'nickname="灵活的胖子" alias="lhdpz" sex="1" /></msg>'
)


class TestDecompress:
    def test_zstd_roundtrip(self):
        assert decompress(zc("你好")) == "你好".encode()
        assert to_text(zc("你好，世界")) == "你好，世界"

    def test_plain_passthrough(self):
        assert decompress(b"hello") == b"hello"
        assert to_text(b"hello") == "hello"
        assert to_text("already text") == "already text"

    def test_empty_and_none(self):
        assert decompress(None) == b""
        assert to_text(None) == ""


class TestTextMessages:
    def test_private_text(self):
        parsed = parse_payload(1, zc("在吗？"))
        assert parsed.kind == "text" and parsed.text == "在吗？" and parsed.sender_hint == ""

    def test_group_text_sender_prefix(self):
        parsed = parse_payload(1, zc("wxid_demo_peer02:\n安徵综测有结果吗"))
        assert parsed.kind == "text"
        assert parsed.sender_hint == "wxid_demo_peer02"
        assert parsed.text == "安徵综测有结果吗"

    def test_system_message(self):
        parsed = parse_payload(10000, zc('"Alan"通过扫描"群主"分享的二维码加入群聊'))
        assert parsed.kind == "system"
        assert "加入群聊" in parsed.text


class TestRichMessages:
    def test_image_metadata(self):
        parsed = parse_payload(3, zc(IMAGE_XML))
        assert parsed.kind == "image"
        meta = parsed.meta
        assert meta.md5 == "8ecb83c641ff47037d2744260b371b0e"
        assert meta.length == 506768
        assert meta.width == 201 and meta.height == 432
        assert meta.aeskey.startswith("4d839c5c")
        assert parsed.text == "[图片] 201×432 494.9 KB"

    def test_voice_metadata(self):
        parsed = parse_payload(34, zc(VOICE_XML))
        assert parsed.kind == "voice"
        assert parsed.meta.duration_ms == 27547
        assert parsed.meta.length == 48655
        assert parsed.text == "[语音 28″]"

    def test_video_metadata(self):
        parsed = parse_payload(43, zc(VIDEO_XML))
        assert parsed.kind == "video"
        assert parsed.meta.duration_ms == 27000
        assert parsed.meta.md5.startswith("a63a2e4d")

    def test_location_metadata(self):
        parsed = parse_payload(48, zc(LOCATION_XML))
        assert parsed.kind == "location"
        assert parsed.meta.poi == "程庄东265米"
        assert abs(parsed.meta.latitude - 33.74164) < 1e-6
        assert "平顶山市" in parsed.text

    def test_call_duration(self):
        parsed = parse_payload(50, zc(CALL_XML))
        assert parsed.kind == "call"
        assert parsed.meta.call_duration_s == 80
        assert "01:20" in parsed.text

    def test_file_appmsg(self):
        parsed = parse_payload(49, zc(FILE_XML))
        assert parsed.kind == "file"
        assert parsed.meta.title == "清单.pdf"
        assert parsed.meta.extra.get("fileext") == "pdf"
        assert parsed.text == "[文件] 清单.pdf"

    def test_quote_appmsg(self):
        parsed = parse_payload(49, zc(QUOTE_XML))
        assert parsed.kind == "quote"
        assert parsed.meta.quoted.get("content") == "我也愿意吹风"
        assert parsed.meta.quoted.get("chat") == "wxid_bob"

    def test_emoji(self):
        parsed = parse_payload(47, zc(EMOJI_XML))
        assert parsed.kind == "emoji"
        assert parsed.meta.md5 == "60228b8f953b59256551093e65eeafbd"

    def test_card(self):
        parsed = parse_payload(42, zc(CARD_XML))
        assert parsed.kind == "card"
        assert parsed.meta.nickname == "灵活的胖子"
        assert parsed.meta.username == "wxid_demo_peer01"

    def test_group_prefixed_xml(self):
        parsed = parse_payload(3, zc("wxid_bob:\n" + IMAGE_XML))
        assert parsed.sender_hint == "wxid_bob"
        assert parsed.kind == "image"

    def test_garbage_is_safe(self):
        parsed = parse_payload(3, b"\x00\x01\x02\x03")
        assert parsed.kind == "image"          # type is authoritative
        assert parsed.meta.length == 0
        parsed2 = parse_payload(999, b"\xff\xfe\xfd")
        assert parsed2.kind in ("other", "text")
