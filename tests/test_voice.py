"""Voice playback tests (M4): SILK -> WAV decoding, caching and graceful fallback."""
from __future__ import annotations

import io
import math
import struct
import wave
from pathlib import Path

import pytest

from chattrace.service import voice as voice_mod

pysilk = pytest.importorskip("pysilk", reason="SILK decoder (silk-python) not installed")

RATE = 24000


def _pcm_tone(seconds: float) -> bytes:
    frames = int(RATE * seconds)
    return b"".join(
        struct.pack("<h", int(12000 * math.sin(2 * math.pi * 440 * i / RATE))) for i in range(frames)
    )


def _silk_payload(seconds: float) -> bytes:
    src = io.BytesIO(_pcm_tone(seconds))
    dst = io.BytesIO()
    pysilk.encode(src, dst, RATE, RATE)
    return dst.getvalue()


class TestSilkToWav:
    def test_roundtrip_produces_valid_wav(self):
        silk = _silk_payload(0.5)
        assert silk[:1] == b"\x02", "WeChat prefixes SILK frames with a version byte"
        wav = voice_mod.silk_to_wav(silk)
        assert wav is not None
        assert wav[:4] == b"RIFF"
        with wave.open(io.BytesIO(wav), "rb") as handle:
            assert handle.getnchannels() == 1
            assert handle.getsampwidth() == 2
            assert handle.getframerate() == RATE
        # duration should be close to the source (SILK adds small frame padding)
        assert 0.4 < voice_mod.wav_duration_seconds(wav) < 0.8

    def test_accepts_payload_without_version_byte(self):
        silk = _silk_payload(0.3)
        wav = voice_mod.silk_to_wav(silk[1:])
        assert wav is not None and wav[:4] == b"RIFF"

    def test_empty_and_garbage_return_none(self):
        assert voice_mod.silk_to_wav(b"") is None
        assert voice_mod.silk_to_wav(b"\x00" * 32) is None

    def test_decoder_available_is_bool(self):
        assert isinstance(voice_mod.decoder_available(), bool)

    def test_wav_duration_of_broken_data(self):
        assert voice_mod.wav_duration_seconds(b"not a wav") == 0.0


class TestCache:
    def test_cached_path_layout(self, tmp_path: Path):
        path = voice_mod.cached_wav_path(tmp_path, "abc123", 42)
        assert path == tmp_path / "voice" / "abc123" / "42.wav"

    def test_write_cached_wav_is_atomic_and_idempotent(self, tmp_path: Path):
        target = voice_mod.cached_wav_path(tmp_path, "abc", 7)
        wav = voice_mod.silk_to_wav(_silk_payload(0.2))
        assert wav is not None
        voice_mod.write_cached_wav(target, wav)
        assert target.is_file() and target.read_bytes() == wav
        mtime = target.stat().st_mtime_ns
        voice_mod.write_cached_wav(target, wav)          # same size -> no rewrite
        assert target.stat().st_mtime_ns == mtime
        assert not list(target.parent.glob("*.tmp"))
