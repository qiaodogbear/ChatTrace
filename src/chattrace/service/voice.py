"""Voice playback: decode WeChat SILK v3 voices to WAV for in-UI playback (M4).

WeChat stores voice messages as SILK v3 payloads inside the decrypted
``media_*.db`` ``VoiceInfo.voice_data`` blobs.  Browsers cannot play SILK, so the
payload is decoded to 16-bit mono PCM and wrapped in a WAV container.

Decoding uses `silk-python <https://github.com/synodriver/pysilk>`_ (BSD-3-Clause,
providing the ``pysilk`` module).  The dependency is optional at runtime: when it
is unavailable the caller gets ``None`` and the UI shows a plain voice placeholder
instead of a file download.
"""
from __future__ import annotations

import io
import wave
from pathlib import Path

DEFAULT_SAMPLE_RATE = 24000


def decoder_available() -> bool:
    """True when a SILK decoder is importable in this process."""
    try:
        import pysilk  # noqa: F401
    except Exception:
        return False
    return True


def _pcm_from_silk(silk: bytes, sample_rate: int) -> bytes | None:
    try:
        import pysilk
    except Exception:
        return None

    candidates = [silk]
    if silk[:1] == b"\x02":          # WeChat prefixes the frame with a version byte
        candidates.append(silk[1:])
    if not silk.endswith(b"\xff\xff"):
        candidates.append(silk + b"\xff\xff")

    for payload in candidates:
        try:
            dst = io.BytesIO()
            pysilk.decode(io.BytesIO(payload), dst, sample_rate)
        except Exception:
            continue
        pcm = dst.getvalue()
        if len(pcm) > 64:            # anything shorter is a failed decode
            return pcm
    return None


def silk_to_wav(silk: bytes, sample_rate: int = DEFAULT_SAMPLE_RATE) -> bytes | None:
    """Decode a SILK v3 payload into WAV bytes; ``None`` when decoding is impossible."""
    if not silk:
        return None
    pcm = _pcm_from_silk(bytes(silk), sample_rate)
    if pcm is None:
        return None
    out = io.BytesIO()
    with wave.open(out, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        handle.writeframes(pcm)
    return out.getvalue()


def wav_duration_seconds(wav: bytes) -> float:
    try:
        with wave.open(io.BytesIO(wav), "rb") as handle:
            frames = handle.getnframes()
            rate = handle.getframerate() or DEFAULT_SAMPLE_RATE
        return frames / rate
    except Exception:
        return 0.0


def cached_wav_path(cache_dir: Path, chat_key: str, local_id: int) -> Path:
    return Path(cache_dir) / "voice" / chat_key / f"{int(local_id)}.wav"


def write_cached_wav(path: Path, wav: bytes) -> Path:
    """Atomically materialise a decoded voice so repeat plays are instant."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.stat().st_size != len(wav):
        tmp = path.with_suffix(".wav.tmp")
        tmp.write_bytes(wav)
        tmp.replace(path)
    return path
