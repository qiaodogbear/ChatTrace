"""Offline resolution of the WeChat 4.x "V2" image keys.

V2 ``.dat`` layout (verified against real 4.1.12 / 4.1.13 accounts)::

    [15B header][AES-128-ECB ciphertext][single-byte-XOR trailer]

    header := 6B magic (07 08 "V2" 08 07) + u32le aes_size + u32le xor_size + 1B pad

The AES segment is PKCS7 padded to a whole number of blocks, and a size that is
already a multiple of 16 still gains one extra block -- i.e. the real ciphertext
length is ``aes_size + 16 - aes_size % 16`` (1024 -> 1040).  Everything after it
is XORed with a single byte.

Both keys are *derived*, not scraped from the running process:

* ``code``    -- the digits in ``<wechat-config>/<net*>/kvcomm/key_<code>_*.statistic``
* ``xor_key`` -- ``code & 0xFF``
* ``aes_key`` -- ``md5(f"{code}{wxid}").hexdigest()[:16]``, used as 16 ASCII bytes

More than one ``code`` can be present on a machine, so every candidate is
verified against a real V2 ciphertext block before it is trusted; the caller
passes one or more blocks taken from the account's own image files.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

V2_MAGIC = bytes.fromhex("070856320807")
V2_HEADER_SIZE = 15
_AES_BLOCK = 16

#: ``key_<code>_<...>.statistic`` next to the kvcomm cache.
_KVCOMM_KEY_RE = re.compile(r"^key_(\d+)_.+\.statistic$", re.IGNORECASE)
#: ``wxid_abc`` optionally followed by the data-dir disambiguator ``_8146``.
_SUFFIXED_WXID_RE = re.compile(r"^(wxid_[^_]+)(?:_.+)$", re.IGNORECASE)
_MAX_CODE = 0xFFFFFFFF

_MAGICS: tuple[tuple[bytes, str, str], ...] = (
    (b"\xff\xd8\xff", "jpg", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png", "png"),
    (b"GIF87a", "gif", "gif"),
    (b"GIF89a", "gif", "gif"),
    (b"wxgf", "wxgf", "wxam"),
    (b"WXGF", "wxgf", "wxam"),
)


@dataclass(frozen=True)
class ImageKeys:
    """Resolved V2 keys plus provenance for the UI/diagnostics."""

    code: int
    aes_key: bytes
    xor_key: int
    wxid: str
    source: str = ""

    @property
    def aes_key_ascii(self) -> str:
        try:
            return self.aes_key.decode("ascii")
        except UnicodeDecodeError:  # pragma: no cover - derivation is always ascii
            return self.aes_key.hex()

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "xor_key": f"0x{self.xor_key:02X}",
            "wxid": self.wxid,
            "source": self.source,
            "aes_key_fingerprint": hashlib.sha256(self.aes_key).hexdigest()[:8],
        }


# ------------------------------------------------------------------- deriving

def clean_wxid(value: str | None) -> str:
    """Map ``wxid_abc_8146`` (data-dir name) to the bare ``wxid_abc``."""
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    match = _SUFFIXED_WXID_RE.fullmatch(candidate)
    return match.group(1) if match else candidate


def derive_image_keys(code: int, wxid: str, *, source: str = "") -> ImageKeys:
    """Derive the XOR byte and 16-byte ASCII AES key for one kvcomm code."""
    if isinstance(code, bool) or not isinstance(code, int) or not (0 < code <= _MAX_CODE):
        raise ValueError("code must be an integer in 1..0xffffffff")
    cleaned = clean_wxid(wxid)
    if not cleaned:
        raise ValueError("wxid must not be empty")
    digest = hashlib.md5(f"{code}{cleaned}".encode("utf-8")).hexdigest()
    return ImageKeys(
        code=code,
        aes_key=digest[:16].encode("ascii"),
        xor_key=code & 0xFF,
        wxid=cleaned,
        source=source,
    )


# ------------------------------------------------------------------ kvcomm

def default_wechat_config_roots() -> list[Path]:
    """Standard Windows locations of the ``xwechat`` configuration directory."""
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "Tencent" / "xwechat")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "Tencent" / "xwechat")
    return [r for r in roots if r.is_dir()]


def iter_kvcomm_dirs(roots: Iterable[Path]) -> Iterator[Path]:
    """Yield every ``kvcomm`` cache directory below the given config roots."""
    seen: set[Path] = set()
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        candidates: list[Path] = []
        try:
            candidates.extend(p for p in root.glob("*/kvcomm") if p.is_dir())
            candidates.extend(p for p in root.glob("radium/*/kvcomm") if p.is_dir())
            candidates.extend(p for p in root.glob("radium/*/*/kvcomm") if p.is_dir())
            direct = root / "kvcomm"
            if direct.is_dir():
                candidates.append(direct)
        except OSError:
            continue
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def find_kvcomm_codes(roots: Iterable[Path] | None = None) -> list[tuple[int, str]]:
    """Return ``(code, statistic-file-path)`` for every kvcomm code on disk."""
    if roots is None:
        roots = default_wechat_config_roots()
    found: dict[int, str] = {}
    for kv_dir in iter_kvcomm_dirs(roots):
        try:
            names = os.listdir(kv_dir)
        except OSError:
            continue
        for name in names:
            match = _KVCOMM_KEY_RE.match(name)
            if not match:
                continue
            code = int(match.group(1))
            if 0 < code <= _MAX_CODE and code not in found:
                found[code] = str(kv_dir / name)
    return sorted(found.items())


# ------------------------------------------------------------------ decoding

def image_format_of(plaintext: bytes) -> str | None:
    """Return the image kind (``jpg``/``png``/...) of a decoded payload."""
    if not plaintext:
        return None
    for magic, kind, _family in _MAGICS:
        if plaintext.startswith(magic):
            return kind
    return None


def decrypted_header(data: bytes, aes_key: bytes) -> bytes | None:
    """Decrypt the first V2 block; ``None`` when the data is not a V2 payload."""
    if len(data) < V2_HEADER_SIZE + _AES_BLOCK or data[:6] != V2_MAGIC:
        return None
    from Cryptodome.Cipher import AES

    try:
        cipher = AES.new(aes_key[:_AES_BLOCK], AES.MODE_ECB)
        return cipher.decrypt(bytes(data[V2_HEADER_SIZE : V2_HEADER_SIZE + _AES_BLOCK]))
    except (ValueError, TypeError):  # pragma: no cover - key length is fixed
        return None


def probe_image_keys(keys: ImageKeys, blocks: Sequence[bytes]) -> str | None:
    """Verify a candidate key set against real V2 ciphertext blocks.

    Returns the image kind when *any* block decrypts to a known image signature;
    a wrong key essentially never does (>=3 magic bytes must match).
    """
    for block in blocks:
        if len(block) < _AES_BLOCK:
            continue
        try:
            from Cryptodome.Cipher import AES

            plain = AES.new(keys.aes_key[:_AES_BLOCK], AES.MODE_ECB).decrypt(
                bytes(block[:_AES_BLOCK])
            )
        except (ValueError, TypeError):  # pragma: no cover
            continue
        kind = image_format_of(plain)
        if kind:
            return kind
    return None


def infer_xor_key_from_tail(data: bytes) -> int | None:
    """Recover the trailer XOR byte from the JPEG ``FF D9`` end-of-image marker.

    The trailer is XORed with the same byte used for ``code & 0xFF``, so
    ``tail[0] ^ 0xFF`` must equal ``tail[1] ^ 0xD9``.
    """
    if len(data) < 2:
        return None
    first = data[-2] ^ 0xFF
    second = data[-1] ^ 0xD9
    return first if first == second else None


def decode_v2(data: bytes, keys: ImageKeys) -> bytes:
    """Decode one V2 ``.dat`` payload into its plaintext image bytes."""
    import struct

    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Padding

    if data[:6] != V2_MAGIC:
        raise ValueError("not a V2 dat payload")
    _, aes_size, xor_size = struct.unpack_from("<6sLL", data)
    if aes_size <= 0:
        raise ValueError("V2 header carries a non-positive aes_size")
    aligned = aes_size + _AES_BLOCK - (aes_size % _AES_BLOCK)

    body = data[V2_HEADER_SIZE:]
    if aligned > len(body):
        raise ValueError("V2 header claims more ciphertext than the file holds")

    plain = AES.new(keys.aes_key[:_AES_BLOCK], AES.MODE_ECB).decrypt(body[:aligned])
    try:
        plain = Padding.unpad(plain, _AES_BLOCK)
    except ValueError:
        # Tolerate a non-PKCS7 tail rather than dropping the image entirely.
        pass

    if xor_size:
        middle = body[aligned : len(body) - xor_size]
        trailer = bytes(b ^ keys.xor_key for b in body[-xor_size:])
    else:
        middle = body[aligned:]
        trailer = b""
    return plain + middle + trailer


# ------------------------------------------------------------------ templates

def v2_template_blocks(
    account_dir: Path,
    *,
    limit: int = 24,
    max_scan: int = 4000,
) -> list[bytes]:
    """Collect ciphertext blocks from the account's own V2 image files.

    Only the 15-byte header plus the first AES block is read per file, so this
    stays cheap even on accounts with tens of thousands of images.
    """
    attach = Path(account_dir) / "msg" / "attach"
    if not attach.is_dir():
        return []
    blocks: list[bytes] = []
    scanned = 0
    try:
        sender_dirs = [p for p in os.scandir(attach) if p.is_dir()][:200]
    except OSError:
        return []
    for sender in sender_dirs:
        try:
            month_dirs = [p for p in os.scandir(sender.path) if p.is_dir()]
        except OSError:
            continue
        for month in month_dirs:
            img_dir = Path(month.path) / "Img"
            if not img_dir.is_dir():
                continue
            try:
                entries = os.scandir(img_dir)
            except OSError:
                continue
            with entries:
                for entry in entries:
                    if not entry.name.endswith(".dat"):
                        continue
                    scanned += 1
                    if scanned > max_scan:
                        break
                    try:
                        with open(entry.path, "rb") as handle:
                            head = handle.read(V2_HEADER_SIZE + _AES_BLOCK)
                    except OSError:
                        continue
                    if head[:6] == V2_MAGIC:
                        blocks.append(head[V2_HEADER_SIZE:])
                        if len(blocks) >= limit:
                            return blocks
            if scanned > max_scan:
                break
        if scanned > max_scan:
            break
    return blocks


class ImageKeyResolver:
    """Resolve (and cache) the V2 key set for one account."""

    def __init__(
        self,
        account_dir: Path,
        account_id: str,
        *,
        config_roots: Iterable[Path] | None = None,
    ) -> None:
        self.account_dir = Path(account_dir)
        self.account_id = account_id
        self._config_roots = list(config_roots) if config_roots is not None else None
        self._keys: ImageKeys | None = None
        self._resolved = False
        self._reason = ""

    # ------------------------------------------------------------------ api
    @property
    def reason(self) -> str:
        """Human-readable explanation when no key set could be resolved."""
        return self._reason

    def keys(self) -> ImageKeys | None:
        if not self._resolved:
            self._keys = self._resolve()
            self._resolved = True
        return self._keys

    def invalidate(self) -> None:
        self._resolved = False
        self._keys = None
        self._reason = ""

    # -------------------------------------------------------------- internals
    def _resolve(self) -> ImageKeys | None:
        wxid = clean_wxid(self.account_id)
        roots = self._config_roots
        candidates = find_kvcomm_codes(roots)
        if not candidates:
            self._reason = "未找到 kvcomm 密钥缓存（微信尚未登录过该账号？）"
            return None

        blocks = v2_template_blocks(self.account_dir)
        if not blocks:
            self._reason = "该账号目录下没有 V2 图片可供校验"
            return None

        for code, path in candidates:
            try:
                keys = derive_image_keys(code, wxid, source=path)
            except ValueError:
                continue
            kind = probe_image_keys(keys, blocks)
            if kind:
                self._reason = ""
                return keys

        self._reason = "kvcomm 中的候选密钥均无法解密本账号的 V2 图片"
        return None

    # ----------------------------------------------------------- diagnostics
    def describe(self) -> dict[str, object]:
        keys = self.keys()
        if keys is None:
            return {"status": "unavailable", "reason": self._reason}
        return {"status": "ok", **keys.as_dict()}
