"""Automatic static location of the WeChat 4.x codec anchors inside Weixin.dll.

Strategy (verified on 4.1.12.55, see docs/evidence/):
1. Find the 'MMV1' magic:
   a) as an immediate operand of `cmp dword ptr [reg], 'MMV1'` in .text  (magic_check)
   b) as a string literal in .rdata
2. Scan .text for rip-relative lea/mov that references the .rdata string (mmv1_ref).
3. Walk backwards from that reference to the enclosing function entry (entry).
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

from ..models import AnchorSet

PREFIXES = {0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D}
PROLOGUE_PATTERNS = (
    b"\x48\x89\x5c\x24\x08",  # mov [rsp+8], rbx
    b"\x48\x89\x6c\x24\x10",  # mov [rsp+10h], rbp
    b"\x48\x89\x74\x24\x18",  # mov [rsp+18h], rsi
    b"\x48\x89\x7c\x24\x20",  # mov [rsp+20h], rdi
    b"\x40\x53",  # push rbx
    b"\x40\x55",  # push rbp
    b"\x40\x56",  # push rsi
    b"\x40\x57",  # push rdi
    b"\x48\x81\xec",  # sub rsp, imm32
    b"\x48\x83\xec",  # sub rsp, imm8
    b"\x48\x8b\xc4",  # mov rax, rsp
)


class LocateError(RuntimeError):
    pass


def _load_pe_sections(dll_bytes: bytes) -> tuple[int, list[dict]]:
    if len(dll_bytes) < 0x40 or dll_bytes[:2] != b"MZ":
        raise LocateError("not a PE file")
    pe_off = struct.unpack_from("<I", dll_bytes, 0x3C)[0]
    if dll_bytes[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise LocateError("invalid PE signature")
    num_sections = struct.unpack_from("<H", dll_bytes, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", dll_bytes, pe_off + 20)[0]
    image_base = struct.unpack_from("<Q", dll_bytes, pe_off + 24)[0]
    opt = pe_off + 24
    if dll_bytes[opt] == 0x20:  # PE32+
        image_base = struct.unpack_from("<Q", dll_bytes, pe_off + 24)[0]
    else:
        image_base = struct.unpack_from("<I", dll_bytes, pe_off + 28)[0]
    section_table = opt + opt_size
    sections = []
    for i in range(num_sections):
        base = section_table + i * 40
        name = dll_bytes[base : base + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize = struct.unpack_from("<I", dll_bytes, base + 8)[0]
        va = struct.unpack_from("<I", dll_bytes, base + 12)[0]
        raw_size = struct.unpack_from("<I", dll_bytes, base + 16)[0]
        raw_ptr = struct.unpack_from("<I", dll_bytes, base + 20)[0]
        sections.append(
            {"name": name, "va": va, "vsize": vsize, "raw_ptr": raw_ptr, "raw_size": raw_size}
        )
    return image_base, sections


def _rva_of_file_off(sections: list[dict], off: int) -> int | None:
    for s in sections:
        if s["raw_ptr"] <= off < s["raw_ptr"] + s["raw_size"]:
            return s["va"] + (off - s["raw_ptr"])
    return None


def locate_anchors(weixin_dll: Path, wechat_version: str = "unknown") -> AnchorSet:
    dll_path = Path(weixin_dll).resolve()
    if not dll_path.exists():
        raise LocateError(f"Weixin.dll not found: {dll_path}")
    data = dll_path.read_bytes()
    image_base, sections = _load_pe_sections(data)
    text = next((s for s in sections if s["name"] == ".text"), None)
    if text is None:
        raise LocateError("no .text section")

    def text_local(off: int) -> int | None:
        return off - text["raw_ptr"] if text["raw_ptr"] <= off < text["raw_ptr"] + text["raw_size"] else None

    # 1) magic immediate: cmp dword ptr [reg], 'MMV1' -> bytes 81 <modrm in 0x38..0x3F> 4D 4D 56 31
    #    (mod=00; rm=000..111; e.g. 0x39 == [rcx] on 4.1.12.55)
    magic_rva: int | None = None
    start = 0
    while True:
        i = data.find(b"MMV1", start)
        if i < 0:
            break
        if i >= 2 and data[i - 2] == 0x81 and 0x38 <= data[i - 1] <= 0x3F:
            rva = _rva_of_file_off(sections, i - 2)
            if rva is not None:
                magic_rva = rva
                break
        start = i + 1

    # 2) .rdata string MMV1 + rip-rel references
    rdata = next((s for s in sections if s["name"].lower() in (".rdata", "_rdata")), None)
    str_vas: set[int] = set()
    if rdata:
        start = 0
        while True:
            i = data.find(b"MMV1", start)
            if i < 0:
                break
            rva = _rva_of_file_off(sections, i)
            if rva is not None and text["va"] <= rva:  # in .rdata (after .text)
                str_vas.add(image_base + rva)
            start = i + 1

    ref_rvas: list[int] = []
    raw = data[text["raw_ptr"] : text["raw_ptr"] + text["raw_size"]]
    for i in range(len(raw) - 7):
        b0 = raw[i]
        if b0 not in (0x8D, 0x8B) or i < 1 or raw[i - 1] not in PREFIXES:
            continue
        if raw[i + 1] & 0xC7 != 0x05:
            continue
        disp = struct.unpack_from("<i", raw, i + 2)[0]
        prefix_len = 1
        instr_len = 1 + prefix_len + 1 + 4
        instr_rva = text["va"] + (i - prefix_len)
        target = image_base + instr_rva + instr_len + disp
        if target in str_vas:
            ref_rvas.append(instr_rva)
    if not ref_rvas:
        raise LocateError("no rip-relative reference to MMV1 string found")

    # 3) enclosing function entry: walk backwards for prologue/padding
    ref_rva = min(ref_rvas)
    entry_rva: int | None = None
    local = ref_rva - text["va"]
    if local is not None:
        window = raw[max(0, local - 0x4000) : local]
        window_base = max(0, local - 0x4000)
        best: int | None = None
        for pat in PROLOGUE_PATTERNS:
            pos = 0
            while True:
                j = window.find(pat, pos)
                if j < 0:
                    break
                cand = window_base + j
                if cand < local:
                    best = cand if best is None else max(best, cand)  # nearest to anchor
                pos = j + 1
        if best is not None:
            # prefer a candidate whose preceding bytes look like padding/other func
            entry_rva = text["va"] + best
    if entry_rva is None:
        raise LocateError("could not determine enclosing function entry above MMV1 reference")

    return AnchorSet(
        wechat_version=wechat_version,
        entry=entry_rva,
        mmv1_ref=ref_rva,
        magic_check=magic_rva if magic_rva is not None else 0,
    )
