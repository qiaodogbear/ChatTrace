"""Locate 'MMV1' magic references in Weixin.dll (4.1.12.55) to find the codec config function.

Outputs file offsets / RVAs / VAs and surrounding bytes for human review.
"""
import struct
import sys

DLL = r"C:\Program Files\Weixin\4.1.12.55\Weixin.dll"
KNOWN_26_OFFSET = 0x3486140  # codec config function entry offset reported for 4.1.12.26

import pefile

pe = pefile.PE(DLL, fast_load=True)
image_base = pe.OPTIONAL_HEADER.ImageBase
sections = []
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode("ascii", "replace")
    sections.append(
        {
            "name": name,
            "va": s.VirtualAddress,
            "vsize": s.Misc_VirtualSize,
            "raw_ptr": s.PointerToRawData,
            "raw_size": s.SizeOfRawData,
        }
    )
print("image_base =", hex(image_base))
for s in sections:
    print(f"section {s['name']:<8} rva=0x{s['va']:08X} vsize=0x{s['vsize']:08X} raw=0x{s['raw_ptr']:08X} rawsize=0x{s['raw_size']:08X}")

data = open(DLL, "rb").read()
print("file size =", len(data))


def file_off_to_rva(off: int):
    for s in sections:
        if s["raw_ptr"] <= off < s["raw_ptr"] + s["raw_size"]:
            return s["va"] + (off - s["raw_ptr"])
    return None


# 1) find MMV1 occurrences
mmv1_file_offs = []
start = 0
while True:
    i = data.find(b"MMV1", start)
    if i < 0:
        break
    mmv1_file_offs.append(i)
    start = i + 1
print(f"\nMMV1 occurrences (file offsets): {len(mmv1_file_offs)}")
mmv1_vas = set()
for off in mmv1_file_offs:
    rva = file_off_to_rva(off)
    if rva is None:
        print(f"  off=0x{off:X} outside sections")
        continue
    va = image_base + rva
    mmv1_vas.add(va)
    print(f"  off=0x{off:X} rva=0x{rva:X} va=0x{va:X} ctx={data[off-16:off+16]!r}")

# 2) scan .text for rip-relative lea/mov referencing any MMV1 VA
text = next((s for s in sections if s["name"] == ".text"), None)
if text is None:
    print("no .text section")
    sys.exit(1)

text_raw = data[text["raw_ptr"] : text["raw_ptr"] + text["raw_size"]]
PREFIXES = {0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D}
refs = []  # (instr_rva, prefix_len, opcode, target_va, raw_bytes)
i = 0
n = len(text_raw)
while i < n:
    b = text_raw[i]
    opcode = None
    prefix_len = 0
    if b in (0x8D, 0x8B) and i >= 1 and text_raw[i - 1] in PREFIXES:
        opcode = b
        prefix_len = 1
    elif b in (0x8D, 0x8B) and i >= 2 and text_raw[i - 1] in PREFIXES and text_raw[i - 2] in PREFIXES:
        # two prefixes (rare) e.g. 41 48 8D? not typical; keep simple
        pass
    if opcode is not None and (text_raw[i + 1] & 0xC7) == 0x05:
        modrm = text_raw[i + 1]
        if i + 6 < n:
            disp = struct.unpack_from("<i", text_raw, i + 2)[0]
            instr_len = 1 + prefix_len + 1 + 4  # opcode + prefix + modrm + disp32
            instr_rva = text["va"] + (i - prefix_len)
            instr_end_va = image_base + instr_rva + instr_len
            target = instr_end_va + disp
            if target in mmv1_vas:
                raw = text_raw[i - prefix_len : i - prefix_len + instr_len]
                refs.append((instr_rva, prefix_len, opcode, target, raw))
    i += 1

print(f"\nrip-relative refs to MMV1 in .text: {len(refs)}")
for rva, plen, opcode, target, raw in refs:
    off = text["raw_ptr"] + (rva - text["va"])
    print(
        f"  instr rva=0x{rva:X} off=0x{off:X} opcode=0x{opcode:X} target_va=0x{target:X} bytes={raw.hex()}"
    )

# 3) nearest earlier function-entry heuristics: show preceding bytes around each ref
for rva, plen, opcode, target, raw in refs:
    print(f"\n--- context before ref at rva=0x{rva:X} ---")
    ctx_start = text["va"] - rva + max(0, (rva - text["va"]) - 0x80)
    # simpler: print previous 0x40 bytes raw
    local = rva - text["va"]
    for back in (0x10, 0x40, 0x100):
        if local - back >= 0:
            chunk = text_raw[local - back : local]
            print(f"  prev {back:#x} bytes: {chunk.hex()}")
            break
