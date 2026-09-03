"""Find candidate function entries above anchor A (file 0x353B099) in Weixin.dll .text."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = r"C:\Program Files\Weixin\4.1.12.55\Weixin.dll"
ANCHOR_A = 0x353B099

pe = pefile.PE(DLL, fast_load=True)
text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
raw = open(DLL, "rb").read()
lo = ANCHOR_A - text.PointerToRawData  # offset inside .text raw
chunk = raw[text.PointerToRawData + lo - 0x4000 : text.PointerToRawData + lo]
# scan for typical x64 prologue starts
import re

# patterns (bytes within chunk); we search relative to anchor going backwards
base = lo - 0x4000
patterns = {
    "mov[rsp+8]": b"\x48\x89\x5c\x24\x08",
    "mov[rsp+10]": b"\x48\x89\x6c\x24\x10",
    "mov[rsp+18]": b"\x48\x89\x74\x24\x18",
    "push_rbx": b"\x40\x53",
    "push_rbp": b"\x40\x55",
    "push_rdi": b"\x40\x57",
    "push_r14": b"\x41\x56",
    "sub_rsp_big": b"\x48\x81\xec",
    "sec_cookie_xor": b"\x48\x33\xc4",  # xor rax,rsp? no: xor eax/rax, rsp is 48 33 C4
    "mov_rcx_rsp48": b"\x48\x8b\xc4",
    "int3cc": b"\xcc\xcc\xcc\xcc",
}
hits = {}
for name, pat in patterns.items():
    pos = 0
    while True:
        i = chunk.find(pat, pos)
        if i < 0:
            break
        off = base + i
        if off < lo:
            hits.setdefault(name, []).append(off)
        pos = i + 1

cands = set()
for name, lst in hits.items():
    for off in lst:
        # distance from anchor
        if 0 < lo - off <= 0x4000:
            cands.add(off)
cands = sorted(cands, key=lambda o: lo - o)
print("candidate prologues before anchor (text-internal offsets, nearest first):")
for off in cands[:25]:
    print(f"  text+0x{off:X}  file 0x{text.PointerToRawData + off:X}  dist={lo - off:#x}")

# print disassembly from the closest few candidates
md = Cs(CS_ARCH_X86, CS_MODE_64)
shown = 0
for off in cands:
    if shown >= 3:
        break
    # sanity: ensure preceding bytes look like padding/prologue region & function has room
    va = text.VirtualAddress + off
    dis = md.disasm(raw[text.PointerToRawData + off : text.PointerToRawData + off + 0x60], va)
    print(f"\n--- candidate entry text+0x{off:X} (file 0x{text.PointerToRawData + off:X}) ---")
    count = 0
    for insn in dis:
        print(f"  0x{insn.address:09X}  {insn.mnemonic:8s} {insn.op_str}")
        count += 1
        if count >= 18 or insn.mnemonic == "ret":
            break
    shown += 1
