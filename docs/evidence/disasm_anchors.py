"""Disassemble around the two MMV1 anchors in Weixin.dll 4.1.12.55 to locate codec function entries."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = r"C:\Program Files\Weixin\4.1.12.55\Weixin.dll"
A_OFF = 0x353B099   # lea rcx, [MMV1 str]
B_OFF = 0x704F904   # cmp dword ptr [rcx], 'MMV1'

pe = pefile.PE(DLL, fast_load=True)
text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text_raw = open(DLL, "rb").read()[text.PointerToRawData : text.PointerToRawData + text.SizeOfRawData]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False


def show(off_in_text, label, before=0x140, after=0x60):
    print(f"\n===== {label}  (text-offset 0x{off_in_text:X}, file-offset 0x{text.PointerToRawData + off_in_text:X}) =====")
    chunk = text_raw[off_in_text - before : off_in_text + after]
    base = off_in_text - before
    # print hex column with file offsets of boundaries
    for insn in md.disasm(chunk, text.VirtualAddress + base):
        marker = "  <-- ANCHOR" if abs(insn.address - (text.VirtualAddress + off_in_text)) < 8 else ""
        print(f"  0x{insn.address:09X}  {insn.mnemonic:8s} {insn.op_str}{marker}")


show(A_OFF, "anchor A: lea rcx,[MMV1str] (0x353B099)")
show(B_OFF, "anchor B: cmp [rcx],'MMV1' (0x704F904)")
