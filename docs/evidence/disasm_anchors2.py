"""Disassemble precisely around MMV1 anchors (file offsets), locate function entries."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = r"C:\Program Files\Weixin\4.1.12.55\Weixin.dll"
A_FILE = 0x353B099   # lea rcx,[MMV1str]  (instr start)
B_FILE = 0x704F902   # 81 39 4D 4D 56 31 -> cmp dword ptr [rcx], 'MMV1' (instr start, 2 bytes before magic)

pe = pefile.PE(DLL, fast_load=True)
text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
assert text.PointerToRawData <= A_FILE < text.PointerToRawData + text.SizeOfRawData
raw = open(DLL, "rb").read()


def local_of(file_off):
    return file_off - text.PointerToRawData


def disasm_window(file_off, label, before=0x240, after=0x80):
    lo = local_of(file_off)
    chunk = raw[file_off - before : file_off + after]
    base_va = text.VirtualAddress + (lo - before)
    print(f"\n===== {label} :: anchor file-off=0x{file_off:X} (va=0x{text.VirtualAddress + lo:X}) =====")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    anchor_va = text.VirtualAddress + lo
    for insn in md.disasm(chunk, base_va):
        mark = "   <== ANCHOR" if insn.address == anchor_va else ""
        if insn.address >= anchor_va - 0x30 or mark:
            print(f"  0x{insn.address:09X}  {insn.mnemonic:8s} {insn.op_str}{mark}")


# A: show a window that starts well before the containing function
disasm_window(A_FILE, "anchor A lea rcx,[MMV1str]", before=0x600, after=0x20)
disasm_window(B_FILE, "anchor B cmp [rcx],'MMV1'", before=0x240, after=0x20)
