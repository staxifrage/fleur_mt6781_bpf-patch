#!/usr/bin/env python3
"""Disassemble a range of a raw arm64 kernel Image.

    pip install capstone
    python3 research/disasm.py dump/kernel 0x178080 0x178120      # file offsets, hex

Handy for checking which function a patch site really lives in: look for the prologue
(stp x29,x30 / sub sp), the argument registers it uses, and where the branch targets go.
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

path, start = sys.argv[1], int(sys.argv[2], 16)
end = int(sys.argv[3], 16) if len(sys.argv) > 3 else start + 0x100
data = open(path, "rb").read()
for i in Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(data[start:end], start):
    print(f"0x{i.address:x}: {i.mnemonic} {i.op_str}")
