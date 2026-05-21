#!/usr/bin/env python3

import re
import struct
from intelhex import IntelHex

reg_names = ['r0', 'r1', 'r2', 'r3', 'r4',
        'r5', 'r6', 'r7', 'r8', 'r9',
        'r10', 'r11', 'r12', 'lr', 'pc',
        'sp', 'xpsr']

def load_state(filename):
    reg_regex = re.compile(r"^([^=]{2,4})=0x([0-9a-f]+)$")

    with open(filename, "r") as file:
        reg_vals = {}

        for _ in range(len(reg_names)):
            line = file.readline()
            name, val_str = reg_regex.match(line).groups()
            val = int(val_str, 16)
            reg_vals[name] = val

        mem_segments = {}
        intel_hex = IntelHex(file)
        for addr, end in intel_hex.segments():
            contents = intel_hex.gets(addr, end - addr)
            mem_segments[addr] = contents

        return reg_vals, mem_segments

def get_dword(regions, wanted):
    for addr, content in regions.items():
        if addr <= wanted <= addr + len(content) - 4:
            return struct.unpack("<I", content[wanted-addr:wanted-addr+4])[0]

    return 0

def is_mapped_and_non_full_zero_page(regions, wanted):
    for addr, content in regions.items():
        if addr <= wanted <= addr + len(content) - 4:
            return True

    return False
