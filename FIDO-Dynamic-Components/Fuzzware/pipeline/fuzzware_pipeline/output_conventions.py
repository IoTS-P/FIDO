import re

MSG_HIT_EXITAT_ADDRESS = b"Hit exit basic block address: "
MSG_HIT_EXITAT_ADDRESS_END = b","
def exit_at_address_from_emu_output(emu_output):
    start = emu_output.find(MSG_HIT_EXITAT_ADDRESS)
    if start == -1:
        return None
    start += len(MSG_HIT_EXITAT_ADDRESS)
    end = emu_output.find(MSG_HIT_EXITAT_ADDRESS_END, start)
    if end == -1:
        return None

    addr_str = emu_output[start:end]
    return int(addr_str, 16)

REGEX_INVALID_ACCESS_ADDR = r"INVALID (?:READ|WRITE|Write|Read): addr\= 0x([0-9a-fA-F]+)"
def segfault_addr_from_emu_output(emu_output):
    m = re.findall(REGEX_INVALID_ACCESS_ADDR, emu_output)

    if len(m) == 1:
        return int(m[0], 16)
    return None

REGEX_PC = r"pc: (0x[0-9a-fA-F]*)"
REGEX_LR = r"lr: (0x[0-9a-fA-F]*)"
def pc_lr_from_emu_output(emu_output):
    m = re.findall(REGEX_PC, emu_output)

    if len(m) == 1:
        pc = int(m[0], 16)
        m = re.findall(REGEX_LR, emu_output)
        if len(m) == 1:
            lr = int(m[0], 16)
            return pc, lr

    return None, None
