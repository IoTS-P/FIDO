from fuzzware_harness import globs
from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x20fc4e

def on_CVE(uc):
    try:
        ipv6 = uc.regs.r6
        ipv6_size = uc.mem.u32(ipv6 + 8)
        uncomp_header_len = uc.regs.r5
        copy_size = uc.regs.r2
    except UcError:
        return None

    if uncomp_header_len + copy_size > ipv6_size:
        add_bug("new-Bug-CVE-2023-24819")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)
