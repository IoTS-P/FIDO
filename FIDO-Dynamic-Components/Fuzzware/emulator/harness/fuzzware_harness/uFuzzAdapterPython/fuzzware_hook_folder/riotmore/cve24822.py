from fuzzware_harness import globs
from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x20f192

def on_CVE(uc):
    try:
        pkt = uc.regs.r7
        next = uc.mem.u32(pkt)
        next_next = uc.mem.u32(next)
    except UcError:
        return None

    if next_next == 0:
        add_bug("new-Bug-CVE-2023-24822")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)
