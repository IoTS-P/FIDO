from fuzzware_harness import globs
from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x20d696

def on_CVE(uc):
    try:
        frag_size = uc.regs.r4
    except UcError:
        return None

    if frag_size > 0x80000000:
        add_bug("new-Bug-CVE-2023-24821")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)
