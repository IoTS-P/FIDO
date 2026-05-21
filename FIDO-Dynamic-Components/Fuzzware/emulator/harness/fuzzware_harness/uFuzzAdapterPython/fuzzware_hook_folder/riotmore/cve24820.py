from fuzzware_harness import globs
from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x20fc70

def on_CVE(uc):
    try:
        sixlo_size = uc.regs.r2
        payload_offset = uc.regs.r4
    except UcError:
        return None

    if payload_offset > sixlo_size:
        add_bug("new-Bug-CVE-2023-24820")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)

