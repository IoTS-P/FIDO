from fuzzware_harness import globs
from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

def on_gnrc_rpl_srh_process(uc):
    rh = uc.regs.r1
    try:
        len = uc.mem.u8(rh + 1)
        compre = uc.mem.u8(rh + 4) & 0x0F
        padding = uc.mem.u8(rh + 5) >> 4
    except UcError:
        return None

    if len * 8 < padding + (16 - compre):
        add_bug("new-Bug-CVE-2023-24817")

def call_on_gnrc_rpl_srh_process(uc, address, size, user_data):
    if uc.regs.pc == uc.symbols['gnrc_rpl_srh_process']:
        on_gnrc_rpl_srh_process(uc)
