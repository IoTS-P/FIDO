from fuzzware_harness import globs
from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

class NetifHdr:
    def __init__(self, missing_src=0):
        self.missing_src = missing_src

netif_hdr = NetifHdr()

def on_gnrc_sixlowpan_frag_vrb_get(uc):
    try:
        src_len = uc.regs.r1
    except UcError:
        return None

    if src_len == 0:
        netif_hdr.missing_src = 1

def on_gnrc_netif_hdr_build(uc):
    try:
        src_len = uc.regs.r1
    except UcError:
        return None

    if src_len == 0 and netif_hdr.missing_src == 1:
        add_bug("new-Bug-CVE-2023-24818")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == uc.symbols['gnrc_sixlowpan_frag_vrb_get']:
        on_gnrc_sixlowpan_frag_vrb_get(uc)
    elif pc == uc.symbols['gnrc_netif_hdr_build']:
        on_gnrc_netif_hdr_build(uc)

