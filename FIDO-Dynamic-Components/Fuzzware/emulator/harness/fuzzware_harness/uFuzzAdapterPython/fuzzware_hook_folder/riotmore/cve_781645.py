from fuzzware_harness import globs
from unicorn import UcError
class NetifHdr:
    def __init__(self, missing_src=0):
        self.missing_src = missing_src

netif_hdr = NetifHdr()

class Pktbuf:
    def __init__(self, data_nullptr=0):
        self.data_nullptr = data_nullptr

pktbuf = Pktbuf()

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# 24817
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
        
# 24818
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

# 24819
def on_24819(uc):
    try:
        ipv6 = uc.regs.r6
        ipv6_size = uc.mem.u32(ipv6 + 8)
        uncomp_header_len = uc.regs.r5
        copy_size = uc.regs.r2
    except UcError:
        return None

    if uncomp_header_len + copy_size > ipv6_size:
        add_bug("new-Bug-CVE-2023-24819")

# 24820
def on_24820(uc):
    try:
        sixlo_size = uc.regs.r2
        payload_offset = uc.regs.r4
    except UcError:
        return None

    if payload_offset > sixlo_size:
        add_bug("new-Bug-CVE-2023-24820")

# 24821
def on_24821(uc):
    try:
        frag_size = uc.regs.r4
    except UcError:
        return None

    if frag_size > 0x80000000:
        add_bug("new-Bug-CVE-2023-24821")

# 24822
def on_24822(uc):
    try:
        pkt = uc.regs.r7
        next = uc.mem.u32(pkt)
        next_next = uc.mem.u32(next)
    except UcError:
        return None

    if next_next == 0:
        add_bug("new-Bug-CVE-2023-24822")

# 24823
def on_24823(uc):
    try:
        snippet = uc.regs.r3
        size = uc.mem.u32(snippet + 8)
    except UcError:
        return None

    if size > 8:
        add_bug("new-Bug-CVE-2023-24823")

# 24825
def on_gnrc_pktbuf_mark(uc):
    try:
        pkt = uc.regs.r0
        pkt_size = uc.mem.u32(pkt + 8)
        mark_size = uc.regs.r1
    except UcError:
        return None

    if pkt_size == mark_size:
        pktbuf.data_nullptr = 1

def on_gnrc_sixlowpan_iphc_recv(uc):
    try:
        sixlo = uc.regs.r0
        data = uc.mem.u32(sixlo + 4)
    except UcError:
        return None

    # check NULL pointer deref on sixlo->data
    if data == 0 and pktbuf.data_nullptr == 1:
        add_bug("new-Bug-CVE-2023-24825")

# 24826
def sched_arq_timeout(uc):
    try:
        timer = uc.symbols['_arq_timer']
        callback = uc.mem.u32(timer + 8)
    except UcError:
        return None

    if callback == 0:
        add_bug("new-Bug-CVE-2023-24826")

def check_call(uc, address, size, user_data):
    symbol_function = {
        uc.symbols['gnrc_rpl_srh_process']: on_gnrc_rpl_srh_process,
        uc.symbols['gnrc_sixlowpan_frag_vrb_get']: on_gnrc_sixlowpan_frag_vrb_get,
        uc.symbols['gnrc_netif_hdr_build']: on_gnrc_netif_hdr_build,
        0x20fcb2: on_24819,# bl memcpy
        0x20fc3e: on_24820,# subs       ext_len,ext_len,r4
        0x20d660: on_24821,# add.w      r9,rfrag,#0x4
        0x20f180: on_24822,# mov        tmp,r6
        # 0x20f108: on_24823,# adds       dispatch_size,#0x8
        uc.symbols['gnrc_pktbuf_mark']: on_gnrc_pktbuf_mark,
        uc.symbols['gnrc_sixlowpan_iphc_recv']: on_gnrc_sixlowpan_iphc_recv,
        uc.symbols['_sched_arq_timeout']: sched_arq_timeout
    }
    
    # 检查address是否在symbol_function字典中
    if address in symbol_function:
        function_name = symbol_function[address]
        print(f"Function {function_name.__name__} is called at address {hex(address)}")
        function_name(uc)

