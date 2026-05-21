from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

class Pktbuf:
    def __init__(self, data_nullptr=0):
        self.data_nullptr = data_nullptr

pktbuf = Pktbuf()

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

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == uc.symbols['gnrc_pktbuf_mark']:
        on_gnrc_pktbuf_mark(uc)
    elif pc == uc.symbols['gnrc_sixlowpan_iphc_recv']:
        on_gnrc_sixlowpan_iphc_recv(uc)

