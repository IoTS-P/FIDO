from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x00205b48

def on_CVE(uc):
    try:
        chan_ind = uc.regs.r6
    except UcError:
        return None

    if (chan_ind >> 8) & 0xff != 0:
        add_bug("new-Bug-CVE-2022-41873")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)
