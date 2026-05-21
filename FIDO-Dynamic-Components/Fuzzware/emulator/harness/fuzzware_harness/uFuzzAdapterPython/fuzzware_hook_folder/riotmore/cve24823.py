from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x20f150

def on_CVE(uc):
    try:
        snippet = uc.regs.r3
        size = uc.mem.u32(snippet + 8)
    except UcError:
        return None

    if size > 8:
        add_bug("new-Bug-CVE-2023-24823")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)
