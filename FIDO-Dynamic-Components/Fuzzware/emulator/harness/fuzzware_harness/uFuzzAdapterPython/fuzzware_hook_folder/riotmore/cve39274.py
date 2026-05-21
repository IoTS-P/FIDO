from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x08006c62

def on_CVE(uc):
    try:
        size = uc.regs.r6
    except UcError:
        return None

    if size == 0:
        add_bug("new-Bug-CVE-2022-39274")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)
