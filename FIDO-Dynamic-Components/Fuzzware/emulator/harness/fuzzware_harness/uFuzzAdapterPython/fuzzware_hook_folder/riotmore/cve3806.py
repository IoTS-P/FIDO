from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x8006a44

def on_CVE(uc):
    try:
        driver_fn_err = uc.regs.r4
    except UcError:
        return None

    # The bug occurs in case net_buf_unref is called despite an error being returned
    if driver_fn_err != 0:
        add_bug("new-Bug-CVE-2022-3806")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)

