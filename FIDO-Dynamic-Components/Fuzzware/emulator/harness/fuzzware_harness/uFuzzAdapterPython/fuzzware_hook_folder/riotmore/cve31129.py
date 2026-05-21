from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

# HOOKED_ADDR constant
HOOKED_ADDR = 0x207d9c

def on_CVE(uc):
    try:
        retval = uc.regs.r0
    except UcError:
        return None

    # Check for NULL pointer condition of return value
    if retval == 0:
        add_bug("new-Bug-CVE-2023-31129")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == HOOKED_ADDR:
        on_CVE(uc)
