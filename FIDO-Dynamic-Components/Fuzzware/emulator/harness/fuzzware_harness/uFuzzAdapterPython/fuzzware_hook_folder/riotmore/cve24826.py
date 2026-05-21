from unicorn import UcError

def add_bug(name):
    print(f"Heureka! {name}", flush=True)

def sched_arq_timeout(uc):
    try:
        timer = uc.symbols['_arq_timer']
        callback = uc.mem.u32(timer + 8)
    except UcError:
        return None

    if callback == 0:
        add_bug("new-Bug-CVE-2023-24826")

def check_and_call(uc, address, size, user_data):
    pc = uc.regs.pc
    if pc == uc.symbols['_sched_arq_timeout']:
        sched_arq_timeout(uc)

