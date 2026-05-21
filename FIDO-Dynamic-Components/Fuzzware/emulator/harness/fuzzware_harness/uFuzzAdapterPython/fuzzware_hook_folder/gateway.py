import json
# map
fucntion_times = {}
#0x8001c82:0,0x8001bf0:0,
addr_times = {0x8001c42:0,0x8001c56:0,0x8001c76:0,0x8001c82:0}
from unicorn import UC_HOOK_CODE,UC_HOOK_BLOCK
from ...globs import uc
# Create a reverse mapping of function addresses to function names
gateway_address_to_word = None

def add_bug(name):
    print(f"Heureka! {name}", flush=True)
def addr_times_handler(uc, address, size, user_data):
    addr_times[address] += 1
    print(json.dumps(addr_times))
    # if address == 0x80069f4 and uc.regs.r0 == 0:
    #     add_bug("gateway-80069f4")


def hook_gateway_addr(uc):
    for address in addr_times.keys():
        uc.hook_add(UC_HOOK_CODE, addr_times_handler, begin=address-1, end=address|1)

# def hook_gateway_bug(uc, address, size, user_data):
#     if uc.regs.pc == 0x80069f4:
#         add_bug("gateway-80069f4")