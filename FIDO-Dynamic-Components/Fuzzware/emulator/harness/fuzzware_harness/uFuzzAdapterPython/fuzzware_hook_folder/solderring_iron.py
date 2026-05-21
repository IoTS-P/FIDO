import json
from unicorn import UC_HOOK_BLOCK
addr_times = {}
def addr_times_handler(uc, address, size, user_data):
    addr_times[address] += 1
    print(json.dumps(addr_times))

def global_block_handler(uc, address, size, user_data):
    if address in addr_times:
        addr_times[address] += 1
        print(json.dumps(addr_times))

def avail_div_allfunc(uc):
    import yaml
    symbols = {}
    with open("/home/n0vic3/fuzzers/fuzzware-uFuzzAdapter/emulator/harness/fuzzware_harness/uFuzzAdapterPython/fuzzware_hook_folder/solderring_iron_symbols.yml","r") as f:
        symbols = yaml.safe_load(f)
    # print(symbols)
    for address in symbols["symbols"].keys():
    # 为每个地址添加代码hook
        addr_times[address] = 0
    uc.hook_add(UC_HOOK_BLOCK, global_block_handler, user_data=None, begin=0, end=0xffffffff)