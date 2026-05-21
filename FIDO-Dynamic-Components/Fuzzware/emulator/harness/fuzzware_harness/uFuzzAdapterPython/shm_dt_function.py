import os,pickle,ctypes,json
from ..util import my_debug_log
from unicorn import UC_HOOK_CODE,UC_HOOK_BLOCK

def find_rule_file(binary_dir):
    """Find semu-fuzz rule file (*.txt with R_/T_/S_ lines) in directory."""
    for f in os.listdir(binary_dir):
        if not f.endswith('.txt'):
            continue
        fpath = os.path.join(binary_dir, f)
        try:
            with open(fpath) as fp:
                first = fp.readline().strip()
                if first and first[0] in 'RTSCO' and '_' in first:
                    return fpath
        except Exception:
            continue
    return None

def find_json_file(binary_dir):
    """Find DT JSON file in directory (not shared_memory files)."""
    for f in os.listdir(binary_dir):
        if f.endswith('.json') and 'shared_memory' not in f.lower():
            return os.path.join(binary_dir, f)
    return None

def parse_rule_file(rule_path):
    """Extract DR (R_/T_) and SR (S_) addresses from semu-fuzz rule file."""
    drs, srs = [], []
    with open(rule_path) as f:
        for line in f:
            line = line.strip()
            if not line or '_' not in line:
                continue
            typ = line[0]
            if typ not in 'RTS':
                continue
            try:
                addr = int(line.split('_')[1], 16)
            except (ValueError, IndexError):
                continue
            if typ in ('R', 'T'):
                drs.append(addr)
            elif typ == 'S':
                srs.append(addr)
    return list(set(drs)), list(set(srs))  # dedup

def read_from_shm_json(config,c_lib,vtor):
    '''
    used to read data from shared memory
    '''
    emulation_handler_serialized_data = None
    
        # read from shared memory file
        # os.walk get include shared_memory.txt
    shm_file = None
    flag = False
    for root, dirs, files in os.walk(os.path.dirname(config["binary_file"])):
        for file in files:
            if file.endswith(".json"):
                shm_file = os.path.join(root, file)
                flag = True
                # print(shm_file)
                break
        if flag:
            break
    emulation_handler_serialized_data = json.load(open(shm_file, "r"))
    irq_dt_set = emulation_handler_serialized_data["irq_dt_set"]
    main_dt_set = emulation_handler_serialized_data["main_dt_set"]
    fill_global_datatracker_array(c_lib,main_dt_set,irq_dt_set,vtor)
    # call c function to save irq_dt_set and main_dt_set
    my_debug_log("Shared memory is read")
    my_debug_log("Recover dt hooks complete")

def convert_to_ctypes(dt_object):
    from .data_tracker import StructDataTracker
    dt = StructDataTracker()
    dt.dr = dt_object.get('dr', 0)
    dt.callread_pc = dt_object.get('callread_pc', 0)
    dt.read_pc = dt_object.get('read_pc', 0)
    dt.buffer_addr = dt_object.get('buffer_addr', 0)
    dt.irq_pc = dt_object.get('irq_pc', 0)
    dt.avail_pc = dt_object.get('avail_pc', 0)
    dt.rx_head = dt_object.get('rx_head', 0)
    dt.rx_tail = dt_object.get('rx_tail', 0)
    dt.buffer_len = dt_object.get('buffer_len', 0)
    dt.buffer_min_len = dt_object.get('buffer_min_len', 0)
    dt.consume_count = dt_object.get('consume_count', 0)
    return dt


def fill_global_datatracker_array(c_lib,main_dt_set,irq_dt_set,vtor):
    for i, get_dt in enumerate(main_dt_set):
    # Assuming convert_to_ctypes returns a properly populated StructDataTracker instance
        dt = convert_to_ctypes(get_dt)
        res = c_lib.fill_data_tracker_main_dt_array(dt.dr,dt.callread_pc,dt.read_pc,dt.buffer_addr,dt.irq_pc,dt.avail_pc,dt.rx_head,dt.rx_tail,dt.buffer_len,dt.buffer_min_len,dt.consume_count)
        if res != 0:
            my_debug_log("fill_data_tracker_array error")
            return
        else:
            my_debug_log("fill_data_tracker_array success")
    for i, get_dt in enumerate(irq_dt_set):
        dt = convert_to_ctypes(get_dt)
        res = c_lib.fill_data_tracker_irq_dt_array(dt.dr,dt.callread_pc,dt.read_pc,dt.buffer_addr,dt.irq_pc,dt.avail_pc,dt.rx_head,dt.rx_tail,dt.buffer_len,dt.buffer_min_len,dt.consume_count,vtor)
        if res != 0:
            my_debug_log("fill_data_tracker_array error")
            return
        else:
            my_debug_log("fill_data_tracker_array success")
            
from capstone import Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_MCLASS|CS_MODE_THUMB)
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_IPSR
def _hook_instruction(uc, address, size, user_data):
    '''
    dump instruction disassembly and log. 
    Used if globs.debug_level > 2.
    '''
    curpc = uc.reg_read(UC_ARM_REG_PC)
    mem = uc.mem_read(address, size)
    ipsr = uc.reg_read(UC_ARM_REG_IPSR)
    # 执行代码块
    # 执行代码
    for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
        my_debug_log
        ("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))
    my_debug_log(f"function:{user_data} PC: {curpc:#016x} IPSR: {ipsr:#x}")


def my_add_hooks(uc):
    '''
    Add hooks to the emulator.
    '''
    
    uc.hook_add(UC_HOOK_CODE, _hook_instruction, "spi_stm32_isr",0x800a85c,0x800a87e)
    # uc.hook_add(UC_HOOK_CODE, _hook_instruction, "uart_stm32_isr",0x800ab40,0x800ab48)



def _hook_irq_function(uc, address, size, user_data):
    '''
    hook irq function. 
    '''
    my_debug_log(f"irq function: {address:#x}")
    my_debug_log(f"irq function: {size:#x}")
    ipsr = uc.reg_read(UC_ARM_REG_IPSR)
    print(f"irq function: {ipsr:#x}")
    
def hook_fuzzware_bugs(uc):
    from .fuzzware_hook_folder import cve3319,cve3320,cve3321,cve3322,cve3323,cve3329,cve3330,cve10064,cve10065,cve10066,heat_press,plc,gateway,solderring_iron
    from .fuzzware_hook_folder.riotmore import cve23_00000,cve_781645,cve_902353
    # uc.hook_add(UC_HOOK_CODE,cve23_00000.check_call)
    # uc.hook_add(UC_HOOK_CODE,cve_781645.check_call)
    # uc.hook_add(UC_HOOK_CODE,cve_902353.check_call)
    # on_basic_block(uc,cve3319.call_on_CVE_2021_3319)
    # on_basic_block(uc,cve3320.call_on_CVE_2021_3320)
    # on_basic_block(uc,cve3321.call_on_CVE_2021_3321)
    # on_basic_block(uc,cve3322.call_on_CVE_2021_3322)
    # on_basic_block(uc,cve3323.call_on_CVE_2021_3323)
    # on_basic_block(uc,cve3329.call_on_CVE_2021_3329)
    # on_basic_block(uc,cve3330.call_on_CVE_2021_3330)
    # on_basic_block(uc,cve10064.call_on_CVE_2020_10064)
    # on_basic_block(uc,cve10065.call_on_CVE_2020_10065)
    # on_basic_block(uc,cve10066.call_on_CVE_2020_10066)
    # heat_press.hook_heat_press_words(uc)
    # plc.hook_plc_words(uc)
    # plc.hook_plc_addr(uc)
    # heat_press.hook_heat_press_addr(uc)
    # uc.hook_add(UC_HOOK_BLOCK,soldering_iron_idle,0x8006a68-1,0x8006a68|1)
    gateway.hook_gateway_addr(uc)
    # on_basic_block(uc,gateway.hook_gateway_bug)
    # cve10064.avail_div_allfunc(uc)
    # solderring_iron.avail_div_allfunc(uc)
    # on_basic_block(uc,_hook_irq_function)
    
    pass


def on_basic_block(uc,callback):
    uc.hook_add(UC_HOOK_BLOCK, callback)

    
    

def main_3320(uc):
    from .fuzzware_hook_folder import cve3320
    on_basic_block(uc,cve3320.call_on_CVE_2021_3320,uc.symbols['ieee802154_recv'] + 0x42)

def main_3321(uc):
    from .fuzzware_hook_folder import cve3321
    on_basic_block(uc,cve3321.call_on_CVE_2021_3321,uc.symbols['memmove'])

def main_3322(uc):
    from .fuzzware_hook_folder import cve3322
    on_basic_block(uc,cve3322.call_on_CVE_2021_3322,uc.symbols['net_6lo_uncompress'])

def main_3323(uc):
    from .fuzzware_hook_folder import cve3323
    on_basic_block(uc,cve3323.call_on_CVE_2021_3323,uc.symbols['net_6lo_uncompress'] + 0x3e)
    on_basic_block(uc,cve3323.call_on_CVE_2021_3323,uc.symbols['net_6lo_uncompress'] + 0x46)

def main_3329(uc):
    from .fuzzware_hook_folder import cve3329
    on_basic_block(uc,cve3329.on_semaphore_init,uc.symbols['z_impl_k_sem_init'])
    on_basic_block(uc,cve3329.on_bt_init, uc.symbols['bt_init'] + 0x1e0)
    on_basic_block(uc, cve3329.on_CVE_2021_3329, uc.symbols['send_frag'])
    on_basic_block(uc, cve3329.on_z_impl_k_sem_take, uc.symbols['z_impl_k_sem_take'])
    on_basic_block(uc, cve3329.on_timeout_callback, uc.symbols['z_clock_announce'] + 0x84)
    on_basic_block(uc, cve3329.on_tx_free, uc.symbols['tx_free'])
    on_basic_block(uc, cve3329.on_net_buf_simple_push, uc.symbols['net_buf_simple_push'])
    on_basic_block(uc, cve3329.on_z_add_timeout, uc.symbols['z_add_timeout'])
    on_basic_block(uc, cve3329.on_k_delayed_work_init, uc.symbols['k_delayed_work_init'])

def main_10066(uc):
    from .fuzzware_hook_folder import cve10066
    on_basic_block(uc,cve10066.call_on_CVE_2020_10066,0)

def heat_press_change_pc(uc, address, size, user_data):
    '''
    hook function to change pc
    '''
    uc.reg_write(UC_ARM_REG_PC, 0x0802aa)

# soldering_idle_times= 0
# def soldering_iron_idle(uc, address, size, user_data):
#     '''
#     hook function to change pc
#     '''
#     global soldering_idle_times
#     soldering_idle_times += 1
#     import json
#     print(json.dumps({"soldering_iron_idle":soldering_idle_times}))

