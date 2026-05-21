import json
plc_words = [
    "_ZN6Modbus11getRxBufferEv",
    "digitalWrite",
    "is_pin_configured",
    "get_GPIO_Port",
    "digital_io_write",
    "HAL_GPIO_WritePin",
    "_ZN6Modbus15validateRequestEv",
    "_Z8makeWordhh",
    "_ZN6Modbus14buildExceptionEh",
    "_ZN6Modbus12sendTxBufferEv",
    "_ZN6Modbus7calcCRCEh",
    "millis",
    "GetCurrentMilli",
    "HAL_GetTick",
    "_ZN6Modbus11process_FC1EPth",
    "_ZN6Modbus11process_FC3EPth",
    "_ZN6Modbus11process_FC5EPth",
    "_ZN6Modbus11process_FC6EPth",
    "_ZN6Modbus12process_FC15EPth",
    "_ZN6Modbus12process_FC16EPth"
]
# map
fucntion_times = {}
for word in plc_words:
    fucntion_times[word] = 0
addr_times = {0x8000b56:0,0x8000b62:0,0x80006c6:0,0x80006d2:0}
from unicorn import UC_HOOK_CODE,UC_HOOK_BLOCK
from ...globs import uc
# Create a reverse mapping of function addresses to function names
plc_address_to_word = None

# Modify the function_times_handler to use the reverse mapping
def function_times_handler(uc, address, size, user_data):
    # Check if the current address is in the reverse mapping
    if address in plc_address_to_word.keys():
        # Get the function name from the reverse mapping
        word = plc_address_to_word[address]
        # Increment the count of this function in the map
        fucntion_times[word] += 1
        print(json.dumps(fucntion_times))

def hook_plc_words(uc):
    global plc_address_to_word
    plc_address_to_word = {uc.symbols[word]: word for word in plc_words}
    for address in plc_address_to_word.keys():
        uc.hook_add(UC_HOOK_BLOCK, function_times_handler, begin=address-1, end=address|1)

def addr_times_handler(uc, address, size, user_data):
    addr_times[address] += 1
    print(json.dumps(addr_times))

def hook_plc_addr(uc):
    for address in addr_times.keys():
        uc.hook_add(UC_HOOK_BLOCK, addr_times_handler, begin=address-1, end=address|1)
