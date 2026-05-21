heat_press_words = [
    "millis",
    "_ZN6Modbus11getRxBufferEv",
    "digitalWrite",
    "pinMode",
    "adc_disable_channel",
    "pmc_enable_periph_clk",
    "PIO_Configure",
    "pmc_disable_periph_clk",
    "PIO_GetOutputDataStatus",
    "PIO_PullUp",
    "PIO_SetOutput",
    "_ZN6Modbus14validateAnswerEv",
    "_ZN6Modbus7get_FC3Ev",
    "_Z8makeWordhh"
]
# map
import json
fucntion_times = {}
for word in heat_press_words:
    fucntion_times[word] = 0
addr_times = {0x80444:0,0x80470:0,0x801c8:0,0x801d2:0}

from unicorn import UC_HOOK_CODE,UC_HOOK_BLOCK
from ...globs import uc
# Create a reverse mapping of function addresses to function names
heat_press_address_to_word = None

# Modify the function_times_handler to use the reverse mapping
def function_times_handler(uc, address, size, user_data):
    # Check if the current address is in the reverse mapping
    if address in heat_press_address_to_word.keys():
        # Get the function name from the reverse mapping
        word = heat_press_address_to_word[address]
        # Increment the count of this function in the map
        fucntion_times[word] += 1
        print(json.dumps(fucntion_times))

def hook_heat_press_words(uc):
    global heat_press_address_to_word
    heat_press_address_to_word = {uc.symbols[word]: word for word in heat_press_words}
    for address in heat_press_address_to_word.keys():
        uc.hook_add(UC_HOOK_BLOCK, function_times_handler, begin=address-1, end=address|1)

def addr_times_handler(uc, address, size, user_data):
    addr_times[address] += 1
    print(json.dumps(addr_times))

def hook_heat_press_addr(uc):
    for address in addr_times.keys():
        uc.hook_add(UC_HOOK_BLOCK, addr_times_handler, begin=address-1, end=address|1)