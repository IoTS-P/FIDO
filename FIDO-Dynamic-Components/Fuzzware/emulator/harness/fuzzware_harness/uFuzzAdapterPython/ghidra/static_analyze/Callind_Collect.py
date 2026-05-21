# coding:utf-8
import ghidra.app.script.GhidraScript
import ghidra.program.model.address.GenericAddress
from ghidra.program.database import ProgramDB
from ghidra.program.model.listing import Function, Variable
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.pcode import PcodeOp, Varnode, PcodeOpAST, HighSymbol
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.listing import Data
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.pcode import HighParam,HighLocal,HighVariable
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import Structure,TypedefDataType,StructureDataType
import time

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
decomp_result_dict = {} # highfunc cache

callinds_backet = set()

#get the highfunction instance,highfunction is use for print all the pcodes in this function
def get_highfunc_callind(func):
    if not func:
        return None
    decomp_result = decomp_result_dict.get(func)
    if not decomp_result:
        decomp_result = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
        if not decomp_result:
            return None     
        decomp_result_dict[func] = decomp_result
    high_func = decomp_result.getHighFunction()
    return high_func


def get_callind_addrs():
    #get all functions in this program,and for each function,print their pcodes and find the callind PCODE.
    print("get_callind_addrs here")
    for func in currentProgram.getFunctionManager().getFunctions(True):
        if not func:
            continue
        hfunc = get_highfunc_callind(func)
        if not hfunc:
            continue
        # get all the pcode in this function,if you wanna get the Specific address in this function,use hfunc.getPcodeOps(toAddr(0x0000))
        for pcode in hfunc.getPcodeOps():
            if pcode.getOpcode() == PcodeOp.CALLIND:
                pc = pcode.getSeqnum().getTarget()
                callinds_backet.add('0x'+str(pc))


def cc_main():

    start = time.time()
    get_callind_addrs()
    end = time.time()
    
    print("time = ",end-start)
    print("Finish!")
    return list(callinds_backet)


print("exec finish")   
# main()