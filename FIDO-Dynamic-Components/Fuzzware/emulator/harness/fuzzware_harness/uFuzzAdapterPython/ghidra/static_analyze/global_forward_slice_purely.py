# coding:utf-8
import ghidra.app.script.GhidraScript
import ghidra.program.model.address.GenericAddress
from ghidra.program.database import ProgramDB
from ghidra.program.database.symbol import NamespaceManager, SymbolManager
from ghidra.program.model.listing import Function, Variable
from ghidra.program.model.symbol import Symbol, SymbolType
from ghidra.program.model.symbol import SymbolTable
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.pcode import PcodeBlockBasic
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlock
from ghidra.program.model.pcode import PcodeOp, Varnode, PcodeOpAST, HighSymbol
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.listing import Data
from ghidra.program.model.block import PartitionCodeSubModel
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.util.exception import DuplicateNameException
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.pcode import HighParam,HighLocal,HighVariable
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.pcode import GlobalSymbolMap
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.data import Structure,TypedefDataType,StructureDataType
from collections import defaultdict
from ghidra.util.datastruct import ListAccumulator
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.app.cmd.function import DecompilerSwitchAnalysisCmd
import sys
import os
import time
import Queue as queue



decomp_result_dict = {} # highfunc cache

block_model = BasicBlockModel(currentProgram)

#forward slice global var
all_global_symbols = []
read_except_func = None
global_symbols = set()
ForwardSliceFunc = set()# 用来存放正向切片的函数,以ghidra_func的形式
MULTIEQUAL_set = set()  #用于去重MULTIEQUAL
already_visit_func= set()
global_addrs = set() # 所有相关global的集合
callinds_backet = set() #所有间接调用处PC的集合
vn_global_dict = {}
ptradd_call_dict = {}#用来存放PTRADD与CALL中的vn对应关系的字典
temp_input_result_pc = []
callinds_dict = {}
base_offset_addr_set = set()
global_vn_set = set()

mainread_callread_consume_None = set() # 用来存放固件读中不存在消耗点的callread

setup_flag = False
firmware_type = None
irq_store_trace = None # 用于固件读的情况借用store追踪函数
final_consume_point = []

callread_pcs = []

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
# options = DecompileOptions()
# decompiler.setOptions(options)

#analyse consume global var
temp_get = []

consume_pcs = set()
consume_bbs = set()

CompareOps_list = [PcodeOp.INT_EQUAL,PcodeOp.INT_NOTEQUAL,PcodeOp.INT_LESS,PcodeOp.INT_SLESS,PcodeOp.INT_LESSEQUAL,PcodeOp.INT_SLESSEQUAL]
ComputeOps_list = [PcodeOp.INT_ADD,PcodeOp.INT_SUB,PcodeOp.INT_MULT,PcodeOp.INT_DIV,PcodeOp.INT_OR,PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_AND,PcodeOp.INT_XOR,PcodeOp.INT_NEGATE]


# f = open("C:/Users/User/Desktop/ptrsub2.txt", "w")
#global_file_handler = open("C:/Users/User/Desktop/global.txt", "w")

Current_Func_vn = []
Current_offset_vn = []
Current_head_vn = []
Current_tmp_param_result = []

#比较2个varnode是否完全相同
def cmp_vn(curvn,vn):
    return hash(curvn) == hash(vn)


def decompiler_func(func):
    decomp_result = decomp_result_dict.get(func,0)
    if not decomp_result:
        decomp_result = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
        if not decomp_result:
            return None     
        decomp_result_dict[func] = decomp_result
    return decomp_result    

def get_highfunc(func):
    if not func:
        return None
    decomp_result = decomp_result_dict.get(func,0)
    if not decomp_result:
        decomp_result = decompiler_func(func)
    high_func = decomp_result.getHighFunction()
    switch_table = high_func.getJumpTables()
    if switch_table and len(switch_table):
        #recover the missing switch pcodes
        cmd = DecompilerSwitchAnalysisCmd(decomp_result)
        cmd.applyTo(currentProgram,ConsoleTaskMonitor())
        decomp_result_dict[func] = decomp_result
        high_func = decomp_result.getHighFunction()
    return high_func

def get_bb(bb_addr):
    basic_block = block_model.getCodeBlocksContaining(bb_addr,monitor)[0]
    return basic_block

def get_const_vn(vn):
    if vn.isConstant():
        #print("come to const")
        temp_get.append(vn)
        return vn.getAddress()
    elif vn.isAddress():
        vn_data = getDataAt(vn.getAddress())
        if not vn_data:
            return None
        return vn_data.getValue()
    elif vn.isUnique():
        return calc_pcode(vn.getDef(),get_const_vn)
    elif vn.isRegister():
        return calc_pcode(vn.getDef(),get_const_vn)
    elif vn.isAddrTied():
        return calc_pcode(vn.getDef(),get_const_vn)

def get_param_value(vn):
    if not Current_Func_vn:
        return None
    for i in Current_Func_vn:
        if cmp_vn(vn,i):
            print(">>>get_param_value :",vn)
            Current_tmp_param_result.append(True)
            return True
    if vn.isAddress():
        vn_data = getDataAt(vn.getAddress())
        if not vn_data:
            return None
        return vn_data.getValue()
    elif vn.isConstant():
        return vn.getAddress()
    elif vn.isUnique():
        return calc_pcode(vn.getDef(),get_param_value)
    elif vn.isRegister():
        return calc_pcode(vn.getDef(),get_param_value)
    elif vn.isAddrTied():
        return calc_pcode(vn.getDef(),get_param_value)    

def get_value(vn):
    try:
        if vn.isAddress():
            vn_data = getDataAt(vn.getAddress())
            if not vn_data:
                return None
            return vn_data.getValue()
        elif vn.isConstant():
            return vn.getAddress()
        elif vn.isUnique():
            return calc_pcode(vn.getDef(),get_value)
        elif vn.isRegister():
            calc = calc_pcode(vn.getDef(),get_value)
            if not calc:
                return 0
            return calc
        elif vn.isAddrTied():
            return calc_pcode(vn.getDef(),get_value)
    except:
        return None

def calc_pcode(pcode,value_func):
    if isinstance(pcode, PcodeOpAST):
        opcode = pcode.getOpcode()
        print("current_calc:",pcode)
        if opcode == PcodeOp.PTRSUB:
            #print("Enter PTRSUB:")
            var_node_1 = pcode.getInput(0)
            var_node_2 = pcode.getInput(1)
            
            Current_head_vn.append(var_node_1)

            if var_node_2.isConstant():
                Current_offset_vn.append(var_node_2)
             
            value_1 = value_func(var_node_1)
            value_2 = value_func(var_node_2)
            if value_1 == True or value_2 == True:
                #it seems the write_vn need to concat the offset,so we need to return the offset value(Because it is in PTRSUB)
                temp = []
                temp.append(var_node_2)
                #return True
                return temp
            #print("value1=",value_1)        
            #print("value2=",value_2)
            
            if isinstance(value_1, GenericAddress) and isinstance(value_2, GenericAddress):
                addr = toAddr(value_1.offset + value_2.offset)
                # #f.write("ptrsub: {}\n".format(toAddr(value_1.offset + value_2.offset)))
                return addr
            
        elif opcode == PcodeOp.PTRADD:
            var_node_0 = pcode.getInput(0)
            var_node_1 = pcode.getInput(1)
            var_node_2 = pcode.getInput(2)
            
            Current_head_vn.append(var_node_0)
            
            try:
                #print("Enter PTRADD:")
                #print(pcode,pcode.getSeqnum().getTarget())
                value_0 = value_func(var_node_0)
                
                if value_0 == True:
                    return True
                #print("value0=",value_0)
                if not isinstance(value_0, GenericAddress):
                    return 
                if pcode.getInput(1).isConstant():
                    value_1 = var_node_1.getOffset()
                else:
                    value_1 = value_func(var_node_1) #继续追踪
                    #if not isinstance(value_1, GenericAddress):
                    #    return
                #print("value1=",value_1)
                if pcode.getNumInputs() == 3:
                    value_2 = value_func(var_node_2)
                    if value_1 == True or value_2 == True:
                        return True
                    if not isinstance(value_2, GenericAddress):
                        return 
                    #print(toAddr(value_0.offset + value_1 * value_2.offset))
                    return toAddr(value_0.offset + value_1 * value_2.offset)
                elif pcode.getNumInputs() == 2:
                    return toAddr(value_0.offset + value_1)
            except Exception as err:
                #print("error")
                return None
            except:
                #print("error")
                return None

        elif opcode == PcodeOp.INT_MULT or opcode == PcodeOp.INT_ADD or opcode == PcodeOp.INT_SUB:
            var_node_0 = pcode.getInput(0)
            var_node_1 = pcode.getInput(1)
            value_0 = value_func(var_node_0)
            value_1 = value_func(var_node_1)
            if value_0 == True or value_1 == True:
                return True            
            if value_0 is not None and value_1 is not None:
                if isinstance(value_0, ghidra.program.model.scalar.Scalar):
                    value_0 = value_0.getUnsignedValue()  # or .getSignedValue(), depending on your needs
                elif isinstance(value_0, GenericAddress):
                    value_0 = value_0.offset

                # Ensure value_1 is an integer
                if isinstance(value_1, ghidra.program.model.scalar.Scalar):
                    value_1 = value_1.getUnsignedValue()  # or .getSignedValue(), depending on your needs
                elif isinstance(value_1, GenericAddress):
                    value_1 = value_1.offset
                                        
                if opcode == PcodeOp.INT_MULT:
                    # print("mult!the result is ",value_0 * value_1)
                    return value_0 * value_1
                elif opcode == PcodeOp.INT_ADD:
                    # print("add!the result is ",value_0 + value_1)
                    return value_0 + value_1
                elif opcode == PcodeOp.INT_SUB:
                    # print("sub!the result is ",value_0 - value_1)
                    return value_0 - value_1
            else:
                return None
        
        elif opcode == PcodeOp.COPY or opcode == PcodeOp.INDIRECT or opcode == PcodeOp.CAST or opcode == PcodeOp.INT_ZEXT or opcode == PcodeOp.INT_SEXT or opcode == PcodeOp.INT_NEGATE or opcode == PcodeOp.SUBPIECE or opcode == PcodeOp.MULTIEQUAL:
            #print("Enter Input0 branch:")
            #print(pcode,pcode.getSeqnum().getTarget())
            var_node_0 = pcode.getInput(0)
            value_0 = value_func(var_node_0)
            if value_0 == True:
                return True
            #print("value =",value_1)
            if isinstance(value_0, GenericAddress):
                return value_0
            else:
                return None
        
        elif opcode == PcodeOp.LOAD:
            #print("Enter Input1 branch:")
            #print(pcode,pcode.getSeqnum().getTarget())
            var_node_1 = pcode.getInput(1)
            value_1 = value_func(var_node_1)
            if value_1 == True:
                return True
            #print("value =",value_1)
            if isinstance(value_1, GenericAddress):
                return value_1
            else:
                return None            
    else:
        return 0

#Find the global vn of Corresponding index 
def find_param_by_slot(func,index):
    hfunc = get_highfunc(func)
    if not hfunc:
        return None
    if index >= hfunc.getLocalSymbolMap().getNumParams() or index < 0:
        return None
    param = hfunc.getLocalSymbolMap().getParam(index)
    if not param:
        return None
    varnode = param.getRepresentative()
    return varnode

#analyse consume func
def slice_match(target_vn,origin_vn):
    if cmp_vn(target_vn,origin_vn):
        return True
    if not origin_vn or not target_vn:
        return False
    desvn_stack = []
    des_vn = origin_vn
    #print("success1")
    desvn_stack.append(des_vn)
    while(len(desvn_stack)):
        des_vn = desvn_stack[-1]
        desvn_stack.pop()
        if not des_vn:
            continue
        descs = des_vn.getDescendants()
        if not descs:
            return False
        for des in descs:
            for i in range(des.getNumInputs()):
                if cmp_vn(des.getInput(i),des_vn) and cmp_vn(des.getInput(i),target_vn):
            #        print("success3")
                    return True
            des_vn = des.getOutput()
            if not des_vn:
                continue
            desvn_stack.append(des_vn)
    #print("fail")
    return False

# trace the situation of the global varnode is the pointer of the global structure
def global_param_trace(addr):
    func = getFunctionContaining(addr)
    hfunc = get_highfunc(func)

    write_vn = None
    ##f.write("Success1\n")
    if not hfunc:
        return None
    param_count = hfunc.getLocalSymbolMap().getNumParams()
    if not param_count:
        return None

    #Get the store data, and try to trace it to the function param
    #if the target param is global varnode (in our result dict),and we slice it,return true
    for pcode in hfunc.getPcodeOps(addr):
        if pcode.getOpcode()== PcodeOp.STORE:
            write_vn = pcode.getInput(2)
            break
            
    if not write_vn:
        return None

    for slot in range(param_count):
        del Current_tmp_param_result[:]
        param_vn = find_param_by_slot(func,slot)
        Current_Func_vn.append(param_vn)
        result = get_param_value(write_vn)
        del Current_head_vn[:]
        del Current_offset_vn[:]

        if result != True and not len(Current_tmp_param_result) and not isinstance(result,list):
        #if result != True:
            continue
        if isinstance(result,list):
            offset_vn = result[0]
        else:
            offset_vn = None
        #We can trace it, so next we need to check if the result is in our result dict and return the real global addr
        ##f.write("Success2\n")
        if hash(param_vn) in vn_global_dict.keys():
            ##f.write("Success3\n")
            global_addr = vn_global_dict[hash(param_vn)]
            if offset_vn:
                global_addr = toAddr(global_addr.offset + offset_vn.offset)
            if global_addr:
                global_addrs.add(global_addr)
            ##f.write("Now the addr is :")
            ##f.write(str(global_addr))
            ##f.write("\n")
            return global_addr

    return None

def add_multiequal_pcode(op):
    if op.getOpcode() == PcodeOp.MULTIEQUAL:
        if op not in MULTIEQUAL_set:
            MULTIEQUAL_set.add(op)

# Handle the situation of the global varnode is the pointer of the global structure
def handle_global_structure_pointer(global_base_add_list,slot,called_func):
    queue = global_base_add_list
    
    for addr in queue:
        refs = getReferencesTo(addr)

        #Only handle the write ref, and we trace the store data
        for ref in refs:
            ref_addr = ref.getFromAddress()
            # print("ref write addr :",ref_addr)
            if ref.getReferenceType() == RefType.WRITE:
                #Trace the real global instance
                
                global_addr = global_param_trace(ref_addr)
                # print("the ref global trace addr :",global_addr)
                if not global_addr:
                    continue
                #save the global varnode and the real global addr to dict
                param_vn = find_param_by_slot(called_func,slot-1)
                
                if not param_vn:
                    return None
                
                vn_global_dict[hash(param_vn)] = global_addr
                ##f.write("Successs to add the global array!it real address:")
                ##f.write(str(global_addr))
                ##f.write("\n")
                return global_addr

def handle_PTRSUB_pcode(op,param_vn):
    vn1 = op.getInput(0)
    vn2 = op.getInput(1)
    if not cmp_vn(vn1,param_vn):
        return
    base_addr = 0
    offset = 0
    for vn_global in vn_global_dict.keys():
        if hash(vn1) == vn_global:
            base_addr = vn_global_dict[hash(vn_global)]
    if not base_addr:
        return
    
    #handle the vn2,which is the offset of the global variable,but it may have more than one offset,so we need to trace it until the descendant is STORE or LOAD
    offset += vn2.offset

    output_vn = None
    worklist = []
    des = op.getOutput().getDescendants()
    if not des:
        return
    for i in des:
        worklist.append(i)

    while len(worklist):
        desc_pcode = worklist[-1]
        ##f.write("The origin desc_pcode is {}\n".format(desc_pcode))
        worklist.pop()
        fliter_set = set()
        #Continue to find the next descendant,and keep adding the offset until the descendant is STORE or LOAD
        while desc_pcode.getOpcode() != PcodeOp.STORE and desc_pcode.getOpcode() != PcodeOp.LOAD and desc_pcode.getOpcode() != PcodeOp.CALL and desc_pcode.getOpcode() != PcodeOp.CALLIND and desc_pcode not in MULTIEQUAL_set:
            #print(desc_pcode)
            add_multiequal_pcode(desc_pcode)
            if des in fliter_set:
                break
            fliter_set.add(des)
            if desc_pcode.getOpcode() == PcodeOp.PTRSUB:
                offset += desc_pcode.getInput(1).offset
            output_vn = desc_pcode.getOutput()
            if output_vn:
                desc = output_vn.getDescendants()
                if desc:
                    for i in desc:
                        worklist.append(i)
            desc_pcode = worklist[-1]
            worklist.pop()
            
        if not base_addr:
            continue
                            
        #print(desc_pcode)
        # Concat the base_addr and the offset of global variable
        final_addr = toAddr(base_addr.offset + offset)
        base_offset_addr_set.add((base_addr,offset))
        # print("final_addr = ",final_addr)
        if final_addr:
            global_addrs.add(final_addr)
        
        #Example:
        #  ---  CALL (ram, 0x8008680, 8) , (unique, 0x1000009e, 4) , (ram, 0x8008d34, 4)
        #  (unique, 0x1000009e, 4) CAST (register, 0x30, 4)
        # In this example, (unique, 0x1000009e, 4) is the output_vn.
        #Save the lasest Call structure global vn
        
        slot = -1
        ##f.write("the output_vn is {}\n".format(output_vn))
        if desc_pcode.getOpcode() == PcodeOp.CALL:# or desc_pcode.getOpcode() == PcodeOp.CALLIND:
                for i in range(desc_pcode.getNumInputs()):
                    vn = desc_pcode.getInput(i)

                    #it seems that the desc_pcode is an origin CALL pcode, not from forward slice.so it doesn't have output_vn before.
                    if not output_vn:
                        if not vn.isRegister():
                            ##f.write("not register\n")
                            continue
                        ##f.write("Pass the register,the vn is {},the final addr is {}\n".format(vn,final_addr))
                        
                    elif not cmp_vn(vn,output_vn):
                        continue
                    
                    called_func = getFunctionContaining(desc_pcode.getInput(0).getAddress())
                    slot = i-1
                    called_func_vn = find_param_by_slot(called_func,slot)
                    if called_func_vn:
                        ForwardSliceFunc.add(called_func)
                        vn_global_dict[hash(called_func_vn)] = final_addr
                        ##f.write("write the global:{} to function :{}\n".format(final_addr,called_func))       


#get the global varnodes of all iterations
def get_called_functions(function, called_functions=None):
    if called_functions is None:
        called_functions = []
    if not function:
        return
    
    now_global_param = []
    #f.write("Now the Function is: {}".format(function.getName()))
    # print(str(function.getEntryPoint()))

    highfunc = get_highfunc(function)
    if not highfunc:
        print("function {} has no highfunc".format(function.getName()))
        return None

    param_count = highfunc.getLocalSymbolMap().getNumParams()

    #Find every param in the function and try to match the global varnode which is the structure member of the global param
    for slot in range(param_count):
        param_vn = find_param_by_slot(function,slot)
        for global_vn in vn_global_dict.keys():
            if hash(param_vn) != global_vn:
                continue
            now_global_param.append(param_vn)

            Descs = param_vn.getDescendants()
            if not Descs:
                continue
                
            #handle the ptrsub situation
            for op in Descs:
                add_multiequal_pcode(op)
                if op.getOpcode() != PcodeOp.PTRSUB:
                    continue
                handle_PTRSUB_pcode(op,param_vn)
    
    #if the switch_pcodes exists,they will be append in the pcodes with original hfunc_pcodes
    # high_codes = []
    # high_codes.extend()
    # high_codes.extend(all_pcodes)
    # all_pcodes.extend(highfunc.getPcodeOps())
    
    
    # Iterate other all funcs in this function
    for op in highfunc.getPcodeOps():
        #f.write("the new pc ={},pcode = {}\n".format(op.getSeqnum().getTarget(),op))

        add_multiequal_pcode(op)
        
        #PTRADD is used to catch some array global pointer,such as "uart_handlers[4]"
        if op.getOpcode() == PcodeOp.PTRADD:
            add_vn = op.getInput(0)
            #Try to get the global's array head address
            global_base_addr = check_if_global(add_vn)
            if global_base_addr:
                # print("global_base_addr is",global_base_addr)
                # print(op)
                fliter_set = set()
                des = op
                while des.getOpcode() != PcodeOp.CALL and des.getOpcode() != PcodeOp.CALLIND and des.getOutput() and des not in MULTIEQUAL_set:
                    #print(des)
                    add_multiequal_pcode(des)
                    if des in fliter_set:
                        break
                    fliter_set.add(des)
                    out = des.getOutput()
                    if out.getDescendants().hasNext():
                        des = out.getDescendants().next()
                    else:
                        break
                        
                if des.getOpcode() == PcodeOp.CALL or des.getOpcode() == PcodeOp.CALLIND:
                    # Save the vn->global_base_addr,and it will be used when the CALL pcode is handled
                    glo_addr = check_if_global(out)
                    temp_list = []
                    if glo_addr and glo_addr != global_base_addr:
                        # print("glo_addr = ",glo_addr)
                        temp_list.append(glo_addr)

                    # print("global_base_addr = ",global_base_addr)                        
                    temp_list.append(global_base_addr) 
                    des = out.getDescendants().next()
                    for i in range(des.getNumInputs()):
                        if des.getInput(i) == out:
                            out = des.getInput(i)
                            # print("Find!",out)
                            break
                    ptradd_call_dict[out] = temp_list

        #When the opcode is CALL, check if the param is global varnode
        if op.getOpcode() == PcodeOp.CALL or op.getOpcode() == PcodeOp.CALLIND:
            #Record the CALLIND PC
            callind_called_func = None
            pc = op.getSeqnum().getTarget()
            #f.write("pc = {}\n".format(pc))
            if op.getOpcode() == PcodeOp.CALLIND:
                print("CALLIND!")
                if callinds_dict:
                    if pc in callinds_dict.keys():
                        print("GET CALLIND!")
                        print("src addr:",pc)
                        
                        func_addr = callinds_dict[pc]
                        print("dest addr:",func_addr)
                        callind_called_func = getFunctionContaining(func_addr)
                        print(callind_called_func)
                        ForwardSliceFunc.add(callind_called_func)
                        # called_functions.append(callind_called_func)
                        # get_called_functions(callind_called_func,called_functions)
                    else:
                        continue
                        
            vn_0 = op.getInput(0)
            # print(op)
            # print(pc)
            if not vn_0.isRegister():
                called_func = getFunctionContaining(vn_0.getAddress())
            else:
                if callind_called_func:
                    called_func = callind_called_func
                else:
                    continue
            
            for i in range(1,op.getNumInputs()):
                vn = op.getInput(i)
                global_addr = check_if_global(vn)
                #f.write("the call global_addr = {}\n".format(global_addr))
                #Handle the PTRADD situation
                #If the global varnode is the pointer of the global structure,then we need to trace it to find the instance of the global structure
                if vn in ptradd_call_dict.keys():
                    # print("current index = ",i)
                    # print("vn =",vn)
                    global_base_addr = ptradd_call_dict[vn]
                    # print("now the list is ",global_base_addr)
                    temp = handle_global_structure_pointer(global_base_addr,i,called_func)
                    if temp:
                        global_addr = temp
                    # print("current true ptradd global = ",global_addr)

                #if the vn self is not a global and it is not stored in dict and it isn't match with the this func's global param, skip
                if not global_addr and hash(vn) not in vn_global_dict.keys() and vn not in now_global_param:
                    #f.write("the hash vn = {},continue".format(hash(vn)))
                    #f.write("current dict = {}".format(vn_global_dict))
                    continue
                    
                # Check if the global varnode is the pointer of the global structure
                # The first method is judge whether the global varnode is the pointer of the global structure,but we can only use Exclusion method,this may cause some false positives
                if global_addr:

                    data = getDataAt(global_addr)
                    if data:
                        DataType = data.getDataType()
                        
                        if isinstance(DataType, TypedefDataType):
                            DataType = DataType.getBaseDataType()
                        
                        if not isinstance(DataType, Structure):
                            print("the before global pointer is",global_addr)
                            if global_addr:
                                global_addrs.add(global_addr)
                            global_addr_list = [global_addr]
                            temp = handle_global_structure_pointer(global_addr_list,i,called_func)
                            print("the after global pointer is",temp)
                            if not temp:
                                continue
                            global_addr = temp
                                
                if not global_addr:
                    global_addr = vn_global_dict[hash(vn)]
                    #f.write("Now the fix global addr: {}\n".format(global_addr))

                slot = i-1

                param_vn = find_param_by_slot(called_func,slot)

                if param_vn:
                    #Save the "vn:global_addr" pair to dict
                    #f.write("final save vn:{},global_addr = {}".format(hash(param_vn),global_addr))
                    vn_global_dict[hash(param_vn)] = global_addr
                    if global_addr:
                        global_addrs.add(global_addr)
                    ForwardSliceFunc.add(called_func)

            # print(called_func)
            #f.write("called_func = {}\n".format(called_func))

            if called_func not in called_functions:
                called_functions.append(called_func)
                get_called_functions(called_func, called_functions)


    #print(vn_global_dict)      
    return called_functions


# Starting from the starting point, determine whether the parameter of the CALL pcode where this callread is located, 
# or whether the return value of this pcode is a global variable
def find_real_callread_addr(callread_addr,slot = None):
    global firmware_type,irq_store_trace
    func = getFunctionContaining(callread_addr)
    hfunc = get_highfunc(func)
    if not hfunc:
        return None
    for pcode in hfunc.getPcodeOps(callread_addr):
        #If it is a case of interrupted reading, it is necessary to find the PCODE instruction related to CALL
        if pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND or pcode.getOpcode() == PcodeOp.LOAD or (irq_store_trace != None and pcode.getOpcode() == PcodeOp.STORE):
            if firmware_type == "irq" and irq_store_trace == None:
                output_vn = pcode.getOutput()
                print("find_real_callread:pcode = {},pc = {}".format(pcode,callread_addr))
                #first if the global_variable in the call pcode param   
                if slot != None:
                    vn = pcode.getInput(slot + 1)
                    if vn:
                        global_addr = check_if_global(vn)
                        if global_addr:
                            return True
                        print("no global with slot")
                # 如果索引为空，则检查每个参数是否有全局变量
                else:
                    for i in range(1,pcode.getNumInputs()):
                        vn = pcode.getInput(i)
                        global_addr = check_if_global(vn)
                        if global_addr:
                            print("global_addr = ",global_addr)
                            return True
                    print("no global")
                    
                # then check the return value of call pcode
                if output_vn:
                    global_addr = check_if_global(output_vn)
                    print("the output global_addr = ",global_addr)
                    #check wheter the output_vn is global_variable
                    if global_addr:
                        print("the ret is global")
                        return True
                    
                    #后向切片寻找该ret_vn是否是全局变量
                    else:
                        #if not,then backforward found the pcode of output_vn to check wheter the ret_vn is global_variable
                        des_out = output_vn
                        fliter_set = set()
                        while des_out:
                            descs = des_out.getDescendants()
                            if not descs.hasNext():
                                break
                            des = descs.next()
                            if des in MULTIEQUAL_set:
                                break
                            add_multiequal_pcode(des)
                            if des in fliter_set:
                                break
                            fliter_set.add(des)
                            # print(des)
                            for i in range(des.getNumInputs()):
                                ret = check_if_global(des.getInput(i))
                                if ret:
                                    print("finally found the ret is global")
                                    return True
                            des_out = des.getOutput()
                            
                            if des_out and des_out.isAddress():
                                print("the value adress = ",des_out.getAddress())
                                if des_out.getAddress() in all_global_symbols:
                                    return True
                        print("no global 2")
                        #check the output_vn whether is the param of the prev CALL pcode
                        ret = whether_match_func_param_vn(callread_addr,output_vn)

                        if ret != None:
                            return ret
                        print("no global 3")
                        #if not found,then try to trace the vn to param_vn
                        for i in range(hfunc.getLocalSymbolMap().getNumParams()):
                            del Current_tmp_param_result[:]
                            param_vn = find_param_by_slot(func,i)
                            Current_Func_vn.append(param_vn)
                            ret = get_param_value(output_vn)
                            if ret == True or len(Current_tmp_param_result):
                                return i
                        
                        if slot:
                            target_vn = pcode.getInput(slot + 1)
                            ret = whether_match_func_param_vn(callread_addr,target_vn)
                            if ret != None:
                                print("slot cores = ",ret)
                                return ret

                # if all failed,return False
                return False
                       
            #If it is a firmware read situation, it is necessary to find the load PCODE
            
            #固件读的情况,以及中断读中追踪store的情况，也需要借用此处的函数实现
            elif firmware_type == "main" or irq_store_trace != None:
                #从该pcode出发开始前向切片，直到遇到store或consume切片
                # 如果此时切片遇到了消耗类型切片，则直接返回
                # 由于固件读的情况下消耗点仅用于判断退出使用，精度在函数级即可，所以直接返回callread
                # 但在这个环节中如果均不满足条件的callread,将不再向上追溯，并且消耗点需要标记为None
                print("firmware main >>>")
                
                #如果这个环节存在slot，则说明上一轮是通过函数参数传递上来的，则需要找到对应的函数参数的vn，以它为起点
                #如果不存在slot，则说明上一轮是通过return操作传递上来的，则需要找到call指令对应的返回值，以它为起点
                
                #如果是中断读的STORE指令追踪进入，则优先向上追溯
                if pcode.getOpcode() == PcodeOp.STORE and irq_store_trace != None:
                    base_vn = pcode.getInput(1)
                    result = backforward_find_param_vn(callread_addr,base_vn)
                    if result != None:
                        print("backforward_find_param_vn >>> {}".format(result))
                        return result
                
                
                if slot != None:
                    #如果存在slot，则需要对slot对应的vn先回溯，找到基vn后，再从基vn开始往下切
                    target_vn = pcode.getInput(slot + 1)
                    print("pcode = {},pcode.slot = {}".format(pcode,target_vn))
                    base_vn = handle_index_backward_vn(target_vn)
                    print("backward_vn = ",base_vn)
                    #假如后向没有找到其他的基vn，则直接做前向会默认切到本CALL指令的返回值，所以这里选择优先往前向寻找
                    if base_vn == target_vn:
                        result = backforward_find_param_vn(callread_addr,target_vn)
                        if result != None:
                            print("backforward_find_param_vn >>> {}".format(result))
                            return result
                    
                    store_node = main_read_consume_trace(None,"store",base_vn)
                    return_node = main_read_consume_trace(None,"return",base_vn)                
                    
                else:
                    store_node = main_read_consume_trace(pcode,"store")
                    return_node = main_read_consume_trace(pcode,"return")
                
                if store_node and store_node.has_consume == True:
                    final_consume_point.append(store_node.value)
                    return True
                
                #如果没切到consume切到了store,则检查store后续的切片是否出没在return和函数参数处
                elif store_node and store_node.has_store == True:
                    des = store_node.value
                    store_return_node = main_read_consume_trace(des,"return")
                    
                    #如果在return处找到了，则继续向上追溯
                    if store_return_node:
                        print("store_return_node! >>>")
                        return False
                    
                    write_vn = des.getInput(1)
                    
                    result = backforward_find_param_vn(callread_addr,write_vn)
                    print("backforward_find_param_vn >>> {}".format(result))
                    return result

                
                # 遇到了return切片，则继续向上追溯
                elif return_node and return_node.has_return == True:
                    print("return!")
                    return False
                
                #若均不满足，则消耗点为None
                else:
                    if irq_store_trace != None:
                        func = getFunctionContaining(pcode.getSeqnum().getTarget())
                        final_consume_point.append(func.getEntryPoint())
                    return None


def backforward_find_param_vn(callread_addr,write_vn):
    #如果没出现在return处,则寻找是否在函数参数处
    print("the write_vn need to compute is :",write_vn)
    slot = whether_match_func_param_vn(callread_addr,write_vn)
    print(slot == None)
    if slot != None:
        print("slot was found = ",slot)
        return slot
    
    print("second try")
    #if not found,then try to trace the vn to param_vn
    ret = match_func_param_vn_by_backtrace(callread_addr,write_vn)
    if ret != None:
        print("slot was found = ",ret)
        return ret
    else:
        print("slot back trace failed! ")
        return None


#用于处理索引传入后后向找基切片的情况
def handle_index_backward_vn(vn):
    upper_pcode = vn.getDef()
    if not upper_pcode:
        return vn
    upper_pcode_opcode = upper_pcode.getOpcode()
    upper_pcode_output = upper_pcode.getOutput()
    upper_pcode_input0 = upper_pcode.getInput(0)
    print(upper_pcode)
    print(upper_pcode_input0.isRegister())
    print('0x54' in hex(upper_pcode_input0.getAddress().offset))
    #如果栈寄存器(0x54)在PTRSUB中，则直接取与它所在相同地址,且vn类型为stack的output_vn     
    if upper_pcode_opcode == PcodeOp.PTRSUB and upper_pcode_input0.isRegister() and '0x54' in hex(upper_pcode_input0.getAddress().offset):
        pc = upper_pcode.getSeqnum().getTarget()
        hfunc = get_highfunc(getFunctionContaining(pc))
        for pcode in hfunc.getPcodeOps(pc):
            o_vn = pcode.getOutput()
            if 'stack' in str(o_vn.getAddress().getAddressSpace()):
                print(">>> stack")
                return o_vn
    else:
        if upper_pcode_output:
            return upper_pcode_output
        else:
            return vn
    
def get_calling(func):
    return getReferencesTo(func.getEntryPoint())
    
def get_calling_callpcodes(func,slot = None,calling_functions = []):
    if calling_functions is None:
        calling_functions = []
    print("now the func is :{},slot = {}".format(func,slot))
    func_pc = func.getEntryPoint()
    if not func:
        print("no func")
        return
    
    references = get_calling(func)

    if not references:
        print("no ref,maybe indirect")
        final_consume_point.append(func_pc)
        return
    
    ref_addrs = set()
    
    #整理引用的地址
    for ref in references:
        print("ref_addr = ",ref.getFromAddress())
        if not ref.getReferenceType().isCall():
            continue
        ref_addr = ref.getFromAddress()
        ref_addrs.add(ref_addr)
        
    #将间接调用的情况也考虑
    for key,value in callinds_dict.items():
        if getInstructionBefore(value).getAddress() == func_pc:
            ref_addrs.add(key)
    
    if not len(ref_addrs):
        print("no ref,maybe indirect")
        final_consume_point.append(func_pc)
        return
    
    for ref_addr in ref_addrs:
        print("ref_addr = ",ref_addr)
        calling_function = getFunctionContaining(ref_addr)
        hfunc = get_highfunc(calling_function)
        if not hfunc:
            print("no hfunc,continue")
            continue
        for pcode in hfunc.getPcodeOps(ref_addr):
            # print("pcode:",pcode)
            if pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND:
                # print("call_pcode:",pcode)
                result_slot = find_real_callread_addr(ref_addr,slot)
                print("result_slot = ",result_slot)
                
                if isinstance(result_slot, bool):
                    global irq_store_trace
                    if result_slot == True and ref_addr not in callread_pcs and irq_store_trace == None:
                        callread_pcs.append(ref_addr)
                      
                    #not found the global and slot,call the new func without slot
                    elif result_slot == False and calling_function not in calling_functions:
                        #calling_functions.append(calling_function)
                        print("calling_function :",calling_function)
                        get_calling_callpcodes(calling_function,None,calling_functions)
                        
                #got the slot,then call the new func with slot
                elif isinstance(result_slot, int):
                    if calling_function not in calling_functions:
                        #calling_functions.append(calling_function)
                        print("calling_function :",calling_function)
                        print("result_slot = ",result_slot)
                        get_calling_callpcodes(calling_function,result_slot,calling_functions)
                
                #如果返回值为None,则将该callread存入mainread_callread_consume_None中,来表示此处的消耗点为None
                elif result_slot == None:
                    mainread_callread_consume_None.add(ref_addr)
                    
                               
                    
#Traverse each layer of the function and check its corresponding number of calls, returning different results based on the number of calls              
def get_calling_refs_count(func,visited = []):
    print("current func =",func)
    refs = get_calling(func)
    lst = []
    lst.extend(refs)
    fli_lst = filter(lambda x:x.getReferenceType().isCall(),lst)
    #if len(refs) == 1,continue. if len(refs) == 0, over.If len(refs) > 1,save it and return.
    if len(fli_lst) > 1:
        print("ret count =",len(fli_lst))
        return[x.getFromAddress() for x in fli_lst]
        
    elif len(fli_lst) == 0:
        return None
    
    else:
        for ref in fli_lst:
            ref_addr = ref.getFromAddress()
            calling_function = getFunctionContaining(ref_addr)
            if calling_function not in visited:
                visited.append(calling_function)
                ret = get_calling_refs_count(calling_function,visited)
                # print("ret count =",ret)
                return ret
                   
                    
def get_all_callread_from_one_read(origin_addr):
    consume_start_pcs = []
    func = getFunctionContaining(origin_addr)
    
    # First,Starting from here, traverse all functions upwards and record the number of references in each layer
    if firmware_type == "irq":
        len_ret = get_calling_refs_count(func)
        if len_ret == None:
            callread_pcs.append(origin_addr)
            consume_start_pcs.append(origin_addr)
            return consume_start_pcs
        
        len_ret = list(set(len_ret))
        
        print("len_ret = ",len_ret)
        if len_ret == None and origin_addr not in callread_pcs:
            callread_pcs.append(origin_addr)
            print("not found the multi call, so final result is origin callread:",callread_pcs)
            return callread_pcs
    #If the number of references in the current layer is greater than 1, it means that there are multiple references to the current layer, and the current layer is the callread layer
    
    result = find_real_callread_addr(origin_addr)
    print("result is :",result)
    if isinstance(result, bool):
        #表示已找到目标callread
        if result == True and origin_addr not in callread_pcs:
            callread_pcs.append(origin_addr)
            return callread_pcs
        elif result == False:
            get_calling_callpcodes(func)
    #表示找到了index
    elif result != None:
        get_calling_callpcodes(func,result)
    
    #表示消耗点为空
    elif result == None:
        callread_pcs.append(origin_addr)
        mainread_callread_consume_None.add(origin_addr)
                
    # for ret in len_ret:
    #     if ret not in callread_pcs:
    #         callread_pcs.append(ret)
    
    # if not callread_pcs:
    #     callread_pcs.extend(len_ret)
    #     print("no callread_pcs,final result:",callread_pcs)
    # else:
    print("final result:",callread_pcs)
    
    
    # check each update callread_pc has ret_vn.If not ,its consume_start_addr need to change to the origin callread_pc
    # 仅中断读的情况需要判断是否有返回值，如果没有返回值，则消耗点为中断读的起始点
    if firmware_type == "irq":
        for callread_pc in callread_pcs:
            # ret = pcode_has_ret(callread_pc)
            # if not ret:
            #     consume_start_pcs.append(origin_addr)
            # else:
            consume_start_pcs.append(origin_addr)
    else:
        consume_start_pcs = callread_pcs
    return consume_start_pcs
    


def pcode_has_ret(addr):
    func = getFunctionContaining(addr)
    hfunc = get_highfunc(func)
    for pcode in hfunc.getPcodeOps(addr):
        if pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND:
            if pcode.getOutput():
                return True
    return False
    
 
                    
def get_calling_function(func):
    calling_functions = set()
    references = get_calling(func)
    for ref in references: 
        calling_function = getFunctionContaining(ref.getFromAddress())
        if calling_function is not None:
            calling_functions.add(calling_function)
    return calling_functions

#检查consume的return切片的所有调用，并返回那些存在返回值的切片
def get_calling_function_retvn(func):
    ret_vn_set = set()
    references = get_calling(func)
    for ref in references: 
        ref_addr = ref.getFromAddress()
        calling_function = getFunctionContaining(ref_addr)
        hfunc = get_highfunc(calling_function)
        if not hfunc:
            continue
        for pcode in hfunc.getPcodeOps(ref_addr):
            if pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND:
                if pcode.getOutput():
                    ret_vn_set.add(pcode.getOutput())
    return ret_vn_set


def get_calling_func_with_callinstr(addr):
    func = getFunctionContaining(addr)
    hfunc = get_highfunc(func)
    call_pcode = None
    for pcode in hfunc.getPcodeOps(addr):
        if pcode.getOpcode() == PcodeOp.CALL:
            call_pcode = pcode
            break
    if not call_pcode:
        return None
    calling_func = getFunctionContaining(call_pcode.getInput(0).getAddress())
    return calling_func
 

def get_global_symbols():
# 获取内存块（Memory Blocks）
    memory = currentProgram.getMemory()
    # 获取符号表
    symbolTable = currentProgram.getSymbolTable()

    # 遍历所有内存块
    for block in memory.getBlocks():
        # 跳过 .text 段、.vector 段和以 .debug 开头的段
        if block.getName() == ".text" or block.getName() == ".vector" or block.getName().startswith(".debug"):
            continue

        # 获取内存块的起始和结束地址
        start = block.getStart()
        end = block.getEnd()

        # 遍历内存块中的地址
        currentAddr = start
        while currentAddr is not None and currentAddr.compareTo(end) <= 0:
            symbol = symbolTable.getPrimarySymbol(currentAddr)
            if symbol is not None and not any(char == ":" for char in str(currentAddr)):
                all_global_symbols.append(currentAddr)
                
            currentAddr = currentAddr.next()


def check_if_global(vn):
    result = get_value(vn)#获取全局变量地址
    del Current_offset_vn[:]
    del Current_head_vn[:]
    # #f.write("check_if_global_result = {}\n".format(result))
    if not result:
        return None
    #print("result:",result)
    global_addr = result
    #print("global_addr:",global_addr)
    try:
        symbol = currentProgram.getSymbolTable().getPrimarySymbol(global_addr)
    except:
        return None
    if not symbol:
        return None
    sym_addr = symbol.getAddress()
    if sym_addr not in all_global_symbols:
        
        return None
    #print("Symbol_addr:",symbol.getAddress())
    return global_addr


def next_instr_addr(addr):
    instr = currentProgram.getListing().getInstructionAt(addr)
    ##f.write("\n下一跳地址为:")
    if not instr:
        return None
    ##f.write(str(instr.getDefaultFallThrough()))
    ##f.write("\n")
    next_addr = instr.getDefaultFallThrough()
    return next_addr

#获取该PC所在基本块的所有前继基本块的起止地址
def get_predecessors_blocks(cbranch):
    branches = cbranch.getSources(monitor)
    branch_set = set()
    while branches.hasNext():
        branch_addr = branches.next().getSourceAddress()
        branch_block = get_bb(branch_addr)
        branch_set.add(branch_block)
    return branch_set

#获取该PC所在基本块的所有后继基本块的起止地址
def get_succerssors_blocks(cbranch):
    branches = cbranch.getDestinations(monitor)
    branch_set = set()
    while branches.hasNext():
        branch_addr = branches.next().getDestinationAddress()
        #print("branch_addr = ",branch_addr)
        branch_block = get_bb(branch_addr)
        addr_start = branch_block.getMinAddress()
        addr_end = branch_block.getMaxAddress()
        #affected_blocks.add((addr_start,addr_end))
        branch_set.add((addr_start,addr_end))
    return branch_set


def get_callers(func):
    """获取调用指定函数的所有函数"""
    callers = []
    references = getReferencesTo(func.getEntryPoint())
    for ref in references:
        caller_func = getFunctionContaining(ref.getFromAddress())
        if caller_func:
            callers.append(caller_func)
    return callers

"""求地址集合的最小公共函数"""
def get_ancestor_caller(addresses):
    functions = [getFunctionContaining(addr) for addr in addresses]
    main_found = {}  # 保存每个起始函数的调用链中是否找到了main函数
    top_calls = {}  # 保存没有main标记的函数中最上层的调用
    def dfs(func, visited, depth, chain):
        if func in visited:
            return
        visited[func] = depth
        if func.getName() == 'main':
            main_found[start_func] = True
        for parent in get_callers(func):
            dfs(parent, visited, depth+1, chain + [func])
    visited_by = [{} for _ in functions]  # 修改为未访问任何函数
    for func, visited in zip(functions, visited_by):
        start_func = func  # 保存起始函数
        main_found[start_func] = False  # 初始化为未找到main
        dfs(func, visited, 0, [func])
        if not main_found[start_func]:  # 如果在该函数的调用链中未找到main
            top_calls[start_func] = max(visited, key=visited.get)  # 保存最上层的调用
    common_ancestors = set.intersection(*[set(visited.keys()) for visited in visited_by])
    if not common_ancestors:  # 没有找到公共祖先
        functions_with_main = [func for func in functions if main_found[func]]
        if functions_with_main:  # 如果存在在调用链中找到main的函数
            # 对它们再求一次公共最近祖先
            visited_by = [visited for func, visited in zip(functions, visited_by) if func in functions_with_main]
            common_ancestors = set.intersection(*[set(visited.keys()) for visited in visited_by])
            if 'main' in common_ancestors:
                return 'main'
            else:
                print("return min_not_main_ancestors")
                return (min(common_ancestors, key=lambda func: max(visited[func] for visited in visited_by)),top_calls)
        else:  # 否则，返回没有main标记的函数中最上层的调用
            print("return top_calls")
            return top_calls
    else:#如果找到了公共祖先，则直接返回
        common_ancestor = min(common_ancestors, key=lambda func: max(visited[func] for visited in visited_by))
        print("return common_ancestor")
        return common_ancestor


"""Get the ancestor block of the given basic block"""
def get_ancestor_block(bbs):
    top_calls = {}  # 保存没有main标记的函数中最上层的调用
    def dfs(bb, visited, depth, chain):
        if bb in visited:
            return
        visited[bb] = depth
        for parent in get_predecessors_blocks(bb):
            dfs(parent, visited, depth+1, chain + [bb])
    visited_by = [{} for _ in bbs]  # 修改为未访问任何函数
    for bb, visited in zip(bbs, visited_by):
        start_bb = bb  # 保存起始函数
        dfs(bb, visited, 0, [])
        top_calls[start_bb] = max(visited, key=visited.get)  # 保存最上层的调用
    common_ancestors = set.intersection(*[set(visited.keys()) for visited in visited_by])
    if not common_ancestors:  # 没有找到公共祖先
        print("return top_calls")
        return top_calls
    else:#如果找到了公共祖先，则直接返回
        common_ancestor = min(common_ancestors, key=lambda bb: max(visited[bb] for visited in visited_by))
        #print("return common_ancestor")
        return common_ancestor

"""If the basic block is independent of other basic blocks in the set, save it"""
def handle_whether_bb_in_intersection(cur_bb,collect_bbs):
    for collect_bb in collect_bbs:
        if collect_bb == cur_bb:
            continue
        bbs = [collect_bb,cur_bb]
        ances_bb = get_ancestor_block(bbs)
        # if ances_bb is one of the collect_bb or cur_bb, it means that the other bb is need to discard.
        if ances_bb == cur_bb or ances_bb == collect_bb:
            return False
        # if ances_bb isn't the one of the collect_bb or cur_bb,so we need to add the cur_bb,because they are independent.
        else:
            continue
    return True


'''该处为固件读类型消耗点的树算法，用来实现追踪到store切片后剩余的切片满足消耗点条件的PC结算'''
class TreeNode:
    def __init__(self, value, has_store=False, has_consume=False, has_return=False, has_call=False):
        self.value = value
        self.children = []  # 初始化为空列表
        self.has_store = has_store
        self.has_consume = has_consume
        self.has_return = has_return
        self.has_call = has_call
        self.parent = None  # 父节点初始化为空
    def add_child(self, child):
        self.children.append(child)
        child.parent = self  # 设置父节点
    def get_ancestors(self):
        ancestors = []
        current = self.parent
        while current:
            ancestors.append(current)
            current = current.parent
        return ancestors
    
def find_child(exit_type,node,output_vn = None):
    if not output_vn:
        #如果是store切片，需要取第1个元素
        if node.getOpcode() == PcodeOp.STORE:
            output_vn = node.getInput(1)
        else:
            output_vn = node.getOutput()

    if output_vn:
        children_value = []
        children = []
        tmp = output_vn.getDescendants()
        children_value.extend(tmp)
        for child in children_value:
            #在中断读的筛选切片中，需要保留CALL的情况，其余场景则不需要保留
            if exit_type != "all" and child.getOpcode() == PcodeOp.CALL or child.getOpcode() == PcodeOp.CALLIND:
                continue
            c = TreeNode(child)
            children.append(c)
            print("the children value = {},pc = {}".format(c.value,c.value.getSeqnum().getTarget()))
        return children
    else:
        return []

def is_store(node):
    if node.getOpcode() == PcodeOp.STORE:
        return True
    else:
        return False

def is_call(node):
    if node.getOpcode() == PcodeOp.CALL or node.getOpcode() == PcodeOp.CALLIND:
        return True
    else:
        return False
   
def is_return(node):
    if node.getOpcode() == PcodeOp.RETURN:
        return True
    else:
        return False

def is_consume(node):
    if node.getOpcode() in CompareOps_list:
        return True
    else:
        return False

def get_child_attr(child):
    child.has_store = is_store(child.value)
    child.has_consume = is_consume(child.value)
    child.has_return = is_return(child.value)
    child.has_call = is_call(child.value)

def bfs_with_check(root,exit_type,ret_vn = None):
    fliter = set()
    queue = None
    all_slice = set()
    if root:
        queue = [root]
    #如果传递进来的参数是vn，则先用vn求子切片，再依次放入初始队列中
    elif ret_vn:
        root_lst = find_child(exit_type,None,ret_vn)
        print([x.value for x in root_lst])
        #针对all模式下,需要考虑第一轮的child也是否包含在最终结果内的情况
        if exit_type == "all":
            for child in root_lst:
                print("child = ",child.value)
                get_child_attr(child)
                if child.has_call or child.has_consume or child.has_store or child.has_return:
                    print("origin vn is 'all' child = {}".format(child.value))
                    all_slice.add(child.value)                
        queue = root_lst
        
    while queue:
        node = queue.pop(0)
        print("current parent node = ",node.value)
        
        children = find_child(exit_type,node.value)  # 动态找到子节点
        node.children = children  # 更新节点的子节点列表
        for child in children:
            #如果切到了CALL指令则跳过，因为切到的往往是CALL指令的参数，而从CALL处往下切则是由其返回值决定，导致跟错的情况发生
            if exit_type != "all" and child.value.getOpcode() == PcodeOp.CALL:
                continue
            child.parent = node  # 设置子节点的父节点
            get_child_attr(child)
            if child.value not in fliter:
                queue.append(child)  # 将子节点加入队列
            fliter.add(child.value)
            # 方案修改:如果遇到了比较切片,则此处即为固件读最终消耗点;遇到store切片后直接返回，交由后续计算
            if exit_type == "store" and (child.has_consume or child.has_store):
                print("is store or consume,return child = {}".format(child.value))
                return child
            # 用于判断从根节点出发是否存在return切片，如果存在则直接返回
            if exit_type == "return" and child.has_return:
                print("is return child = {}".format(child.value))
                return child
            if exit_type == "all" and (child.has_call or child.has_consume or child.has_store or child.has_return):
                print("is all child = {}".format(child.value))
                all_slice.add(child.value)
                
    #收集所有满足条件的切片，而不止是遇到第一个就退出
    if exit_type == "all" and len(all_slice) > 0:
        print("collect the all_slice is :",all_slice)
        return all_slice
        
    #否则属于无消耗点
    print("no target slice")
    return None


#固件读的情况需要使用树结构筛出遍历到包含STORE指令层时所有满足消耗条件的切片,因此使用树结构遍历求解
def main_read_consume_trace(pcode,exit_type,vn = None):
    # 从根节点开始
    root = None
    print("type = :", exit_type)
    if pcode:
        print("pcode:", pcode.getSeqnum().getTarget())
        root = TreeNode(pcode)
        root.has_consume = is_consume(root.value)
        root.has_store = is_store(root.value)
    else:
        print("no pcode,the vn is :",vn)
    
    # 运行算法
    result_node = bfs_with_check(root,exit_type,vn)
    return result_node
    


# Find the Cbranch pcode in every basic block
def handle_bb_pcode(addr_start,addr_end,mode):
    
    global read_except_func
    #print("current start:",addr_start)
    addr_pointer = addr_start
    if not addr_pointer:
        return None
    if mode == 'read':
        read_flag = False
    already_visit_func.add(getFunctionContaining(addr_start))
    hfunc = get_highfunc(getFunctionContaining(addr_start))
    while addr_pointer <= addr_end:
        for pcode in hfunc.getPcodeOps(addr_pointer):
            pc = pcode.getSeqnum().getTarget()
            #print(pc)
            #Catch the CALL opcode first, then make forward slice to find the Cbranch pcode
            if (pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND) and mode == 'avail':
                flag = True
                visit_func = getFunctionContaining(pcode.getInput(0).getAddress())
                output = pcode.getOutput()
                avail_candi_bb = None
                if not visit_func or not output or visit_func not in ForwardSliceFunc or visit_func in already_visit_func or visit_func == read_except_func:
                    flag = False
                    pc = pcode.getSeqnum().getTarget()
                    if pc in callinds_dict.keys():
                        target_callind_dest_addr = callinds_dict[pc]
                        visit_func = getFunctionContaining(target_callind_dest_addr)
                        print("*********")
                        #find all the avail call point in callind_dict
                        avail_called_point_bbs = []
                        for key,value in callinds_dict.items():
                            if value == target_callind_dest_addr:
                                print("the candidates avail pc is {}".format(key))
                                bb = get_bb(key)
                                avail_called_point_bbs.append(bb)
                            
                        if len(avail_called_point_bbs) > 1:
                            print("compute ancestor ")
                            avail_candi_bb = get_ancestor_block(avail_called_point_bbs)
                            avail_pc = avail_candi_bb.getMinAddress()
                            print("ancestor avail_pc = {}".format(avail_pc))
                            return avail_pc
                        else:
                            avail_candi_bb = bb
                        print(visit_func)
                        if visit_func in ForwardSliceFunc and visit_func not in already_visit_func and visit_func == read_except_func:
                            print("the func is True")
                            flag = True
                
                if not flag:
                    continue
                                
                while output:
                    for p in output.getDescendants():
                        if p.getOpcode() == PcodeOp.CBRANCH:
                            pc = pcode.getSeqnum().getTarget()
                            # func_addr = visit_func.getEntryPoint()
                            # refs = getReferencesTo(func_addr)
                            # bbs = []
                            # if avail_candi_bb:
                            #     print("candi")
                            #     bbs.append(avail_candi_bb)
                            # #judge if other places has avail_func,and it should accompanied by read_func
                            # for ref in refs:
                            #     if ref.getReferenceType().isCall():
                            #         ref_addr = ref.getFromAddress()
                            #         bb = get_bb(ref_addr)
                            #         ret_code = handle_bb_pcode(bb.getMinAddress(),bb.getMaxAddress(),'read')
                            #         if ret_code == True:
                            #             bbs.append(bb)
                            # if len(bbs) > 1:
                            #     avail_bb = get_ancestor_block(bbs)
                            #     avail_pc = avail_bb.getMinAddress()
                            #     return avail_pc
                            # elif len(bbs) == 1:
                            #     return bbs[0].getMinAddress()                            
                            # else:
                            return pc
                        else:   
                            output = p.getOutput()
                            break
            
            elif (pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND) and mode == 'read':
                visit_func = 0
                if pcode.getOpcode() == PcodeOp.CALL:
                    visit_func = getFunctionContaining(pcode.getInput(0).getAddress())
                elif pcode.getOpcode() == PcodeOp.CALLIND:
                    if pc in callinds_dict.keys():
                        target_callind_dest_addr = callinds_dict[pc]
                        visit_func = getFunctionContaining(target_callind_dest_addr)
                        
                if visit_func == read_except_func:
                    read_flag = True
             
        addr_pointer = next_instr_addr(addr_pointer)
        if not addr_pointer:
            break
    if mode == 'read':
        if read_flag == True:
            return True
        else:
            return False
    return False

#在队列遍历过程中发现全局变量时进行的处理流程
def handle_global_symbol(global_addr):
    
    if not global_addr:
        return None
    
    symbol = currentProgram.getSymbolTable().getPrimarySymbol(global_addr)
    if not symbol:
        return None

    #如果该global已经检查过了，就跳过
    if symbol in global_symbols:
        return None

    #print("current global:",global_addr)
    global_symbols.add(symbol)

    #获得该全局变量的所有引用
    refs = getReferencesTo(global_addr)
        
    for ref in refs:
        ref_addr = ref.getFromAddress()
        func = getFunctionContaining(ref_addr)
        if not func:
            continue
        
        func_set = get_calling_function(func)
        
        #if this function which contain this ref is a callind func, and it is not in the dict of callind, we need to run it.
        if not len(func_set) and func.getEntryPoint() not in callinds_dict.values():
            get_called_functions(func)
        
        hfunc = get_highfunc(func)
        if ref.getReferenceType() == RefType.WRITE:#筛去WRITE类型的ref
            continue
                
        #如果是PARAM类型,则获取传参后的function和varnode
        if ref.getReferenceType() == RefType.PARAM:
            for pcode in hfunc.getPcodeOps():
                if pcode.getOpcode() == PcodeOp.CALL:
                    for i in range(pcode.getNumInputs()):
                        vn = pcode.getInput(i)
                        global_addr = check_if_global(vn)
                        if not global_addr:
                            continue
                        slot = i-1
                        called_func = getFunctionContaining(pcode.getInput(0).getAddress())
                        vn = find_param_by_slot(called_func,slot)
                        if vn:
                            global_vn_set.add(vn)
                            ForwardSliceFunc.add(func)
                            vn_global_dict[hash(vn)] = global_addr
                            break

        #如果是READ类型，那么直接存储
        if ref.getReferenceType() == RefType.READ:
            for pcode in hfunc.getPcodeOps(ref_addr):
                if pcode.getOpcode() == PcodeOp.LOAD:
                    vn = pcode.getOutput()
                    global_vn_set.add(vn)
                    ForwardSliceFunc.add(func)
                    vn_global_dict[hash(vn)] = global_addr




# trace the consume store code put data to which global addr,and try to find the refs of this global addr
def trace_store_global_refs_consume_slice(addr):
    func = getFunctionContaining(addr)
    hfunc = get_highfunc(func)

    write_vn = None
    ##f.write("Success1\n")
    if not hfunc:
        return None
    param_count = hfunc.getLocalSymbolMap().getNumParams()
    if not param_count:
        return None

    #Get the store data, and try to trace it to the function param
    #if the target param is global varnode (in our result dict),and we slice it,return true
    for pcode in hfunc.getPcodeOps(addr):
        if pcode.getOpcode()== PcodeOp.STORE:
            write_vn = pcode.getInput(1)
            break
            
    if not write_vn:
        return None
    
    del Current_offset_vn[:]
    del Current_head_vn[:]
    del Current_tmp_param_result[:]
    #try to trace the write_vn to param_vn
    param_vn = None

    ret = get_param_value(write_vn)
    #if failed,use the current_head_vn which got during the trace process,try to match the param_vn with the head_vns
    if ret != True and not len(Current_tmp_param_result):
        for head in Current_head_vn:
            result = whether_match_func_param_vn(addr,head)
            if result == None:
                continue
            else:
                param_vn = find_param_by_slot(func,result)
                offset_vn = Current_offset_vn[0]
                break

    else:
        index = whether_match_func_param_vn(addr,write_vn)
        if index == None:
            return None
        param_vn = find_param_by_slot(func,index)
        offset_vn = Current_offset_vn[0]
            
    del Current_offset_vn[:]
    del Current_head_vn[:]

    if not param_vn:
        return None
    
    print("success match the consume store slice!")
    if hash(param_vn) in vn_global_dict.keys():
        print("find the param_vn in the vn_global_dict")
        global_head_addr = vn_global_dict[hash(param_vn)]
        if global_head_addr:
            offset = offset_vn.offset
            refs = get_member_refs(global_head_addr,offset)
            if not refs:
                print("the refs is None")
                return None
            #judge each ref whether is satisfy the consume slice
            get_consume_slices_from_store_refs(refs)
            
    return None


"""get the global member addr's references"""
def get_member_refs(global_head_addr,offset):
    data = getDataAt(global_head_addr)
    if not data:
        print("no data found!")
        return None
    struct_dtype = data.getDataType()
    if not isinstance(struct_dtype, Structure):
        print("the data is not struct!")
        return None
    member = struct_dtype.getComponentAt(offset)
    if not member:
        return None
    member_name = str(member.getFieldName())
    print("got member_name = ",member_name)
    lst = ListAccumulator()
    ReferenceUtils.findDataTypeReferences(lst, struct_dtype, member_name, currentProgram, None)
    s = set()
    for l in lst:
        ref_addr = l.getLocationOfUse()
        print("ref_addr =",ref_addr)
        s.add(ref_addr)
    return s

# filter the refs which need the compute and compare but not the store or call
def get_consume_slices_from_store_refs(refs):
    for ref_addr in refs:
        func = getFunctionContaining(ref_addr)
        hfunc = get_highfunc(func)
        if not hfunc:
            continue
        com_flag = False
        store_flag = False
        
        #if there are compute or compare slice and no store or called slice,save it,if found the load,continue 3 times to slice it 
        for pcode in hfunc.getPcodeOps(ref_addr):
            if not pcode:
                continue
            if pcode.getOpcode() in CompareOps_list:
                com_flag = True
                print("com_flag = ",com_flag)
            elif pcode.getOpcode() == PcodeOp.STORE:
                store_flag = True
                print("store_flag = ",store_flag)
            elif pcode.getOpcode() == PcodeOp.LOAD:
                output = pcode.getOutput()
                if not output:
                    continue
                for i in range(3):
                    suc_pcode = output.getDescendants().next()
                    if suc_pcode.getOpcode() in CompareOps_list:
                        com_flag = True
                        break
                    elif suc_pcode.getOpcode() == PcodeOp.CALL or suc_pcode.getOpcode() == PcodeOp.CALLIND:
                        store_flag = True
                        break
                    else:
                        output = suc_pcode.getOutput()
                        if not output:
                            break
        if com_flag and not store_flag:
            print("store the addr {} to consume_pcs".format(ref_addr))
            consume_pcs.add(ref_addr)   

                
# 方案修改后，此处消耗点计算仅用于中断读类型固件
"""Try to find the data consume PC from the read buffer pc"""
def find_consume_pc(start_addr):
    func = getFunctionContaining(start_addr)
    hfunc = get_highfunc(func)  
    return_vn = None
    ret_queue = []
    const_vns = set()
    temp_descs = []
    global firmware_type
    print("callread_pc = {},firmware_type = {}".format(start_addr,firmware_type))
    
    # 如果是中断读类型的固件求消耗点，则相当于追溯buffer的去处，即为消耗点
    # if firmware_type == "irq":
    """Catch the return value which is const, and compare with the calling func's cbranch value"""
    for pcode in hfunc.getPcodeOps(start_addr):
        if pcode.getOpcode() == PcodeOp.LOAD or pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND:
            if pcode.getOpcode() == PcodeOp.CALL:
                read_func = getFunctionContaining(pcode.getInput(0).getAddress())
            #如果是间接调用,则找到目标读函数
            elif pcode.getOpcode() == PcodeOp.CALLIND:
                pc = pcode.getSeqnum().getTarget()
                if pc in callinds_dict.keys():
                    target_callind_dest_addr = callinds_dict[pc]
                    read_func = getFunctionContaining(target_callind_dest_addr)
                else:
                    read_func = None    
            if not pcode.getOutput():
                continue
            return_vn = pcode.getOutput()
            break

        
    if not return_vn:
        print(return_vn)
        print("not read_func or not return_vn")       
        return None
    
    #检查该返回值是否是全局变量
    glo_addr = check_if_global(return_vn)
    print("glo_addr = ",glo_addr)

    if read_func:
        rhfunc = get_highfunc(read_func)
        #Count the values of constant in all RETURN PcodeOp
        for pcode in rhfunc.getPcodeOps():
            if not pcode.getOpcode() == PcodeOp.RETURN:
                continue
            if not pcode.getInput(1):
                continue
            ret_vn = pcode.getInput(1)

            data = get_const_vn(ret_vn)
            if len(temp_get):
                data = temp_get[-1]
                temp_get.pop()
            if not data:
                continue
            try:
                if data.isConstant():
                    const_vns.add(data.getAddress())
            except:
                continue
   
    consume_slice_fliter(ret_queue,return_vn,const_vns)
    if len(consume_pcs):
        return consume_pcs
    else:
        return None


# 每次会对一个新的切片进行结算
# 首先会检查该切片的所有前向切片，从中筛出计算，比较，存储，调用和返回类型的PCODE
# 然后针对筛出的所有切片，分别进行处理
def consume_slice_fliter(ret_queue,return_vn,const_vns):
    ret_queue.append(return_vn)
    while(len(ret_queue)):
        return_vn = ret_queue[-1]
        ret_queue.pop()
        if not return_vn:
            continue
        
        #筛出所有符合条件的切片
        temp_descs = main_read_consume_trace(None,'all',return_vn)
        consume_slice_type_handle(ret_queue,temp_descs,const_vns,return_vn)
        if len(consume_pcs):
            return

    return

#针对筛出的切片，根据切片的不同类型做不同处理
def consume_slice_type_handle(ret_queue,temp_descs,const_vns,return_vn):
    start_judge = True
    
    call_pcodes = set()
    store_pcodes = set()
    return_pcodes = set()
    
    for des in temp_descs:
        print("des = ",des)
        PC = des.getSeqnum().getTarget()
        print("pc = ",PC)
        cur_bb = get_bb(PC)
        func = getFunctionContaining(PC)
        
        if des.getOpcode() in CompareOps_list:
            print("in CompareOps_list")
            if not start_judge:
                stat_consume_slice(cur_bb,PC)
            else:
                for i in range(des.getNumInputs()):
                    v = des.getInput(i)
                    #print("v= {}".format(v))
                    if not v.isConstant():
                        #print(v.isConstant())
                        continue
                    #print("const_vns = {}".format(const_vns))
                    if v.getAddress() in const_vns:
                        #print("fix compare pc = {}".format(PC))
                        start_judge = False
                    elif not len(const_vns):
                        start_judge = False
                        
                if start_judge:
                    stat_consume_slice(cur_bb,PC)     
    

        #if slice is CALL,save the correct slot vn,if there is no other slices,use the call slice.
        elif des.getOpcode() == PcodeOp.CALL or des.getOpcode() == PcodeOp.CALLIND:
            print("in Call_list")
            result = handle_whether_bb_in_intersection(cur_bb,consume_bbs)
            if result or not len(consume_bbs):
                call_pcodes.add(des)
        
        #if all slice is not belonging to the above three types,and check if it is the Store Pcode.go to find all the read reference to continue.
        elif des.getOpcode() == PcodeOp.STORE:
            print("in store_list")
            store_pcodes.add(des)
                
        elif des.getOpcode() == PcodeOp.RETURN:
            print("in return_list")
            return_pcodes.add(des)

    if len(consume_pcs):
        return
    
    # 判定完毕后，对consume,call,return,store集合中的结果分别进行结算
    # if run here, it seems that no Effective PcodeOp is catched.So if there is CALL pcode,we use it.
    temp_vn = return_vn
    print("run here,to use call pcode")
    for call in call_pcodes:
        called_func = getFunctionContaining(call.getInput(0).getAddress())
        for i in range(call.getNumInputs()):
            v = call.getInput(i)
            #print(v)
            #print("return vn = {}".format(temp_vn))
            if not slice_match(v,temp_vn):
                continue
            
            #print("Success Match!")
            #print(v)
            slot = i-1
            return_vn = find_param_by_slot(called_func,slot)
            #print(slot)
            ret_queue.append(return_vn)
    
    #If the slice does not contain the above three types, check if it contains the store type
    if not len(call_pcodes):
        # 如果只剩下store类型的切片，则需要先追踪其去向,若无向上传递，则再检查其是否为全局变量。如果均不通过，则此处为最终消耗点
        if len(store_pcodes):
            for store in store_pcodes:
                pc = store.getSeqnum().getTarget()
                #开启中断读追踪store模式
                global irq_store_trace
                irq_store_trace = True
                del final_consume_point[:]
                print(">>> irq_store_trace,now the store pc =",pc)
                
                result = find_real_callread_addr(pc)
                if isinstance(result, bool):
                    #表示已找到目标消耗点
                    if result == True:
                        print(">>> store consume is find in 1 round:",final_consume_point[-1])
                        return consume_pcs.add(final_consume_point[-1])
                    elif result == False:
                        get_calling_callpcodes(func)
                #表示找到了index
                elif result:
                    get_calling_callpcodes(func,result)
                
                #查看最后是否已找到
                if len(final_consume_point):
                    print(">>> store consume is final found:",final_consume_point[-1])
                    return consume_pcs.add(final_consume_point[-1])
                else:
                    print(">>> start compute the store global references")
                    ret = trace_store_global_refs_consume_slice(pc)
                    if not ret:
                        consume_pcs.add(pc)
                
        elif len(return_pcodes):
            for ret_pcode in return_pcodes:
                pcode_pc = ret_pcode.getSeqnum().getTarget()
                func = getFunctionContaining(pcode_pc)
                ret_vn_set = get_calling_function_retvn(func)
                for ret_vn in ret_vn_set:
                    ret_queue.append(ret_vn)
            


def stat_consume_slice(cur_bb,PC):
    if not len(consume_bbs):
        #print("add first bb")
        consume_bbs.add(cur_bb)
        consume_pcs.add(PC)
    else:
        result = handle_whether_bb_in_intersection(cur_bb,consume_bbs)
        #print("result:",result)
        if result:
            consume_bbs.add(cur_bb)
            consume_pcs.add(PC)
    

# Reverse the Control flow to find the previous basic block
def Find_Backfoward_Cbranch(read_PC,channel_flag = None):
    already_visit_func.add(getFunctionContaining(read_PC))
    #Queue = queue.Queue()
    Queue = []
    addr_start = read_PC
    flagg = 0
    read_avail_addr = None
    duration_time = time.time()
    while True:
        bb = get_bb(addr_start)
        bb_func = getFunctionContaining(addr_start)
        flagg += 1
        #print("time is ",time.time() - duration_time)
        if time.time() - duration_time > 1 :
            print("Time out!Don't need to pass the check, or not find the check point!")
            #if not found ,use the function entrypoint of read_pc as the avail_pc
            if not len(temp_input_result_pc):
                # read_avail_addr = getInstructionBefore(read_PC).getAddress()
                if channel_flag == True:
                    read_avail_addr = read_PC
                else:
                    read_avail_addr = getFunctionContaining(read_PC).getEntryPoint()
                break
            else:
                input_Address = temp_input_result_pc[-1]
                # input_Address = getInstructionBefore(input_Address).getAddress()
                read_avail_addr = getFunctionContaining(input_Address).getEntryPoint()
                print("The nearest Condition PC is: " + str(input_Address) + "\n")
                break

        pre_bbs = get_predecessors_blocks(bb)
        #print(pre_bbs)
        for pre_bb in pre_bbs:
            pre_bb_func = getFunctionContaining(pre_bb.getMinAddress())
            if pre_bb_func != bb_func:
                prepre_bbs = get_predecessors_blocks(pre_bb)
                for prepre_bb in prepre_bbs:
                    Queue.append(prepre_bb)
            else:
                Queue.append(pre_bb)
            
        if not len(Queue):
            break
        
        pre_bb = Queue[-1]
        Queue.pop()
        
        addr_start = pre_bb.getMinAddress()
        addr_end = pre_bb.getMaxAddress()
        input_Address = handle_bb_pcode(addr_start,addr_end,'avail')

        # Find the nearest Condition PC
        if input_Address:
            #input_Address = getInstructionBefore(input_Address).getAddress()
            print("The nearest Condition PC is: " + str(input_Address) + "\n")
            read_avail_addr = input_Address
            break

    return read_avail_addr    


'''get the funtions which global symbol has visited '''
def get_all_forward_slice():
    #visited_funcs = set()
    varnodes = set()
    #varnodes = []
    #pcodeops = set()
    worklist = queue.Queue()

    for vn in global_vn_set:            #将初始队列的varnode加入进来
        #print("seed",vn)
        worklist.put(vn)

    while not worklist.empty():
        curvn = worklist.get()
        
        if not curvn:
            continue
    
        """对varnode进行去重,去除完全相同的varnode"""
        next_one = 0
        
        ##f.write("Current varnode.The varnode = {},The Address = {}\n\n".format(curvn,curvn.getPCAddress()))
        for vn in varnodes:
            if cmp_vn(curvn,vn):
                next_one = 1 
                break
        
        if next_one:
            ##f.write("\nSame varnode!!!! The varnode = {},The Address = {}\n".format(curvn,curvn.getPCAddress()))
            continue

        """若为新vn,则对vn进行切片"""
        varnodes.add(curvn)

        iter = curvn.getDescendants()
        
        if not iter:
            continue

        for op in iter:
            curvn_new = None
            op_addr = op.getSeqnum().getTarget()
            #print("The current pcode is =",op,op_addr,getFunctionContaining(op_addr))
            ForwardSliceFunc.add(getFunctionContaining(op_addr))
            if not op:
                #print("no op")
                continue
            
            # PcodeOp.MULTIEQUAL 对MULTIEQUAL情况进行去重
            if op.getOpcode() == PcodeOp.MULTIEQUAL:
                add_multiequal_pcode(op)
                
            elif op.getOpcode() == PcodeOp.PTRSUB:
                # print("ptrsub_op = ",op)
                # print("ptr_pc = ",op.getSeqnum().getTarget())
                #f.write("ptrsub_op = {},pc = {}".format(op,op.getSeqnum().getTarget()))
                handle_PTRSUB_pcode(op,curvn)
            
                """  PcodeOp.CALL  """
            elif op.getOpcode() == PcodeOp.CALL or op.getOpcode() == PcodeOp.CALLIND:
                #print("1111")
                slot = -1
                for i in range(1,op.getNumInputs()):
                    if cmp_vn(op.getInput(i),curvn):
                        slot = i-1
                    #elif getDataAt(op.getInput(i).getAddress()):

                #print("slot = ",slot)
                ##f.write("The current pcode is = {} {} {}\n".format(op, op_addr, getFunctionContaining(op_addr)))
                if slot < 0:
                    #print("slot < 0,continue")
                    ##f.write("slot < 0,continue\n")
                    continue

                func_new = getFunctionContaining(op.getInput(0).getAddress())

                #if func_new not in visited_funcs:#之前没访问过  
                vn = find_param_by_slot(func_new,slot)  
                if vn:
                    #print("new func =",func_new)    
                    curvn_new = vn
                else:
                    print("visited!")

                """  PcodeOp.RETURN  """
            elif op.getOpcode() == PcodeOp.RETURN:  
                #print("enter return")
                if op.getNumInputs() < 2:
                    #print("Invalid return pcode,continue")
                    continue    
                
                refs = getReferencesTo(getFunctionContaining(op_addr).getEntryPoint())
                current_func = getFunctionContaining(op_addr)

                for ref in refs:
                    addr = ref.getFromAddress()
                    func = getFunctionContaining(addr)
                    hfunc = get_highfunc(func)
                    
                    if not hfunc:
                        #print("RETURN,No hfunc,continue")
                        continue

                    for pcode in hfunc.getPcodeOps(addr):
                        if pcode.getOpcode() == PcodeOp.CALL:
                            #print(pcode)
                            if pcode.getOutput():
                                #print("CALL has Output:",pcode.getOutput())
                                worklist.put(pcode.getOutput())

            #不属于上面任何一种类型，则保存其输出
            else:
                #print("default curvn_new")
                ##f.write("default curvn_new\n")
                curvn_new = op.getOutput()
            #防止陷入死循环
            if curvn_new:
                #print("############The curvn_new = ",curvn_new,curvn_new.getPCAddress())
                ##f.write("The curvn_new =  {} {}\n".format(curvn_new, curvn_new.getPCAddress()))
                worklist.put(curvn_new)
            else:
                # print("Don't have new varnode!")
                pass

    return varnodes

#handle the ref which concat the baseaddr and offset to find a new global member's all references
#!But the module ReferenceUtils.findDataTypeReferences take a lot time,so we temporarily close it
def handle_base_offset_pair():
    #handle the base_offset_pair
    for base_addr, offset in base_offset_addr_set:
        print("len = ",len(base_offset_addr_set))
        refs = get_member_refs(base_addr,offset)
        if not refs:
            continue
        for ref_addr in refs:
            func = getFunctionContaining(ref_addr)
            if not func:
                continue
            ForwardSliceFunc.add(func)
            hfunc = get_highfunc(func)
            if not hfunc:
                continue
            for pcode in hfunc.getPcodeOps(ref_addr):
                if pcode.getOpcode() == PcodeOp.LOAD:
                    vn = pcode.getOutput()
                    global_vn_set.add(vn)
                    # vn_global_dict[hash(vn)] = toAddr(ref_addr.offset + offset)
                    break
    
def whether_match_func_param_vn(addr,target_vn):
    func = getFunctionContaining(addr)
    hfunc = get_highfunc(func)
    param_count = hfunc.getLocalSymbolMap().getNumParams()
    for slot in range(param_count):
        param_vn = find_param_by_slot(func,slot)
        if cmp_vn(param_vn,target_vn):
            return slot
    return None    


def match_func_param_vn_by_backtrace(addr,target_vn):
    func = getFunctionContaining(addr)
    hfunc = get_highfunc(func)
    
    for i in range(hfunc.getLocalSymbolMap().getNumParams()):
        del Current_Func_vn[:]
        del Current_tmp_param_result[:]
        param_vn = find_param_by_slot(func,i)
        print(">> try to match param_vn = ",param_vn)
        Current_Func_vn.append(param_vn)

        ret = get_param_value(target_vn)
        print("ret = ",ret)
        if ret == True or len(Current_tmp_param_result):
            print("match success:{}".format(param_vn))
            return i
    return None

# escape the buffer clear opeartions in some firmwares
def escape_buffer_clear_block(callread_pc):
    bb = get_bb(callread_pc)
    max_addr = bb.getMaxAddress()
    next_block_addr = getInstructionAfter(max_addr).getAddress()
    return next_block_addr
    
    


def clear_gfsp_global_variables():
    global_symbols.clear()
    already_visit_func.clear()
    del Current_Func_vn[:]
    del Current_offset_vn[:]
    del Current_head_vn[:]        

def clear_acp_global_variables():
    del temp_get[:]
    consume_pcs.clear()
    consume_bbs.clear()

def clear_global_variables():
    del temp_input_result_pc[:]
    del callread_pcs[:]
    del final_consume_point[:]
    
    del Current_Func_vn[:]
    del Current_offset_vn[:]
    del Current_head_vn[:]
    
    del temp_get[:]
    consume_pcs.clear()
    consume_bbs.clear()
    
    global_symbols.clear()
    already_visit_func.clear()
    
    global firmware_type
    firmware_type = None

def setup_process(callread_addr,read_addr,entry_point,irq_pc = None,buffer_addr = None,filename = None):
    
    start_time = time.time()
    print("start_time:",start_time)
    get_global_symbols()
    
    lst = [callread_addr,read_addr,entry_point,irq_pc,buffer_addr]
    for index in range(len(lst)):
        member = lst[index]
        if not member:
            continue
        try:
            member = toAddr(hex(int(member)))
            lst[index] = member
            
        except:
            member = toAddr(member)
            lst[index] = member
    
    callread_addr = lst[0]
    read_addr = lst[1]
    entry_point = lst[2]
    irq_pc = lst[3]
    buffer_addr = lst[4]
    print("addr:",lst)
    
    
    # if callread_addr:
    #     if buffer_addr != None:
    #         callread_addr = toAddr(callread_addr.offset-1)
    #         callread_addr = getInstructionBefore(callread_addr).getAddress()
    
    
    if filename and os.path.isfile(filename):
        with open(filename, 'r') as file:
            # callinds_dict.update(file.read().eval())
            content = eval(file.read())
            for key,value in content.items():
                try:
                    key_addr = toAddr(hex(int(key)))
                    value_addr = toAddr(hex(int(value)))
                except:
                    key_addr = toAddr(key)
                    value_addr = toAddr(value)
                                        
                if key_addr and value_addr:
                    callinds_dict[key_addr] = value_addr
            print(callinds_dict)
    else:
        print("file '{}' not exist.".format(filename))
    
    if buffer_addr:
        global_addrs.add(buffer_addr)

    # get_called_functions from main loop
    if not entry_point:
        print("Error in entry_point_addr!")
        return
    func1 = getFunctionContaining(entry_point)
    if not func1:
        print("Error in entry_point_func!")
        return 
 
    called_functions1 = get_called_functions(func1)
    
    if not called_functions1 or len(called_functions1) <= 3:
        for func in currentProgram.getFunctionManager().getFunctions(True):
            if 'main' == str(func.getName()):
                print("repeat run the loop from main not reset_handler")
                get_called_functions(func)

    # get_called_functions from irq func
    if irq_pc:
        func2 = getFunctionContaining(irq_pc)
        if not func2:
            print("irq_pc = ",irq_pc)
            print("Error in irq_pc_func!")
            return
        get_called_functions(func2)
    
    return callread_addr,read_addr,entry_point,irq_pc,buffer_addr,filename

def gfsp_main(callread_addr,read_addr,entry_point,irq_pc,buffer_addr = None,filename = None):
    global setup_flag
    if not setup_flag:
        callread_addr,read_addr,entry_point,irq_pc,buffer_addr,filename = setup_process(callread_addr,read_addr,entry_point,irq_pc,buffer_addr,filename)
        setup_flag = True

    #Record all the function the global_symbol has visited
    # handle_base_offset_pair()

    clear_gfsp_global_variables()
    
    '''get the global slice'''
    for global_addr in global_addrs:  
        handle_global_symbol(global_addr) 

    get_all_forward_slice()

    print("The all global are here:")
    print("global_addrs_begin")
    addr_glist = []
    for i in global_addrs:
        print(i)
        addr_glist.append('0x'+str(i))
    print("global_addrs_end")

    #输出所有前向切片切到的函数
    print("All func")
    for func in ForwardSliceFunc:
        # print(func.getEntryPoint())
        print(func)
    print("\n\n")

    global read_except_func
    #read_func.add(get_calling_func_with_callinstr(read_addr))
    read_except_func = getFunctionContaining(read_addr)
    read_avail_addr = Find_Backfoward_Cbranch(callread_addr)

    if not read_avail_addr:
        print("Not find effective addr. So avail_addr is the front of callread_addr!")
        read_avail_addr = callread_addr

    print("read_avail_addr:",read_avail_addr)
    result = []
    
    result.append('0x'+str(read_avail_addr))
    result.extend(addr_glist)
    
    # ret = acp_main(callread_addr,read_addr)
    
    if result:
        return result
    else:
        return None

def acp_main(callread_addr):
    print("hello")
    start_time = time.time()
    print(start_time)
    
    #先清空所有全局变量
    clear_acp_global_variables()
    
    ret = find_consume_pc(callread_addr)  
    
    end_time = time.time()
    run_time = end_time - start_time
    print("total time:", run_time, "seconds")
    
    if not ret:
        # print("Consume PC = {}".format(result))
        print("ret is None")
        return ret
    else:
        result = []
        for i in ret:
            result.append('0x'+str(i))
        print("Consume PC = {}".format(result))
        return result

#combine all the module
def all_main(callread_addr,read_addr,entry_point,irq_pc = None,buffer_addr = None,filename = None):
    start_time = time.time()
    clear_global_variables()

    global setup_flag
    setup_flag = False
    
    if not setup_flag:
        callread_addr,read_addr,entry_point,irq_pc,buffer_addr,filename = setup_process(callread_addr,read_addr,entry_point,irq_pc,buffer_addr,filename)
        setup_flag = True
    #Save the origin_callread
    
    #Save each instance,each one is a dict
    dt_instance = []
    
    func = getFunctionContaining(callread_addr)
    hfunc = get_highfunc(func)
    
    callread_type = None
    
    if irq_pc != None:
        callread_type = "irq"
    elif irq_pc == None:
        callread_type = "main"
    
    global firmware_type
    firmware_type = callread_type
    
    consume_start_pcs = get_all_callread_from_one_read(callread_addr)
    global_vars = []
    
    print(consume_start_pcs)
    
    #for each callread_pc, run the avail_func to got corespond avail_pc and consume_pc
    for index in range(len(callread_pcs)):
        #run the consume_module use the consume_start_pc_set
        #if the consume_set is None,it seems this point may not be a effective read_pc,skip it. 
        if callread_type == "irq":
            consume_pc_set = acp_main(consume_start_pcs[index])
            if consume_pc_set == None:
                print("not a effective read point ,skip it")
                continue
        elif callread_type == "main":
            #如果目标的callread没有消耗点，则不为其创建dt
            if consume_start_pcs[index] in mainread_callread_consume_None:
                continue
            #否则将callread所在函数头作为消耗点
            else:
                consume_pc_set = ['0x'+str(getFunctionContaining(consume_start_pcs[index]).getEntryPoint())]
                
                
        if callread_type == "irq":
            # run the avail_module
            avail_and_globals = gfsp_main(callread_pcs[index],read_addr,entry_point,irq_pc,buffer_addr,filename)
            avail_pc = avail_and_globals[0]
        
            if global_vars == []:
                global_vars = avail_and_globals[1:]
            pass
                
        # if this is a load pcode,the avail_pc is the callread_pc  
        elif callread_type == "main":
            avail_pc = callread_pcs[index]

        print(callread_type)
        #if the consume_pc_set is not None,save all the data to the dt
        dt = {}
        dt["avail_pc"] = str(avail_pc)
        dt["callread_pc"] = '0x'+str(callread_pcs[index])
        dt["consume_pc_set"] = consume_pc_set
        
        #finally add the dt which is finish collecting data
        dt_instance.append(dt)
    
    #如果有多通道的情况，则需要对多通道情况下的avail默认值重新计算
    if len(dt_instance) > 1 and callread_type == "irq":
        for dt in dt_instance:
            callread_pc = toAddr(dt["callread_pc"])
            avail_pc = Find_Backfoward_Cbranch(callread_pc,True)
            dt["avail_pc"] = '0x'+str(avail_pc)
            
    
    # if escapre_data_input_point != None:
    #     dt_instance.append('0x'+str(escapre_data_input_point))
    #     print("dt_instance = ",dt_instance)
    #     return dt_instance
    
    #put the global_vars to last index
    dt_instance.append(global_vars)
    
    
    print("dt_instance = ",dt_instance)

    end_time = time.time()
    print("total time:", end_time - start_time, "seconds")
    return dt_instance


# Gateway
# all_main('0x8002ee2', '0x8008b80','0x800365d', '0x8008818', '0x2000070d',None)

# Steering_Control
# all_main('0x811d4', '0x81264', '0x80bfd', '0x80718','0x20070c08',None)

# PLC
# all_main('0x80006dc', '0x800425e', '0x8000d19', '0x8003fe0','0x20000345',None)

# Heatpress
# all_main('0x801de', '0x81448', '0x80f35', '0x80abc','0x20070b80',None)

# Console
# all_main('0x231a', '0x22f4','0x1674', '0x99d', '0x1fff0578','callind_dict.txt')

# CNC
# all_main('0x800822e', '0x8007e28', '0x8009260', None, None,'callind_dict.txt')

# Drone
# all_main('0x8001ab4', '0x8001ab4', '0x8004f44', None, None,'callind_dict.txt')

# Robot
# all_main('0x80025a8', '0x80025a8', '0x80056b8', None, None,'callind_dict.txt')

# Reflow_Oven
# all_main('0x80028a0', '0x80028a0', '0x8001c78', None, None,'callind_dict.txt')
