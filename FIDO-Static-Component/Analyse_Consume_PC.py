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
from ghidra.program.model.listing import Function
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
from ghidra.program.model.pcode import HighSymbol
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import Structure,TypedefDataType,StructureDataType
from collections import defaultdict
import sys
import time
import argparse
import Queue as queue
import json

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
block_model = BasicBlockModel(currentProgram)
decomp_result_dict = {} # highfunc cache

# cbranch_bbs= set()
temp_get = []

consume_pcs = set()
consume_bbs = set()

# start_judge_global = [True]

# Current_Func_vn = []

CompareOps_list = [PcodeOp.INT_EQUAL,PcodeOp.INT_NOTEQUAL,PcodeOp.INT_LESS,PcodeOp.INT_SLESS,PcodeOp.INT_LESSEQUAL,PcodeOp.INT_SLESSEQUAL]
ComputeOps_list = [PcodeOp.INT_ADD,PcodeOp.INT_SUB,PcodeOp.INT_MULT,PcodeOp.INT_DIV,PcodeOp.INT_OR,PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_AND,PcodeOp.INT_XOR,PcodeOp.INT_NEGATE]



def cmp_vn(curvn,vn):
    return hash(curvn) == hash(vn)

def get_highfunc(func):
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

def get_value(vn):
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
        return calc_pcode(vn.getDef(),get_value)
    elif vn.isAddrTied():
        return calc_pcode(vn.getDef(),get_value)

def get_param_value(vn):
    #f.write(str(vn.getDef()))
    if not Current_Func_vn:
        return None
    for i in Current_Func_vn:
        if cmp_vn(vn,i):
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

def calc_pcode(pcode,value_func):
    if isinstance(pcode, PcodeOpAST):
        opcode = pcode.getOpcode()
        if opcode == PcodeOp.PTRSUB:
            #print("Enter PTRSUB:")
            tar = pcode.getSeqnum().getTarget()
            var_node_1 = pcode.getInput(0)
            var_node_2 = pcode.getInput(1)
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
                return addr
            else:
                return None
            
        elif opcode == PcodeOp.PTRADD:
            var_node_0 = pcode.getInput(0)
            var_node_1 = pcode.getInput(1)
            var_node_2 = pcode.getInput(2)
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
                    value_1 = pcode.getInput(1).getOffset()
                else:
                    value_1 = 0 #设置为没有偏移
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
                print("error")
                return None
            except:
                print("error")
                return None

        elif opcode == PcodeOp.INT_MULT or opcode == PcodeOp.INT_ADD or opcode == PcodeOp.INT_SUB:
            var_node_0 = pcode.getInput(0)
            var_node_1 = pcode.getInput(1)
            value_0 = value_func(var_node_0)
            value_1 = value_func(var_node_1)
            if value_0 == True or value_1 == True:
                return True            
            #print(pcode,pcode.getSeqnum().getTarget())
            #print("value1=",value_1)
            #print("value2=",value_2)
            if isinstance(value_0, GenericAddress) and isinstance(value_1, GenericAddress):
                return toAddr(value_0.offset)
            else:
                return None

        elif opcode == PcodeOp.COPY or opcode == PcodeOp.INDIRECT or opcode == PcodeOp.CAST or opcode == PcodeOp.INT_ZEXT or opcode == PcodeOp.INT_SEXT or opcode == PcodeOp.INT_NEGATE :
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
        return None


def check_if_global(vn):
    result = get_value(vn)#获取全局变量地址
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

def get_bb(bb_addr):
    basic_block = block_model.getCodeBlocksContaining(bb_addr,monitor)[0]
    return basic_block


def get_predecessors_blocks(cbranch):
    branches = cbranch.getSources(monitor)
    branch_set = []
    while branches.hasNext():
        branch_addr = branches.next().getSourceAddress()
        branch_block = get_bb(branch_addr)
        branch_set.append(branch_block)
    return branch_set


"""Continue slicing other slices that do not belong to these types until they are converted to thesetypes"""
def run_until_satisfy_special_pcode(pcode):
    descendant_queue = []
    descendant_queue.append(pcode)
    result = []
    while(len(descendant_queue)):
        origin_des = descendant_queue[-1]
        #print("Current des = {}".format(origin_des))
        descendant_queue.pop()
        temp_des = origin_des
        flag = 1
        while temp_des.getOpcode() not in ComputeOps_list and temp_des.getOpcode() not in CompareOps_list and temp_des.getOpcode() != PcodeOp.CALL and temp_des.getOpcode() != PcodeOp.CALLIND and temp_des.getOpcode() != PcodeOp.STORE and temp_des.getOpcode() != PcodeOp.RETURN:
            flag = 0
            temp_out = temp_des.getOutput()
            if not temp_out:
                break
            for temp_des in temp_out.getDescendants():
                descendant_queue.append(temp_des)
                #print("temp_des = {}".format(temp_des))
        if flag:
            result.append(temp_des)
    return result


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
def handle_whether_bb_in_intersection(cur_bb):
    for consume_bb in consume_bbs:
        if consume_bb == cur_bb:
            continue
        bbs = [consume_bb,cur_bb]
        ances_bb = get_ancestor_block(bbs)
        # if ances_bb is one of the consume_bb or cur_bb, it means that the other bb is need to discard.
        if ances_bb == cur_bb or ances_bb == consume_bb:
            return False
        # if ances_bb isn't the one of the consume_bb or cur_bb,so we need to add the cur_bb,because they are independent.
        else:
            continue
    return True    


def get_calling_function_retvn(func):
    ret_vn_set = set()
    references = getReferencesTo(func.getEntryPoint())
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


"""Try to find the data consume PC from the read buffer pc"""
def find_consume_pc(buffer_read_pc,read_func_pc):
    func = getFunctionContaining(buffer_read_pc)
    hfunc = get_highfunc(func)
    return_vn = None
    ret_queue = []
    temp_descs = []
    const_vns = set()
    verify_slice_PC = None
    
    is_readpc_exist = read_func_pc != None and read_func_pc != buffer_read_pc
    
    if is_readpc_exist:
        read_func = getFunctionContaining(read_func_pc)
        """Catch the return value which is const, and compare with the calling func's cbranch value"""
        for pcode in hfunc.getPcodeOps(buffer_read_pc):
            if pcode.getOpcode() == PcodeOp.CALL or pcode.getOpcode() == PcodeOp.CALLIND:
                if pcode.getOutput():
                    return_vn = pcode.getOutput()
                    break
    else:
        for pcode in hfunc.getPcodeOps(buffer_read_pc):
            if pcode.getOpcode() == PcodeOp.LOAD:
                if pcode.getOutput():
                    return_vn = pcode.getOutput()
                    break
    
    if not return_vn:
        print(return_vn)
        print("not read_func or not return_vn")       
        return None
    
    if is_readpc_exist:
        rhfunc = get_highfunc(read_func)
        #Count the values of constant in all RETURN PcodeOp
        for pcode in rhfunc.getPcodeOps():
            if not pcode.getOpcode() == PcodeOp.RETURN:
                continue
            if not pcode.getInput(1):
                continue
            ret_vn = pcode.getInput(1)
            #print(ret_vn.getDef())
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
           
    ret_queue.append(return_vn)

    while(len(ret_queue)):
        return_vn = ret_queue[-1]
        ret_queue.pop()
        if not return_vn:
            continue
        descs = return_vn.getDescendants()
        call_pcodes = set()
        store_pcodes = set()
        return_pcodes = set()
        for des in descs:
            temp_descs.append(des)
            #print("Current des = {}".format(des))
        
        """if the slice pcode type is not belong compute,compare and call pcode,continue to slice it until its type in three type""" 
        for des in temp_descs:
            result_list = run_until_satisfy_special_pcode(des)
            #print("result_list = {}".format(result_list))
            for i in result_list:
                if des in temp_descs:
                    index = temp_descs.index(des)
                    temp_descs.remove(des)
                temp_descs.insert(index,i)
                index += 1
        
        temp_descs = sorted(temp_descs,key = lambda x:x.getSeqnum().getTarget()) 
        #print("all the des is:")
        #for des in temp_descs:
        #    print(des)
        
        start_judge = True
        for des in temp_descs:
            print("des = ",des)
            PC = des.getSeqnum().getTarget()
            cur_bb = get_bb(PC)
            func = getFunctionContaining(PC)
            #Current_Func_vn.clear()
            #print("des = {}".format(des))
            #print("des pc = {}".format(PC))
            # if the forward slice is the about compare operation, if it is the first time to judge.
            if des.getOpcode() in CompareOps_list:
                if not start_judge:
                    if not len(consume_bbs):
                        #print("add first bb")
                        consume_bbs.add(cur_bb)
                        consume_pcs.add(PC)
                    else:
                        result = handle_whether_bb_in_intersection(cur_bb)
                        #print("result:",result)
                        if result:
                            consume_bbs.add(cur_bb)
                            consume_pcs.add(PC)
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
                            verify_slice_PC = PC
                            start_judge = False
                        elif not len(const_vns):
                            start_judge = False 
                                           
                    #Check if the compare pcode is not the Data validity check vn
                    if start_judge:
                        start_judge = False
                        if not len(consume_bbs):
                            consume_bbs.add(cur_bb)
                            consume_pcs.add(PC)
                        else:
                            result = handle_whether_bb_in_intersection(cur_bb)
                            #print("result:",result)
                            if result:
                                consume_bbs.add(cur_bb)
                                consume_pcs.add(PC)
                        
            elif des.getOpcode() in ComputeOps_list:
                if not len(consume_bbs):
                    #print("add first bb")
                    consume_bbs.add(cur_bb)
                    consume_pcs.add(PC)
                else:
                    result = handle_whether_bb_in_intersection(cur_bb)
                    #print("result:",result)
                    if result:
                        consume_bbs.add(cur_bb)
                        consume_pcs.add(PC)       

            #if slice is CALL,save the correct slot vn,if there is no other slices,use the call slice.
            elif des.getOpcode() == PcodeOp.CALL or des.getOpcode() == PcodeOp.CALLIND:
                result = handle_whether_bb_in_intersection(cur_bb)
                if result or not len(consume_bbs):
                    call_pcodes.add(des)
            
            #if all slice is not belonging to the above three types,and check if it is the Store Pcode.go to find all the read reference to continue.
            elif des.getOpcode() == PcodeOp.STORE:
                    #cur_func = getFunctionContaining(PC)
                    #hfunc = get_highfunc(cur_func)
                    #for slot in hfunc.getLocalSymbolMap().getNumParams():
                    #    Current_Func_vn.append(find_param_by_slot(cur_func,slot))
                    store_pcodes.add(des)
                    
            elif des.getOpcode() == PcodeOp.RETURN:
                return_pcodes.add(des)

        if len(consume_pcs):
            return consume_pcs
        #if run here, it seems that no Effective PcodeOp is catched.So if there is CALL pcode,we use it.
        temp_vn = return_vn
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
            if len(store_pcodes):
                for store in store_pcodes:
                    pc = store.getSeqnum().getTarget()
                    consume_pcs.add(pc)
                    
            elif len(return_pcodes):
                for ret_pcode in return_pcodes:
                    pcode_pc = ret_pcode.getSeqnum().getTarget()
                    func = getFunctionContaining(pcode_pc)
                    ret_vn_set = get_calling_function_retvn(func)
                    for ret_vn in ret_vn_set:
                        ret_queue.append(ret_vn)
                
    print("Over")
    if len(consume_pcs):
        return consume_pcs
    else:
        # tmp = set()
        # print("run here")
        # tmp.add(verify_slice_PC)
        return None


def acp_main(callread_addr,read_addr):
    print("hello")
    start_time = time.time()
    print(start_time)
    # args = getScriptArgs()
    try:
        callread_addr = toAddr(hex(int(callread_addr)))
        read_addr = toAddr(hex(int(read_addr)))
    except:
        callread_addr = toAddr(callread_addr)
        read_addr = toAddr(read_addr)
    
    if callread_addr:
        callread_addr = toAddr(callread_addr.offset-1)
        callread_addr = getInstructionBefore(callread_addr).getAddress()
    
    ret = find_consume_pc(callread_addr,read_addr)  
    #ret = find_consume_pc(toAddr(0x8002ee2),toAddr(0x8008b6e))
    # ret = find_consume_pc(toAddr(0x800061e),toAddr(0x800424c))
    
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
# main()