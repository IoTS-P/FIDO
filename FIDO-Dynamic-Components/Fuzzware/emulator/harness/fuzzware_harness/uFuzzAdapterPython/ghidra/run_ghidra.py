# coding:utf-8
# usage: ghidra server, This script is used to run the ghidra script in the ghidra headless mode.
import socket 
import json
import os
import argparse
import os,logging
import threading
import subprocess
# debug_file_path = os.path.join(os.path.dirname(globs.args.input_file),"debug.log")
debug_file_path = "/tmp/debug.log" 
logging.basicConfig(level=logging.DEBUG, filename=debug_file_path, filemode='w+')
my_debug_log = logging.debug

#from static_analyze import Callind_Collect,global_forward_slice_purely,Analyse_Consume_PC

args = getScriptArgs()
port = int(args[0])
# semu_fuzz_name = str(args[-2])
# my_debug_log("port = ",port)
# global_dict = globals()
now_path = os.path.dirname(__file__)
with open(os.path.join(now_path, "static_analyze/Callind_Collect.py"), "r") as ccf,open(os.path.join(now_path, "static_analyze/global_forward_slice_purely.py"), "r") as gfspf:
    ccf_code = ccf.read()
    exec(ccf_code)
    gfspf_code = gfspf.read()
    exec(gfspf_code)
    my_debug_log("write success!")
    my_debug_log("port = ",port)
    
def run():
    my_debug_log("current_dir ={}".format(os.getcwd()))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # port = 10045   
    my_debug_log("port = {}".format(port))               
    while(True):
        try:
            server_address = ('localhost', port)
            my_debug_log("server_address = {}".format(server_address))
            server_socket.bind(server_address)
            server_socket.listen(1000)
            my_debug_log("current port is :{}".format(port))
            break
        except:
            my_debug_log("error") 
            continue

    my_debug_log("listening on port %d" % port)
    #get the code from the file
    try:
        while True:
            # 等待客户端连接
            client_socket, client_address = server_socket.accept()
            my_debug_log('Connect :{}'.format(client_address))
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
            #my_debug_log('Connect :', client_address)
            client_thread.join()
    
    finally:
        # 关闭服务器套接字
        client_thread.stop()
        client_socket.close()
        server_socket.close() 


def handle_client(client_socket):
    try:
        while True:
            # 接收数据

            param_data = client_socket.recv(1024)
            if not param_data:
                my_debug_log('Received but no data')
                my_debug_log('break,and wait for next connection')
                break
            param_data = param_data.decode()
            # 解析参数
            list = json.loads(param_data)
            my_debug_log('Received : {}'.format(param_data))
            run_type = list[0]
            #my_debug_log("run_type:", list[0])
            response = "null"
            my_debug_log('run_type : {}'.format(run_type))
            
            # 运行间接调用脚本
            if run_type == "callind_collect":
                my_debug_log('exe the ccf code')
                response = cc_main()

            # 运行总脚本(avail脚本和consume脚本)
            elif run_type == "global_static_data":
                my_debug_log('exe the all_main_code')
                my_debug_log("list = {}".format(list))
                response = all_main(list[1],list[2],list[3],list[4],list[5],list[6])
            
            # 用于纠正Lr寄存器
            elif run_type == "correct_lr":
                my_debug_log('exe the correct_lr')
                callread_pc = list[1]
                my_debug_log('origin callread = {}'.format(callread_pc))
                callread_pc = toAddr(int(callread_pc) - 1)
                my_debug_log('hex callread = {}'.format(callread_pc))
                response = '0x'+str(getInstructionBefore(callread_pc).getAddress())
                my_debug_log('response callread = {}'.format(response))
            
            # 用于计算公共节点
            elif run_type == "get_ancestor":
                my_debug_log('exe the get_ancestor')
                my_debug_log("list = {}".format(list))
                pc = int(list[1])
                pc_addr = toAddr(pc)
                bb = get_bb(pc_addr)
                bb_addr = bb.getMinAddress()
                my_debug_log("bb_addr = {}".format(bb_addr))    
                response = ['0x'+str(bb_addr)]
                my_debug_log("response:{}".format(response))
                pass
            else:
                my_debug_log('error run_type!')
                continue
            
            print("response:{}".format(response))
            
            # 发送响应数据
            if response != "null":
                my_debug_log("Success got the response")
                my_debug_log("response:{}".format(response))
                json_response = json.dumps(response)
                client_socket.sendall(json_response.encode())
            else:
                my_debug_log("No response!")
                break
    except:
        import traceback
        my_debug_log('Error when recv or handle data!')
        my_debug_log(traceback.format_exc())
        client_socket.close()

        pass
    finally:
        client_socket.close()

        print("Connection closed.")
        my_debug_log("Connection closed.")

 
run()