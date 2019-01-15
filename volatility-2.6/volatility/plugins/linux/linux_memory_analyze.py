#coding=utf-8
# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Archer Day
@license:      GNU General Public License 2.0
@contact:      ahdhy2008@gmail.com
@organization: 
"""



import volatility.plugins.linux.info_regs as linux_info_regs

import volatility.plugins.linux.pslist as linux_pslist
import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common

import struct
import re
import datetime

import os
import time


import socket    

import collections

import volatility.debug as debug
try:
    import distorm3
    distorm_loaded = True
except:
    distorm_loaded = False

offsets = {}
# x86 offsets - It works on my Linux machine.
offsets['32bit'] = [
'ebx',
'ecx',
'edx',
'esi',
'edi',
'ebp',
'eax',
'ds',
'es',
'fs',
'gs',
'orig_eax',
'eip',
'cs',
'eflags',
'esp',
'ss'
]

# x64 offsets
offsets['64bit'] = [
'r15',
'r14',
'r13',
'r12',
'rbp',
'rbx',
'r11',
'r10',
'r9',
'r8',
'rax',
'rcx',
'rdx',
'rsi',
'rdi',
'unknown', # I'm not sure what this field is
'rip',
'cs',
'eflags',
'rsp',
'ss',
'fs_base',
'gs_base',
'ds',
'es',
'fs',
'gs'
]

reg_size = {}
reg_size['32bit'] = 0x4
reg_size['64bit'] = 0x8

fmt = {}
fmt['32bit'] = '<I'
fmt['64bit'] = '<Q'

def FuncSet(str):
    patternfunc = re.compile(r"<.*>")
    functionList = re.findall(patternfunc, str)
    return functionList
    
def objdump_handle():   
    #with open("./initial/objfile/example1.s",'r') as f:   #set path  ***  #这个函数可以单独提取出来测试 知道最终获取的字典内容
    with open("/home/kong/JavaMemory/volatility-2.6/objfile/stackdump",'r') as f:   #set path  ***  虚拟机中正在运行的c语言程序的反汇编码文件
         total_str = f.read()

    #the initial range  "libc  ---  main "
    # start_index = total_str.find("<__libc_start_main@plt>:")
    # end_index =  total_str.find("<__libc_csu_fini>:")   #modify
    start_index = total_str.find("<_init>:")
    end_index = total_str.find("<_fini>:")  # modify
    total_str = total_str[start_index:end_index]        #从反汇编码中 获取其中一段 从<__libc_start_main@plt>:到<__libc_csu_fini>:
    # print total_str
    funcList = FuncSet(total_str)
    
    handle_dict = {}
    pattern1 = re.compile(r"call.*<.*>") #function call   例如 call   400864 <func>
    pattern2 = re.compile(r"[0-9a-zA-Z]+:")   #return_address 例如  0000000000400b28 <C>:
    call_iter = re.finditer(pattern1, total_str)    #见  finditer用法

    #string handle ---> dict
    handle_str = total_str
    for call_str in call_iter:
        call_index = handle_str.find(call_str.group())
        handle_str = handle_str[call_index:]
        return_address = re.search(pattern2,handle_str)
        handle_dict[return_address.group()[:-1]] = call_str.group()
    print "handle_dict", handle_dict
    return handle_dict


def yield_address(space, start, length = None, reverse = False):
    """
    A function to read a series of values starting at a certain address.

    @param space: address space
    @param start: starting address
    @param length: the size of the values to read
    @param reverse: option to read in the other direction
    @return: an iterator
    """
    if not length:
        length = 8
    cont = True
    while space.is_valid_address(start) and cont:
        try:
            value = read_address(space, start, length)
            yield value
        except struct.error:
            cont = False
            yield None
        if reverse:
            start -= length
        else:
            start += length

def read_address(space, start, length = None):
    """
    Read an address in a space, at a location, of a certain length.
    @param space: the address space
    @param start: the address
    @param length: size of the value
    """
    if not length:
        length = 8
        #print length
    fmt = "<I" if length == 4 else "<Q"
    return struct.unpack(fmt, space.read(start, length))[0]

def build_event(event_name, event_value, event_id):
    ver = 1
    cmd = 101
    event_head = "<xml type=\"event\" name=\"" + event_name + "\" num=\"" + str(event_id) + "\" attr=\""
    event_tail = "\"><x>" + str(event_value) + "</x><t>" + str(event_id) + "</t></xml>"
    event_attr = '*' * (100 - len(event_head) - len(event_tail))
    event_str = event_head + event_attr + event_tail
    print event_str
    header = [ver, event_str.__len__(), cmd]
    headPack = struct.pack("!3I", *header)
    return headPack + event_str.encode()

def get_event_name(list):
    new_list = list[:]
    new_list.reverse()
    ans = []
    i = 0
    while i + 1 < len(new_list):
        str1 = new_list[i][0][1:-1].split("_")[-1].replace("@plt", "")
        str2 = new_list[i + 1][0][1:-1].split("_")[-1].replace("@plt", "")
        print str1 + "_" + str2
        ans.append(str1 + "_" + str2)
        i += 1
    return ans


#class linux_memory_analyze(linux_common.AbstractLinuxCommand):
class linux_memory_analyze(linux_pslist.linux_pslist):
    """Gather active tasks by walking the task_struct->task list"""
    global read_address_size
    read_address_size = 8
    
    def __init__(self, config, *args, **kwargs):
        #linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        linux_common.set_plugin_members(self)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
        

        self.thread_offset = self.profile.vtypes['task_struct'][1]['thread_group'][0]

        self.inforegs = linux_info_regs.linux_info_regs(config)

        self.bits = 0
        self.reg_size = 0
        self.offsets = []
        self.fmt = ""
        self.task = None

        if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            address_size = 4
        else:
            address_size = 8

         #2016.12.12
        if distorm_loaded:  #这个插件需要python2.7
            self.decode_as = distorm3.Decode32Bits #if linux_proc_info.address_size == 4 else distorm3.Decode64Bits
        else:
            debug.error("You really need the distorm3 python module for this plugin to function properly.")

    def parse_kernel_stack(self, task):
        result = collections.OrderedDict()
        if 1 or task.mm:
            sp0 = task.thread.sp0
            #proc_as = task.get_process_address_space()
            addr = sp0

            for reg in self.offsets[::-1]: # reverse list, because we read up in the stack
                #debug.info("Reading {:016x}".format(addr))
                addr -= self.reg_size
                val_raw = self.addr_space.read(addr, self.reg_size)
                val = struct.unpack(self.fmt, val_raw)[0]
                result[reg] = val
            return result
        return None

    def get_inforegs(self, task):
        linux_common.set_plugin_members(self)

        self.bits = self.profile.metadata.get('memory_model', '32bit')
        self.reg_size = reg_size[self.bits]
        self.offsets = offsets[self.bits]
        self.fmt = fmt[self.bits]

        thread_name = task.comm
        tid = task.pid
        regs = self.parse_kernel_stack(task)
        thread_registers = []
        thread_registers.append((thread_name, regs, tid))
        yield task, thread_name, thread_registers
        # for proc in linux_pslist.linux_pslist(self._config).calculate():
        #     name = proc.get_commandline()
        #     thread_registers = []
        #     for thread_task in proc.threads():
        #         # thread_name = thread_task.comm
        #         # regs = self.parse_kernel_stack(thread_task)
        #         # tid = thread_task.pid
        #         thread_registers.append((thread_name,regs, tid))
        #     yield proc, name, thread_registers

    def get_registers_value(self, inforegs):
        """get registers value ---dhy 2016-11-27 """
        # taskinfo = inforegs.calculate()
        if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            rsp_register = "esp"
            rbp_register = "ebp"
            rip_register = "eip"
        else:
            rsp_register = "rsp"
            rbp_register = "rbp"
            rip_register = "rip"
        inforegs = self.get_inforegs(self.task)
        for task, name, thread_regs in inforegs:
            fmt = str(2*0x8)
            for thread_name, regs, tid in thread_regs:
                if regs != None:
                    for m in regs:
                        # print "regkeys()", m
                        if m == rsp_register:
                            rspValue = regs[m]
                            print "rsp_value: ", hex(rspValue)
                        if m == rbp_register:
                            rbpValue = regs[m]
                            print "rbp_value: ", hex(rbpValue)
                        if m == rip_register:
                            ripValue = regs[m]
                            print "rip_value: ", hex(ripValue)
                return rspValue
                    #for reg, value in regs.items():
                    #    print "type:",type(regs)
                    #    debug.info(("dhy::    {:8s}: {:0" + fmt + "x}\n").format(reg, value))


    def is_return_address(self, address, process_info): 
        """
        Checks if the address is a return address by checking if the preceding instruction is a 'CALL'.
        @param address: An address
        @param process_info: process info object
        @return True or False
        #这是使用了 distrom3 插件  查看当前地址address是否为返回地址 （这个函数最终没有使用，可以借鉴）
        """
        proc_as = process_info.get_process_address_space() 
        size = 5
        # print type(size) ,type(address)
        start_code_address = process_info.mm.start_code
        end_code_address = process_info.mm.end_code
        if distorm_loaded and start_code_address < address < end_code_address: #and process_info.is_code_pointer(address):
            offset = address - size
            instr = distorm3.Decode(offset, proc_as.read(offset, size), self.decode_as)
            # last instr, third tuple item (instr string), first 7 letters
            if instr[-1][2][:7] == 'CALL 0x':
                print(instr[-1][2])
            if len(instr) > 0:
                return instr[-1][2][:4] == 'CALL'
            # there's also call <register>
        return False





    def virtual_process_from_physical_offset(self, offset):
        pspace = utils.load_as(self._config, astype = 'physical')
        vspace = utils.load_as(self._config)
        task = obj.Object("task_struct", vm = pspace, offset = offset)
        parent = obj.Object("task_struct", vm = vspace, offset = task.parent)
        print "task:",task
        for child in parent.children.list_of_type("task_struct", "sibling"):
            if child.obj_vm.vtop(child.obj_offset) == task.obj_offset:
                return child

        return obj.NoneObject("Unable to bounce back from task_struct->parent->task_struct")

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")   #init_task 1号进程
        print "task_struct",hex(init_task_addr)
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)
        init_mm = obj.Object("mm_struct", vm = self.addr_space, offset=0x1a8)
        print type(init_mm)
        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
                yield task


           

    def calculate(self):
        linux_common.set_plugin_members(self)

        # pidlist = self._config.PID
        # if pidlist:
        #     pidlist = [int(p) for p in self._config.PID.split(',')]
        processname = "stack"
        for task in self.allprocs():
             # if not pidlist or task.pid in pidlist:
                if str(task.comm) in processname:
                    print "task.pid: ", task.pid
                    self.task = task
                    yield task


    def render_text(self, outfd, data):

        print ">>>>>>>> render_text >>>>>>>"

        testDict = {}
        testDict = objdump_handle()
        event_id = 1
        for task in data:
            print "process name:",task.comm
            print "start_stack:",hex(task.mm.start_stack)
            print "start_code and end_code:",hex(task.mm.start_code),hex(task.mm.end_code)

            proc_as = task.get_process_address_space()   #address space
            start_stack_address = task.mm.start_stack #task_struct->mm_struct->start_stack  ,stack bottom

            #  x86 or x64  : read_length  and size
            start_read_address = start_stack_address - 0x400 #栈大小1M
            l_old = []

            match_dict = {}
            match_dict = objdump_handle()  #
            #address = ('10.210.50.241', 21001)
            #address = ('10.108.167.101', 21001)  
            #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
            #s.connect(address)
            # for i in range(50000):
            sender = None
            tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcpSocket.bind(('', 6666))
            tcpSocket.listen(5)
            # try:
            #     print "waiting for connection..."
            #     sender, addr = tcpSocket.accept()
            #     print "...connected from:", addr
            # except Exception, e:
            #     print e

            i = 3
            while (i):
                time.sleep(0.1)
                i = i - 1
                start = datetime.datetime.now()
                l_new = []
                indexAddr = None

                rspV = self.get_registers_value(self.inforegs)  #获得栈顶寄存器值
                start_read_address = int(rspV)
                print type(start_read_address)


                for indexAddr in range(0, 512):
                    testAddr = start_read_address + indexAddr * 4
                    testValue = read_address(proc_as, testAddr, 4)  #读地址内容哦（地址空间，读取地址，读取长度）


                    print "Address: ", hex(testAddr), "Value: ", hex(testValue)
                    flag_tf = self.is_return_address(testValue, task)
                    if flag_tf is True:
                        print "flag_tf: ", flag_tf
                    # if flag_tf:
                    #     self.find_function_address(proc_as, testValue)


                    testStr = hex(testValue)[2:]                        #地址内容转16进制 去掉0x
                    # print "hex(testValue)[2:]", testStr
                    if testStr in testDict:
                        print flag_tf
                        print testStr, type(testStr)
                        listStr = testDict[testStr]
                        print "listStr", listStr
                        ppStr = FuncSet(listStr)
                        l_new.append(ppStr)                         
                    # print "l_new1::",l_new
                # l_new.append(['<main>'])
                print "l_new2::",l_new

                if cmp(l_old,l_new) != 0:               #l_old和l_new 即栈变化才打印
                    print "Analyze %s :" % i
                    str_new = "<-".join([str(x) for x in l_new])
                    print str_new
                    list_event_name = get_event_name(l_new)
                    for event_name in list_event_name:
                        event_str_with_head = build_event(event_name, 1, event_id)
                        print event_str_with_head
                        event_id += 1
                        if sender is not None:
                            sender.send(event_str_with_head)
                    #s.send(str_new)
                    end = datetime.datetime.now()
                    print "analyze time:",(end - start)
                else:
                    pass
                print "l_old: ", l_old
                l_old = l_new[:]

            #s.close()



