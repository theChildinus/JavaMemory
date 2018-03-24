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
from volatility.plugins.linux.linux_proc_info import address_size

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

import cPickle  #...
import os
import time


import socket    

 

import volatility.debug as debug
try:
    import distorm3
    distorm_loaded = True
except:
    distorm_loaded = False



def FuncSet(str):
    patternfunc = re.compile(r"<.*>")
    functionList = re.findall(patternfunc, str)
    return functionList
    
def objdump_handle():    #这个函数可以单独提取出来测试 知道最终获取的字典内容
    #with open("./initial/objfile/example1.s",'r') as f:   #set path  *** 
    with open("./initial/objfile/uclientobj",'r') as f:   #set path  ***  虚拟机中正在运行的c语言程序的反汇编码文件
         total_str = f.read()

    #the initial range  "libc  ---  main "
    start_index = total_str.find("<__libc_start_main@plt>:")    
    end_index =  total_str.find("<__libc_csu_fini>:")   #modify    
    total_str = total_str[start_index:end_index]        #从反汇编码中 获取其中一段 从<__libc_start_main@plt>:到<__libc_csu_fini>:
    #print total_str
    #funcList = FuncSet(total_str)
    
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
    #print handle_dict  
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


#class linux_memory_analyze(linux_common.AbstractLinuxCommand):
class linux_memory_analyze(linux_pslist.linux_pslist):
    """Gather active tasks by walking the task_struct->task list"""
    #global read_address_size
    read_address_size = 8
    
    def __init__(self, config, *args, **kwargs):
        #linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        linux_common.set_plugin_members(self)
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
        

        #self.thread_offset = self.profile.vtypes['task_struct'][1]['thread_group'][0]

        self.inforegs = linux_info_regs.linux_info_regs(config)


        #if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            #address_size = 4
        #else:
        #address_size = 8

         #2016.12.12
        #if distorm_loaded:
        #    self.decode_as = distorm3.Decode64Bits #if linux_proc_info.address_size == 4 else distorm3.Decode64Bits
        #else:
        #    debug.error("You really need the distorm3 python module for this plugin to function properly.")

    def get_registers_value(self,inforegs):
        """get registers value ---dhy 2016-11-27 """
        #taskinfo = inforegs.calculate()
        rsp_register = "rsp"
        for task, name, thread_regs in inforegs.calculate():
            fmt = str(2*0x8)
            for thread_name, regs in thread_regs:
                if regs != None:
                    for m in regs:
                        #print "regkeys()",m
                        if  m == rsp_register:
                            #print "true"
                            rspvalue = regs[m]
                            #print "rsp_value::",hex(rspvalue)
        return rspvalue
                    #for reg, value in regs.items():
                    #    print "type:",type(regs)
                    #    debug.info(("dhy::    {:8s}: {:0" + fmt + "x}\n").format(reg, value)) 


    def is_return_address(self, address, process_info): #这是使用了 distrom3 插件  查看当前地址address是否为返回地址 （这个函数最终没有使用，可以借鉴）
        """
        Checks if the address is a return address by checking if the preceding instruction is a 'CALL'.
        @param address: An address
        @param process_info: process info object
        @return True or False
        """
        proc_as = process_info.get_process_address_space()
        size = 5
        #print type(size) ,type(address)
        start_code_address = process_info.mm.start_code
        end_code_address = process_info.mm.end_code
        if distorm_loaded and start_code_address < address < end_code_address: #and process_info.is_code_pointer(address):
            offset = address - size
            instr = distorm3.Decode(offset, proc_as.read(offset, size), self.decode_as)
            # last instr, third tuple item (instr string), first 7 letters
            # if instr[-1][2][:7] == 'CALL 0x':
            #     print(instr[-1][2])
            if len(instr) > 0:
                return instr[-1][2][:4] == 'CALL'
            # there's also call <register>
        return False






    """
    def virtual_process_from_physical_offset(self, offset):
        pspace = utils.load_as(self._config, astype = 'physical')
        vspace = utils.load_as(self._config)
        task = obj.Object("task_struct", vm = pspace, offset = offset)
        parent = obj.Object("task_struct", vm = vspace, offset = task.parent)
        print "task:",task
        for child in parent.children.list_of_type("task_struct", "sibling"):
            if child.obj_vm.vtop(child.obj_offset) == task.obj_offset:
                return child
        
        return obj.NoneObject("Unable to bounce back from task_struct->parent->task_struct")"""

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        print "task_struct",hex(init_task_addr)
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)
        #init_mm = obj.Object("mm_struct", vm = self.addr_space, offset=0x1a8)
        #print type(init_mm)
        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
                yield task



            



    def calculate(self):
        linux_common.set_plugin_members(self)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]
        processname = "./uclient1 || ./example1"
        for task in self.allprocs():
            if not pidlist or task.pid in pidlist:
              if str(task.comm) in processname:  
                yield task

    def render_text(self, outfd, data):

        """self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("Pid", "15"),
                                  ("Uid", "15"),
                                  ("Gid", "6"),
                                  ("DTB", "[addrpad]"),
                                  ("Start Time", ""),
                                  ("start_stack","[addrpad]"),
                                  ("pgd","[addrpad]")])"""



        testDict = {}
        testDict = objdump_handle()
        for task in data:
            #if task.mm.pgd == None:
            #    dtb = task.mm.pgd
            #else:
            #    dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd
                #print "start_code:",hex(task.mm.start_code)
            print "process name:",task.comm
            print "start_stack:",hex(task.mm.start_stack)
            print "start_code:",hex(task.mm.start_code),hex(task.mm.end_code)
            proc_as = task.get_process_address_space()   #address space
            start_stack_address = task.mm.start_stack #task_struct->mm_struct->start_stack  ,stack bottom

                #  x86 or x64  : read_length  and size
            start_read_address = start_stack_address - 0x400  #range ??
            #match_dict = {}
            #match_dict = objdump_handle()  #

            l_old = []
            address = ('10.210.50.241', 21001)
            #address = ('10.108.167.101', 21001)  
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
            s.connect(address)
            #for i in range(50000):
            i=0
            while(1):
                #time.sleep(0.2)
                i=i%1000000   
                start = datetime.datetime.now()
                #rspV = self.get_registers_value(self.inforegs)
                #start_read_address = int(rspV)
                #print type( start_read_address)
                l_new = []
                indexAddr = None

                for indexAddr in range(0,256):
                    testAddr = read_address(proc_as,start_read_address + indexAddr*4,4)
                    #print hex(testAddr)
                    #flag_tf = self.is_return_address(testAddr, task)
                    #print flag_tf
                    #if flag_tf:
                            #self.find_function_address(proc_as, testAddr)
                    testStr = hex(testAddr)[2:]
                    #print "hex(testAddr)[2:]", testStr

                    if testStr in testDict:
                            #print flag_tf
                            #print testStr,type(testStr)
                        listStr = testDict[testStr]
                        #print listStr
                        ppStr = FuncSet(listStr)
                        l_new.append(ppStr)
                    #print "l_new1::",l_new    
                #l_new.append(['<main>'])
                #print "l_new2::",l_new
                if cmp(l_old,l_new) != 0:
                    #rp = open(rfPath,'w')
                    print "Analyze %s :" % i
                    #print "!!",l_new
                    str_new = "<-".join([str(x) for x in l_new])
                    print str_new
                    s.send(str_new)  
                    #rp.write(str_new)
                    #rp.close()




                    end = datetime.datetime.now()
                    print "analyze time:",(end - start)
                else:
                    pass
                l_old = l_new[:]

                #print "??",l_old,"\n"

                #print "\n"
                    #print self.find_function_address(proc_as, testAddr)
		      #end = datetime.datetime.now()
            print "\n  !!!!!!!!!!!!!!!!!!!!!!!!!!!!"    
            s.close()

            """"k=1
            for j in yield_address(proc_as,start_read_address,4):
                k=k+1;
                if k < 256:
                    print hex(j)
                else:
                    continue"""            
                    #print hex(testAddr)
                    #flag_tf = False
                    #if match_dict.has_key(str(hex(testAddr))[2:]):
                        #print match_dict[str(hex(testAddr))[2:]]
                        #print match_dict.get(str(hex(testAddr))[2:],'error')
            #print  type(flag_tf)
                #print hex(testAddr)
            #print type(testAddr)
            """self.table_row(outfd, task.obj_offset,
                                  task.comm,
                                  str(task.pid),
                                  str(task.uid) if task.uid else "-",
                                  str(task.gid) if task.gid else "-",
                                  dtb,
                                  task.get_task_start_time(),
                                  task.mm.start_stack,
                                  task.mm.pgd)"""


