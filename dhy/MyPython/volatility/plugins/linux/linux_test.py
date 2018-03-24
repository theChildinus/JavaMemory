# -*- coding: cp936 -*-
#
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#from volatility.plugins.linux.process_info import address_size

"""
@author:       Archer Day
@license:      GNU General Public License 2.0 or later
@contact:      ahdhy2008@gmail.com
"""

import struct
import sys
import os
import re
import string
import time
import datetime
#import collections
#import itertools

import volatility.plugins.linux.pslist as linux_pslist
#import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.common as linux_common
#import volatility.plugins.linux.threads as linux_threads

import volatility.debug as debug
#import struct
import time
import volatility.InfoProgram as InfoPro

#import ConfigParser
#file_conf = ConfigParser.ConfigParser()

try:
    import distorm3
    distorm_loaded = True
except:
    distorm_loaded = False

#address_size = 8
#TypeDict = {'int':4,'long int':8,'double':8,'float':4,'char':1}
"""def file_handle():
    with open("./filehandle/src/main.objdump",'r') as f:   #set path  ***  try except
        objdump_str = f.read()
    
    #the initial range  "libc  ---  main "
    start_index = objdump_str.find("<__libc_start_main@plt>:")
    end_index =  objdump_str.find("<__libc_csu_fini>:")   #modify    
    objdump_str = objdump_str[start_index:end_index]
    #print total_str
    
    #pattern0 = re.compile(r"<.*>:")
    pattern1 = re.compile(r"call.*<.*>") #function call
    pattern2 = re.compile(r"[0-9a-zA-Z]+:")   #return_address
    
    #func_list = re.findall(pattern0,objdump_str)
    call_iter = re.finditer(pattern1, objdump_str)

    #string handle ---> dict
    handle_dict = {}
    handle_str = objdump_str
    for call_str in call_iter:
        call_string = call_str.group()
        
        call_index = handle_str.find(call_string)
        handle_str = handle_str[(call_index + len(call_string)):]
        return_address = re.search(pattern2,handle_str)
    #print total_str[call_index:],"!!!!!"
        handle_dict[return_address.group()[:-1]] = call_string
    print handle_dict
    return handle_dict"""

"""def conf_handle():
        file_conf.read("./filehandle/src/main.conf")
        sections_list = file_conf.sections()
        sections_dict = {}

        for func in sections_list:
            paranum = file_conf.get(func, "ParaNum")
            paratype = file_conf.get(func, "ParaType")
            parasize = file_conf.get(func, "ParaSize")
            para_list = [paranum,paratype,parasize]
            sections_dict[func] = para_list
        print sections_dict
        
        return sections_dict"""
        

        
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

def read_address_range(addr_space,start,numaddr,length = None):
    """ """
    if not length:
        length = 8
    for i in (1,numaddr+1):
        readAddr =start + i*length
        yield read_address(addr_space,readAddr,length)








# Main command class
class linux_func_analyze(linux_pslist.linux_pslist):  
    """analyze memory by reading stack"""

    def __init__(self, config, *args, **kwargs):
        #linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        linux_common.set_plugin_members(self)
        
    
        self.ObjdumpDict = {}
        self.ObjdumpList = []
        
        global linux_address_size
        if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            linux_address_size = 4
        else:
            linux_address_size = 8

        if distorm_loaded:
            self.decode_as = distorm3.Decode32Bits if linux_address_size == 4 else distorm3.Decode64Bits
        else:
            debug.error("You really need the distorm3 python module for this plugin to function properly.")



    def is_return_address(self, address, process_info):
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


    def find_function_address(self, proc_as, ret_addr):
        """
        Calculates the function address given a return address. Disassembles code to get through the double indirection
        introduced by the Linux PLT.
        @param proc_as: Process address space
        @param ret_addr: Return address
        @return The function address or None
        """
        if distorm_loaded:
            decode_as = self.decode_as
            retaddr_assembly = distorm3.Decode(ret_addr - 5, proc_as.read(ret_addr - 5, 5), decode_as)
            if len(retaddr_assembly) == 0:
                return None
            #print(retaddr_assembly)
            retaddr_assembly = retaddr_assembly[0] # We're only getting 1 instruction
            #print retaddr_assembly
            # retaddr_assembly[2] = "CALL 0x400620"
            instr = retaddr_assembly[2].split(' ')
            #print(instr)
            if instr[0] == 'CALL':
                try:
                    target = int(instr[1][2:], 16)
                except ValueError:
                    return None
                bytes = proc_as.read(target, 6)
                if not bytes:
                    # We're not sure if this is the function address
                    return target
                plt_instructions = distorm3.Decode(target, bytes, decode_as)
                plt_assembly = plt_instructions[0] # 1 instruction
                #print(plt_assembly)
                instr2 = plt_assembly[2].split(' ')
                #print(instr2)
                if instr2[0] == 'JMP':
                    final_addr = None
                    if instr2[1] == 'DWORD':
                        target2 = int(instr2[2][3:-1], 16)
                    elif instr2[1] == 'QWORD': # if QWORD
                        target2 = int(instr2[2][7:-1], 16)
                    else: # if 0xADDRESS
                        final_addr = int(instr2[1][2:],16)
                    if not final_addr:
                        final_addr = target + 6 + target2
                    debug.info("Found function address from instruction1 {} at offset 0x{:016x}".format(instr2, target))
                    return hex(target)#read_address(proc_as, final_addr,4)
                elif instr2[0] == 'PUSH' and instr2[1] == 'RBP':
                    # This is an internal function
                    debug.info("Found function address from instruction2 {} at offset 0x{:016x}".format(instr, target))
                    return hex(target)
                else:
                    # In case push rbp is removed
                    debug.info("Found function address from instruction3 {} at offset 0x{:016x}".format(instr, target))
                    return hex(target)
            return None
        else:
            return None


    def calculate(self):

        #lpi=linux_pslist.linux_pslist()
        #tasks=lpi.calculate(self)
        #reload('linux_pslist','pslist.py')
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            self.task = task
            #print task

            # Yield a process object
            yield self.task



    def get_map(self, task, address):
        """
        Get the vm_area to which an address points.

        @param task: the task_struct
        @param address: an address
        @return: a vm_area_struct corresponding to the address
        """
        for m in task.get_proc_maps():
            if m.vm_start <= address <= m.vm_end:
                return m
            
            
    def InfoHandle(self):  #chuan can  ke yi shi  wen jian lu jing huo zhe 
        """get information for *.c *.objdump"""

        filepathname = "/initial/objfile/main2.objdump"
        filepath = ''.join([os.getcwd(),filepathname])
        #print filepath
        #print os.path.join(os.getcwd(),filepathname)
        pattern = re.compile(r"[0-9a-z]+ <.*>:")   
    
    
        try: 
            with open(filepath ,'r') as pf:
                objdump_str = pf.read()
                #print "right"
        except IOError:
            print "Failed to read objdump file!"
            sys.exit()

            #filepath = os.path.join(os.getcwd(),"/objfile/main.objdump")
            #if os.path.exists(filepath):
            #debug.info("file exists:{}".format(filepath))
        obj_list = re.findall(pattern, objdump_str)

        #print obj_list
        
        for func_str in obj_list:
            func_list = func_str.split(" ",1)
            funcaddr = func_list[0][-6:]   
            #''.join('0x',funcaddr)
            funcname = func_list[1][1:-2]
            
            #print funcaddr,funcname
            self.ObjdumpDict.setdefault(funcaddr,funcname)
            #self.funcaddr_list.append(func_list[0][-6:])    #4004c4
            #self.funcname_list.append(func_list[1][1:-2])    #func1
        self.ObjdumpList = sorted(self.ObjdumpDict.iteritems(),key = lambda D:D[0],reverse = False)
        #print self.ObjdumpList
        #print self.ObjdumpDict
            
            
        infopro = InfoPro.InfoProgram()

        infopro.GetReadOffsetAddr()
        infopro.GetAnalyzeCount()
        return infopro
    
    def find_funcstack_name(self,objList,retAddr):
        objListLen = len(objList)
        for index in range(0,(objListLen-1)):
            if objList[index][0] < retAddr < objList[index + 1][0]:
                #print objList[index]
                return objList[index][1]
            else:
                pass
        return False
    
    def BinaryTofloat(self,Bin):
        pass
        
    def ParaAnalyze(self,infopro ,num,stackname,paraList):
        ListLenght = len(paraList)
        if ListLenght == 0:
            print "0 parameter!",stackname
            return False
        
        NumPara = num 
        TypeList = infopro.FunctionDict[stackname]
        
        for i in range(0,ListLenght):
            ParaValue = paraList[ListLenght -1 - i]
            ParaType = TypeList[i]
            ParaLen = infopro.TypeSizeDict[TypeList[i]]

    def render_text(self, outfd, data):
        #self.outfd = outfd
        exa = self.InfoHandle()
        print exa.start_read_offset_address,exa.analyze_count 
        
        for task in data:
            #if task.mm.pgd == None:
            #    dtb = task.mm.pgd
            #else:
            #    dtb = self.addr_space.vtop(task.mm.pgd) or task.mm.pgd
                #print "start_code:",hex(task.mm.start_code)
            #print "start_stack:",hex(task.mm.start_stack)
            proc_as = task.get_process_address_space()   #address space
            #print "start_code --- end_code:",hex(task.mm.start_code),hex(task.mm.end_code)
            start_stack_address = task.mm.start_stack #task_struct->mm_struct->start_stack  ,stack bottom

                #  x86 or x64  : read_length  and size
            offset_read = 0x400
            
            start_read_address = start_stack_address - offset_read  #range ??
            offset_num = offset_read/linux_address_size
            print hex(start_stack_address),hex(start_read_address),offset_num


            analyze_count = exa.analyze_count
            print offset_read
            StartAnalyzeTime = datetime.datetime.now()
            for count in range(100):
                print "\n\nAnalyze %s : " % count
                #time.sleep(1) 
                for num in range(0,offset_num):
                    read_stack_address = start_read_address + num * linux_address_size
                    DataInStack = read_address(proc_as, read_stack_address,linux_address_size)
                    #print hex(read_stack_address),":",hex(DataInStack)
                    
                    if self.is_return_address(DataInStack, task):
                        print hex(DataInStack),"is return_address"
                        
                        RetAddr = DataInStack
                        RetAddrStr = hex(RetAddr)[2:]
                        
                        CallAddr = self.find_function_address(proc_as, DataInStack)
                        CallAddrStr = CallAddr[2:]
                        #print CallAddrStr  

                        #print RetAddrStr ,CallAddrStr
                        
                        stackname = self.find_funcstack_name(self.ObjdumpList,RetAddrStr)
                        print "stack %s :" % stackname
                        paraList = []
                        """if stackname is not None and stackname in exa.NumDict:
                            num = exa.NumDict[stackname]
                            num_read = num % 2 + num  
                            for i in range(num_read):
                                para = read_address(proc_as, read_stack_address + (i + 1) * linux_address_size,linux_address_size)
                                paraList.append(hex(para))"""
                            #print paraList
                print "\n\n"
                
            EndAnylyzeTime = datetime.datetime.now()
            print "Analyze 20 total time :",EndAnylyzeTime -StartAnalyzeTime
        
    
                    
    