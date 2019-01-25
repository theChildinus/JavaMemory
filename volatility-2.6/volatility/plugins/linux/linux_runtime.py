#!usr/bin/python
# -*- coding:utf-8 -*-
# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistringibute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distringibuted in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@license:      GNU General Public License 2.0
@organization:
"""

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
import struct
import jpype
import volatility.plugins.linux.java.readelf
import socket
import time
import paramiko
import os
import datetime

from volatility.plugins.linux.java import readelf
from volatility.plugins.linux.java.conf import Conf


def ssh_cmd(hostname, port, username, password, cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(hostname=hostname, port=port, username=username, password=password)
    stdin, stdout, stderr = client.exec_command(cmd)
    result = stdout.read()
    error = stderr.read()
    if error.decode() is not None:
        print error.decode()
    client.close()
    return result


class linux_runtime(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option='p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='string')

    def read_address(self, space, start, length=None):
        """
        Read an address in a space, at a location, of a certain length.
        @param space: the address space
        @param start: the address
        @param length: size of the value
        """
        # if not length:
        #     length = 8
        #     # print length
        fmt = "<I" if length == 4 else "<Q"
        res = space.read(start, length)
        if not res:
            # print "waiting", start, length
            return None
        return struct.unpack(fmt, res)[0]

    def virtual_process_from_physical_offset(self, offset):
        pspace = utils.load_as(self._config, astype='physical')
        vspace = utils.load_as(self._config)
        task = obj.Object("task_struct", vm=pspace, offset=offset)
        parent = obj.Object("task_struct", vm=vspace, offset=task.parent)

        for child in parent.children.list_of_type("task_struct", "sibling"):
            if child.obj_vm.vtop(child.obj_offset) == task.obj_offset:
                return child

        return obj.NoneObject("Unable to bounce back from task_struct->parent->task_struct")

    def allprocs(self):
        linux_common.set_plugin_members(self)
        # 获取linux 内核第一个进程 0号进程
        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm=self.addr_space, offset=init_task_addr)

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
            yield task

    def calculate(self):
        linux_common.set_plugin_members(self)

        # pidlist = self._config.PID
        # if pidlist:
        #     pidlist = [int(p) for p in self._config.PID.split(',')]

        #依次获取进程 直到获取参数指定的进程
        process_name = "java"
        tasks = []
        for task in self.allprocs():
            # if not pidlist or task.pid in pidlist:
            if str(task.comm) in process_name:
                tasks.append(task)
        tasks.sort()
        return tasks

    # 地址内存获取
    def read(self, task, addr, num):
        task_space = task.get_process_address_space()
        ans = []
        while num > 0:
            test_addr = self.read_address(task_space, addr, 8)
            if test_addr is None:
                return []
            num -= 8
            addr += 8
            # ans.append(long(test_addr))
            for i in range(8):
                d = (test_addr & 255)
                test_addr >>= 8
                if d > 127:
                    d -= 256
                ans.append(int(d))
        return ans

    def render_text(self, outfd, data):
        # local_conf = Conf()
        # local_conf.config_no()
        # local_conf.start()
        print ">>>>>> render_test >>>>>>"
        # start JVM, j_test_path is param represent DLL
        j_test_path = '-Djava.class.path=/home/kong/JavaMemory/JDI/out/artifacts/JDI/JDI.jar'
        jpype.startJVM(jpype.getDefaultJVMPath(), j_test_path)
        # tasks 表示被监控程序的进程Id（JVM）
        tasks = self.calculate()
        if len(tasks) > 0:
            # task = tasks[0]
            task = tasks[-1]
            print "task.pid is ", task.pid
        else:
            jpype.shutdownJVM()
            raise Exception("no task or wrong pid")

        # configuration
        self.fnames = ['func1', 'func2', 'func3', 'func4']
        self.vnames = [['x', 'y'], ['x', 'y'], ['x', 'y'], ['x', 'y']]
        self.vtypes = [[1, 1], [2, 2], [3, 3], [4, 4]]

        # ssh
        hostname = '10.108.164.232'
        port = 22
        username = 'root'
        password = '123456'

        cmd = 'java -jar /home/vm/pyagent.jar ' + str(task.pid)
        ssh_res = ssh_cmd(hostname=hostname, port=port, username=username, password=password, cmd=cmd)
        if 'yes' not in ssh_res:
            print ssh_res.decode()
            raise Exception("no task or wrong pid")
        else:
            print 'pyagent.jar return yes'
        libnames = [] # 共享库名称
        libbases = [] # 共享库起始地址
        libs = []
        name_set = set()
        # 获取共享库函数在进程中的虚拟地址映射
        # vma 虚拟内存空间
        for vma in task.get_proc_maps():
            fname = vma.vm_name(task)
            if fname == "Anonymous Mapping":
                fname = ""
            if len(fname) > 0 and fname not in name_set:
                name_set.add(fname)
                lib = Library()
                lib.base = vma.vm_start
                lib.name = fname
                libnames.append(str(lib.name))
                libbases.append(long(lib.base))
                libs.append(lib)

        for lib in libs:
            if ".so" in lib.name or "java" in lib.name:
                print "base:", hex(lib.base), "name:", lib.name
        # 获取子线程tid
        threadsId = []
        for thread in task.threads():
            threadsId.append(long(thread.pid))

        print threadsId

        self.libnames = libnames
        self.libbases = libbases
        self.threadsId = threadsId
        self.currentTask = task
        self.libs = libs
        self.symbolDict = {}
        # read elf function, symbol represent share lib offset
        symbol = volatility.plugins.linux.java.readelf.read_sym_offset("/home/kong/JavaMemory/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so")
        self.symbolDict["/home/vm/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so"] = symbol

        # java interface for python
        PyDump = jpype.JPackage('sun.tools.python').PyDump
        self.PyDump = PyDump

        # python interface for java
        method_dict = {
            'getThreadsId': self.getThreadsId,
            'getLibName': self.getLibName,
            'getLibBase': self.getLibBase,
            'lookUpByName': self.lookUpByName,
            'readBytesFromProcess': self.readBytesFromProcess
        }
        jp = jpype.JProxy('sun.jvm.hotspot.debugger.linux.PythonMethodInterface', dict = method_dict)

        # java init
        PyDump.initVM(jp, int(task.pid))
        # self.first_fp = PyDump.initJavaFirstFPAddress("testBusyThread", True)
        self.first_fp = PyDump.initJavaFirstFPAddress("main", True)
        print 'first_fp:', hex(self.first_fp)
        # event
        self.event_front_1 = '<xml type="event"'
        self.event_front_2 = '">'
        self.event_middle_1 = '<'
        self.event_middle_2 = '>'
        self.event_middle_3 = '</'
        self.event_middle_4 = '>'
        self.event_end = '</xml>\r\n\r\n'

        self.client = None

        print "===== START =====", os.getpid()

        # d1wait = datetime.datetime.now()
        # tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # tcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # tcpSocket.bind(('', 6666))
        # tcpSocket.listen(5)
        # try:
        #     print "waiting for connection..."
        #     self.client, addr = tcpSocket.accept()
        #     print "...connected from:", addr
        #     # self.conf = Conf()
        #     # self.conf.config(self.run_command, self.stop_command)
        #     # self.conf.start()
        # except Exception, e:
        #     print repr(e)
        count = 10
        while count > 0:
            print "#######################"
            try:
                time.sleep(0.1)
                time_start = time.clock()
                result = self.getEvent(self.first_fp, self.fnames, self.vnames, self.vtypes, self.client)
                time_end = time.clock()
                print "start, end: ", time_start, ",", time_end
                print "Durning: ", (time_end - time_start) * 1000, "ms"
                count -= 1

            except Exception, e:
                print repr(e)

        PyDump.stop()
        jpype.shutdownJVM()
            # tcpSocket.close()
        # def run_command(self):
        #     inf = self.getEvent(self.first_fp, self.fnames, self.vnames, self.vtypes, self.client)
        #     self.conf.t1_insert(inf + '\n\n')
        #     print 'run over\n'
        #
        # def stop_command(self):
        #     self.conf.stop()

    def getEvent(self, first_fp, fnames, vnames, vtypes, client):
        memory = self.readMemory(first_fp - 5000, 6000)
        self.memory = memory
        frame = Frame(first_fp, memory, self)
        inf = ""
        while frame is not None:
            methodName = frame.getName()
            if methodName is not None:
                print methodName, "fp:", hex(frame.fp),
                if frame.fp in frame.memory[1]:
                    print hex(frame.memory[1][frame.fp])
                else:
                    print
            if methodName is not None and methodName in fnames:
                inf += "->"
                index = fnames.index(methodName)
                variables = frame.getLocals(vtypes[index])
                result = self.event_front_1 + methodName + self.event_front_2
                inf += (methodName + "(")
                for i, val in enumerate(variables):
                    result += (self.event_middle_1 + vnames[index][i] + self.event_middle_2)
                    result += val
                    result += (self.event_middle_3 + vnames[index][i] + self.event_middle_4)
                    inf += (val + ',')
                result += self.event_end
                # print result
                if client is not None:
                    client.sendall(result)
                inf += ")"
            elif methodName is not None:
                inf += "->"
                inf += methodName
            frame = frame.getNextFrame()
            if frame is None:
                print "nextFrame is None"
        return inf

    def getThreadsId(self):
        return self.threadsId

    def getLibName(self):
        return self.libnames

    def getLibBase(self):
        return self.libbases

    # 根据符号名称在共享库中查找符号在内存的地址 （起始地址 + 偏移量）
    def lookUpByName(self, objectName, symbol):
        for lib in self.libs:
            if objectName in lib.name:
                if lib.name in self.symbolDict:
                    d = self.symbolDict[lib.name]
                else:
                    d = readelf.read_sym_offset(lib.name)
                    self.symbolDict[lib.name] = d
                if symbol in d:
                    return long(lib.base + d[symbol])
        return 0

    def readBytesFromProcess(self, address, numBytes):
        result = self.read(self.currentTask, int(address), int(numBytes))
        return result

    # 栈内存获取模块
    def readMemory(self, address, numBytes):
        # 获取进程地址空间
        space = self.currentTask.get_process_address_space()
        str = space.read(address, numBytes)
        # address -> memory
        res1 = {}
        # memory -> address
        res2 = {}
        if str is None:
            print "none"
            return None, None
        for i in range(numBytes / 8):
            # 转换出内存的整型结果
            unpack_res = struct.unpack("<Q", str[i * 8 :(i + 1) * 8])
            res1[address + i * 8] = unpack_res[0]
            res2[unpack_res[0]] = address + i * 8
        return res1, res2

    def readAddressByAddress(self, address):
        space = self.currentTask.get_process_address_space()
        str = space.read(address, 8)
        unpack_res = struct.unpack("<Q", str)
        return unpack_res[0]

    def getNameByAddress(self, address):
        return self.PyDump.getMethodName(long(address))

    def isComplied(self, threadName, funcName):
        return self.PyDump.isCompliedFrame(threadName, funcName)

    def getNextCompliedSP(self, sp):
        frameSize = 8
        sp = 0
        while (frameSize < 64):
            unextendedSP = sp - frameSize
            pc = self.memory[0][self.memory[1][unextendedSP] + 16]
            # TODO:scopeDesc.check()
            check1 = False
            if check1 is True:
                sp = self.memory[1][unextendedSP] + 24
                break
            else:
                pc = self.memory[0][unextendedSP - 8]
                # TODO:scopeDesc.check()
                check2 = False
                if check2 is True:
                    sp = unextendedSP
                    break
                else:
                    frameSize += 8
        return sp

class Library:
    def __init__(self):
        pass


class Frame:
    def __init__(self, fp, memory, debugger, complied = False):
        self.fp = fp
        self.memory = memory
        self.debugger = debugger
        self.complied = complied

    # 得到本地变量
    def getLocals(self, types, static=False):
        res = []
        if self.memory[0] is not None and self.fp - 48 in self.memory[0].keys():
            local = self.memory[0][self.fp - 48]
            tmp_local = local
            print 'fp - 48:', hex(self.fp - 48), hex(local)
            if not static:
                local -= 8
            i = 0

            while tmp_local != local - 72:
                value = self.memory[0][tmp_local]
                print 'Address: ', hex(tmp_local), ' value: ', hex(value)
                tmp_local -= 8

            while local in self.memory[0].keys() and i < len(types):
                if types[i] == 4 or types[i] == 2:
                    local -= 8
                value = self.memory[0][local]
                v = self.getVal(value, types[i])
                print 'GetParam >> Address: ', hex(local), 'Value: ', v
                res.append(v)
                local -= 8
                i += 1
        return res


    def getVal(self, value, vtype):
        if vtype == 1:
            val = int(value)
            return str(val)
        elif vtype == 2:
            val = long(value)
            return str(val)
        elif vtype == 3:
            val = self.debugger.PyDump.jf(int(hex(value)[-8:], 16))
            return str(val)
        elif vtype == 4:
            val = self.debugger.PyDump.jd(long(value))
            return str(val)
        else:
            return str(value)

    # 得到名称
    def getName(self):
        res = None
        if self.memory[0] is not None and self.fp - 24 in self.memory[0].keys():
            name = self.memory[0][self.fp - 24]
            res = self.debugger.getNameByAddress(name)
            if len(res) == 0:
                res = None
        return res

    def getFP(self):
        return hex(self.fp)

    # 得到下一栈帧
    def getNextFrame(self):
        frame = None
        # methodName = self.getName()
        # if methodName is not None:
        #     compiled = self.debugger.isComplied("main", methodName)
        #     if compiled:
        #         print "curMethodName: " + methodName + " CompliedFrame"
        #
        #     else:
        #         print "curMethodName: " + methodName + " InterpretedFrame"
        # else:
        #     print "methodName is None"
        if self.memory[1] is not None and self.fp in self.memory[1].keys():
            nfp = self.memory[1][self.fp]
            frame = Frame(nfp, self.memory, self.debugger)
        # else:
        #     print "can not get InterpretedFrame, try to get CompiledFrame"
        #     sp = self.debugger.getNextCompliedSP(self.fp - 16)
        #     nfp = sp - 16
        #     frame = Frame(nfp, self.memory, self.debugger)
        return frame
