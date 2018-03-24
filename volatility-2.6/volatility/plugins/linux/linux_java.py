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
import time
import paramiko

from volatility.plugins.linux.java import readelf


def ssh_cmd(hostname, port, username, password, cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(hostname=hostname, port=port, username=username, password=password)
    stdin, stdout, stderr = client.exec_command(cmd)
    result = stdout.read()
    client.close()
    return result


class linux_java(linux_common.AbstractLinuxCommand):
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
            print "waiting", start, length
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

        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm=self.addr_space, offset=init_task_addr)

        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
            yield task

    def calculate(self):
        linux_common.set_plugin_members(self)

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        tasks = []
        for task in self.allprocs():
            if not pidlist or task.pid in pidlist:
                tasks.append(task)
        return tasks

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
        j_test_path = '-Djava.class.path=/root/JDI.jar'
        jpype.startJVM(jpype.getDefaultJVMPath(), j_test_path)
        tasks = self.calculate()

        if len(tasks) > 0:
            task = tasks[0]
        else:
            jpype.shutdownJVM()
            raise Exception("no task or wrong pid")

        # ssh
        hostname = '10.108.166.165'
        port = 22
        username = 'root'
        password = '123456'

        cmd = 'java -jar pyagent.jar ' + str(task.pid)
        ssh_res = ssh_cmd(hostname=hostname, port=port, username=username, password=password, cmd=cmd)
        if 'yes' not in ssh_res:
            print ssh_res
            raise Exception("wrong ssh")

        libnames = []
        libbases = []
        libs = []
        name_set = set()
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
                print "base:", lib.base, "name:", lib.name
        threadsId = []
        for thread in task.threads():
            threadsId.append(long(thread.pid))

        self.libnames = libnames
        self.libbases = libbases
        self.threadsId = threadsId
        self.currentTask = task
        self.libs = libs
        self.symbolDict = {}
        symbol = volatility.plugins.linux.java.readelf.read_sym_offset("/usr/local/development/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so")
        self.symbolDict["/usr/local/development/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so"] = symbol
        PyDump = jpype.JPackage('sun.tools.python').PyDump
        self.PyDump = PyDump
        method_dict = {
            'getThreadsId': self.getThreadsId,
            'getLibName': self.getLibName,
            'getLibBase': self.getLibBase,
            'lookUpByName': self.lookUpByName,
            'readBytesFromProcess': self.readBytesFromProcess
        }
        jp = jpype.JProxy('sun.jvm.hotspot.debugger.linux.PythonMethodInterface', dict = method_dict)

        fpAddress = 0
        spAddress = 0
        first_fp = 0
        print "input:"
        cmd = raw_input()
        vm_state = False
        while "q" not in cmd:
            if "1" in cmd:
                if vm_state:
                    print "input:"
                    cmd = raw_input()
                    continue
                PyDump.initVM(jp, int(task.pid))
                print "init VM"
                vm_state = True
            elif "2" in cmd:
                fpAddress = PyDump.initJavaLastFPAddress("main", True)
                spAddress = PyDump.initJavaLastSPAddress("main", True)
                print "get the address of last fp and sp"
            elif "3" in cmd:
                try:
                    if fpAddress != 0 and spAddress != 0:
                        print fpAddress, spAddress
                        t1 = time.time()
                        fp = self.readAddressByAddress(fpAddress)
                        print time.time() - t1
                        fp = self.readAddressByAddress(fpAddress)
                        print time.time() - t1
                        sp = self.readAddressByAddress(spAddress)
                        print time.time() - t1
                        res = self.readMemory(sp, 1000)[0]
                        fp = self.readAddressByAddress(fpAddress)
                        print time.time() - t1
                        for i in range(5):
                            print hex(fp), hex(sp)
                            local = res[fp - 48]
                            print "locals:",
                            for j in range(5):
                                print res[local - j * 8],
                            print
                            sp = fp + 16
                            fp = res[fp]
                    else:
                        print "failed"
                except Exception, e:
                    print "except:", repr(e)
            elif "4" in cmd:
                if not vm_state:
                    PyDump.initVM(jp, int(task.pid))
                    vm_state = True
                first_fp = PyDump.initJavaFirstFPAddress("main", True)
                PyDump.clear()
                print "get the address of first fp"
                print first_fp
            elif "5" in cmd:
                wide = 1
                try:
                    wide = int(cmd)
                except Exception, e:
                    print "except:", repr(e)
                for ju in range(wide):

                    time.sleep(1)
                    mns = []
                    mls = {'func4':'4.4,6.6',
                           'func5':'',
                           'func1':'5,3',
                           'func2':'100100010000,200200020000',
                           'func3':'7.7,9.9'}

                    self.readValueByFirstFP(first_fp)
                    memory = self.readMemory(first_fp - 2000, 3000)
                    frame = Frame(first_fp, memory, self)
                    while frame is not None:
                        methodName = frame.getName()
                        if methodName is not None:
                            mns.append(methodName)
                            # ml = []
                            # try:
                            #     t = int(methodName[-1])
                            #     ml = frame.getLocals([t,t])
                            # except Exception, e:
                            #     #print "except:", repr(e)
                            #     pass
                            # mls.append(ml)
                        else:
                            break
                        frame = frame.getNextFrame()
                    if ju % 2 == 0:
                        continue
                    index = 0
                    for mn in mns:
                        if mn in 'sleep':
                            break
                        print '->',
                        lstr = ''
                        if mn in mls():
                            lstr = mls[mn]
                        print '%s(%s)' % (mn, lstr),
                        index += 1
                    print
            else:
                start = time.time()
                end = time.time()
                statistic = []
                repeat_s = []
                st_set = set()
                count = 0
                while end - start < 300:
                    time.sleep(1)
                    t1 = time.time()
                    memory = self.readMemory(first_fp - 2000, 3000)
                    print time.time() - t1,
                    frame = Frame(first_fp, memory, self)
                    t1 = time.time()
                    while frame is not None:
                        methodName = frame.getName()
                        if methodName is not None:
                            if 'func1' in methodName and not frame.isLastFrame():
                                methodLocals = frame.getLocals([2], True)
                                for m in methodLocals:
                                    print m,
                                    if m not in st_set:
                                        st_set.add(m)
                                        statistic.append(m)
                                    repeat_s.append(m)
                            print methodName,
                        else:
                            break
                        frame = frame.getNextFrame()
                    print time.time() - t1
                    end = time.time()
                    count += 1
                print "length:", len(st_set), len(repeat_s), count
                print "set:", st_set
                print "list:", statistic

            print "input:"
            cmd = raw_input()

        PyDump.stop()
        jpype.shutdownJVM()

    def getThreadsId(self):
        return self.threadsId

    def getLibName(self):
        return self.libnames

    def getLibBase(self):
        return self.libbases

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

    def readMemory(self, address, numBytes):
        space = self.currentTask.get_process_address_space()
        read_str = space.read(address, numBytes)
        res1 = {}
        res2 = {}
        if read_str is None:
            print "none"
            return None, None
        for i in range(numBytes / 8):
            unpack_res = struct.unpack("<Q", read_str[i * 8 :(i + 1) * 8])
            res1[address + i * 8] = long(unpack_res[0])
            res2[long(unpack_res[0])] = address + i * 8
        return res1, res2

    def readAddressByAddress(self, address):
        space = self.currentTask.get_process_address_space()
        str = space.read(address, 8)
        unpack_res = struct.unpack("<Q", str)
        return unpack_res[0]

    def getNameByAddress(self, address):
        return self.PyDump.getMethodName(long(address))

    def readValueByFirstFP(self, first_fp):
        try:
            if first_fp != 0:
                return self.readMemory(first_fp - 2000, 3000)
        except Exception, e:
            print "except:", repr(e)


class Library:
    def __init__(self):
        pass


class Frame:
    def __init__(self, fp, memory, debugger, complied = False):
        self.fp = fp
        self.memory = memory
        self.debugger = debugger
        self.complied = complied
        self.name = None

    def getLocals(self, types, static=False):
        res = []
        if self.memory[0] is not None and self.fp - 48 in self.memory[0]:
            local = self.memory[0][self.fp - 48]
            if not static:
                local -= 8
            i = 0
            while local in self.memory[0] and i < len(types):
                if types[i] == 4 or types[i] == 2:
                    local -= 8
                value = self.memory[0][local]
                res.append(self.getVal(value, types[i]))
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
            val = self.debugger.PyDump.jf(int(value))
            return str(val)
        elif vtype == 4:
            val = self.debugger.PyDump.jd(long(value))
            return str(val)
        else:
            return str(value)

    def getName(self):
        if self.name is not None:
            return self.name
        res = None
        if self.memory[0] is not None and self.fp - 24 in self.memory[0]:
            name = self.memory[0][self.fp - 24]
            res = self.debugger.getNameByAddress(name)
            if len(res) == 0:
                res = None
        self.name = res
        return res

    def getNextFrame(self):
        frame = None
        if self.memory[1] is not None and self.fp in self.memory[1]:
            nfp = self.memory[1][self.fp]
            frame = Frame(nfp, self.memory, self.debugger)
            if frame.getName() is None:
                frame = None
        return frame

    def isLastFrame(self):
        return self.getNextFrame() is None
