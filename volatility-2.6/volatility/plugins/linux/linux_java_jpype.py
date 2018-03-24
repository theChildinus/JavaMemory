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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
import struct
import jpype
import volatility.plugins.linux.java.readelf
import time




class linux_java_jpype(linux_common.AbstractLinuxCommand):
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
        t1 = time.time()
        res = space.read(start, length)
        t2 = time.time()
        self.rr_time += (t2 - t1)
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
        t1 = time.time()
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
        t2 = time.time()
        self.total_time += (t2 - t1)
        return ans

    def render_text(self, outfd, data):
        j_test_path = '-Djava.class.path=/root/JDI-old.jar'
        jpype.startJVM(jpype.getDefaultJVMPath(), j_test_path)
        tasks = self.calculate()

        if len(tasks) > 0:
            task = tasks[0]
        else:
            jpype.shutdownJVM()
            raise Exception("no task or wrong pid")
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
        self.total_time = 0
        self.rr_time = 0
        symbol = volatility.plugins.linux.java.readelf.read_sym_offset("/usr/local/development/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so")
        self.symbolDict["/usr/local/development/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so"] = symbol
        j_frames = jpype.JPackage('sun.tools.jdi').Frames
        method_dict = {
            'getThreadsId' : self.getThreadsId,
            'getLibName' : self.getLibName,
            'getLibBase' : self.getLibBase,
            'lookUpByName' : self.lookUpByName,
            'readBytesFromProcess': self.readBytesFromProcess
        }
        jp = jpype.JProxy('sun.jvm.hotspot.debugger.linux.PythonMethodInterface', dict = method_dict)
        j_frames.init(str(task.pid), jp, 1, 'func4')
        print "real read time is", self.rr_time
        print "read time is", self.total_time
        cmd = raw_input()
        while "q" not in cmd:
            res = j_frames.getThread('func4')
            if res == 0:
                print "not contains"
                cmd = raw_input()
                continue
            self.total_time = 0
            self.rr_time = 0
            t1 = time.time()
            j_frames.pythonTest(str(cmd), 'func4')
            t2 = time.time()
            print "real read time is", self.rr_time
            print "read time is", self.total_time
            print "time is", t2 - t1
            cmd = raw_input()
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
                    d = volatility.plugins.linux.java.readelf.read_sym_offset(lib.name)
                    self.symbolDict[lib.name] = d
                if symbol in d:
                    return long(lib.base + d[symbol])
        return 0

    def readBytesFromProcess(self, address, numBytes):
        result = self.read(self.currentTask, int(address), int(numBytes))
        return result


class Library:
    pass
