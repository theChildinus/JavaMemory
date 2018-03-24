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
import traceback
from socket import *
import volatility.plugins.linux.java.readelf

def read_address(space, start, length=None):
    """
    Read an address in a space, at a location, of a certain length.
    @param space: the address space
    @param start: the address
    @param length: size of the value
    """
    if not length:
        length = 8
        # print length
    fmt = "<I" if length == 4 else "<Q"
    res = space.read(start, length)
    if not res:
        print "waiting"
        return None
    # while not res:
    #     res = space.read(start, length)
    return struct.unpack(fmt, res)[0]


class linux_java_socket(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option='p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='string')

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
            test_addr = read_address(task_space, addr, 8)
            if test_addr is None:
                return []
            print "the raw data is" + str(test_addr)
            num -= 8
            addr += 8
            for i in range(8):
                d = (test_addr & 255)
                test_addr >>= 8
                ans.append(d)
        return ans

    def render_text(self, outfd, data):
        tasks = self.calculate()
        if len(tasks) > 0:
            task = tasks[0]
        else:
            raise Exception("no task or wrong pid")
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
                libs.append(lib)

        name = task.get_commandline()
        threads = []
        for thread in task.threads():
            threads.append(thread)
            print "tread_name:", thread.comm, " pid:", thread.pid

        for lib in libs:
            if ".so" in lib.name or "java" in lib.name:
                print "base:", lib.base, "name:", lib.name

        start_stack_addr = task.mm.start_stack
        task_space = task.get_process_address_space()
        #addr = start_stack_addr
        # flag = 4096/8
        # while flag > 0:
        #     test_addr = read_address(task_space, addr, 8)  # length byte
        #     data = []
        #     for i in range(8):
        #         d = (test_addr & 255)
        #         data.append(d)
        #         test_addr >>= 8
        #     print "task.start_stack_addr:", addr, "value:", data, "type:", type(test_addr)
        #     addr += 8
        #     flag -= 1
        # datas = []
        # for data in self.read(task, start_stack_addr, 4096):
        #     if data >> 7 > 0:
        #         d = ((~data + 1) & 127)
        #         d = -d
        #     else:
        #         d = data
        #     datas.append(d)
        tcpSocket = socket(AF_INET, SOCK_STREAM)
        tcpSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        tcpSocket.bind(('', 6666))
        tcpSocket.listen(5)

        while True:
            try:
                print "waiting for connection..."
                client, addr = tcpSocket.accept()
                print "...connected from:", addr
                while True:
                    cds = []
                    print "receiving ..."
                    data = client.recv(1024)
                    print data
                    cds.append(data)
                    if "thread" in cds:
                        string = ""
                        for thread in threads:
                            string += (str(thread.pid) + " ")
                    elif "libname" in cds:
                        string = ""
                        for lib in libs:
                            string += (lib.name + " ")
                    elif "libbase" in cds:
                        string = ""
                        for lib in libs:
                            string += (str(lib.base) + " ")
                    elif "r_e_a_d" in cds[0]:
                        string = ""
                        cmd = cds[0].split()
                        for d in self.read(task, int(cmd[1]), int(cmd[2])):
                            string += (str(d) + " ")
                    elif "l_o_o_k_u_p" in cds[0]:
                        string = ""
                        cmd = cds[0].split()
                        for lib in libs:
                            if cmd[1] in lib.name:
                                libname = lib.name
                                d = volatility.plugins.linux.java.readelf.read_sym_offset(libname)
                                if cmd[2] in d:
                                    string += (str(lib.base + d[cmd[2]]) + " ")
                                    break
                    elif "detach" in cds:
                        break
                    print string
                    client.sendall(string + "\n")
            except:
                traceback.print_exc()
            finally:
                client.close()
        tcpSocket.close()






class Library:
    pass

class JavaThread:
    pass