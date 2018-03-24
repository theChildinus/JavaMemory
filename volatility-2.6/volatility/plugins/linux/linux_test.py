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
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
import pdb
import struct
import time


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
    return struct.unpack(fmt, space.read(start, length))[0]


class linux_test(linux_common.AbstractLinuxCommand):
    """Gather active tasks by walking the task_struct->task list"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option='p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='str')

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
        # pdb.set_trace()

        pidlist = self._config.PID
        if pidlist:
            pidlist = [int(p) for p in self._config.PID.split(',')]

        for task in self.allprocs():
            if not pidlist or task.pid in pidlist:
                yield task

    def render_text(self, outfd, data):

        for task in data:
            start_stack_addr = task.mm.start_stack
            task_space_test = task.get_process_address_space()
            print "input:"
            cmd = raw_input()
            while "q" not in cmd:
                size = int(cmd) * 8
                self.read(task_space_test, start_stack_addr, size)
                time.sleep(0.2)
                self.read(task_space_test, start_stack_addr + 16, size)
                time.sleep(0.2)
                self.read(task_space_test, start_stack_addr + 2 * 16, size)
                print "input:"
                cmd = raw_input()

    def read(self, space, addr, size):
        t1 = time.time()
        res = space.read(addr, size)
        t2 = time.time()
        print t2 - t1, addr
        print res
        if res:
            print len(res)
        else:
            print "None Value."
            return
        for i in range(size/8):
            unpack_res = struct.unpack("<Q", res[i * 8 :(i + 1) * 8])
            test_addr = unpack_res[0]
            print "addr[" + str(i + 1) + "]:", hex(test_addr), test_addr, res[i * 8 :(i + 1) * 8]
        print "total time", time.time() - t1, "atime", time.time() - t2
