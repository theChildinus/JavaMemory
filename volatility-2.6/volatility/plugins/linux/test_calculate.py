# -*- coding:utf-8 -*-
import volatility.obj as obj
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.pidhashtable as linux_pidhashtable
import volatility.plugins.linux.pslist_cache as linux_pslist_cache
import volatility.plugins.linux.common as linux_common

class test_calculate(linux_common.AbstractLinuxCommand):

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")  # init_task 1号进程
        print "task_struct", hex(init_task_addr)
        init_task = obj.Object("task_struct", vm=self.addr_space, offset=init_task_addr)
        init_mm = obj.Object("mm_struct", vm=self.addr_space, offset=0x1a8)
        print type(init_mm)
        # walk the ->tasks list, note that this will *not* display "swapper"
        for task in init_task.tasks:
            yield task

    def calculate(self):
        linux_common.set_plugin_members(self)

        processname = "java"
        tasks = []
        for task in self.allprocs():
            if str(task.comm) in processname:
                tasks.append(task)
        return tasks


    def render_text(self, outfd, data):
        print ">>>>>>> render_test >>>>>>"
        tasks = self.calculate()
        for task in tasks:
            print task.comm, task.pid