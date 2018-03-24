import volatility.utils as utils
import volatility.commands as commands
import volatility.win32.tasks as tasks

class ExamplePlugin(commands.Command):
    """This method performs the work"""
    def calculate(self):

        addr_space=utils.load_as(self._config)
        for proc in tasks.pslist(addr_space):
            yield proc

    def render_text(self,outfd,data):

        for proc in data:
            outfd.write("Process:{0}\n".format(proc.ImageFileName))
