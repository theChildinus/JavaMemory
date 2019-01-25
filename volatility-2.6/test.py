# -*- coding:utf-8 -*-
import paramiko
import os
import subprocess
import time, threading
import ctypes
import inspect

# configure for java Example
hostname = '10.108.164.232'
port = 22
username = 'root'
password = '123456'

# configure for c Example
# hostname = '10.108.167.219'
# port = 22
# username = 'vm'
# password = '123456'

def ssh_cmd(hostname, port, username, password, cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(hostname=hostname, port=port, username=username, password=password)
    stdin, stdout, stderr = client.exec_command(cmd)
    result = stdout.read()
    error = stderr.read()
    # if error.decode() is not None:
    #     print error.decode()
    # client.close()
    return result


def terminate_thread(thread):
    """Terminates a python thread from another thread.

    :param thread: a threading.Thread instance
    """
    if not thread.isAlive():
        return

    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident), exc)
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

def loop():
    # configure for java Example
    # vm_cmd1 = 'java -cp /home/vm/ThreadTest.jar MainThreadException'
    # vm_cmd1 = 'java -cp /home/vm/ThreadTest.jar SubThreadException'
    # vm_cmd1 = 'java -cp /home/vm/ThreadTest.jar ThreadWaiting'
    vm_cmd1 = 'java -cp /home/vm/ThreadTest.jar FuncTest'

    # configure for c Example
    # vm_cmd1 = 'cd /home/vm/tmp/buffer-overflow-attack/; ./stack'
    ssh_res = ssh_cmd(hostname=hostname, port=port, username=username, password=password, cmd=vm_cmd1)
    print ssh_res

# configure for java Example
def get_jvm_id():
    vm_cmd_jps = '/home/vm/jdk1.7.0_79/bin/jps'
    ssh_res = ssh_cmd(hostname=hostname, port=port, username=username, password=password, cmd=vm_cmd_jps)
    print ssh_res
    jvm_id = []
    lines = ssh_res.splitlines()
    for line in lines:
        key, value = line.split(" ")
        if "FuncTest" in value:
            jvm_id.append(key)
    jvm_id.sort()
    return jvm_id

# configure for c Example
def get_process_id():
    vm_cmd_ps = '''ps -ef | grep "stack" | grep -v grep | awk '{print $2}' '''
    ssh_res = ssh_cmd(hostname=hostname, port=port, username=username, password=password, cmd=vm_cmd_ps)
    proc_id = []
    lines = ssh_res.splitlines()
    for line in lines:
        proc_id.append(line)
    proc_id.sort()
    return proc_id

def kill_example(tasks):
    for task in tasks:
        cmd = 'kill -9 ' + str(task)
        ssh_res = ssh_cmd(hostname=hostname, port=port, username=username, password=password, cmd=cmd)

if __name__ == "__main__":

    count = 100
    while count > 0:
        print '--------------------------------------' + str(100 - count + 1)
        subThread = threading.Thread(target = loop, name = "TestExample")
        subThread.start()
        time.sleep(5)
        # configure for java Example
        tasks = get_jvm_id()

        # configure for c Example
        # tasks = get_process_id()
        if tasks is None:
            terminate_thread(subThread)
            continue
        else:
            task = tasks[-1]
            print task

        # configure for java Example
        sh_cmd = "python /home/kong/JavaMemory/volatility-2.6/vol.py -l vmi://ubuntu --profile=LinuxUbuntu1604_139x64 linux_runtime"

        # configure for c Example
        # sh_cmd = "python /home/kong/JavaMemory/volatility-2.6/vol.py -l vmi://ubuntu12.04_32bit --profile=LinuxUbuntu1204_23x86 linux_memory_analyze"

        res = os.system(sh_cmd)
        print res

        kill_example(tasks)
        terminate_thread(subThread)
        count -= 1