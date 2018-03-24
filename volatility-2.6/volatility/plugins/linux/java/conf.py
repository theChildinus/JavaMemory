#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Tkinter import *


class Conf:
    def __init__(self):
        self.root = root = Tk()
        root.title('Monitor')
        root.geometry('800x600')
        fr1 = Frame(root, width=400, height=600)
        self.fr1 = fr1
        fr1.place(x=0, y=100, anchor='nw')

        label_vm = Label(fr1, text=u'虚拟机名称', font=('Arial', 18))
        label_vm.grid(row=0, column=0, padx=1, pady=5)
        self.entry_vm = Entry(fr1, font=('Arial', 18))
        self.entry_vm.grid(row=0, column=1, padx=1, pady=5)

        label_pid = Label(fr1, text='pid', font=('Arial', 18))
        label_pid.grid(row=1, column=0, padx=1, pady=5)
        self.entry_pid = Entry(fr1, font=('Arial', 18))
        self.entry_pid.grid(row=1, column=1, padx=1, pady=5)

        label_fname = Label(fr1, text=u'函数名称', font=('Arial', 18))
        label_fname.grid(row=2, column=0, padx=1, pady=5)
        self.entry_fname = Entry(fr1, font=('Arial', 18))
        self.entry_fname.grid(row=2, column=1, padx=1, pady=5)

        label_count = Label(fr1, text=u'参数数量', font=('Arial', 18))
        label_count.grid(row=3, column=0, padx=1, pady=5)
        self.entry_count = Entry(fr1, font=('Arial', 18))
        self.entry_count.grid(row=3, column=1, padx=1, pady=5)

        label_type = Label(fr1, text=u'参数类型', font=('Arial', 18))
        label_type.grid(row=4, column=0, padx=1, pady=5)
        self.entry_type = Entry(fr1, font=('Arial', 18))
        self.entry_type.grid(row=4, column=1, padx=1, pady=5)

        label_port = Label(fr1, text=u'发送端口', font=('Arial', 18))
        label_port.grid(row=5, column=0, padx=1, pady=5)
        self.entry_port = Entry(fr1, font=('Arial', 18))
        self.entry_port.grid(row=5, column=1, padx=1, pady=5)

        fr2 = Frame(root, width=400, height=600)
        fr2.place(x=410, y=50, anchor='nw')
        t1 = Text(fr2, width=50, height=30, font=('Arial', 10))
        t1.place(x=0, y=0, anchor='nw')
        self.t1 = t1

    def start(self):
        self.root.mainloop()

    def stop(self):
        self.root.quit()

    def config_no(self):
        def func1():
            print 'save'
            self.root.destroy()

        def func2():
            self.root.destroy()

        fr1 = self.fr1
        button_run = Button(fr1, text=u'保存', font=('Arial', 18), command=func1)
        button_run.grid(row=6, column=0, padx=1, pady=15)
        button_run = Button(fr1, text=u'退出', font=('Arial', 18), command=func2)
        button_run.grid(row=6, column=1, padx=1, pady=15)

    def config(self, func1, func2):
        fr1 = self.fr1
        button_run = Button(fr1, text=u'运行', font=('Arial', 18), command=func1)
        button_run.grid(row=6, column=0, padx=1, pady=15)
        button_run = Button(fr1, text=u'停止', font=('Arial', 18), command=func2)
        button_run.grid(row=6, column=1, padx=1, pady=15)
        self.entry_vm.insert('end', 'centod')
        self.entry_pid.insert('end', '8134')
        self.entry_fname.insert('end', 'func1,func2,func3,func4')
        self.entry_count.insert('end', '2,2,2,2')
        self.entry_type.insert('end', '[int,int],[long,long],[float,float],[double,double]')
        self.entry_port.insert('end', '6666')

    def config_c(self, func1, func2):
        fr1 = self.fr1
        button_run = Button(fr1, text=u'运行', font=('Arial', 18), command=func1)
        button_run.grid(row=6, column=0, padx=1, pady=15)
        button_run = Button(fr1, text=u'停止', font=('Arial', 18), command=func2)
        button_run.grid(row=6, column=1, padx=1, pady=15)
        self.entry_vm.insert('end', 'centod')
        self.entry_pid.insert('end', '13585')
        self.entry_fname.insert('end', 'add,sub')
        self.entry_count.insert('end', '2,2')
        self.entry_type.insert('end', '[double,double],[double,double]')
        self.entry_port.insert('end', '6666')

    def t1_insert(self, inf):
        self.t1.insert('end', inf)
        self.t1.see('end')
