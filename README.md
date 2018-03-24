# 宿主机
## volatility需要安装的包
https://github.com/volatilityfoundation/volatility/wiki/Installation
1. **python 2.7**
    - sudo pip install py-bcrypt
    - sudo pip install utils
    - sudo apt-get install python-tk
2. **distorm3**
    - https://github.com/gdabah/distorm/releases
    - sudo python setup.py build
    - sudo python setup.py install
3. **pycrypto-2.6.1**
    - https://www.dlitz.net/software/pycrypto/
    - sudo apt-get install python-dev
    - sudo python setup.py build
    - sudo python setup.py install
4. **yara**
    - https://yara.readthedocs.io/en/v3.7.0/gettingstarted.html
5. **jpype**
    - https://github.com/originell/jpype/releases
6. **setuptool**
    - pip install setuptool   
7. **elftools**
    - pip install pyelftools
8. **paramiko**
    - pip install paramiko
9. **libvmi-0.10.1**
    - https://github.com/libvmi/libvmi
    - ./autogen.sh
    - sudo apt-get install libgnomeui-dev
    - sudo apt-get install check-devel
    - sudo apt-get install libvirt-dev
    - ./configure --enable-xen=no
    - make
    - cd tools/pyvmi/
    - sudo python setup.py build
    - sudo python setup.py install

- 将volatility官方提供的压缩包放到javamemory/volatility-2.6/volatility/plugins/overlays/linux目录下  
- python vol.py -l vmi://ubuntu --profile=LinuxUbuntu1604x64 linux_pslist

# 虚拟机
1. **Creating a new profile** 
    - 安装jdk 设置jdk配置
  https://blog.csdn.net/rflyee/article/details/8989663
2. **导入jar包**
    - pyagent.jar 
    - Test.jar
# 工程相关
1. sudo 运行pyCharm
 
    - 遇到错误提示 ImportError: libvmi-0.9.so: cannot open shared object file: No such file or directory
    - 在环境变量/etc/profile.d/jdk.sh 中添加 export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
2. 修改 linux_runtime.py 文件中的路径 包括
    - j_test_path ---> -Djava.class.path=/home/kong/java memory/JDI.jar
    - symbol ---> /home/kong/java memory/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so 
    - self.symbolDict ---> /home/vm/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so
3. JDI工程需要导入包 jdk1.7.0_79/lib/sa.jdi.jar

# 运行流程
1. 虚拟机执行命令 java -jar -Xint Test.jar 运行测试程序
2. 虚拟机另开终端 执行命令jps 获取jar对应的[线程号] 并执行命令 sudo java -jar pyagent.jar [线程号]
3. 宿主机 修改编译参数为 -l vmi://ubuntu --profile=LinuxUbuntu1604x64 linux_runtime -p [线程号]
4. vmi 为虚拟机的名字
