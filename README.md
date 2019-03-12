# 内存重构文档

[内存重构实现原理解析](Review.md)

## 分析结果

分析运行在虚拟机中的Java程序，包含四个方法 func1，func2，func3，func4和func5

```java
public void func1(int a, int b) {
    int var1 = a + b;
    this.func2(100100010000L, 200200020000L);
}

public void func2(long a, long b) {
    long var2 = a + b;
    this.func3(1.1F, 6.6F);
}

public void func3(float a, float b) {
    float var3 = a + b;
    this.func4(7.7D, 9.9D);
}

public void func4(double a, double b) {
    double var4 = a + b;
    this.func5();
}

public int func5() {
    int m = 100;
    byte n = 88;

    try {
        Thread.sleep(1000L);
    } catch (InterruptedException e) {
        e.printStackTrace();
    }

    return m + n;
}
```

```txt
Volatility Foundation Volatility Framework 2.6
>>>>>> render_test >>>>>>

获取到虚拟机中运行的Java程序的pid
task.pid is  2313
INFO    : paramiko.transport  : Connected (version 2.0, client OpenSSH_7.2p2)
INFO    : paramiko.transport  : Authentication (publickey) failed.
INFO    : paramiko.transport  : Authentication (publickey) failed.
INFO    : paramiko.transport  : Authentication (password) successful!

pyagent.jar return yes
虚拟机中JVM启动所需的共享库名称及起始地址
base: 0x400000L name: /home/vm/jdk1.7.0_79/bin/java
base: 0x7f12d6008000L name: /home/vm/jdk1.7.0_79/jre/lib/amd64/libzip.so
base: 0x7f12d6223000L name: /lib/x86_64-linux-gnu/libnss_files-2.23.so
base: 0x7f12d6435000L name: /lib/x86_64-linux-gnu/libnss_nis-2.23.so
base: 0x7f12d6641000L name: /lib/x86_64-linux-gnu/libnsl-2.23.so
base: 0x7f12d685a000L name: /lib/x86_64-linux-gnu/libnss_compat-2.23.so
base: 0x7f12d6a63000L name: /home/vm/jdk1.7.0_79/jre/lib/amd64/libjava.so
base: 0x7f12d6c8e000L name: /home/vm/jdk1.7.0_79/jre/lib/amd64/libverify.so
base: 0x7f12d6e9c000L name: /lib/x86_64-linux-gnu/librt-2.23.so
base: 0x7f12d70a4000L name: /lib/x86_64-linux-gnu/libm-2.23.so
base: 0x7f12d73ad000L name: /home/vm/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so
base: 0x7f12d8227000L name: /lib/x86_64-linux-gnu/libc-2.23.so
base: 0x7f12d85f1000L name: /lib/x86_64-linux-gnu/libdl-2.23.so
base: 0x7f12d87f5000L name: /home/vm/jdk1.7.0_79/lib/amd64/jli/libjli.so
base: 0x7f12d8a0c000L name: /lib/x86_64-linux-gnu/libpthread-2.23.so
base: 0x7f12d8c29000L name: /lib/x86_64-linux-gnu/ld-2.23.so
[2313L, 2314L, 2315L, 2316L, 2317L, 2318L, 2319L, 2320L, 2321L, 2322L]

JVM中的所有线程：
2019-01-22 21:20:07 INFO sun.tools.python.PyTool initThread Service Thread
2019-01-22 21:20:08 INFO sun.tools.python.PyTool initThread C2 CompilerThread1
2019-01-22 21:20:08 INFO sun.tools.python.PyTool initThread C2 CompilerThread0
2019-01-22 21:20:08 INFO sun.tools.python.PyTool initThread Signal Dispatcher
2019-01-22 21:20:08 INFO sun.tools.python.PyTool initThread Finalizer
2019-01-22 21:20:08 INFO sun.tools.python.PyTool initThread Reference Handler
2019-01-22 21:20:08 INFO sun.tools.python.PyTool initThread main
2019-01-22 21:20:08 INFO sun.tools.python.PyTool initThread find Thread: main
2019-01-22 21:20:09 INFO sun.tools.python.PyTool initJavaFirstFPAddress count: 7

main线程虚拟机栈的栈底地址
first_fp: 0x7f12d8e319d8L

开始分析
===== START ===== 3061
#######################
main fp: 0x7f12d8e319d8L 0x7f12d8e31968L

函数 func1 对应的栈帧地址
func1 fp: 0x7f12d8e31968L 0x7f12d8e318e0L
fp - 48: 0x7f12d8e31938L 0x7f12d8e31990
Address:  0x7f12d8e31990  value:  0xeb4531f8
Address:  0x7f12d8e31988  value:  0x1       // 函数参数 int a
Address:  0x7f12d8e31980  value:  0x2       // 函数参数 int b
Address:  0x7f12d8e31978  value:  0x3       // 局部变量 int var1
Address:  0x7f12d8e31970  value:  0x7f12cd006058
Address:  0x7f12d8e31968  value:  0x7f12d8e319d8
Address:  0x7f12d8e31960  value:  0x7f12d8e31980
Address:  0x7f12d8e31958  value:  0x7f12d8e31900
Address:  0x7f12d8e31950  value:  0xfb080988
Address:  0x7f12d8e31948  value:  0x0
GetParam >> Address:  0x7f12d8e31988 Value:  1
GetParam >> Address:  0x7f12d8e31980 Value:  2

函数 func2 对应的栈帧地址
func2 fp: 0x7f12d8e318e0L 0x7f12d8e31870L
fp - 48: 0x7f12d8e318b0L 0x7f12d8e31920
Address:  0x7f12d8e31920  value:  0xeb4531f8
Address:  0x7f12d8e31918  value:  0xc6b9f
Address:  0x7f12d8e31910  value:  0x174e6cf010   // 函数参数 long a
Address:  0x7f12d8e31908  value:  0x7f12d7bc8423
Address:  0x7f12d8e31900  value:  0x2e9cd9e020   // 函数参数 long b
Address:  0x7f12d8e318f8  value:  0x0
Address:  0x7f12d8e318f0  value:  0x45eb46d030   // 局部变量 long var2
Address:  0x7f12d8e318e8  value:  0x7f12cd006058
Address:  0x7f12d8e318e0  value:  0x7f12d8e31968
Address:  0x7f12d8e318d8  value:  0x7f12d8e31900
GetParam >> Address:  0x7f12d8e31910 Value:  100100010000
GetParam >> Address:  0x7f12d8e31900 Value:  200200020000

函数 func3 对应的栈帧地址
func3 fp: 0x7f12d8e31870L 0x7f12d8e317e8L
fp - 48: 0x7f12d8e31840L 0x7f12d8e31898
Address:  0x7f12d8e31898  value:  0xeb4531f8
Address:  0x7f12d8e31890  value:  0x173f8ccccd    // 函数参数 float a
Address:  0x7f12d8e31888  value:  0x7f1240d33333  // 函数参数 float b
Address:  0x7f12d8e31880  value:  0x40f66666      // 局部变量 float var3
Address:  0x7f12d8e31878  value:  0x7f12cd006058
Address:  0x7f12d8e31870  value:  0x7f12d8e318e0
Address:  0x7f12d8e31868  value:  0x7f12d8e31888
Address:  0x7f12d8e31860  value:  0x7f12d8e31808
Address:  0x7f12d8e31858  value:  0xfb080b98
Address:  0x7f12d8e31850  value:  0x0
GetParam >> Address:  0x7f12d8e31890 Value:  1.10000002384
GetParam >> Address:  0x7f12d8e31888 Value:  6.59999990463

函数 func4 对应的栈帧地址
func4 fp: 0x7f12d8e317e8L 0x7f12d8e31778L
fp - 48: 0x7f12d8e317b8L 0x7f12d8e31828
Address:  0x7f12d8e31828  value:  0xeb4531f8
Address:  0x7f12d8e31820  value:  0x7f12d0009800
Address:  0x7f12d8e31818  value:  0x401ecccccccccccd // 函数参数 double a
Address:  0x7f12d8e31810  value:  0x7f12d000a128
Address:  0x7f12d8e31808  value:  0x4023cccccccccccd // 函数参数 double b
Address:  0x7f12d8e31800  value:  0x0
Address:  0x7f12d8e317f8  value:  0x403199999999999a // 局部变量 double var4
Address:  0x7f12d8e317f0  value:  0x7f12cd006058
Address:  0x7f12d8e317e8  value:  0x7f12d8e31870
Address:  0x7f12d8e317e0  value:  0x7f12d8e31808
GetParam >> Address:  0x7f12d8e31818 Value:  7.7
GetParam >> Address:  0x7f12d8e31808 Value:  9.9

函数 func5 对应的栈帧地址
func5 fp: 0x7f12d8e31778L 0x7f12d8e31708L
sleep fp: 0x7f12d8e31708L 0x7f12d8e316a0L
sleep fp: 0x7f12d8e316a0L 0x7f12d8e31600L
nextFrame is None
start, end:  14.645319 , 14.907558
Durning:  262.239 ms
#######################
```

## 宿主机端配置

### volatility需要安装的包

[volatility github](https://github.com/volatilityfoundation/volatility/wiki/Installation)

1. **python 2.7**
    - sudo pip install py-bcrypt
    - sudo pip install utils
    - sudo apt-get install python-tk
2. **distorm3**
    - [参考官方文档](https://github.com/gdabah/distorm/releases)
    - sudo python setup.py build
    - sudo python setup.py install
3. **pycrypto-2.6.1**
    - [参考官方文档](https://www.dlitz.net/software/pycrypto/)
    - sudo apt-get install python-dev
    - sudo python setup.py build
    - sudo python setup.py install
4. **yara**
    - [参考官方文档](https://yara.readthedocs.io/en/v3.7.0/gettingstarted.html)
5. **jpype**
    - [参考官方文档](https://github.com/originell/jpype/releases)
6. **setuptool**
    - pip install setuptool
7. **elftools**
    - pip install pyelftools
8. **paramiko**
    - pip install paramiko
9. **libvmi-0.10.1**
    - *建议下载 libvmi-0.10.1 版本 其他版本编译有问题*
    - [官方文档](https://github.com/libvmi/libvmi)
    - ./autogen.sh
    - sudo apt-get install libgnomeui-dev
    - sudo apt-get install check-devel
    - sudo apt-get install libvirt-dev
    - ./configure --enable-xen=no
    - make
    - sudo make install
    - cd tools/pyvmi/
    - sudo python setup.py build
    - sudo python setup.py install
    - ldconfig

## 虚拟机端配置

1. [**安装jdk 配置jdk**](https://blog.csdn.net/rflyee/article/details/8989663)
2. 分析Java程序需导入
   - pyagent.jar
   - ThreadTest.jar
3. 分析C程序需导入
   - buffer_overflow_attack文件夹

## 工程相关（宿主机端）

1. pyCharm运行程序
    - 遇到错误提示 ImportError: libvmi-0.9.so: cannot open shared object file: No such file or directory
    - 在环境变量/etc/profile.d/jdk.sh 中添加 export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
2. 在 `JavaMemory/volatility-2.6/volatility/plugins/linux` 路径下
   - `linux_runtime_py` 用于分析Java程序
   - `linux_memory_analyze.py` 用于分析C程序
3. `linux_runtime.py` 中需要修改的路径有：

    | 变量名          | 默认值                |
    | --------------- | ------------------- |
    | j_test_path     | -Djava.class.path=/home/kong/JavaMemory/JDI/out/artifacts/JDI_jar/JDI.jar |
    | symbol          | /home/kong/JavaMemory/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so          |
    | self.symbolDict | /home/vm/jdk1.7.0_79/jre/lib/amd64/server/libjvm.so                       |
4. `linux_memory_analyze.py` 中需要修改的地方有：

    | 变量名       | 默认值          |
    | ----------- | -------------- |
    | calculate 函数中 processname | ./stack 需要修改为分析的C程序名称 |

5. JDI工程需要导入包

- `jdk1.7.0_79/lib/sa-jdi.jar`
- `JavaMemory/JDI.jar`

IDEA中打JDI包方法[参考](https://www.jianshu.com/p/2e06dd2ea4da)，要将官方`JDI.jar`、`sa-jdi.jar` Extracted Directory到项目中

## 测试环境

- **测试volatility是否可以获取到虚拟机信息**
  - volatitlity工程 Pycharm配置参数（如果虚拟机为64位） `-l vmi://ubuntu --profile=LinuxUbuntu1604_内核版本号x64 linux_pslist`
  - （如果虚拟机为32位） `-l vmi://ubuntu12.04_32bit --profile=LinuxUbuntu1204_23x86 linux_pslist`
  - 其中 `vmi` 代表虚拟机名称，`profile` 代表在虚拟机内部打包生成的profile名称，`x64、x86` 代表虚拟机位数
  - 若未显示虚拟机进程信息，可能虚拟机内核版本与overlays目录下的压缩包不匹配 虚拟中通过 `uname -a` 查看内核版本 并执行以下步骤生成profile，可参考[官方文档](https://github.com/volatilityfoundation/volatility/wiki/Linux)（虚拟机中）：
    1. 将volatility工程拷到虚拟机中
    2. `sudo apt-get install dwarfdump`
    3. `sudo apt-get install build-essential`
    4. 建议禁止内核自动升级，设置中停止更新，并 `sudo apt-mark hold 内核版本号`
    5. `cd volatility/tools/linux 并 make`
    6. `head module.dwarf`
    7. `sudo zip volatility-2.6/volatility/plugins/overlays/linux/Ubuntu系统版本号_内核版本号.zip volatility-2.6/tools/linux/module.dwarf /boot/System.map-内核版本号`
    8. 将生成的zip文件拷到宿主机的 `volatility-2.6/volatility/plugins/overlays/linux`目录下 并修改参数

## 运行流程

### 分析Java程序

1. 虚拟机执行命令 `java -cp ThreadTest.jar FuncTest` 运行测试程序
2. 虚拟机另开终端 执行命令jps 获取jar对应的 `线程号` 并执行命令 `sudo java -jar pyagent.jar 线程号`
3. 宿主机 添加配置参数为 `-l vmi://ubuntu --profile=LinuxUbuntu1604_内核版本号x64 linux_runtime -p 测试程序进程号` 并运行

### 分析C程序

1. 虚拟机执行命令 `./stack` 运行测试程序
2. 宿主机 添加配置参数为 `-l vmi://ubuntu12.04_32bit --profile=LinuxUbuntu1204_内核版本号x86 linux_memory_analyze -p 测试程序进程号` 并运行

如果提示 `waiting connection...` 即 该volatility 工程为socket服务端，等待IOT工程作为客户端的连接

## JDI

此文件夹是通过 Volatility 进行内存分析时，jpype调用的java接口实现

## JDI_Local

此文件夹是本地进行Java内存分析的代码，运行流程为：

- root权限打开该工程
- 添加 `jdk1.7/lib/sa-jdi.jar` 到工程中
- 使用1.7版本java 运行的测试程序，cd到jdk1.7 bin目录下，`./java -jar -Xint path/of/test.jar`
- jps获取测试程序进程号，并修改工程中的cmd变量值
- **测试程序需要sleep一下，否则 Volatility 框架无法获取内存信息**

## [buffer-overflow-attack](https://github.com/theChildinus/buffer-overflow-attack)

图片中左侧为缓冲区溢出攻击前的堆栈情况，右侧为攻击后的堆栈情况

![buffer_overflow_attack](others/buffer_overflow_attack.png)

## Q & A

1. 推荐阅读：
    - [HotSpot Serviceability Agent 实现浅析](https://yq.aliyun.com/articles/20231)
    - [JVM 内存模型概述](https://blog.csdn.net/justloveyou_/article/details/71189093)
    - [doc Serviceability Agent](https://docs.oracle.com/javase/jp/8/docs/serviceabilityagent/)
    - [x86-64 下函数调用及栈帧原理](https://zhuanlan.zhihu.com/p/27339191)
