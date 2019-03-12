package sun.tools.python;

import sun.jvm.hotspot.HotSpotTypeDataBase;
import sun.jvm.hotspot.LinuxVtblAccess;
import sun.jvm.hotspot.debugger.JVMDebugger;
import sun.jvm.hotspot.debugger.MachineDescription;
import sun.jvm.hotspot.debugger.MachineDescriptionAMD64;
import sun.jvm.hotspot.debugger.linux.LinuxDebuggerLocal;
import sun.jvm.hotspot.runtime.VM;
import sun.jvm.hotspot.types.TypeDataBase;
import sun.tools.util.MyLog;

public class PyBugSpotAgent {

    private JVMDebugger debugger;
    private MachineDescription machDesc;
    private TypeDataBase db;

    private int pid;
    private String[] jvmLibNames;

    public void attach(int processID) {
        pid = processID;
        ////////////////////////////////////////
        // 1. 设置虚拟机库文件名
        ////////////////////////////////////////
        // setupDebuggerLinux().setupJVMLibNamesLinux().setupJVMLibNamesSolaris()
        jvmLibNames = new String[] { "libjvm.so", "libjvm_g.so", "gamma_g" };
        ////////////////////////////////////////
        // 2. new一个LinuxDebuggerLocal
        ////////////////////////////////////////
        // setupDebuggerLinux().MachineDescriptionAMD64()
        machDesc = new MachineDescriptionAMD64();
        debugger = new LinuxDebuggerLocal(machDesc, true);
        MyLog.getInstance().getLogger().info(String.valueOf(debugger.getClass()));
        MyLog.getInstance().getLogger().info(String.valueOf(debugger.getClass().getClassLoader()));
        ////////////////////////////////////////
        // 3. 调用LinuxDebuggerLocal的attach方法
        ////////////////////////////////////////
        // setupDebuggerLinux().attachDebugger() 调用 LinuxDebuggerLocal 的 attach方法
        debugger.attach(pid);

        ////////////////////////////////////////
        // 1. 构建HotSpotTypeDataBase
        ////////////////////////////////////////
        // setupVM().HotSpotTypeDataBase()
        db = new HotSpotTypeDataBase(machDesc, new LinuxVtblAccess(debugger, jvmLibNames), debugger, jvmLibNames);
        ////////////////////////////////////////
        // 2. 设置原生类型大小，从目标VM获取
        ////////////////////////////////////////
        debugger.configureJavaPrimitiveTypeSizes(db.getJBooleanType().getSize(),
                db.getJByteType().getSize(),
                db.getJCharType().getSize(),
                db.getJDoubleType().getSize(),
                db.getJFloatType().getSize(),
                db.getJIntType().getSize(),
                db.getJLongType().getSize(),
                db.getJShortType().getSize());
        ////////////////////////////////////////
        // 3. 构建目标VM的本机表示
        ////////////////////////////////////////
        VM.initialize(db, debugger);
    }

    public boolean detach() {
        VM.shutdown();
        return debugger.detach();
    }

    public JVMDebugger getDebugger() {
        return debugger;
    }
}
