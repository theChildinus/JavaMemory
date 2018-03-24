package sun.tools.python;

import sun.jvm.hotspot.HotSpotTypeDataBase;
import sun.jvm.hotspot.LinuxVtblAccess;
import sun.jvm.hotspot.debugger.JVMDebugger;
import sun.jvm.hotspot.debugger.MachineDescription;
import sun.jvm.hotspot.debugger.MachineDescriptionAMD64;
import sun.jvm.hotspot.debugger.linux.LinuxDebuggerLocal;
import sun.jvm.hotspot.runtime.VM;
import sun.jvm.hotspot.types.TypeDataBase;

public class PyBugSpotAgent {

    private JVMDebugger debugger;
    private MachineDescription machDesc;
    private TypeDataBase db;

    private int pid;
    private String[] jvmLibNames;

    public void attach(int processID) {
        pid = processID;
        jvmLibNames = new String[] { "libjvm.so", "libjvm_g.so", "gamma_g" };
        machDesc = new MachineDescriptionAMD64();
        debugger = new LinuxDebuggerLocal(machDesc, true);
        debugger.attach(pid);
        db = new HotSpotTypeDataBase(machDesc, new LinuxVtblAccess(debugger, jvmLibNames), debugger, jvmLibNames);
        debugger.configureJavaPrimitiveTypeSizes(db.getJBooleanType().getSize(),
                db.getJByteType().getSize(),
                db.getJCharType().getSize(),
                db.getJDoubleType().getSize(),
                db.getJFloatType().getSize(),
                db.getJIntType().getSize(),
                db.getJLongType().getSize(),
                db.getJShortType().getSize());
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
