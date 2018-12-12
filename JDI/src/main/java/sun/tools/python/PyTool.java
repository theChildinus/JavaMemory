package sun.tools.python;

import sun.jvm.hotspot.code.Location;
import sun.jvm.hotspot.code.LocationValue;
import sun.jvm.hotspot.code.ScopeValue;
import sun.jvm.hotspot.code.VMRegImpl;
import sun.jvm.hotspot.debugger.Address;
import sun.jvm.hotspot.debugger.OopHandle;
import sun.jvm.hotspot.debugger.linux.*;
import sun.jvm.hotspot.oops.Method;
import sun.jvm.hotspot.runtime.*;
import sun.jvm.hotspot.types.AddressField;
import sun.tools.util.MyLog;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PyTool{

    private PyBugSpotAgent pyBugSpotAgent;
    private Map<String, JavaThread> threadMap;

    public void clear() {
        ((LinuxDebuggerLocal)(pyBugSpotAgent.getDebugger())).clear_Cache();
    }

    public void start(int pid) {
        pyBugSpotAgent = new PyBugSpotAgent();
        threadMap = new HashMap<String, JavaThread>();
        pyBugSpotAgent.attach(pid);
    }

    public void stop() {
        if (pyBugSpotAgent != null) {
            pyBugSpotAgent.detach();
        }
        if (threadMap != null) {
            threadMap.clear();
        }
    }

    private JavaThread initThread(String threadName) {
        for (JavaThread thread = VM.getVM().getThreads().first(); thread != null; thread = thread.next()) {
            MyLog.getInstance().getLogger().info(thread.getThreadName());
        }
        for (JavaThread thread = VM.getVM().getThreads().first(); thread != null; thread = thread.next()) {
            String tName = thread.getThreadName();
            if(tName != null && tName.contains(threadName)) {
                MyLog.getInstance().getLogger().info("find Thread: " + tName);
                return thread;
            }
        }
        return null;
    }

    public long initJavaLastFPAddress(String threadName, boolean cached) {
        long result = 0;
        JavaThread javaThread;
        if (!cached || (javaThread = threadMap.get(threadName)) == null) {
            javaThread = initThread(threadName);
            threadMap.put(threadName, javaThread);
        }
        if (javaThread != null) {
            Address javaThreadAddress = javaThread.getAddress();
            AddressField lastJavaFPField = VM.getVM().getTypeDataBase().lookupType("JavaFrameAnchor").getAddressField("_last_Java_fp");
            Address FPAddress = javaThreadAddress.addOffsetTo(JavaThread.getAnchorField().getOffset()).addOffsetTo(lastJavaFPField.getOffset());
            result = ((LinuxAddress)FPAddress).getValue();
        }
        return result;
    }

    public long initJavaLastSPAddress(String threadName, boolean cached) {
        long result = 0;
        JavaThread javaThread;
        if (!cached || (javaThread = threadMap.get(threadName)) == null) {
            javaThread = initThread(threadName);
            threadMap.put(threadName, javaThread);
        }
        if (javaThread != null) {
            Address javaThreadAddress = javaThread.getAddress();
            AddressField lastJavaSPField = VM.getVM().getTypeDataBase().lookupType("JavaFrameAnchor").getAddressField("_last_Java_sp");
            Address SPAddress = javaThreadAddress.addOffsetTo(JavaThread.getAnchorField().getOffset()).addOffsetTo(lastJavaSPField.getOffset());
            result = ((LinuxAddress)SPAddress).getValue();
        }
        return result;
    }

    public long initJavaFirstFPAddress(String threadName, boolean cached) {
        long result = 0;
        JavaThread javaThread;
        if (!cached || (javaThread = threadMap.get(threadName)) == null) {
            javaThread = initThread(threadName);
            threadMap.put(threadName, javaThread);
        }
        if (javaThread != null) {
            int count = 0;
            for (JavaVFrame vf = javaThread.getLastJavaVFrameDbg(); vf != null; vf = vf.javaSender()) {
                count++;
                if (vf.javaSender() == null) {
                    result = ((LinuxAddress)vf.getFrame().getFP()).getValue();
                }
            }
            MyLog.getInstance().getLogger().info("count: " + count);
        }
        return result;
    }

    public String getMethodName(long addr) {
        OopHandle methodOopHandle = new LinuxOopHandle((LinuxDebugger) pyBugSpotAgent.getDebugger(), addr);
        Method method = new Method(methodOopHandle, VM.getVM().getObjectHeap());
        return method.getName().asString();
    }

    public long[] initAddress(String threadName, String funcName, boolean cached) throws Exception {
        long[] result = new long[]{};
        JavaThread javaThread;
        if (!cached || (javaThread = threadMap.get(threadName)) == null) {
            javaThread = initThread(threadName);
            threadMap.put(threadName, javaThread);
        }
        if (javaThread != null) {
            for (JavaVFrame vf = javaThread.getLastJavaVFrameDbg(); vf != null; vf = vf.javaSender()) {
                Method method = vf.getMethod();
                String methodName = method.getName().asString();
                if (methodName != null && methodName.contains(funcName)) {
                    if (vf.isCompiledFrame()) {
                        CompiledVFrame cvf = (CompiledVFrame) vf;
                        List scvList = cvf.getScope().getLocals();
                        int length = scvList.size();
                        result = new long[length];
                        for (int i = 0; i < length; i++) {
                            ScopeValue sv = (ScopeValue) scvList.get(i);
                            if (sv.isLocation()) {
                                Location loc = ((LocationValue) sv).getLocation();
                                Address addr = null;
                                if (loc.isRegister()) {
                                    int reg = loc.getRegisterNumber();
                                    addr = vf.getRegisterMap().getLocation(new VMReg(reg));
                                } else if (loc.isStack() && !loc.isIllegal()) {
                                    addr = vf.getFrame().getUnextendedSP().addOffsetTo(loc.getStackOffset());
                                }
                                if (addr != null) {
                                    result[i] = ((LinuxAddress) addr).getValue();
                                }
                            }
                        }
                    } else {
                        int locals = (int) (method.isNative() ? method.getSizeOfParameters() : method.getMaxLocals());
                        result = new long[locals];
                        for (int i = 0; i < locals; i++) {
                            LinuxAddress addr = (LinuxAddress) vf.getFrame().addressOfInterpreterFrameLocal(i);
                            result[i] = addr.getValue();
                        }
                    }
                }
            }
        }
        return result;
    }
}
