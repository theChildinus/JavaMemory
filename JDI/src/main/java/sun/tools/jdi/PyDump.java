package sun.tools.jdi;

import sun.jvm.hotspot.debugger.Address;
import sun.jvm.hotspot.debugger.linux.LinuxDebuggerLocal;
import sun.jvm.hotspot.oops.Symbol;
import sun.jvm.hotspot.runtime.*;

import java.util.List;

public class PyDump{
    public static void cache(Address stackBase, long stackSize) {
        LinuxDebuggerLocal debugger = Frames.getDebugger();
        long offset = 0;
        for (int i = 0; i < stackSize; i++) {
            stackBase.getAddressAt(-offset);
            offset += 4096;
        }
        System.err.println(stackBase);
        long cacheSize = Frames.getDebugger().getPageCache().getNumPages();
        System.err.println("tmp cache:" + cacheSize);
    }

    public static void getVariables(long firstLongValue, List<Address> variables, String methodName) {
//        Address lastSP = javaThread.getLastJavaVFrameDbg().getFrame().getSP();
//        if (lastSP.greaterThan(javaVFrame.getFrame().getSP())) {
//            return;
//        }
        for (int i = 0; i < variables.size(); i++) {
            System.err.println("Address " + variables.get(i) + " : " +
                    Long.toString(variables.get(i).getJIntAt(0)));
        }
        long cacheSize = Frames.getDebugger().getPageCache().getNumPages();
        System.err.println("tmp cache:" + cacheSize);
    }
}
