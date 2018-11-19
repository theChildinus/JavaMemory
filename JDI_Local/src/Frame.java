
import sun.jvm.hotspot.code.Location;
import sun.jvm.hotspot.code.LocationValue;
import sun.jvm.hotspot.code.NMethod;
import sun.jvm.hotspot.code.ScopeValue;
import sun.jvm.hotspot.code.VMRegImpl;
import sun.jvm.hotspot.debugger.Address;
import sun.jvm.hotspot.debugger.OopHandle;
import sun.jvm.hotspot.interpreter.OopMapCacheEntry;
import sun.jvm.hotspot.oops.Method;
import sun.jvm.hotspot.oops.Oop;
import sun.jvm.hotspot.runtime.*;
import sun.jvm.hotspot.tools.Tool;


import java.text.NumberFormat;
import java.util.List;

public class Frame extends Tool {

    public void run() {
        for (JavaThread thread = VM.getVM().getThreads().first(); thread != null; thread = thread.next()) {
            System.err.println(thread.getThreadName() + ", id = " + thread.getOSThread().threadId());
            for (JavaVFrame javaVFrame = thread.getLastJavaVFrameDbg(); javaVFrame != null; javaVFrame = javaVFrame.javaSender()) {
                System.err.println("FP: " + javaVFrame.getFrame().getFP());
                dumpFrame(javaVFrame, "");
            }
            System.err.println();
        }
    }


    private void dumpFrame(JavaVFrame vf, String name) {
        Method method = vf.getMethod();
        String className = method.getMethodHolder().getName().asString().replace('/', '.');
        String methodName = method.getName().asString();
        String para=method.getSignature().asString().replace('/', '.');
        System.err.println("  # " + className + '.' + methodName +para);//+ " @ " + vf.getBCI());

        boolean flag = (name != null && methodName.contains(name));

        if (vf.isCompiledFrame()) {
            System.err.println("    CompiledFrame");
            dumpCompiledFrame(((CompiledVFrame) vf), flag);
        } else {
            System.err.println("    InterpretedFrame");
            dumpInterpretedFrame(((InterpretedVFrame) vf), flag);
        }
    }

    private void dumpCompiledFrame(CompiledVFrame vf, boolean flag) {
        if (vf.getScope() == null) {
            return;
        }

        NMethod nm = vf.getCode();
        System.err.println("    * code=[" + nm.codeBegin() + "-" + nm.codeEnd() + "], pc=" + vf.getFrame().getPC());

        List locals = vf.getScope().getLocals();
        for (int i = 0; i < locals.size(); i++) {
            ScopeValue sv = (ScopeValue) locals.get(i);
            if (!sv.isLocation()) continue;

            Location loc = ((LocationValue) sv).getLocation();
            Address addr = null;
            String regName = "";

            if (loc.isRegister()) {
                int reg = loc.getRegisterNumber();
                addr = vf.getRegisterMap().getLocation(new VMReg(reg));
                regName = ":" + VMRegImpl.getRegisterName(reg);
            } else if (loc.isStack() && !loc.isIllegal()) {
                addr = vf.getFrame().getUnextendedSP().addOffsetTo(loc.getStackOffset());
            }

            String value = getValue(addr, loc.getType());
            System.err.println("    [" + i + "] " + addr + regName + " = " + value);
        }
    }

    private void dumpInterpretedFrame(InterpretedVFrame vf, boolean flag) {
        Method method = vf.getMethod();
        int locals = (int) (method.isNative() ? method.getSizeOfParameters() : method.getMaxLocals());
        OopMapCacheEntry oopMask = method.getMaskFor(vf.getBCI());

        for (int i = 0; i < locals; i++) {
            Address addr = vf.getFrame().addressOfInterpreterFrameLocal(i);
            String value = getValue(addr, oopMask.isOop(i) ? Location.Type.OOP : Location.Type.NORMAL);
            System.err.println("    [" + i + "] " + addr + " = " + value);
        }
    }

    private String getValue(Address addr, Location.Type type) {
        if (type == Location.Type.INVALID || addr == null) {
            return "(invalid)";
        } else if (type == Location.Type.OOP) {
            return "(oop) " + getOopName(addr.getOopHandleAt(0));
        } else if (type == Location.Type.NARROWOOP) {
            return "(narrow_oop) " + getOopName(addr.getCompOopHandleAt(0));
        } else if (type == Location.Type.NORMAL) {
            String s="\n";
            s+="                (hex) "+ addr.getAddressAt(0)+"\n";
            s+="                (int) "+Long.toString(addr.getJIntAt(0))+"\n";
            s+="                (float) "+Float.toString(addr.getJFloatAt(0))+"\n";
            s+="                (double) "+ NumberFormat.getNumberInstance().format(addr.getJDoubleAt(0))+"\n";
            return s;
            //return "(int) 0x" + Integer.toHexString(addr.getJIntAt(0));
        } else {
            return "(" + type + ") 0x" + Long.toHexString(addr.getJLongAt(0));
        }
    }

    private String getOopName(OopHandle hadle) {
        if (hadle == null) {
            return "null";
        }
        Oop oop = VM.getVM().getObjectHeap().newOop(hadle);
        return oop.getKlass().getName().asString();
    }

    public static void main(String[] args) throws Exception {
        String[] cmd={"17231"};
        try {
            new Frame().start(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}