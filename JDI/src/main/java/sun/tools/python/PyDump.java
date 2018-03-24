package sun.tools.python;

import sun.jvm.hotspot.debugger.linux.PythonMethodInterface;

public class PyDump {

    public static PythonMethodInterface pmi;
    private static PyTool pyTool = new PyTool();

    // init the vm
    public static void initVM(PythonMethodInterface p, int pid) {
        pmi = p;
        pyTool.start(pid);
    }

    // get the last fp of thread
    public static long initJavaLastFPAddress(String threadName, boolean cached) {
        return pyTool.initJavaLastFPAddress(threadName, cached);
    }

    // get the last sp of thread
    public static long initJavaLastSPAddress(String threadName, boolean cached) {
        return pyTool.initJavaLastSPAddress(threadName, cached);
    }

    // get the first fp of thread
    public static long initJavaFirstFPAddress(String threadName, boolean cached) {
        long result = 0;
        try {
            result = pyTool.initJavaFirstFPAddress(threadName, cached);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String getMethodName(long addr) {
        String result = "";
        try {
            result = pyTool.getMethodName(addr);
        } catch (Exception e) {
            //e.printStackTrace();
        }
        return result;
    }

    public static double jd(long a) {
        return Double.longBitsToDouble(a);
    }

    public static float jf(int a) {
        return Float.intBitsToFloat(a);
    }
    public static void clear() {
        pyTool.clear();
    }


    public static void stop() {
        pyTool.stop();
    }
}
