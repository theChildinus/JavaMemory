package sun.jvm.hotspot.debugger.linux;

public interface PythonMethodInterface {
    long[] getThreadsId();
    String[] getLibName();
    long[] getLibBase();
    long lookUpByName(String objectName, String symbol);
    byte[] readBytesFromProcess(long address, long numBytes);
}
