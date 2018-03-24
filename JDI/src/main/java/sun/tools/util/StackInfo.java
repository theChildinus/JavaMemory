package sun.tools.util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class StackInfo {
    private static HashMap<String, Integer> map = new HashMap<String, Integer>();
    public static void getStackInfo() {
        StackTraceElement[] ss = Thread.getAllStackTraces().get(Thread.currentThread());
        for (int i = 3; i < ss.length && i < 5; i++) {
            //System.out.println(ss[i]);
            if (!map.containsKey(ss[i].toString())) {
                map.put(ss[i].toString(), 1);
            } else {
                map.put(ss[i].toString(), map.get(ss[i].toString()) + 1);
            }
        }
        //System.out.println("--");
    }
    public static void printStatistic() {
        Object[] keys =  map.keySet().toArray();
        Arrays.sort(keys);
        for (Object key : keys) {
            System.err.println(key + ":" + map.get(key));
        }
    }
}
