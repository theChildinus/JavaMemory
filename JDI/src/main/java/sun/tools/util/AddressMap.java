package sun.tools.util;

import java.util.*;

public class AddressMap<K> {
    private HashMap<K, K> head = new HashMap<K, K>();
    private HashMap<K, K> tail = new HashMap<K, K>();
    public void put(K key, K value) {
        if (tail.containsKey(key) || head.containsKey(value)) {
            if (tail.containsKey(key)) {
                K tmp = tail.get(key);
                tail.remove(key);
                tail.put(value, tmp);
                head.put(tmp, value);
                key = tmp;
                if (head.containsKey(value)) {
                    tmp = head.get(value);
                    head.remove(value);
                    head.put(key, tmp);
                    tail.put(tmp, key);
                }
            } else {
                if (head.containsKey(value)) {
                    K tmp = head.get(value);
                    head.remove(value);
                    head.put(key, tmp);
                    tail.put(tmp, key);
                }
            }
        } else {
            head.put(key, value);
            tail.put(value, key);
        }
    }
    public void print() {
        int count = 0;
        long sumBytes = 0;
        long min = 150580533714944L;
        long max = 100000000000000L;
        Set entry =  head.keySet();
        List tmp = new ArrayList();
        for (Object o : entry) {
            tmp.add(o);
        }
        Collections.sort(tmp);
        for (Object o : tmp) {
            count++;
            System.out.println("id: " + count + " key: " + o + " value: " + head.get(o) + " memory: " + ((Long) head.get(o) - (Long)o) / 1024.0 + "KB");
            sumBytes += ((Long) head.get(o) - (Long) o);
            if ((Long)o > 130000000000000L && (Long)o < min) {
                min = (Long) o;
            }
            if ((Long) head.get(o) > max) {
                max = (Long) head.get(o);
            }
        }
        System.out.println("Total Memory Read: " + sumBytes / 1024.0 + "KB");
        System.out.println("Read from " + max + " to " + min);
        System.out.println("Memory Read: " + (max - min) / 1024.0 + "KB");
    }

    public void clear() {
        head.clear();
        tail.clear();
    }
}
