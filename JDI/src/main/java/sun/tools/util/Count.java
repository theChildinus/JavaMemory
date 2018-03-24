package sun.tools.util;

public class Count {
    public Count(String name){
        this.name = name;
        this.times = 0;
    }
    private String name;
    private int times;
    public synchronized void add(){
        this.times++;
    }
    public synchronized void minus() {
        this.times--;
    }
    public synchronized String toString() {
        return name + ":" + times;
    }
}
