package sun.tools.jdi;

public class Test {
    public void test(LongTest longTest) {
        long a = longTest.getLong();
        System.out.println(a);
        long tmp = a;
        for (int i = 0; i < 8; i++) {
            byte b = (byte) (a & 255);
            a >>= 8;
            System.out.print(b + " ");
        }
        System.out.println();
        a = tmp;
        for (int i = 0; i < 8; i++) {
            byte b = (byte) (a & 255);
            a >>>= 8;
            System.out.print(b + " ");
        }
        System.out.println();
        for (long b : longTest.getLongs()) {
            System.out.print(b + " ");
        }
        System.out.println();
    }
}
