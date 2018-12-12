package sun.tools.util;

import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class MyLog {
    private static Logger logger = null;
    private static FileHandler fileHandler = null;
    private static volatile MyLog instance = null;

    private MyLog() {
        System.setProperty("java.util.logging.SimpleFormatter.format",
                "%1$tF %1$tT %4$s %2$s %5$s%6$s%n");
        try {
            logger = Logger.getLogger("JDI");
            fileHandler = new FileHandler("log.txt", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static MyLog getInstance() {
        if (instance == null) {
            synchronized (MyLog.class) {
                if (instance == null) {
                    instance = new MyLog();
                }
            }
        }
        return instance;
    }

    public static Logger getLogger() {
        return logger;
    }
}