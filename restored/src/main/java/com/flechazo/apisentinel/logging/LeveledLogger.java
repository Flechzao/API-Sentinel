package com.flechazo.apisentinel.logging;

import burp.api.montoya.logging.Logging;

/**
 * 分级日志器——DEBUG/INFO/WARN/ERROR 四级，适配 Burp 的 Logging 接口。
 */
public class LeveledLogger {

    public enum Level { DEBUG, INFO, WARN, ERROR }

    private volatile Level currentLevel;
    private final Logging logging;

    public LeveledLogger(Logging logging, Level level) {
        this.logging = logging;
        this.currentLevel = level;
    }

    public LeveledLogger(Logging logging) {
        this(logging, Level.INFO);
    }

    public void setLevel(Level level) {
        this.currentLevel = level;
    }

    public Level getLevel() {
        return currentLevel;
    }

    public void debug(String msg) {
        if (currentLevel.ordinal() <= Level.DEBUG.ordinal()) {
            safeLogOutput("[DEBUG] " + msg);
        }
    }

    public void debug(String format, Object... args) {
        if (currentLevel.ordinal() <= Level.DEBUG.ordinal()) {
            safeLogOutput("[DEBUG] " + String.format(format, args));
        }
    }

    public void info(String msg) {
        if (currentLevel.ordinal() <= Level.INFO.ordinal()) {
            safeLogOutput("[INFO] " + msg);
        }
    }

    public void info(String format, Object... args) {
        if (currentLevel.ordinal() <= Level.INFO.ordinal()) {
            safeLogOutput("[INFO] " + String.format(format, args));
        }
    }

    public void warn(String msg) {
        if (currentLevel.ordinal() <= Level.WARN.ordinal()) {
            safeLogOutput("[WARN] " + msg);
        }
    }

    public void warn(String format, Object... args) {
        if (currentLevel.ordinal() <= Level.WARN.ordinal()) {
            safeLogOutput("[WARN] " + String.format(format, args));
        }
    }

    public void error(String msg) {
        safeLogError("[ERROR] " + msg);
    }

    public void error(String msg, Throwable t) {
        safeLogError("[ERROR] " + msg + ": " + t.getMessage());
    }

    public void error(String format, Object... args) {
        safeLogError("[ERROR] " + String.format(format, args));
    }

    private void safeLogOutput(String message) {
        try {
            logging.logToOutput(message);
        } catch (Exception e) {
            System.out.println("[API-Sentinel] " + message);
        }
    }

    private void safeLogError(String message) {
        try {
            logging.logToError(message);
        } catch (Exception e) {
            System.err.println("[API-Sentinel] " + message);
        }
    }
}
