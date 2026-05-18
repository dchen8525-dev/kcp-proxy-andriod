package com.example.kcpvpn.log;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 日志条目结构
 */
public class LogEntry {
    private final long timestamp;
    private final LogLevel level;
    private final String module;
    private final String message;

    private static final String DATE_FORMAT_PATTERN = "yyyy-MM-dd HH:mm:ss.SSS";

    public LogEntry(LogLevel level, String module, String message) {
        this.timestamp = System.currentTimeMillis();
        this.level = level;
        this.module = module;
        this.message = message;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public LogLevel getLevel() {
        return level;
    }

    public String getModule() {
        return module;
    }

    public String getMessage() {
        return message;
    }

    private static String formatTimestamp(long ts) {
        return new SimpleDateFormat(DATE_FORMAT_PATTERN, Locale.getDefault()).format(new Date(ts));
    }

    /**
     * 格式化为字符串
     */
    public String format() {
        String timeStr = formatTimestamp(timestamp);
        return String.format(LogConfig.FORMAT, timeStr, level.getName(), module, message);
    }

    /**
     * 获取简短显示格式（用于 UI）
     */
    public String formatShort() {
        String timeStr = formatTimestamp(timestamp);
        return timeStr + " [" + level.getName() + "] " + message;
    }
}