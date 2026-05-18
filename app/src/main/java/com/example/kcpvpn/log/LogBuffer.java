package com.example.kcpvpn.log;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * 日志内存缓冲区 - 环形缓冲区，用于实时显示
 */
public class LogBuffer {

    private final int maxSize;
    private final CopyOnWriteArrayList<LogEntry> entries;
    private final CopyOnWriteArrayList<Consumer<LogEntry>> listeners;

    public LogBuffer() {
        this.maxSize = LogConfig.BUFFER_SIZE;
        this.entries = new CopyOnWriteArrayList<>();
        this.listeners = new CopyOnWriteArrayList<>();
    }

    /**
     * 添加日志条目
     */
    public void add(LogEntry entry) {
        entries.add(entry);

        // 如果超出容量，批量移除最旧的
        if (entries.size() > maxSize) {
            int excess = entries.size() - maxSize;
            for (int i = 0; i < excess; i++) {
                entries.remove(0);
            }
        }

        // 通知监听器
        for (Consumer<LogEntry> listener : listeners) {
            listener.accept(entry);
        }
    }

    /**
     * 获取所有条目
     */
    public List<LogEntry> getAll() {
        return new ArrayList<>(entries);
    }

    /**
     * 获取指定级别的条目
     */
    public List<LogEntry> getByLevel(LogLevel level) {
        List<LogEntry> result = new ArrayList<>();
        for (LogEntry entry : entries) {
            if (entry.getLevel().getValue() >= level.getValue()) {
                result.add(entry);
            }
        }
        return result;
    }

    /**
     * 清空缓冲区
     */
    public void clear() {
        entries.clear();
    }

    /**
     * 获取条目数量
     */
    public int size() {
        return entries.size();
    }

    /**
     * 添加监听器
     */
    public void addListener(Consumer<LogEntry> listener) {
        listeners.add(listener);
    }

    /**
     * 移除监听器
     */
    public void removeListener(Consumer<LogEntry> listener) {
        listeners.remove(listener);
    }
}