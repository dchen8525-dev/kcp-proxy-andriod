package com.example.kcpvpn.log;

import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 日志文件写入器 - 循环存储
 */
public class LogWriter {

    private final Context context;
    private final AtomicLong currentFileSize;
    private final AtomicInteger currentFileIndex;
    private FileOutputStream currentOutputStream;

    private volatile boolean writing;

    public LogWriter(Context context) {
        this.context = context;
        this.currentFileSize = new AtomicLong(0);
        this.currentFileIndex = new AtomicInteger(1);
        this.writing = false;

        initFile();
    }

    /**
     * 初始化日志文件
     */
    private void initFile() {
        try {
            File logDir = context.getExternalFilesDir(null);
            if (logDir == null) {
                logDir = context.getFilesDir();
            }

            File logFile = new File(logDir, LogConfig.LOG_FILE_1);
            if (!logFile.exists()) {
                logFile.createNewFile();
            }

            currentFileSize.set(logFile.length());
            currentOutputStream = new FileOutputStream(logFile, true);
            writing = true;

        } catch (IOException e) {
            // 忽略初始化错误
        }
    }

    /**
     * 写入日志
     */
    public synchronized void write(LogEntry entry) {
        if (!writing || currentOutputStream == null) {
            return;
        }

        try {
            String line = entry.format() + "\n";
            byte[] data = line.getBytes(StandardCharsets.UTF_8);

            // 检查文件大小
            if (currentFileSize.get() + data.length > LogConfig.MAX_FILE_SIZE) {
                switchFile();
            }

            currentOutputStream.write(data);
            currentOutputStream.flush();
            currentFileSize.addAndGet(data.length);

        } catch (IOException e) {
            // 忽略写入错误
        }
    }

    /**
     * 切换日志文件
     */
    private void switchFile() {
        try {
            if (currentOutputStream != null) {
                currentOutputStream.close();
            }

            // 切换到另一个文件
            int nextIndex = (currentFileIndex.get() == 1) ? 2 : 1;
            String nextFileName = (nextIndex == 1) ? LogConfig.LOG_FILE_1 : LogConfig.LOG_FILE_2;

            File logDir = context.getExternalFilesDir(null);
            if (logDir == null) {
                logDir = context.getFilesDir();
            }

            File nextFile = new File(logDir, nextFileName);

            // 清空目标文件
            if (nextFile.exists()) {
                nextFile.delete();
            }
            nextFile.createNewFile();

            currentOutputStream = new FileOutputStream(nextFile, false);
            currentFileSize.set(0);
            currentFileIndex.set(nextIndex);

        } catch (IOException e) {
            // 忽略切换错误
        }
    }

    /**
     * 清空所有日志文件
     */
    public synchronized void clear() {
        try {
            if (currentOutputStream != null) {
                currentOutputStream.close();
                currentOutputStream = null;
            }

            File logDir = context.getExternalFilesDir(null);
            if (logDir == null) {
                logDir = context.getFilesDir();
            }

            File file1 = new File(logDir, LogConfig.LOG_FILE_1);
            File file2 = new File(logDir, LogConfig.LOG_FILE_2);

            if (file1.exists()) {
                file1.delete();
                file1.createNewFile();
            }
            if (file2.exists()) {
                file2.delete();
            }

            // 重新打开文件1
            currentOutputStream = new FileOutputStream(file1, false);
            currentFileSize.set(0);
            currentFileIndex.set(1);

        } catch (IOException e) {
            // 忽略清空错误
        }
    }

    /**
     * 关闭写入器
     */
    public synchronized void close() {
        writing = false;
        try {
            if (currentOutputStream != null) {
                currentOutputStream.close();
                currentOutputStream = null;
            }
        } catch (IOException e) {
            // 忽略关闭错误
        }
    }

    /**
     * 获取日志目录路径
     */
    public String getLogDirectory() {
        File logDir = context.getExternalFilesDir(null);
        if (logDir == null) {
            logDir = context.getFilesDir();
        }
        return logDir.getAbsolutePath();
    }
}