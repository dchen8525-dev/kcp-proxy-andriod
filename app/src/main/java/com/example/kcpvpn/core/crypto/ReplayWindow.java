package com.example.kcpvpn.core.crypto;

/**
 * 重放攻击防护 - 与 C++ crypto.cpp check_and_update_replay_window 一致
 * 使用64位滑动窗口检测重放包
 */
public class ReplayWindow {

    private static final int WINDOW_SIZE = CryptoConfig.REPLAY_WINDOW_BITS;

    private long highestReceived;
    private long replayWindow;
    private boolean anyReceived;

    public ReplayWindow() {
        this.highestReceived = 0;
        this.replayWindow = 0;
        this.anyReceived = false;
    }

    /**
     * 检查并更新重放窗口
     * @param counter 接收到的计数器值
     * @return true 表示有效（非重放），false 表示无效（重放或过旧）
     */
    public synchronized boolean checkAndUpdate(long counter) {
        if (!anyReceived) {
            // 首次接收
            anyReceived = true;
            highestReceived = counter;
            replayWindow = 0;
            return true;
        }

        if (counter > highestReceived) {
            // 新的最高计数器，滑动窗口
            long shift = counter - highestReceived;
            if (shift >= WINDOW_SIZE) {
                // 窗口完全滑动
                replayWindow = 0;
            } else {
                // 滑动窗口并标记新位置
                replayWindow = (replayWindow << shift) | (1L << (shift - 1));
            }
            highestReceived = counter;
            return true;
        }

        if (counter == highestReceived) {
            // 与最高计数器相同，重放
            return false;
        }

        // 计数器小于最高值，检查是否在窗口内
        long offset = highestReceived - counter;
        if (offset > WINDOW_SIZE) {
            // 太旧，超出窗口范围
            return false;
        }

        // 检查窗口位图
        long bit = 1L << (offset - 1);
        if ((replayWindow & bit) != 0) {
            // 已经接收过，重放
            return false;
        }

        // 标记为已接收
        replayWindow |= bit;
        return true;
    }

    /**
     * 重置重放窗口
     */
    public synchronized void reset() {
        highestReceived = 0;
        replayWindow = 0;
        anyReceived = false;
    }

    /**
     * 获取最高接收计数器
     */
    public synchronized long getHighestReceived() {
        return highestReceived;
    }

    /**
     * 是否已接收过任何包
     */
    public synchronized boolean hasReceivedAny() {
        return anyReceived;
    }
}