package com.dchen.kcpvpn.core.crypto;

import java.util.BitSet;

/**
 * 重放攻击防护 - 与 C++ crypto.cpp check_replay_window/commit_replay_window 一致的
 * 2048 位滑动窗口。check() 为纯读，commit() 必须在 AEAD 标签校验通过后调用，
 * 防止伪造的高计数器包永久污染窗口。
 */
public class ReplayWindow {

    private static final int WINDOW_BITS = CryptoConfig.REPLAY_WINDOW_BITS;

    private long highestReceived;
    private final BitSet window;
    private boolean anyReceived;

    public ReplayWindow() {
        this.highestReceived = 0;
        this.window = new BitSet(WINDOW_BITS);
        this.anyReceived = false;
    }

    /**
     * 纯读检查：counter 是否可接受（未重放、未过期）。不修改任何状态。
     */
    public synchronized boolean check(long counter) {
        if (!anyReceived) {
            return true;
        }
        if (counter > highestReceived) {
            return true;
        }
        if (counter == highestReceived) {
            return false;
        }
        long offset = highestReceived - counter;
        if (offset > WINDOW_BITS) {
            return false;
        }
        return !window.get((int) (offset - 1));
    }

    /**
     * 记录 counter 已接收。只允许在包通过 AEAD 认证后调用。
     * bit i 对应计数器 (highest - i - 1)。
     */
    public synchronized void commit(long counter) {
        if (!anyReceived) {
            anyReceived = true;
            highestReceived = counter;
            window.clear();
            return;
        }
        if (counter > highestReceived) {
            long shift = counter - highestReceived;
            if (shift > WINDOW_BITS) {
                window.clear();
            } else {
                slideLeft((int) shift);
                window.set((int) (shift - 1));
            }
            highestReceived = counter;
            return;
        }
        if (counter < highestReceived) {
            long offset = highestReceived - counter;
            if (offset <= WINDOW_BITS) {
                window.set((int) (offset - 1));
            }
        }
    }

    /**
     * 窗口整体左移 shift 位（旧 bit i 移到 i+shift，超出窗口的丢弃）。
     */
    private void slideLeft(int shift) {
        BitSet snapshot = window.get(0, WINDOW_BITS);
        window.clear();
        for (int j = snapshot.nextSetBit(0); j >= 0; j = snapshot.nextSetBit(j + 1)) {
            int target = j + shift;
            if (target < WINDOW_BITS) {
                window.set(target);
            }
        }
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
