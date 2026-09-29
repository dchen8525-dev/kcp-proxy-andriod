package com.dchen.kcpvpn.core.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 2048 位滑动窗口重放防护：check() 必须是纯读，只有 commit()（AEAD 校验通过后）才改变状态。
 */
public class ReplayWindowTest {

    @Test
    public void freshWindowAcceptsAnyCounter() {
        ReplayWindow window = new ReplayWindow();
        assertFalse(window.hasReceivedAny());
        assertTrue(window.check(0));
        assertTrue(window.check(Long.MAX_VALUE));
        assertFalse(window.hasReceivedAny());
    }

    @Test
    public void checkDoesNotCommit() {
        ReplayWindow window = new ReplayWindow();
        assertTrue(window.check(42));
        assertTrue(window.check(42));
        window.commit(42);
        assertFalse(window.check(42));
        assertEquals(42, window.getHighestReceived());
    }

    @Test
    public void duplicateAndHighestAreRejected() {
        ReplayWindow window = new ReplayWindow();
        window.commit(10);
        assertFalse(window.check(10));
        window.commit(20);
        assertFalse(window.check(20));
        assertTrue(window.check(21));
        assertEquals(20, window.getHighestReceived());
    }

    @Test
    public void gapExactlyWindowWideIsAcceptedAndBeyondIsRejected() {
        ReplayWindow window = new ReplayWindow();
        window.commit(10_000);
        assertTrue(window.check(10_000 - CryptoConfig.REPLAY_WINDOW_BITS));
        assertFalse(window.check(10_000 - CryptoConfig.REPLAY_WINDOW_BITS - 1));
    }

    @Test
    public void outOfOrderWithinWindowIsAcceptedAndThenRejected() {
        ReplayWindow window = new ReplayWindow();
        window.commit(100);
        assertTrue(window.check(90));
        window.commit(90);
        assertFalse(window.check(90));
        assertTrue(window.check(91));
        assertTrue(window.check(99));
    }

    @Test
    public void slidingKeepsPreviouslyRecordedGaps() {
        ReplayWindow window = new ReplayWindow();
        window.commit(100);
        window.commit(90);
        window.commit(110);
        // 90 与窗口顶点 110 的偏移为 20，仍在窗口内且已记录
        assertFalse(window.check(90));
        assertFalse(window.check(100));
        assertTrue(window.check(105));
        assertEquals(110, window.getHighestReceived());
    }

    @Test
    public void hugeJumpClearsWindowInsteadOfOverflowing() {
        ReplayWindow window = new ReplayWindow();
        for (long i = 1; i <= 50; i++) {
            window.commit(i);
        }
        window.commit(100_000);
        // 大跳跃之后窗口整体清空：窗口外的旧计数器一律视为过期
        assertFalse(window.check(50));
        assertFalse(window.check(100_000 - CryptoConfig.REPLAY_WINDOW_BITS - 1));
        assertTrue(window.check(100_000 - CryptoConfig.REPLAY_WINDOW_BITS));
        assertTrue(window.check(100_001));
    }

    @Test
    public void windowSizeMatchesCppConstant() {
        assertEquals(2048, CryptoConfig.REPLAY_WINDOW_BITS);
    }

    @Test
    public void countersWithHighBitSetAreComparedUnsigned() {
        // counter 直接取自报文 nonce 的 8 字节大端字段，任意 64 位值都可能出现
        // （C++ 侧类型是 uint64_t），所以比较必须按无符号语义。
        ReplayWindow window = new ReplayWindow();
        window.commit(1);
        // 无符号 2^63 大于 1，应视为更新的计数器而接受，而不是当成负数/过期值
        assertTrue(window.check(Long.MIN_VALUE));
        window.commit(Long.MIN_VALUE);
        assertEquals(Long.MIN_VALUE, window.getHighestReceived());
        // 1 此时落后 2^63-1，远超窗口
        assertFalse(window.check(1));
    }

    @Test
    public void farBehindUnsignedCounterIsRejected() {
        ReplayWindow window = new ReplayWindow();
        window.commit(Long.MIN_VALUE);              // 无符号 2^63
        assertFalse(window.check(0));               // 落后 2^63，窗口外
        assertTrue(window.check(Long.MAX_VALUE));   // 落后 1，窗口内且未记录
    }

    @Test
    public void largeUnsignedGapDoesNotProduceNegativeBitIndex() {
        // 回归：最高值 2^62、counter 无符号 2^64-2^62 时，有符号减法
        // highest-counter 溢出成 Long.MIN_VALUE，通过 offset > WINDOW_BITS 判断，
        // 而 (int)(offset-1) == -1，BitSet.get(-1) 抛 IndexOutOfBoundsException。
        // 无符号比较下 counter 更大，直接放行。
        ReplayWindow window = new ReplayWindow();
        window.commit(1L << 62);
        long counter = -(1L << 62);                 // 无符号 2^64 - 2^62
        assertTrue(window.check(counter));
        window.commit(counter);
        assertEquals(counter, window.getHighestReceived());
    }
}
