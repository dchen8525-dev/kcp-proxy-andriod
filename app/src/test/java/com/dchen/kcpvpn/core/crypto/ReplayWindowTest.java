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
}
