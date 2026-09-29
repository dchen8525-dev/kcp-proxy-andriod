package com.dchen.kcpvpn.vpn.cppremote;

import com.dchen.kcpvpn.core.kcp.KcpConfig;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * 出站背压判据：KCP 发送队列到阈值就排队，且阈值必须给整条消息的分片留出空间，
 * 否则 ikcp_send 之前就会先把内存吃光。
 */
public class CppBackpressureTest {

    @Test
    public void thresholdLeavesRoomForOneWholeMessage() {
        assertTrue(KcpConfig.KCP_BACKPRESSURE_THRESHOLD > 0);
        assertTrue("阈值 + 单条消息分片数必须小于发送窗口",
                KcpConfig.KCP_BACKPRESSURE_THRESHOLD + KcpConfig.KCP_MAX_SEGMENTS_PER_MSG
                        < KcpConfig.KCP_SNDWND);
    }

    @Test
    public void capacityFlipsExactlyAtThreshold() {
        int threshold = KcpConfig.KCP_BACKPRESSURE_THRESHOLD;
        assertTrue(CppRemoteKcpSession.hasSendCapacity(0));
        assertTrue(CppRemoteKcpSession.hasSendCapacity(threshold - 1));
        assertFalse(CppRemoteKcpSession.hasSendCapacity(threshold));
        assertFalse(CppRemoteKcpSession.hasSendCapacity(KcpConfig.KCP_SNDWND * 4));
    }
}
