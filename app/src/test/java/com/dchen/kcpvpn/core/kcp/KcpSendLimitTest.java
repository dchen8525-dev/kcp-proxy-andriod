package com.dchen.kcpvpn.core.kcp;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * ikcp_send 的分片数上限：frg 在线上只有 1 字节，count >= 255 必须拒绝——
 * 旧实现用 rcv_wnd(512) 当上限，count ∈ [255,512) 的消息会以截断的 frg 编码
 * 上线，对端重组错乱（与 ikcp.c 的 count >= 255 检查对齐）。
 */
public class KcpSendLimitTest {

    @Test
    public void fragmentCountAt255IsRejected() {
        Kcp kcp = new Kcp(1);
        kcp.setMtu(KcpConfig.KCP_MTU);
        int mss = kcp.getMss();
        byte[] big = new byte[255 * mss];   // count = 255 → 拒绝
        assertEquals(-2, kcp.send(big));
    }

    @Test
    public void fragmentCountUnder255IsAccepted() {
        Kcp kcp = new Kcp(1);
        kcp.setMtu(KcpConfig.KCP_MTU);
        int mss = kcp.getMss();
        byte[] big = new byte[254 * mss];   // count = 254 → 全部入队
        assertEquals(big.length, kcp.send(big));
        assertEquals(254, kcp.waitSend());
    }
}
