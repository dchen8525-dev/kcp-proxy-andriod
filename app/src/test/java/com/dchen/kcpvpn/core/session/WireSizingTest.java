package com.dchen.kcpvpn.core.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.dchen.kcpvpn.core.kcp.KcpConfig;
import com.dchen.kcpvpn.core.protocol.FecFraming;

import org.junit.Test;

/**
 * 线尺寸与 FEC 帧探测的常量钉（对应 C++ config.hpp 的 static_assert 组）。
 */
public class WireSizingTest {

    /**
     * UDP_WIRE_DATAGRAM_MAX 必须容下整个合法对端 MTU 范围的完整报文：
     * salt(16)+nonce(12) + FEC头(6)+长度(2) + MTU(9000) + tag(16) = 9052。
     * C++ 0.3.2 d5bfa44 修的就是"接收缓冲 4096 截断大 MTU 报文、AEAD 永远
     * 验不过"的缺陷；这里钉死推导式防止有人把字面量改回去。
     */
    @Test
    public void wireDatagramMaxCoversEntireLegalMtuRange() {
        assertEquals(16 + 12 + 8 + KcpConfig.KCP_MTU_MAX + 16,
                SessionConfig.UDP_WIRE_DATAGRAM_MAX);
        assertEquals(9052, SessionConfig.UDP_WIRE_DATAGRAM_MAX);

        // 默认 MTU 的报文必须同时装进通用接收缓冲与单会话接收缓冲
        assertTrue(SessionConfig.UDP_RECV_BUF_SIZE >= SessionConfig.UDP_WIRE_DATAGRAM_MAX);
        assertTrue(SessionConfig.UDP_WIRE_DATAGRAM_MAX
                >= 28 + 8 + KcpConfig.KCP_MTU + 16);
    }

    /**
     * looks_like_fec_frame：FEC type 0xf1..0xf3（明文字节 4..5 小端）判真；
     * 裸 KCP 段的命令字节 0x51..0x54 与之不相交，永远判假——服务端据此对
     * "从不发 FEC 帧的安卓端"保持裸格式会话（C++ config.hpp 的自适应规则）。
     */
    @Test
    public void fecFrameProbeMatchesCppDetection() {
        // FEC 数据/校验/OOB 三种类型的帧头 → 判真
        for (byte fecType : new byte[]{(byte) 0xF1, (byte) 0xF2, (byte) 0xF3}) {
            byte[] frame = new byte[16];
            frame[4] = fecType;
            frame[5] = 0;
            assertTrue(FecFraming.looksLikeFecFrame(frame, frame.length));
        }

        // 裸 KCP 段（cmd=0x51..0x54）→ 判假
        for (byte cmd : new byte[]{(byte) 0x51, (byte) 0x52, (byte) 0x53, (byte) 0x54}) {
            byte[] segment = new byte[16];
            segment[4] = cmd;
            segment[5] = 0;
            assertFalse(FecFraming.looksLikeFecFrame(segment, segment.length));
        }

        // 短报文与 null 安全
        assertFalse(FecFraming.looksLikeFecFrame(new byte[7], 7));
        assertFalse(FecFraming.looksLikeFecFrame(null, 0));
    }
}
