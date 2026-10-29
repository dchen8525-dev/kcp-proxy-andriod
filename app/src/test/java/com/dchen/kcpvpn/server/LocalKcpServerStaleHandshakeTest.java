package com.dchen.kcpvpn.server;

import static org.junit.Assert.assertEquals;

import com.dchen.kcpvpn.core.crypto.Crypto;
import com.dchen.kcpvpn.core.protocol.KcpFrame;
import com.dchen.kcpvpn.core.protocol.KcpFrameCodec;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.junit.Test;

/**
 * C++ 0.3.1 e3eff1d 场景的 Java 移植回归：陈旧握手重传不得驱逐活会话。
 *
 * <p>C++ 侧的缺陷是"先驱逐后查墓碑"：旧隧道首包的重传把活会话从端点上拆掉，
 * 自己又被墓碑拒绝，端点既无会话、重传包也永远进不来，隧道瘫到 600s TTL 过期。
 * Java 版 LocalKcpServer 的顺序是"候选会话通过全部关卡之后才驱逐"，本测试把它
 * 钉死：重传被拒后，活会话必须原样存活（会话数保持 1；缺陷行为下会是 0）。
 */
public class LocalKcpServerStaleHandshakeTest {

    private static final String PSK = "unit-test-psk-0123456789";

    @Test
    public void staleHandshakeRetransmitKeepsLiveSession() throws Exception {
        LocalKcpServer server = new LocalKcpServer(0, PSK);
        try {
            InetSocketAddress endpoint = new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), 51000);
            byte[] handshake = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_HELLO, 0, null));

            // 旧隧道：首包被接受，其 salt 进入墓碑
            Crypto oldTunnel = new Crypto(PSK);
            byte[] oldHandshake = oldTunnel.encrypt(handshake);
            server.handleReceive(endpoint, oldHandshake);
            assertEquals(1, server.getSessionCount());

            // 新隧道复用同一端点：fresh salt，按"重连替换"接管端点
            Crypto liveTunnel = new Crypto(PSK);
            server.handleReceive(endpoint, liveTunnel.encrypt(handshake));
            assertEquals(1, server.getSessionCount());

            // 旧隧道的陈旧握手重传（原字节重放）：其 salt 已在墓碑里，必须被拒，
            // 且不得动活会话——e3eff1d 的缺陷行为会在这里把端点清空成 0 个会话
            server.handleReceive(endpoint, oldHandshake);
            assertEquals(1, server.getSessionCount());
        } finally {
            server.stop();
        }
    }

    @Test
    public void unauthenticatedForeignSaltKeepsLiveSession() throws Exception {
        LocalKcpServer server = new LocalKcpServer(0, PSK);
        try {
            InetSocketAddress endpoint = new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), 51001);
            byte[] handshake = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_HELLO, 0, null));

            Crypto liveTunnel = new Crypto(PSK);
            server.handleReceive(endpoint, liveTunnel.encrypt(handshake));
            assertEquals(1, server.getSessionCount());

            // 错误 PSK 的伪包：salt 与活会话不同，认证必须失败，活会话原样存活
            Crypto attacker = new Crypto("wrong-psk-0123456789abcdef");
            server.handleReceive(endpoint, attacker.encrypt(handshake));
            assertEquals(1, server.getSessionCount());
        } finally {
            server.stop();
        }
    }
}
