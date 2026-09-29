package com.dchen.kcpvpn.vpn.cppremote;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.dchen.kcpvpn.core.crypto.CryptoConfig;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * 控制消息编码/识别：magic || session_salt，必须长度与内容精确匹配，
 * 真实隧道数据不得被误判为控制消息（否则会被静默丢弃）。
 */
public class CppControlMessageTest {

    private static final byte[] SALT = new byte[CryptoConfig.SESSION_SALT_SIZE];

    static {
        for (int i = 0; i < SALT.length; i++) {
            SALT[i] = (byte) (i + 1);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    public void controlPayloadAppendsSessionSalt() {
        byte[] payload = CppRemoteKcpSession.controlPayload(CryptoConfig.CONTROL_KEEPALIVE, SALT);
        byte[] expected = new byte[ascii(CryptoConfig.CONTROL_KEEPALIVE).length + SALT.length];
        System.arraycopy(ascii(CryptoConfig.CONTROL_KEEPALIVE), 0, expected, 0,
                ascii(CryptoConfig.CONTROL_KEEPALIVE).length);
        System.arraycopy(SALT, 0, expected, ascii(CryptoConfig.CONTROL_KEEPALIVE).length, SALT.length);
        assertArrayEquals(expected, payload);
        assertEquals(CryptoConfig.CONTROL_KEEPALIVE.length() + CryptoConfig.SESSION_SALT_SIZE,
                payload.length);
    }

    @Test
    public void exactControlMessageIsRecognised() {
        byte[] keepalive = CppRemoteKcpSession.controlPayload(CryptoConfig.CONTROL_KEEPALIVE, SALT);
        byte[] fin = CppRemoteKcpSession.controlPayload(CryptoConfig.CONTROL_FIN, SALT);

        assertTrue(CppRemoteKcpSession.isControlMessage(keepalive,
                CryptoConfig.CONTROL_KEEPALIVE, SALT));
        assertTrue(CppRemoteKcpSession.isControlMessage(fin, CryptoConfig.CONTROL_FIN, SALT));
        assertFalse(CppRemoteKcpSession.isControlMessage(keepalive, CryptoConfig.CONTROL_FIN, SALT));
    }

    @Test
    public void otherSessionSaltIsNotAControlMessage() {
        byte[] keepalive = CppRemoteKcpSession.controlPayload(CryptoConfig.CONTROL_KEEPALIVE, SALT);
        byte[] otherSalt = SALT.clone();
        otherSalt[otherSalt.length - 1] ^= 0x01;
        assertFalse(CppRemoteKcpSession.isControlMessage(keepalive,
                CryptoConfig.CONTROL_KEEPALIVE, otherSalt));
    }

    @Test
    public void tunnelDataStartingWithTheMagicIsForwardedNotDropped() {
        // 真实载荷恰好以 keepalive 开头但更长：绝不能被识别为控制消息
        byte[] longer = new byte[ascii(CryptoConfig.CONTROL_KEEPALIVE).length + SALT.length + 1];
        System.arraycopy(CppRemoteKcpSession.controlPayload(CryptoConfig.CONTROL_KEEPALIVE, SALT),
                0, longer, 0, longer.length - 1);
        longer[longer.length - 1] = 'x';
        assertFalse(CppRemoteKcpSession.isControlMessage(longer,
                CryptoConfig.CONTROL_KEEPALIVE, SALT));

        byte[] bareMagic = ascii(CryptoConfig.CONTROL_KEEPALIVE);
        assertFalse(CppRemoteKcpSession.isControlMessage(bareMagic,
                CryptoConfig.CONTROL_KEEPALIVE, SALT));
    }

    @Test
    public void handshakeAckIsMatchedWithoutSalt() {
        assertTrue(CppRemoteKcpSession.isExactMessage(ascii(CryptoConfig.CONTROL_HELLO_ACK_V2),
                CryptoConfig.CONTROL_HELLO_ACK_V2));
        assertFalse(CppRemoteKcpSession.isExactMessage(ascii(CryptoConfig.CONTROL_HELLO_ACK),
                CryptoConfig.CONTROL_HELLO_ACK_V2));
        assertFalse(CppRemoteKcpSession.isExactMessage(
                new byte[ascii(CryptoConfig.CONTROL_HELLO_ACK_V2).length + 1],
                CryptoConfig.CONTROL_HELLO_ACK_V2));
    }

    @Test
    public void magicsMatchCppServerConstants() {
        assertEquals("KCP_PROXY_HELLO_V2", CryptoConfig.CONTROL_HELLO_V2);
        assertEquals("KCP_PROXY_HELLO_ACK_V2", CryptoConfig.CONTROL_HELLO_ACK_V2);
        assertEquals("KCP_PROXY_FIN_V1", CryptoConfig.CONTROL_FIN);
        assertEquals("KCP_PROXY_KEEPALIVE_V1", CryptoConfig.CONTROL_KEEPALIVE);
        assertEquals(30, CryptoConfig.KEEPALIVE_INTERVAL_SEC);
    }
}
