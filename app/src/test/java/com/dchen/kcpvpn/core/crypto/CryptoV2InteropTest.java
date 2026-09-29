package com.dchen.kcpvpn.core.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * V2 线格式对照测试。期望报文由独立实现（Node.js OpenSSL AES-128-GCM + HKDF）按
 * kcp-proxy-cpp 的规则生成：salt(16) || nonce(8 字节计数器 + 方向 + 3 零) || ciphertext || tag(16)，
 * 计数器起点 = session_salt 前 6 字节大端。安卓端任何一处偏离都会在此暴露。
 */
public class CryptoV2InteropTest {

    private static final String PSK = "test-psk-0123456789";
    private static final byte[] SALT = HkdfSha256Test.hex("00112233445566778899aabbccddeeff");
    private static final long START_COUNTER = 73588229205L;  // 0x001122334455

    private static final byte[] C2S_FIRST = HkdfSha256Test.hex(
            "00112233445566778899aabbccddeeff"
                    + "000000112233445501000000"
                    + "73916e454c9412c88fac2f2a32f31302a38f65ebfd");
    private static final byte[] C2S_SECOND = HkdfSha256Test.hex(
            "00112233445566778899aabbccddeeff"
                    + "000000112233445601000000"
                    + "5ce7ee101ab38542612c65421fe7c6732272b7a233");
    private static final byte[] S2C_FIRST = HkdfSha256Test.hex(
            "00112233445566778899aabbccddeeff"
                    + "000000112233445502000000"
                    + "c321bf0152d74c733ea6985b05fbeac2b9820de489");

    private static Crypto client() {
        return new Crypto(PSK, CryptoConfig.NONCE_DIR_CLIENT, SALT);
    }

    private static Crypto server() {
        return new Crypto(PSK, CryptoConfig.NONCE_DIR_SERVER, SALT);
    }

    @Test
    public void clientEncryptMatchesCrossImplementationVector() throws Exception {
        Crypto crypto = client();
        assertArrayEquals(C2S_FIRST, crypto.encrypt("hello".getBytes(StandardCharsets.UTF_8)));
        assertArrayEquals(C2S_SECOND, crypto.encrypt("world".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void wireFormatIsSaltNonceCiphertextTag() {
        byte[] packet = client().encrypt("hello".getBytes(StandardCharsets.UTF_8));
        assertEquals(CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE
                + "hello".length() + CryptoConfig.TAG_SIZE, packet.length);
        assertArrayEquals(SALT, Arrays.copyOfRange(packet, 0, CryptoConfig.SESSION_SALT_SIZE));

        byte[] nonce = Arrays.copyOfRange(packet, CryptoConfig.SESSION_SALT_SIZE,
                CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE);
        assertEquals(START_COUNTER, NonceGenerator.parseCounter(nonce));
        assertEquals(CryptoConfig.NONCE_DIR_CLIENT, NonceGenerator.parseDirection(nonce));
    }

    @Test
    public void serverEncryptUsesS2cKeyAndDirectionByte() throws Exception {
        byte[] packet = server().encrypt("reply".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(S2C_FIRST, packet);
        assertArrayEquals("reply".getBytes(StandardCharsets.UTF_8), client().decrypt(packet));
    }

    @Test
    public void ownDirectionPacketIsRejectedByDirectionByte() throws Exception {
        // 自发包的方向字节是 CLIENT，对端方向要求 SERVER：控制/回声包不会混成流数据
        Crypto crypto = client();
        byte[] own = crypto.encrypt("hello".getBytes(StandardCharsets.UTF_8));
        try {
            crypto.decrypt(own);
            fail("own-direction packet must not decrypt as peer traffic");
        } catch (Exception e) {
            assertTrue(e.getClass() + ": " + e.getMessage(), e.getMessage().contains("direction"));
        }
    }

    @Test
    public void serverLazilyDerivesFromFirstDatagramAndRoundTrips() throws Exception {
        Crypto clientCrypto = new Crypto(PSK);
        Crypto serverCrypto = Crypto.createServerCrypto(PSK);

        byte[] first = clientCrypto.encrypt("hello".getBytes(StandardCharsets.UTF_8));
        assertFalse(serverCrypto.matchesSalt(first));
        assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), serverCrypto.decrypt(first));
        assertTrue(serverCrypto.matchesSalt(first));

        byte[] ack = serverCrypto.encrypt("ok".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("ok".getBytes(StandardCharsets.UTF_8), clientCrypto.decrypt(ack));

        byte[] second = clientCrypto.encrypt("more".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("more".getBytes(StandardCharsets.UTF_8), serverCrypto.decrypt(second));
    }

    @Test
    public void eachClientSessionUsesAFreshRandomSalt() throws Exception {
        Crypto a = new Crypto(PSK);
        Crypto b = new Crypto(PSK);
        assertFalse(Arrays.equals(a.sessionSalt(), b.sessionSalt()));

        Crypto serverCrypto = Crypto.createServerCrypto(PSK);
        serverCrypto.decrypt(a.encrypt("x".getBytes(StandardCharsets.UTF_8)));
        try {
            serverCrypto.decrypt(b.encrypt("x".getBytes(StandardCharsets.UTF_8)));
            fail("cross-session injection must be rejected");
        } catch (Crypto.ReplayRejectedException e) {
            fail("salt mismatch must not surface as replay rejection");
        } catch (Exception e) {
            assertTrue(e.getMessage() + "", e.getMessage().contains("salt mismatch"));
        }
    }

    @Test
    public void duplicatePacketIsRejectedAsReplayNotAsTagFailure() throws Exception {
        Crypto clientCrypto = new Crypto(PSK);
        Crypto serverCrypto = Crypto.createServerCrypto(PSK);
        byte[] packet = clientCrypto.encrypt("hello".getBytes(StandardCharsets.UTF_8));

        serverCrypto.decrypt(packet);
        try {
            serverCrypto.decrypt(packet);
            fail("replayed packet must be rejected");
        } catch (Crypto.ReplayRejectedException expected) {
            assertTrue(expected.getMessage().contains("replay"));
        }
    }

    @Test
    public void outOfOrderPacketsWithinWindowAreAccepted() throws Exception {
        Crypto clientCrypto = new Crypto(PSK);
        Crypto serverCrypto = Crypto.createServerCrypto(PSK);
        byte[] p1 = clientCrypto.encrypt("1".getBytes(StandardCharsets.UTF_8));
        byte[] p2 = clientCrypto.encrypt("2".getBytes(StandardCharsets.UTF_8));
        byte[] p3 = clientCrypto.encrypt("3".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("3".getBytes(StandardCharsets.UTF_8), serverCrypto.decrypt(p3));
        assertArrayEquals("1".getBytes(StandardCharsets.UTF_8), serverCrypto.decrypt(p1));
        assertArrayEquals("2".getBytes(StandardCharsets.UTF_8), serverCrypto.decrypt(p2));
    }

    @Test
    public void forgedHighCounterDoesNotPoisonTheWindowBecauseCommitHappensAfterAuth()
            throws Exception {
        Crypto clientCrypto = new Crypto(PSK);
        Crypto serverCrypto = Crypto.createServerCrypto(PSK);
        byte[] good = clientCrypto.encrypt("hello".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), serverCrypto.decrypt(good));

        // 伪造包：salt 正确（能过派生），但计数器被推高且密文/标签是垃圾
        byte[] forged = good.clone();
        ByteBuffer.wrap(forged, CryptoConfig.SESSION_SALT_SIZE, CryptoConfig.NONCE_SIZE)
                .putLong(NonceGenerator.parseCounter(Arrays.copyOfRange(good,
                        CryptoConfig.SESSION_SALT_SIZE,
                        CryptoConfig.SESSION_SALT_SIZE + 8)) + 100000L);
        for (int i = CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE; i < forged.length; i++) {
            forged[i] ^= 0xFF;
        }
        try {
            serverCrypto.decrypt(forged);
            fail("forged packet must fail authentication");
        } catch (AEADBadTagException expected) {
            assertTrue(expected.getMessage() != null);
        }

        // 若伪造计数器被提交进窗口，这里会因 offset > 2048 被当作过期包丢弃
        byte[] next = clientCrypto.encrypt("next".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("next".getBytes(StandardCharsets.UTF_8), serverCrypto.decrypt(next));
    }

    @Test
    public void tamperedCiphertextIsRejected() throws Exception {
        Crypto clientCrypto = new Crypto(PSK);
        Crypto serverCrypto = Crypto.createServerCrypto(PSK);
        byte[] packet = clientCrypto.encrypt("hello".getBytes(StandardCharsets.UTF_8));
        packet[CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE] ^= 0x01;
        try {
            serverCrypto.decrypt(packet);
            fail("tampered packet must not decrypt");
        } catch (AEADBadTagException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test
    public void shortPacketsAreRejected() {
        Crypto crypto = Crypto.createServerCrypto(PSK);
        try {
            crypto.decrypt(new byte[CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE
                    + CryptoConfig.TAG_SIZE - 1]);
            fail("short packet must be rejected");
        } catch (Exception expected) {
            assertTrue(expected instanceof IllegalArgumentException);
        }
    }

    @Test
    public void sameSaltReproducesTheSameNonceSequence() throws Exception {
        byte[] salt = client().sessionSalt();
        Crypto a = new Crypto(PSK, CryptoConfig.NONCE_DIR_CLIENT, salt);
        Crypto b = new Crypto(PSK, CryptoConfig.NONCE_DIR_CLIENT, salt);
        byte[] first = "x".getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(a.encrypt(first), b.encrypt(first));
        // 同 salt 即同密钥同计数器起点：这正是一次性 salt 的由来，
        // 会话不得复位计数器复用（AES-GCM (key, nonce) 重用会失去机密性）。
        assertFalse(Arrays.equals(a.encrypt(first), a.encrypt(first)));
    }
}
