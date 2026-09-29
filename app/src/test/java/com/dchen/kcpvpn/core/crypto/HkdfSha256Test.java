package com.dchen.kcpvpn.core.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * HKDF-SHA256 对照测试：期望值由独立实现（Node.js crypto.hkdfSync、RFC 5869 官方向量）生成，
 * 证明安卓端的密钥派生与 C++ 端 EVP_PKEY HKDF 一致。
 */
public class HkdfSha256Test {

    private static final byte[] PSK = "test-psk-0123456789".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SESSION_SALT = hex("00112233445566778899aabbccddeeff");
    private static final byte[] HKDF_SALT = concat(
            CryptoConfig.APP_SALT.getBytes(StandardCharsets.UTF_8), SESSION_SALT);

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    public void matchesRfc5869TestCase1() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] okm = HkdfSha256.derive(ikm,
                hex("000102030405060708090a0b0c"),
                hex("f0f1f2f3f4f5f6f7f8f9"), 42);
        // 42 字节输出会走两轮 expand，同时覆盖跨块拼接
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                hex(okm));
    }

    @Test
    public void derivesProjectSessionKeys() {
        assertArrayEquals(hex("4b3c1444412811060e1410fb2f502da0"),
                HkdfSha256.derive(PSK, HKDF_SALT,
                        CryptoConfig.INFO_C2S.getBytes(StandardCharsets.UTF_8),
                        CryptoConfig.AES_KEY_SIZE));
        assertArrayEquals(hex("d27c44e7312912fdcb89d5f8def608a6"),
                HkdfSha256.derive(PSK, HKDF_SALT,
                        CryptoConfig.INFO_S2C.getBytes(StandardCharsets.UTF_8),
                        CryptoConfig.AES_KEY_SIZE));
    }

    @Test
    public void nullSaltBehavesLikeZeroSalt() {
        assertEquals("ab4ad4cef2f62499b537cdb123b2ed81",
                hex(HkdfSha256.derive(PSK, null,
                        CryptoConfig.INFO_C2S.getBytes(StandardCharsets.UTF_8),
                        CryptoConfig.AES_KEY_SIZE)));
    }

    @Test
    public void differentSessionSaltYieldsDifferentKeys() {
        byte[] info = CryptoConfig.INFO_C2S.getBytes(StandardCharsets.UTF_8);
        byte[] zero = HkdfSha256.derive(PSK, concat(
                CryptoConfig.APP_SALT.getBytes(StandardCharsets.UTF_8),
                new byte[CryptoConfig.SESSION_SALT_SIZE]), info, CryptoConfig.AES_KEY_SIZE);
        byte[] derived = HkdfSha256.derive(PSK, HKDF_SALT, info, CryptoConfig.AES_KEY_SIZE);
        assertEquals(CryptoConfig.AES_KEY_SIZE, derived.length);
        assertFalse(Arrays.equals(zero, derived));
    }
}
