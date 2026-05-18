package com.example.kcpvpn.core.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * HKDF-SHA256 密钥派生 - 与 C++ crypto.cpp hkdf_sha256 一致
 * 使用 HMAC-based Extract-and-Expand Key Derivation Function
 */
public class HkdfSha256 {

    private static final int SHA256_DIGEST_LENGTH = 32;

    /**
     * HKDF-SHA256 密钥派生
     * @param ikm 输入密钥材料
     * @param salt 盐值（可为空，使用全零盐值）
     * @param info 上下文信息
     * @param okmLen 输出密钥材料长度
     * @return 派生的密钥
     */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int okmLen) {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("IKM must not be empty");
        }
        if (okmLen > SHA256_DIGEST_LENGTH * 255) {
            throw new IllegalArgumentException("OKM length too large");
        }

        // RFC 5869: 如果盐值为空，使用全零盐值
        if (salt == null || salt.length == 0) {
            salt = new byte[SHA256_DIGEST_LENGTH];
        }

        // Step 1: Extract - PRK = HMAC-Hash(salt, IKM)
        byte[] prk = hmacSha256(salt, ikm);

        // Step 2: Expand - OKM = T(1) | T(2) | ... | T(n)
        byte[] okm = new byte[okmLen];
        byte[] t = new byte[SHA256_DIGEST_LENGTH];
        byte[] prev = new byte[0];
        int offset = 0;
        int counter = 1;

        while (offset < okmLen) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
            byte[] input = concat(prev, info, new byte[]{(byte) counter});
            t = hmacSha256(prk, input);

            int copyLen = Math.min(SHA256_DIGEST_LENGTH, okmLen - offset);
            System.arraycopy(t, 0, okm, offset, copyLen);
            offset += copyLen;

            prev = t;
            counter++;
        }

        return okm;
    }

    /**
     * HMAC-SHA256 计算
     * @param key HMAC 密钥
     * @param data 输入数据
     * @return HMAC 结果
     */
    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            // 如果密钥长度超过块大小，先哈希
            if (key.length > 64) {
                key = sha256(key);
            }

            // 补齐密钥到块大小
            byte[] paddedKey = new byte[64];
            System.arraycopy(key, 0, paddedKey, 0, key.length);

            // 计算内部哈希: H((key ^ ipad) || data)
            byte[] ipad = new byte[64];
            for (int i = 0; i < 64; i++) {
                ipad[i] = (byte) (paddedKey[i] ^ 0x36);
            }
            byte[] innerData = concat(ipad, data);
            byte[] innerHash = sha256(innerData);

            // 计算外部哈希: H((key ^ opad) || innerHash)
            byte[] opad = new byte[64];
            for (int i = 0; i < 64; i++) {
                opad[i] = (byte) (paddedKey[i] ^ 0x5c);
            }
            byte[] outerData = concat(opad, innerHash);
            return sha256(outerData);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * SHA-256 哈希
     */
    private static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    /**
     * 拼接字节数组
     */
    private static byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) {
            if (arr != null) {
                totalLen += arr.length;
            }
        }

        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] arr : arrays) {
            if (arr != null) {
                System.arraycopy(arr, 0, result, offset, arr.length);
                offset += arr.length;
            }
        }

        return result;
    }
}