package com.dchen.kcpvpn.core.crypto;

import java.nio.ByteBuffer;

/**
 * Nonce 生成器 - 与 C++ crypto.cpp generate_nonce 一致
 * 格式: [counter(8字节, big-endian)] + [direction(1字节)] + [padding(3字节, 零)]
 */
public class NonceGenerator {

    /**
     * 生成 Nonce
     * @param counter 计数器值（8字节）
     * @param direction 方向标识（CLIENT 或 SERVER）
     * @return 12字节 Nonce
     */
    public static byte[] generate(long counter, byte direction) {
        byte[] nonce = new byte[CryptoConfig.NONCE_SIZE];  // 默认全零
        ByteBuffer buf = ByteBuffer.wrap(nonce);

        // 写入计数器（big-endian, 8字节）
        buf.putLong(counter);

        // 写入方向标识（第9字节）
        buf.put(direction);

        // 剩余3字节保持为零（与 C++ std::array<uint8_t, NONCE_SIZE>{} 零初始化一致）

        return nonce;
    }

    /**
     * 从 Nonce 解析计数器
     * @param nonce 12字节 Nonce
     * @return 计数器值
     */
    public static long parseCounter(byte[] nonce) {
        if (nonce == null || nonce.length < CryptoConfig.COUNTER_SIZE) {
            throw new IllegalArgumentException("Invalid nonce length");
        }
        ByteBuffer buf = ByteBuffer.wrap(nonce, 0, CryptoConfig.COUNTER_SIZE);
        return buf.getLong();
    }

    /**
     * 从 Nonce 解析方向标识
     * @param nonce 12字节 Nonce
     * @return 方向标识
     */
    public static byte parseDirection(byte[] nonce) {
        if (nonce == null || nonce.length < CryptoConfig.NONCE_SIZE) {
            throw new IllegalArgumentException("Invalid nonce length");
        }
        return nonce[CryptoConfig.COUNTER_SIZE];
    }
}