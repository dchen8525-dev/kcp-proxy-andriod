package com.dchen.kcpvpn.core.crypto;

/**
 * 加密配置常量 - 与 C++ config.hpp crypto 配置一致
 */
public class CryptoConfig {
    // 加密参数
    public static final int NONCE_SIZE = 12;
    public static final int TAG_SIZE = 16;
    public static final int COUNTER_SIZE = 8;
    public static final int AES_KEY_SIZE = 16;

    // 计数器上限（AES-GCM IND-CPA 安全限制）
    public static final long MAX_COUNTER = (1L << 48);

    // 重放窗口大小
    public static final int REPLAY_WINDOW_BITS = 64;

    // Nonce 方向标识
    public static final byte NONCE_DIR_CLIENT = 0x01;
    public static final byte NONCE_DIR_SERVER = 0x02;

    // 应用固定盐值
    public static final String APP_SALT = "kcp-proxy-hkdf-salt-v1";

    // HKDF info 标签
    public static final String INFO_C2S = "kcp-proxy/c2s/v1";
    public static final String INFO_S2C = "kcp-proxy/s2c/v1";
}