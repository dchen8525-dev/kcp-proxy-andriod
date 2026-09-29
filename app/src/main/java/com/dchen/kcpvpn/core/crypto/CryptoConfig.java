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

    // 每会话随机盐：线格式为 salt(16) + nonce(12) + ciphertext + tag(16)，
    // per-session 密钥 = HKDF(PSK, APP_SALT || session_salt)
    public static final int SESSION_SALT_SIZE = 16;

    // 计数器上限（AES-GCM IND-CPA 安全限制）
    public static final long MAX_COUNTER = (1L << 48);

    // 重放窗口大小（与 C++ 一致：64 位已不足以吸收高吞吐下的 UDP 乱序）
    public static final int REPLAY_WINDOW_BITS = 2048;

    // Nonce 方向标识
    public static final byte NONCE_DIR_CLIENT = 0x01;
    public static final byte NONCE_DIR_SERVER = 0x02;

    // 应用固定盐值
    public static final String APP_SALT = "kcp-proxy-hkdf-salt-v1";

    // HKDF info 标签
    public static final String INFO_C2S = "kcp-proxy/c2s/v1";
    public static final String INFO_S2C = "kcp-proxy/s2c/v1";

    // 应用层控制消息魔数（与 C++ config.hpp 完全一致）。
    // HELLO 为裸 magic；keepalive/FIN 为 magic || session_salt(16)。
    public static final String CONTROL_HELLO = "KCP_PROXY_HELLO_V1";
    public static final String CONTROL_HELLO_ACK = "KCP_PROXY_HELLO_ACK_V1";
    public static final String CONTROL_HELLO_V2 = "KCP_PROXY_HELLO_V2";
    public static final String CONTROL_HELLO_ACK_V2 = "KCP_PROXY_HELLO_ACK_V2";
    public static final String CONTROL_FIN = "KCP_PROXY_FIN_V1";
    public static final String CONTROL_KEEPALIVE = "KCP_PROXY_KEEPALIVE_V1";

    // 空闲超过该秒数时发送应用层 keepalive（服务端 60s 空闲回收，必须小于它）
    public static final int KEEPALIVE_INTERVAL_SEC = 30;

    private CryptoConfig() {
    }
}
