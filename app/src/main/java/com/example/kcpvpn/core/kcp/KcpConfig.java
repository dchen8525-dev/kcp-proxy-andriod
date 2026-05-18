package com.example.kcpvpn.core.kcp;

/**
 * KCP 配置常量 - 与 C++ config.hpp 完全一致
 */
public class KcpConfig {
    // KCP 基础配置
    public static final int KCP_INTERVAL_MS = 10;
    public static final int KCP_SNDWND = 256;
    public static final int KCP_RCVWND = 512;
    public static final int KCP_MTU = 1400;
    public static final int KCP_TIMEOUT_SEC = 60;
    public static final int RECONNECT_DELAY_SEC = 2;

    // 背压控制阈值
    public static final int KCP_BACKPRESSURE_THRESHOLD = KCP_SNDWND * 2;

    // 默认会话号
    public static final int DEFAULT_CONV = 1;

    // nodelay 参数
    public static final int NODELAY_ENABLED = 1;
    public static final int NODELAY_INTERVAL = KCP_INTERVAL_MS;
    public static final int NODELAY_RESEND = 5;       // fastresend 阈值（不是 rx_minrto）
    public static final int NODELAY_NOCWND = 1;        // 禁用拥塞控制
}