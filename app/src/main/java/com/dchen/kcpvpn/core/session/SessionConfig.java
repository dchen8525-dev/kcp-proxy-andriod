package com.dchen.kcpvpn.core.session;

import com.dchen.kcpvpn.core.kcp.KcpConfig;

/**
 * Session 配置 - 与 C++ config.hpp 一致
 */
public class SessionConfig {
    // 默认会话号
    public static final int DEFAULT_CONV = 1;

    // 超时参数
    public static final int KCP_TIMEOUT_MS = KcpConfig.KCP_TIMEOUT_SEC * 1000;
    public static final int CONNECT_TIMEOUT_MS = 15 * 1000;

    // 缓冲区大小
    public static final int UDP_RECV_BUF_SIZE = 65536;
    public static final int FWD_BUF_SIZE = 4096;
    public static final int SOCKS5_REPLY_BUF_SIZE = 512;
}