package com.example.kcpvpn.server;

import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.session.SessionConfig;

/**
 * 服务端配置 - 与 C++ config.hpp 一致
 */
public class ServerConfig {
    // 超时参数
    public static final int KCP_TIMEOUT_MS = KcpConfig.KCP_TIMEOUT_SEC * 1000;
    public static final int CONNECT_TIMEOUT_MS = 15 * 1000;
    public static final int CLEANUP_INTERVAL_MS = 30 * 1000;

    // 最大会话数
    public static final int MAX_CONCURRENT_SESSIONS = 4096;

    // 背压控制阈值
    public static final int BACKPRESSURE_THRESHOLD = KcpConfig.KCP_BACKPRESSURE_THRESHOLD;

    // 缓冲区大小
    public static final int UDP_RECV_BUF_SIZE = SessionConfig.UDP_RECV_BUF_SIZE;
    public static final int FWD_BUF_SIZE = SessionConfig.FWD_BUF_SIZE;

    // 默认监听端口
    public static final int DEFAULT_PORT = 8443;
    public static final String DEFAULT_HOST = "127.0.0.1";
}