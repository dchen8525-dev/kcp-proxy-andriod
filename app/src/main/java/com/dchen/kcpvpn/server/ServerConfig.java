package com.dchen.kcpvpn.server;

import com.dchen.kcpvpn.core.kcp.KcpConfig;
import com.dchen.kcpvpn.core.session.SessionConfig;

/**
 * 服务端配置 - 与 C++ config.hpp 一致
 */
public class ServerConfig {
    // 超时参数（与 C++ CONNECT_TIMEOUT_SEC=15 一致：5s 会把 5-15s 的慢目标连接
    // 在本地模式错杀，而同样的目标在 CPP_REMOTE 模式能连上）
    public static final int KCP_TIMEOUT_MS = KcpConfig.KCP_TIMEOUT_SEC * 1000;
    public static final int CONNECT_TIMEOUT_MS = 15 * 1000;
    public static final int CLEANUP_INTERVAL_MS = 30 * 1000;

    // 最大会话数
    public static final int MAX_CONCURRENT_SESSIONS = 4096;

    // 认证限速（与 C++ get_or_create_session 的两级节流同参数）：每地址每秒失败
    // 上限 + 全局每秒认证尝试预算。recvThread 单线程处理，字段无需并发保护。
    public static final int MAX_AUTH_FAILURES_PER_ADDR_PER_SEC = 20;
    public static final int MAX_AUTH_ATTEMPTS_PER_SEC = 5000;

    // salt 墓碑：会话接受后的 salt 在 TTL 内拒绝重建（死会话首包重放防护，
    // 与 C++ SALT_TOMBSTONE_TTL_SEC/MAX_SALT_TOMBSTONES 同参数）
    public static final int SALT_TOMBSTONE_TTL_MS = 600 * 1000;
    public static final int MAX_SALT_TOMBSTONES = 4 * MAX_CONCURRENT_SESSIONS;

    // 半关闭连接（目标已 EOF、FIN 已发、客户端迟迟不 FIN）的滞留上限。
    // 与 PacketRouter 的 CLOSING_IDLE_TIMEOUT_MS 同值：半关闭语义要求连接
    // 存活等待客户端收尾，但不能无限期占用目标 socket。
    public static final int HALF_CLOSE_IDLE_MS = 150 * 1000;

    // 背压控制阈值
    public static final int BACKPRESSURE_THRESHOLD = KcpConfig.KCP_BACKPRESSURE_THRESHOLD;

    // 缓冲区大小
    public static final int UDP_RECV_BUF_SIZE = SessionConfig.UDP_RECV_BUF_SIZE;
    public static final int FWD_BUF_SIZE = SessionConfig.FWD_BUF_SIZE;

    // 默认监听端口
    public static final int DEFAULT_PORT = 8443;
    public static final String DEFAULT_HOST = "127.0.0.1";
}