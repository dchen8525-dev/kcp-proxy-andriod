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
    // 单条 KCP 消息的上限。必须与 C++ config.hpp 的 FWD_BUF_SIZE 相等：对端用它
    // 作为接收缓冲（kcp_tunnel.hpp 的 kcp_recv_buf_），收到更大的消息会走
    // complete_pending_read(message_size)，服务端 forward_kcp_to_tcp 把它当致命
    // 错误并 close_connection。这个值同时决定 KcpConfig 的段数与背压阈值。
    public static final int FWD_BUF_SIZE = 16384;
    public static final int SOCKS5_REPLY_BUF_SIZE = 512;

    // UDP 内核缓冲（与 C++ UDP_SO_RCVBUF/SNDBUF 一致）：内核缓冲不足时突发丢包
    // 会被 KCP 误判为网络拥塞，触发整窗重传
    public static final int UDP_SO_RCVBUF_BYTES = 4 * 1024 * 1024;
    public static final int UDP_SO_SNDBUF_BYTES = 4 * 1024 * 1024;
}
