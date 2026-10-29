package com.dchen.kcpvpn.core.session;

import com.dchen.kcpvpn.core.crypto.CryptoConfig;
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
    // 单条 UDP 报文的最大线尺寸（与 C++ config.hpp UDP_WIRE_DATAGRAM_MAX 同式）：
    // salt(16) + nonce(12) 明文前缀 + FEC 头(6)+长度(2) + 最大合法 MTU 的 KCP 报文
    // + tag(16)。接收缓冲小于它时内核会静默截断多出的尾部，AEAD tag 永远验不过
    // ——隧道表现为"握手正常但零流量"，只有解密失败日志（C++ 0.3.2 d5bfa44 修的
    // 就是这个：旧值 4096 弄坏了所有 >~4KB 的 --mtu）。对端 --mtu 合法上限是
    // 9000，接收方无法提前知道对端的 MTU，所以按整个合法范围留量。
    public static final int UDP_WIRE_DATAGRAM_MAX = CryptoConfig.SESSION_SALT_SIZE
            + CryptoConfig.NONCE_SIZE + 8 + KcpConfig.KCP_MTU_MAX + CryptoConfig.TAG_SIZE;
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
