package com.dchen.kcpvpn.core.kcp;

import com.dchen.kcpvpn.core.session.SessionConfig;

/**
 * KCP 配置常量 - 与 C++ config.hpp 完全一致
 */
public class KcpConfig {
    // KCP 基础配置
    public static final int KCP_INTERVAL_MS = 10;
    // 窗口按 SEGMENT 计，单条隧道的上限约为 sndWnd * (KCP_MTU - 24) / RTT。
    // C++ 端把默认窗口从 256/512 提到 1024/1024（见 config.hpp KCP_SNDWND 的
    // 注释：190ms RTT 下 256 段只能跑 ~14 Mbps，实测就是瓶颈），这里必须跟到
    // 同一个量级：CPP_REMOTE 方向的抗噪能力由本机发送窗口决定，若仍停在 256，
    // 服务端在 1024 上排队的那一段窗口对我们毫无意义——下载方向（服务端→本机）
    // 反而会被 512 的接收窗口卡住。
    //
    // 只有 conv 和 mtu 必须在两端严格相等；nodelay/interval/resend/nc 是本端
    // 发送行为，rcvWnd 是本端通告值，因此这里允许与 C++ 端不同，但默认值保持
    // 一致，便于用日志直接对照（CppRemoteTunnelManager 打印的就是这两个值）。
    public static final int KCP_SNDWND = 1024;
    public static final int KCP_RCVWND = 1024;
    public static final int KCP_MTU = 1400;
    public static final int KCP_TIMEOUT_SEC = 60;
    public static final int RECONNECT_DELAY_SEC = 2;

    // ikcp 段头部开销（conv4+cmd1+frg1+wnd2+ts4+sn4+una4+len4）
    public static final int KCP_SEGMENT_OVERHEAD = 24;

    // 单条消息最多切成的段数（与 C++ KCP_MAX_SEGMENTS_PER_MSG 同式）
    public static final int KCP_MAX_SEGMENTS_PER_MSG =
            (SessionConfig.FWD_BUF_SIZE + (KCP_MTU - KCP_SEGMENT_OVERHEAD) - 1)
                    / (KCP_MTU - KCP_SEGMENT_OVERHEAD);

    // 背压控制阈值：必须明显小于 sndWnd 且为整条消息留足排队空间，
    // 否则 ikcp_send 会失败而不是背压（与 C++ KCP_BACKPRESSURE_THRESHOLD 同式）
    public static final int KCP_BACKPRESSURE_THRESHOLD =
            KCP_SNDWND - KCP_MAX_SEGMENTS_PER_MSG - 8;

    // 恢复水位（与 C++ KCP_BACKPRESSURE_RESUME_THRESHOLD 同式）：
    // CppRemoteKcpSession 的出站队列在 L3 排队，退避判据必须用低水位，
    // 否则每次唤醒只能塞进一条消息就再次触顶，变成"排队-唤醒"抖动。
    static final int KCP_BACKPRESSURE_BURST_MSGS = 4;
    public static final int KCP_BACKPRESSURE_RESUME_THRESHOLD =
            KCP_BACKPRESSURE_THRESHOLD - KCP_BACKPRESSURE_BURST_MSGS * KCP_MAX_SEGMENTS_PER_MSG;

    // 默认会话号
    public static final int DEFAULT_CONV = 1;

    // nodelay 参数
    public static final int NODELAY_ENABLED = 1;
    public static final int NODELAY_INTERVAL = KCP_INTERVAL_MS;
    public static final int NODELAY_RESEND = 5;       // fastresend 阈值（匹配 C++ KcpWrapper）
    public static final int NODELAY_NOCWND = 1;        // 禁用拥塞控制
}
