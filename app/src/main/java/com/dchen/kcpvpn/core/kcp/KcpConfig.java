package com.dchen.kcpvpn.core.kcp;

import com.dchen.kcpvpn.core.session.SessionConfig;

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

    // 默认会话号
    public static final int DEFAULT_CONV = 1;

    // nodelay 参数
    public static final int NODELAY_ENABLED = 1;
    public static final int NODELAY_INTERVAL = KCP_INTERVAL_MS;
    public static final int NODELAY_RESEND = 5;       // fastresend 阈值（匹配 C++ KcpWrapper）
    public static final int NODELAY_NOCWND = 1;        // 禁用拥塞控制
}
