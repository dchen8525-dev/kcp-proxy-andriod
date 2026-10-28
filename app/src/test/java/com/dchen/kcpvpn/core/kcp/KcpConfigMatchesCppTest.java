package com.dchen.kcpvpn.core.kcp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.dchen.kcpvpn.core.session.SessionConfig;

import org.junit.Test;

/**
 * 两端 KCP 参数的契约测试。
 *
 * <p>C++ 端的基线写在 {@code src/kcp_proxy/config.hpp}，并由
 * {@code kcp_config_line()} 在启动日志里渲染；Android 端必须与"仅 conv 和 mtu
 * 严格相等"这一条规则一致，其余字段（窗口、nodelay 系列）允许不同，但本仓库
 * 有意让默认值对齐，这样运维 diff 两端日志时不会看到噪声差异。
 *
 * <p>本测试的存在理由：{@code CppRemoteTunnelManager} 曾经把
 * {@code sndWnd=256 rcvWnd=512} 写死在日志字符串里，常量改成别的值后日志
 * 依旧是旧数字——日志成了谎报。把期望值钉在这里，任何一侧的漂移都会让
 * {@code ./gradlew test} 直接失败，而不是等到真机吞吐塌陷才发现。
 */
public class KcpConfigMatchesCppTest {
    // C++ src/kcp_proxy/config.hpp 基线。
    private static final int CPP_CONV = 1;
    private static final int CPP_MTU = 1400;
    private static final int CPP_SNDWND = 1024;
    private static final int CPP_RCVWND = 1024;
    private static final int CPP_TIMEOUT_SEC = 60;
    private static final int CPP_NODELAY = 1;
    private static final int CPP_INTERVAL_MS = 10;
    private static final int CPP_RESEND = 5;
    private static final int CPP_NC = 1;

    @Test
    public void wireCriticalParametersMatchCpp() {
        // conv 与 mtu 是唯一"必须相等"的字段：conv 不一致时 ikcp 直接丢弃对端
        // 段，mtu 不一致会切出对端无法拼装的段边界。
        assertEquals(CPP_CONV, KcpConfig.DEFAULT_CONV);
        assertEquals(CPP_MTU, KcpConfig.KCP_MTU);
    }

    @Test
    public void localSendBehaviourMatchesCppByDefault() {
        // 非强制，但默认对齐——对端日志里这两行的差异应当意味着"有人故意改过"，
        // 而不是"两个仓库各自漂移"。
        assertEquals(CPP_NODELAY, KcpConfig.NODELAY_ENABLED);
        assertEquals(CPP_INTERVAL_MS, KcpConfig.KCP_INTERVAL_MS);
        assertEquals(CPP_RESEND, KcpConfig.NODELAY_RESEND);
        assertEquals(CPP_NC, KcpConfig.NODELAY_NOCWND);
        assertEquals(CPP_TIMEOUT_SEC, KcpConfig.KCP_TIMEOUT_SEC);
    }

    @Test
    public void advertisedWindowsMatchCppByDefault() {
        // 窗口只有 256 段时，190ms RTT 下单条隧道被压到 ~14 Mbps（C++ 端实测的
        // 瓶颈）。Android 端必须同量级，否则它自己就是那个瓶颈。
        assertEquals(CPP_SNDWND, KcpConfig.KCP_SNDWND);
        assertEquals(CPP_RCVWND, KcpConfig.KCP_RCVWND);
    }

    @Test
    public void backpressureWatermarksStayOrdered() {
        // 触碰阈值必须低于 sndWnd（否则 ikcp_send 直接 -1 而不是背压），
        // 恢复水位必须低于触碰阈值（否则唤醒一次就立刻再次触顶）。
        assertTrue("threshold must stay below sndWnd",
                KcpConfig.KCP_BACKPRESSURE_THRESHOLD < KcpConfig.KCP_SNDWND);
        assertTrue("resume must sit below threshold",
                KcpConfig.KCP_BACKPRESSURE_RESUME_THRESHOLD
                        < KcpConfig.KCP_BACKPRESSURE_THRESHOLD);
        assertTrue("resume must stay positive",
                KcpConfig.KCP_BACKPRESSURE_RESUME_THRESHOLD > 0);
        // 整条消息（FWD_BUF_SIZE）在触碰阈值之下必须还塞得进去。
        assertTrue("one whole message must fit under the threshold",
                KcpConfig.KCP_BACKPRESSURE_THRESHOLD + KcpConfig.KCP_MAX_SEGMENTS_PER_MSG
                        <= KcpConfig.KCP_SNDWND);
    }

    @Test
    public void maxSegmentsPerMessageMatchesCppFormula() {
        int mss = KcpConfig.KCP_MTU - KcpConfig.KCP_SEGMENT_OVERHEAD;
        int expected = (SessionConfig.FWD_BUF_SIZE + mss - 1) / mss;
        assertEquals(expected, KcpConfig.KCP_MAX_SEGMENTS_PER_MSG);
    }
}
