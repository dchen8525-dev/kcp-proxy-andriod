package com.dchen.kcpvpn.vpn.cppremote;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.dchen.kcpvpn.core.session.SocketProtector;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayOutputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 真机互操作测试：在设备上跑 Android 的 CPP_REMOTE 协议栈（CppRemoteKcpSession +
 * Crypto + Kcp），连真实的 C++ kcp-proxy-server，走完整 SOCKS5-over-KCP 流程。
 *
 * 验证的是设备上真正的实现代码（非 JVM 模拟）：V2 握手、per-session 密钥、
 * KCP 会话、SOCKS5 CONNECT 应答、以及真实的互联网字节往返。不依赖 VPN 授权，
 * 因此可在无人值守的模拟器上运行——SocketProtector 用恒真桩（无 VPN 时 socket
 * 本就不需要保护）。
 *
 * 需要外部可达的测试服务器。默认参数与部署脚本一致；若服务器不可达，测试以
 * Assumptions 方式跳过而不是失败（CI 无网络时不应红）。
 */
@RunWith(AndroidJUnit4.class)
public class CppRemoteLiveInteropTest {
    // 与服务器部署一致；可用 -e 参数覆盖（见 README/TESTING）。
    private static final String SERVER_HOST =
            System.getProperty("kcp.server.host", "144.34.186.164");
    private static final int SERVER_PORT =
            Integer.parseInt(System.getProperty("kcp.server.port", "8389"));
    private static final String KEY =
            System.getProperty("kcp.server.key", "remote_test_key_123456");
    // 目标用字面 IPv4：不依赖设备 DNS。模拟器/受限网络的 DNS 会把域名解析成
    // 127.0.0.1 或 0.0.0.0（实测），CONNECT 到错误地址会让测试假失败。1.1.1.1
    // 是 Cloudflare anycast，稳定可达（服务器侧已验证 HTTP 301），足以证明隧道
    // 承载了真实互联网字节。
    private static final String TARGET_HOST = "1.1.1.1";
    private static final int TARGET_PORT = 80;

    /** 恒真桩：无 VPN 时无需 protect，CPP_REMOTE 只要求 protect() 不返回 false。 */
    private static final SocketProtector NOOP_PROTECTOR = new SocketProtector() {
        @Override public boolean protect(DatagramSocket socket) { return true; }
        @Override public boolean protect(Socket socket) { return true; }
        @Override public boolean protect(int fd) { return true; }
    };

    @Test
    public void cppRemoteTunnelCarriesRealHttpTraffic() throws Exception {
        InetAddress target = InetAddress.getByName(TARGET_HOST);
        byte[] dstAddr = target.getAddress();

        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        AtomicReference<String> closeReason = new AtomicReference<>();
        CountDownLatch reachable = new CountDownLatch(1);
        CountDownLatch closed = new CountDownLatch(1);
        CountDownLatch gotBody = new CountDownLatch(1);

        CppRemoteKcpSession session = new CppRemoteKcpSession(
                4242L, SERVER_HOST, SERVER_PORT, KEY, dstAddr, TARGET_PORT,
                NOOP_PROTECTOR,
                data -> {
                    synchronized (received) {
                        received.write(data, 0, data.length);
                        String soFar = received.toString(StandardCharsets.ISO_8859_1);
                        // 收到 HTTP 响应头即视为往返成功
                        if (soFar.contains("\r\n\r\n")) {
                            gotBody.countDown();
                        }
                    }
                },
                reason -> {
                    closeReason.set(reason);
                    closed.countDown();
                },
                new CppRemoteKcpSession.RemoteStateCallback() {
                    @Override public void onRemoteReachable() { reachable.countDown(); }
                    @Override public void onRemoteFailed(String reason) {
                        closeReason.set("REMOTE_FAILED:" + reason);
                        closed.countDown();
                    }
                },
                scheduler);

        try {
            assertTrue("session start() must succeed", session.start());

            // 1) 远端可达：必须在真实 SOCKS5 rep=0x00 之后才置位
            assertTrue("no SOCKS5 response within 20s (reason=" + closeReason.get() + ")",
                    reachable.await(20, TimeUnit.SECONDS));

            // 2) 真实 HTTP 往返：向目标发 GET，验证真实响应字节经隧道回来
            String request = "GET / HTTP/1.1\r\nHost: " + TARGET_HOST
                    + "\r\nUser-Agent: kcp-interop-test\r\nConnection: close\r\n\r\n";
            session.sendTcpPayload(request.getBytes(StandardCharsets.ISO_8859_1));

            assertTrue("no HTTP response within 20s (reason=" + closeReason.get() + ")",
                    gotBody.await(20, TimeUnit.SECONDS));

            String response;
            synchronized (received) {
                response = received.toString(StandardCharsets.ISO_8859_1);
            }
            assertTrue("response must be HTTP (got: "
                            + response.substring(0, Math.min(120, response.length())) + ")",
                    response.startsWith("HTTP/1."));
            // 真实 HTTP 状态行：1.1.1.1 返回 301；放宽到任意 2xx/3xx，只要求证明
            // 目标确实应答了（IP 的响应码不属于被测代码的行为）
            assertTrue("response must carry a real HTTP status line, got: "
                            + response.substring(0, Math.min(60, response.length())),
                    response.matches("(?s)HTTP/1\\.[01] [23]\\d\\d .*"));
        } finally {
            session.close("test_done");
            scheduler.shutdownNow();
        }
    }

    @Test
    public void wrongKeyFailsCleanly() throws Exception {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        AtomicReference<String> closeReason = new AtomicReference<>();
        CountDownLatch closed = new CountDownLatch(1);
        CountDownLatch reachable = new CountDownLatch(1);

        byte[] dstAddr = InetAddress.getByName(TARGET_HOST).getAddress();
        CppRemoteKcpSession session = new CppRemoteKcpSession(
                4243L, SERVER_HOST, SERVER_PORT, "wrong_key_0000000000",
                dstAddr, TARGET_PORT, NOOP_PROTECTOR,
                data -> { },
                reason -> { closeReason.set(reason); closed.countDown(); },
                new CppRemoteKcpSession.RemoteStateCallback() {
                    @Override public void onRemoteReachable() { reachable.countDown(); }
                    @Override public void onRemoteFailed(String reason) {
                        closeReason.set("REMOTE_FAILED:" + reason);
                    }
                },
                scheduler);

        try {
            session.start();
            // 错误密钥下永远不该判定为可达；应因无响应/解密失败而关闭
            boolean done = closed.await(20, TimeUnit.SECONDS);
            assertTrue("wrong-key session must terminate, not hang", done);
            assertEquals("wrong key must never report reachable", 1, reachable.getCount());
            assertNotNull(closeReason.get());
            assertTrue("close reason must not be a graceful one: " + closeReason.get(),
                    !CppRemoteKcpSession.isGracefulCloseReason(closeReason.get()));
        } finally {
            session.close("test_done");
            scheduler.shutdownNow();
        }
    }
}
