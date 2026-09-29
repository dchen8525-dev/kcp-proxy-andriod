package com.dchen.kcpvpn.vpn.cppremote;

import com.dchen.kcpvpn.core.crypto.Crypto;
import com.dchen.kcpvpn.core.crypto.CryptoConfig;
import com.dchen.kcpvpn.core.kcp.Kcp;
import com.dchen.kcpvpn.core.kcp.KcpConfig;
import com.dchen.kcpvpn.core.session.SessionConfig;
import com.dchen.kcpvpn.core.session.SocketProtector;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.Queue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 对接 C++ kcp-proxy-server 的远程会话（V2 协议）：
 * - 加密线格式 salt(16)+nonce(12)+ct+tag(16)，per-session 密钥（见 Crypto）。
 * - 首条 KCP 消息发送 KCP_PROXY_HELLO_V2，服务端回 HELLO_ACK_V2 后启用半关闭。
 * - 空闲 30s 发送 magic||session_salt 应用层 keepalive；收到的 keepalive/FIN
 *   控制消息在此会话内消化，绝不转发进 TCP 隧道。
 * - 本地 TCP FIN 只发送 FIN 并进入排空态（等待服务端把在途数据发完或回 FIN），
 *   而不是立即拆除会话。
 */
public class CppRemoteKcpSession {
    private static final int UDP_RECV_BUF_SIZE = 4096;
    private static final int KCP_RECV_BUF_SIZE = 64 * 1024;
    private static final int PENDING_LIMIT_BYTES = 512 * 1024;
    private static final int SOCKS5_RESPONSE_TIMEOUT_SEC = 10;
    // 半关闭宽限（与 C++ CLIENT_HALF_CLOSE_GRACE_SEC = 2 * KCP_TIMEOUT_SEC 一致）：
    // 本地 FIN 后，仅凭送达应用的真实数据续命，排空停滞则回收。
    private static final int HALF_CLOSE_GRACE_MS = 120_000;
    // 认证失败阈值：轮询运行在单线程调度器上，计数无需同步。
    private static final int MAX_AUTH_FAILURES = 8;
    // 背压排队上限：TUN 侧已对所有字节回 ACK，Chrome 感知不到拥塞，
    // 链路停摆时出站只能自我封顶；超过即判定会话不可恢复，明确失败而不是无限吃内存。
    private static final int SEND_QUEUE_LIMIT_BYTES = 2 * 1024 * 1024;

    private final long connectionId;
    private final InetSocketAddress serverAddr;
    private final String key;
    private final byte[] dstAddr;
    private final int dstPort;
    private final SocketProtector socketProtector;
    private final DataCallback dataCallback;
    private final CloseCallback closeCallback;
    private final RemoteStateCallback remoteStateCallback;
    private final ScheduledExecutorService kcpScheduler;
    private final Object kcpLock = new Object();
    private final Object pendingLock = new Object();
    private final Object outboundLock = new Object();
    private final Queue<byte[]> pendingClientData = new ArrayDeque<>();
    private final Queue<byte[]> outboundQueue = new ArrayDeque<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final CppSocks5ResponseBuffer socks5ResponseBuffer = new CppSocks5ResponseBuffer();
    private final ByteBuffer udpRecvBuffer = ByteBuffer.allocate(UDP_RECV_BUF_SIZE);

    private final AtomicLong lastKeepaliveSentMs = new AtomicLong(0);
    private final AtomicLong lastHalfCloseProgressMs = new AtomicLong(0);

    private DatagramChannel udpChannel;
    private Kcp kcp;
    private Crypto crypto;
    private ScheduledFuture<?> updateTask;
    private ScheduledFuture<?> socks5ResponseTimeoutTask;
    private volatile boolean running;
    private volatile boolean socks5Done;
    private volatile boolean finEnabled;
    private volatile boolean localFinSent;
    private volatile boolean peerFinReceived;
    private int authFailures;
    private int pendingBytes;
    private int outboundBytes;

    public CppRemoteKcpSession(long connectionId, String serverHost, int serverPort, String key,
                               byte[] dstAddr, int dstPort, SocketProtector socketProtector,
                               DataCallback dataCallback, CloseCallback closeCallback,
                               RemoteStateCallback remoteStateCallback,
                               ScheduledExecutorService kcpScheduler) {
        this.connectionId = connectionId;
        this.serverAddr = new InetSocketAddress(serverHost, serverPort);
        this.key = key;
        this.dstAddr = dstAddr.clone();
        this.dstPort = dstPort;
        this.socketProtector = socketProtector;
        this.dataCallback = dataCallback;
        this.closeCallback = closeCallback;
        this.remoteStateCallback = remoteStateCallback;
        this.kcpScheduler = kcpScheduler;
    }

    public boolean start() {
        try {
            crypto = new Crypto(key);
            kcp = new Kcp(KcpConfig.DEFAULT_CONV);
            kcp.setNodelay(KcpConfig.NODELAY_ENABLED, KcpConfig.NODELAY_INTERVAL,
                    KcpConfig.NODELAY_RESEND, KcpConfig.NODELAY_NOCWND);
            kcp.setWndSize(KcpConfig.KCP_SNDWND, KcpConfig.KCP_RCVWND);
            kcp.setMtu(KcpConfig.KCP_MTU);
            kcp.setOutputCallback(this::handleKcpOutput);

            udpChannel = DatagramChannel.open();
            udpChannel.configureBlocking(false);
            try {
                udpChannel.socket().setReceiveBufferSize(SessionConfig.UDP_SO_RCVBUF_BYTES);
                udpChannel.socket().setSendBufferSize(SessionConfig.UDP_SO_SNDBUF_BYTES);
            } catch (Exception e) {
                Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE UDP buffer size request failed connectionId="
                        + connectionId + " error=" + e.getMessage());
            }
            boolean protectedOk = socketProtector != null && socketProtector.protect(udpChannel.socket());
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE KCP UDP socket protected=" + protectedOk
                    + " connectionId=" + connectionId);
            if (!protectedOk) {
                throw new IOException("KCP_SOCKET_PROTECT_FAILED");
            }
            udpChannel.connect(serverAddr);

            running = true;
            startUpdateThread();

            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE HELLO_V2 connectionId=" + connectionId
                    + " salt=" + hexPrefix(crypto.sessionSalt()));
            sendRaw(CryptoConfig.CONTROL_HELLO_V2.getBytes(StandardCharsets.US_ASCII));
            startSocks5ResponseTimeout();
            return true;
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE session start failed connectionId="
                    + connectionId + " error=" + e.getMessage());
            close("KCP_SESSION_FAILED");
            return false;
        }
    }

    public void sendTcpPayload(byte[] data) {
        if (data == null || data.length == 0 || closed.get()) {
            return;
        }
        if (localFinSent) {
            Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE ignoring payload after local FIN connectionId="
                    + connectionId);
            return;
        }
        if (!socks5Done) {
            synchronized (pendingLock) {
                if (pendingBytes + data.length > PENDING_LIMIT_BYTES) {
                    Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE pending data overflow connectionId="
                            + connectionId);
                    close("SOCKS5_RESPONSE_FAILED");
                    return;
                }
                byte[] copy = data.clone();
                pendingClientData.add(copy);
                pendingBytes += copy.length;
            }
            Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE queued TCP payload before SOCKS5 connectionId="
                    + connectionId + " len=" + data.length);
            return;
        }
        Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE TCP payload -> KCP raw len=" + data.length
                + " connectionId=" + connectionId);
        sendRaw(data);
    }

    /**
     * 本地 TCP 半关闭（应用 FIN）。协商了 V2 时只发送 FIN 控制消息并进入排空态，
     * 让服务端把目标站的在途数据完整送达；未协商（老服务端）时退化为立即关闭，
     * 以免服务端把 FIN 字节当作流数据转发。
     */
    public void sendLocalFin() {
        if (!running || closed.get()) {
            return;
        }
        if (!finEnabled) {
            close("tcp_fin");
            return;
        }
        if (localFinSent) {
            return;
        }
        localFinSent = true;
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE FIN sent (half-close) connectionId=" + connectionId);
        sendRaw(controlPayload(CryptoConfig.CONTROL_FIN, crypto.sessionSalt()));
        lastHalfCloseProgressMs.set(System.currentTimeMillis());
        if (peerFinReceived) {
            close("tcp_fin");
        }
    }

    private void startUpdateThread() {
        updateTask = kcpScheduler.scheduleAtFixedRate(() -> {
            if (!running) {
                return;
            }
            try {
                synchronized (kcpLock) {
                    kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
                    kcp.flush();
                }
                drainOutboundQueue();
                pollUdpPackets();
                maybeSendKeepalive();
                maybeCheckHalfCloseGrace();
            } catch (Exception e) {
                if (running) {
                    Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE update tick error connectionId="
                            + connectionId + " error=" + e.getMessage());
                }
            }
        }, 0, KcpConfig.KCP_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    /** 与 C++ KcpTunnel::maybe_send_keepalive 同构：握手完成后空闲 30s 发送。 */
    private void maybeSendKeepalive() {
        if (!running || !socks5Done || localFinSent) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastKeepaliveSentMs.get() < CryptoConfig.KEEPALIVE_INTERVAL_SEC * 1000L) {
            return;
        }
        synchronized (kcpLock) {
            if (kcp.peekSize() > 0) {
                return;
            }
        }
        lastKeepaliveSentMs.set(now);
        sendRaw(controlPayload(CryptoConfig.CONTROL_KEEPALIVE, crypto.sessionSalt()));
        Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE keepalive sent connectionId=" + connectionId);
    }

    /**
     * 本地 FIN 之后的排空兜底：只有真正送达应用的字节才推进 lastHalfCloseProgressMs，
     * 服务端既不再发数据也不回 FIN 时，超过宽限期回收，避免会话悬挂。
     */
    private void maybeCheckHalfCloseGrace() {
        if (!running || !localFinSent || peerFinReceived || closed.get()) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastHalfCloseProgressMs.get() >= HALF_CLOSE_GRACE_MS) {
            Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE half-close grace expired connectionId="
                    + connectionId + " graceMs=" + HALF_CLOSE_GRACE_MS);
            close("SESSION_TIMEOUT");
        }
    }

    private void startSocks5ResponseTimeout() {
        socks5ResponseTimeoutTask = kcpScheduler.schedule(() -> {
            if (running && !socks5Done) {
                Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE HELLO/SOCKS5 response timeout connectionId="
                        + connectionId + " timeoutSec=" + SOCKS5_RESPONSE_TIMEOUT_SEC);
                close("CPP_SERVER_NO_RESPONSE");
            }
        }, SOCKS5_RESPONSE_TIMEOUT_SEC, TimeUnit.SECONDS);
    }

    private void pollUdpPackets() {
        if (!running || udpChannel == null) {
            return;
        }
        ByteBuffer buf = udpRecvBuffer;
        try {
            int packets = 0;
            while (packets++ < 64) {
                buf.clear();
                if (udpChannel.receive(buf) == null) {
                    return;
                }
                int len = buf.position();
                if (len <= 0) {
                    continue;
                }
                byte[] encrypted = new byte[len];
                buf.flip();
                buf.get(encrypted);
                onUdpPacket(encrypted);
            }
        } catch (IOException e) {
            if (running) {
                Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE UDP receive failed connectionId="
                        + connectionId + " error=" + e.getMessage());
                close("CPP_SERVER_NO_RESPONSE");
            }
        }
    }

    private void onUdpPacket(byte[] encrypted) {
        try {
            byte[] decrypted = crypto.decrypt(encrypted);
            authFailures = 0;
            int ret;
            synchronized (kcpLock) {
                ret = kcp.input(decrypted);
            }
            if (ret < 0) {
                Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE ikcp_input rejected connectionId="
                        + connectionId + " ret=" + ret);
                return;
            }
            deliverKcpData();
        } catch (Crypto.ReplayRejectedException e) {
            authFailures = 0;
            Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE replay/stale packet dropped connectionId="
                    + connectionId + " " + e.getMessage());
        } catch (javax.crypto.AEADBadTagException e) {
            // 与 C++ KcpSession::handle_read 一致：认证失败的包只丢弃，
            // 持续失败超过阈值才判定密钥/协议不匹配，避免伪包直接杀会话。
            onAuthFailure("auth_failed");
        } catch (Exception e) {
            onAuthFailure(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void onAuthFailure(String detail) {
        int failures = ++authFailures;
        if (failures < MAX_AUTH_FAILURES) {
            Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE packet dropped detail=" + detail
                    + " connectionId=" + connectionId + " consecutiveAuthFailures=" + failures);
            return;
        }
        Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE CRYPTO_MISMATCH (auth failed) connectionId="
                + connectionId + " consecutiveAuthFailures=" + failures);
        close("CRYPTO_MISMATCH");
    }

    private void deliverKcpData() {
        // salt 每会话固定，循环外取一次即可
        final byte[] salt = crypto.sessionSalt();
        while (running) {
            byte[] data;
            synchronized (kcpLock) {
                int peek = kcp.peekSize();
                if (peek <= 0) {
                    return;
                }
                byte[] recv = new byte[Math.max(peek, KCP_RECV_BUF_SIZE)];
                int len = kcp.recv(recv);
                if (len <= 0) {
                    return;
                }
                data = new byte[len];
                System.arraycopy(recv, 0, data, 0, len);
            }

            // 控制消息在交给任何消费者之前先剥掉（与 C++ KcpTunnel::handle_read 同序）：
            // keepalive 可能出现在 SOCKS5 响应还在拼装的时候，落入解析器会被当成坏响应。
            if (isControlMessage(data, CryptoConfig.CONTROL_KEEPALIVE, salt)) {
                Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE keepalive received and dropped connectionId="
                        + connectionId);
                continue;
            }
            if (isControlMessage(data, CryptoConfig.CONTROL_FIN, salt)) {
                Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE server FIN received (target half-closed) "
                        + "connectionId=" + connectionId);
                peerFinReceived = true;
                if (localFinSent) {
                    close("tcp_fin");
                    return;
                }
                continue;
            }

            if (!socks5Done) {
                if (isExactMessage(data, CryptoConfig.CONTROL_HELLO_ACK_V2)) {
                    finEnabled = true;
                    Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE handshake confirmed (V2, half-close enabled)"
                            + " connectionId=" + connectionId);
                    sendSocks5Connect();
                    continue;
                }
                if (isExactMessage(data, CryptoConfig.CONTROL_HELLO_ACK)) {
                    finEnabled = false;
                    Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE handshake confirmed (V1 server, "
                            + "half-close disabled) connectionId=" + connectionId);
                    sendSocks5Connect();
                    continue;
                }
                handleSocks5Response(data);
                continue;
            }

            lastHalfCloseProgressMs.set(System.currentTimeMillis());
            Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE KCP raw -> TCP payload len=" + data.length
                    + " connectionId=" + connectionId);
            dataCallback.onData(data);
        }
    }

    private void sendSocks5Connect() {
        byte[] request = CppSocks5RequestBuilder.buildIpv4Connect(dstAddr, dstPort);
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE SOCKS5 CONNECT connectionId=" + connectionId
                + " dst=" + addrToString(dstAddr) + ":" + dstPort);
        sendRaw(request);
    }

    /** 控制消息 = magic || session_salt，长度与内容精确匹配（与 C++ is_control 一致）。 */
    static boolean isControlMessage(byte[] data, String magic, byte[] sessionSalt) {
        int saltLength = (sessionSalt == null) ? 0 : sessionSalt.length;
        if (data == null || data.length != magic.length() + saltLength) {
            return false;
        }
        for (int i = 0; i < magic.length(); i++) {
            if (data[i] != (byte) magic.charAt(i)) {
                return false;
            }
        }
        for (int i = 0; i < saltLength; i++) {
            if (data[magic.length() + i] != sessionSalt[i]) {
                return false;
            }
        }
        return true;
    }

    static boolean isExactMessage(byte[] data, String magic) {
        return isControlMessage(data, magic, new byte[0]);
    }

    static byte[] controlPayload(String magic, byte[] sessionSalt) {
        byte[] m = magic.getBytes(StandardCharsets.US_ASCII);
        byte[] salt = (sessionSalt == null) ? new byte[0] : sessionSalt;
        byte[] out = new byte[m.length + salt.length];
        System.arraycopy(m, 0, out, 0, m.length);
        System.arraycopy(salt, 0, out, m.length, salt.length);
        return out;
    }

    private void handleSocks5Response(byte[] data) {
        CppSocks5ResponseBuffer.Status parseStatus = socks5ResponseBuffer.append(data);
        if (parseStatus == CppSocks5ResponseBuffer.Status.INCOMPLETE) {
            Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE SOCKS5 response incomplete connectionId="
                    + connectionId + " chunkLen=" + data.length);
            return;
        }
        if (parseStatus == CppSocks5ResponseBuffer.Status.INVALID) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE SOCKS5_RESPONSE_FAILED connectionId="
                    + connectionId + " len=" + data.length);
            close("SOCKS5_RESPONSE_FAILED");
            return;
        }
        int status = socks5ResponseBuffer.reply();
        Logger.info(LogConfig.MODULE_VPN, String.format(Locale.US,
                "CPP_REMOTE SOCKS5 response rep=0x%02X connectionId=%d", status, connectionId));
        if (status != 0) {
            close("SOCKS5_CONNECT_FAILED");
            return;
        }
        socks5Done = true;
        cancelSocks5ResponseTimeout();
        remoteStateCallback.onRemoteReachable();
        flushPendingClientData();
        byte[] extra = socks5ResponseBuffer.extraPayload();
        if (extra.length > 0) {
            dataCallback.onData(extra);
        }
    }

    private void flushPendingClientData() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        synchronized (pendingLock) {
            while (!pendingClientData.isEmpty()) {
                byte[] data = pendingClientData.remove();
                out.write(data, 0, data.length);
            }
            pendingBytes = 0;
        }
        byte[] data = out.toByteArray();
        if (data.length > 0) {
            Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE flush queued TCP payload len=" + data.length
                    + " connectionId=" + connectionId);
            sendRaw(data);
        }
    }

    private void sendRaw(byte[] data) {
        if (!running || data == null || data.length == 0) {
            return;
        }
        boolean overflow;
        int queuedBytes;
        synchronized (outboundLock) {
            // 只有队列为空且 KCP 尚有余量才能直接写入；队列非空时必须继续排队，
            // 否则新字节会插到已排队数据前面，打乱 KCP 字节流。
            if (outboundQueue.isEmpty() && hasSendCapacity(waitSend())) {
                writeThroughKcp(data);
                return;
            }
            overflow = outboundBytes + data.length > SEND_QUEUE_LIMIT_BYTES;
            queuedBytes = outboundBytes;
            if (!overflow) {
                outboundQueue.add(data);
                outboundBytes += data.length;
                Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE outbound queued by backpressure connectionId="
                        + connectionId + " len=" + data.length + " queuedBytes=" + outboundBytes);
            }
        }
        if (overflow) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE KCP_BACKPRESSURE_OVERFLOW connectionId="
                    + connectionId + " queuedBytes=" + queuedBytes + " len=" + data.length);
            close("KCP_BACKPRESSURE_OVERFLOW");
        }
    }

    /** KCP 发送队列余量判据，与 C++ 的 wait_send &lt; KCP_BACKPRESSURE_THRESHOLD 同构。 */
    static boolean hasSendCapacity(int waitSend) {
        return waitSend < KcpConfig.KCP_BACKPRESSURE_THRESHOLD;
    }

    /**
     * 更新线程把排队的出站字节按序补进 KCP，直到重新触及阈值。
     * 在 kcpLock 之外调用，避免与 VPN 读线程长时间争锁。
     */
    private void drainOutboundQueue() {
        while (running) {
            byte[] next;
            synchronized (outboundLock) {
                if (outboundQueue.isEmpty() || !hasSendCapacity(waitSend())) {
                    return;
                }
                next = outboundQueue.remove();
                outboundBytes -= next.length;
            }
            writeThroughKcp(next);
        }
    }

    private int waitSend() {
        synchronized (kcpLock) {
            return kcp == null ? 0 : kcp.waitSend();
        }
    }

    private void writeThroughKcp(byte[] data) {
        synchronized (kcpLock) {
            if (kcp == null) {
                return;
            }
            int ret = kcp.send(data);
            if (ret < 0) {
                Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE ikcp_send failed connectionId="
                        + connectionId + " ret=" + ret + " len=" + data.length);
                close("KCP_SESSION_FAILED");
                return;
            }
            kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
            kcp.flush();
        }
    }

    private void handleKcpOutput(byte[] data, int len) {
        if (!running || udpChannel == null) {
            return;
        }
        try {
            byte[] plain = new byte[len];
            System.arraycopy(data, 0, plain, 0, len);
            byte[] encrypted = crypto.encrypt(plain);
            udpChannel.write(ByteBuffer.wrap(encrypted));
            Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE UDP send to "
                    + serverAddr.getHostString() + ":" + serverAddr.getPort()
                    + " len=" + encrypted.length + " connectionId=" + connectionId);
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE UDP_SEND_FAILED connectionId="
                    + connectionId + " error=" + e.getMessage());
            close("UDP_SEND_FAILED");
        }
    }

    public boolean isClosed() {
        return closed.get();
    }

    public void close(String reason) {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        running = false;
        if (udpChannel != null) {
            try {
                udpChannel.close();
            } catch (IOException ignored) {
            }
            udpChannel = null;
        }
        if (updateTask != null) {
            updateTask.cancel(false);
            updateTask = null;
        }
        cancelSocks5ResponseTimeout();
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE connection closed reason=" + reason
                + " connectionId=" + connectionId);
        if (isRemoteFailure(reason)) {
            remoteStateCallback.onRemoteFailed(reason);
        }
        closeCallback.onClosed(reason);
    }

    private static boolean isRemoteFailure(String reason) {
        return reason != null
                && !"manager_stop".equals(reason)
                && !"tcp_rst".equals(reason)
                && !"tcp_fin".equals(reason);
    }

    private void cancelSocks5ResponseTimeout() {
        if (socks5ResponseTimeoutTask != null) {
            socks5ResponseTimeoutTask.cancel(false);
            socks5ResponseTimeoutTask = null;
        }
    }

    private static String hexPrefix(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(4, bytes.length); i++) {
            sb.append(String.format(Locale.US, "%02X", bytes[i]));
        }
        return sb.length() == 0 ? "-" : sb + "..";
    }

    private static String addrToString(byte[] addr) {
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "."
                + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
    }

    public interface DataCallback {
        void onData(byte[] data);
    }

    public interface CloseCallback {
        void onClosed(String reason);
    }

    public interface RemoteStateCallback {
        void onRemoteReachable();
        void onRemoteFailed(String reason);
    }
}
