package com.dchen.kcpvpn.vpn.cppremote;

import com.dchen.kcpvpn.core.crypto.Crypto;
import com.dchen.kcpvpn.core.kcp.Kcp;
import com.dchen.kcpvpn.core.kcp.KcpConfig;
import com.dchen.kcpvpn.core.session.SocketProtector;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.Queue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class CppRemoteKcpSession {
    private static final int UDP_RECV_BUF_SIZE = 4096;
    private static final int KCP_RECV_BUF_SIZE = 64 * 1024;
    private static final int PENDING_LIMIT_BYTES = 512 * 1024;
    private static final int SOCKS5_RESPONSE_TIMEOUT_SEC = 10;

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
    private final Queue<byte[]> pendingClientData = new ArrayDeque<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final CppSocks5ResponseBuffer socks5ResponseBuffer = new CppSocks5ResponseBuffer();
    private final ByteBuffer udpRecvBuffer = ByteBuffer.allocate(UDP_RECV_BUF_SIZE);

    private DatagramSocket udpSocket;
    private DatagramChannel udpChannel;
    private Kcp kcp;
    private Crypto crypto;
    private ScheduledFuture<?> updateTask;
    private ScheduledFuture<?> socks5ResponseTimeoutTask;
    private volatile boolean running;
    private volatile boolean socks5Done;
    private int pendingBytes;

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
            udpSocket = udpChannel.socket();
            boolean protectedOk = socketProtector != null && socketProtector.protect(udpSocket);
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE KCP UDP socket protected=" + protectedOk
                    + " connectionId=" + connectionId);
            if (!protectedOk) {
                throw new IOException("KCP_SOCKET_PROTECT_FAILED");
            }
            udpChannel.connect(serverAddr);

            running = true;
            startUpdateThread();

            byte[] request = CppSocks5RequestBuilder.buildIpv4Connect(dstAddr, dstPort);
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE SOCKS5 CONNECT connectionId=" + connectionId
                    + " dst=" + addrToString(dstAddr) + ":" + dstPort);
            Logger.debug(LogConfig.MODULE_VPN, "SOCKS5 request hex=" + toHex(request)
                    + " connectionId=" + connectionId);
            sendRaw(request);
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

    private void startUpdateThread() {
        updateTask = kcpScheduler.scheduleAtFixedRate(() -> {
            if (!running) {
                return;
            }
            synchronized (kcpLock) {
                kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
                kcp.flush();
            }
            pollUdpPackets();
        }, 0, KcpConfig.KCP_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    private void startSocks5ResponseTimeout() {
        socks5ResponseTimeoutTask = kcpScheduler.schedule(() -> {
            if (running && !socks5Done) {
                Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE SOCKS5 response timeout connectionId="
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
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("replay or stale counter")) {
                Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE replay/stale packet dropped connectionId="
                        + connectionId + " error=" + e.getMessage());
                return;
            }
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE receive failed connectionId=" + connectionId
                    + " error=" + e.getMessage());
            close("CRYPTO_MISMATCH");
        }
    }

    private void deliverKcpData() {
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

            if (!socks5Done) {
                handleSocks5Response(data);
            } else {
                Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE KCP raw -> TCP payload len=" + data.length
                        + " connectionId=" + connectionId);
                dataCallback.onData(data);
            }
        }
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
        synchronized (kcpLock) {
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

    public void close(String reason) {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        running = false;
        if (udpSocket != null) {
            udpSocket.close();
            udpSocket = null;
        }
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

    private static String addrToString(byte[] addr) {
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "."
                + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 3);
        for (int i = 0; i < data.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            int value = data[i] & 0xFF;
            if (value < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(value).toUpperCase(Locale.US));
        }
        return sb.toString();
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
