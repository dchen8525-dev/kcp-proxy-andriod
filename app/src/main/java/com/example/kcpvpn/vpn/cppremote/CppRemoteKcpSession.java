package com.example.kcpvpn.vpn.cppremote;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.kcp.Kcp;
import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.session.SocketProtector;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicBoolean;

public class CppRemoteKcpSession {
    private static final int UDP_RECV_BUF_SIZE = 4096;
    private static final int KCP_RECV_BUF_SIZE = 64 * 1024;
    private static final int PENDING_LIMIT_BYTES = 512 * 1024;

    private final long connectionId;
    private final InetSocketAddress serverAddr;
    private final String key;
    private final byte[] dstAddr;
    private final int dstPort;
    private final SocketProtector socketProtector;
    private final DataCallback dataCallback;
    private final CloseCallback closeCallback;
    private final Object kcpLock = new Object();
    private final Object pendingLock = new Object();
    private final Queue<byte[]> pendingClientData = new ArrayDeque<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);

    private DatagramSocket udpSocket;
    private Kcp kcp;
    private Crypto crypto;
    private Thread recvThread;
    private Thread updateThread;
    private volatile boolean running;
    private volatile boolean socks5Done;
    private int pendingBytes;

    public CppRemoteKcpSession(long connectionId, String serverHost, int serverPort, String key,
                               byte[] dstAddr, int dstPort, SocketProtector socketProtector,
                               DataCallback dataCallback, CloseCallback closeCallback) {
        this.connectionId = connectionId;
        this.serverAddr = new InetSocketAddress(serverHost, serverPort);
        this.key = key;
        this.dstAddr = dstAddr.clone();
        this.dstPort = dstPort;
        this.socketProtector = socketProtector;
        this.dataCallback = dataCallback;
        this.closeCallback = closeCallback;
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

            udpSocket = new DatagramSocket();
            udpSocket.setSoTimeout(1000);
            boolean protectedOk = socketProtector != null && socketProtector.protect(udpSocket);
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE KCP UDP socket protected=" + protectedOk
                    + " connectionId=" + connectionId);
            if (!protectedOk) {
                throw new IOException("KCP_SOCKET_PROTECT_FAILED");
            }
            udpSocket.connect(serverAddr);

            running = true;
            startUpdateThread();
            startRecvThread();

            byte[] request = CppSocks5RequestBuilder.buildIpv4Connect(dstAddr, dstPort);
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE SOCKS5 CONNECT connectionId=" + connectionId
                    + " dst=" + addrToString(dstAddr) + ":" + dstPort);
            Logger.info(LogConfig.MODULE_VPN, "SOCKS5 request hex=" + toHex(request)
                    + " connectionId=" + connectionId);
            sendRaw(request);
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
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE queued TCP payload before SOCKS5 connectionId="
                    + connectionId + " len=" + data.length);
            return;
        }
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE TCP payload -> KCP raw len=" + data.length
                + " connectionId=" + connectionId);
        sendRaw(data);
    }

    private void startUpdateThread() {
        updateThread = new Thread(() -> {
            while (running) {
                try {
                    synchronized (kcpLock) {
                        kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
                        kcp.flush();
                    }
                    Thread.sleep(KcpConfig.KCP_INTERVAL_MS);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "CPP-KCP-Update-" + connectionId);
        updateThread.setDaemon(true);
        updateThread.start();
    }

    private void startRecvThread() {
        recvThread = new Thread(() -> {
            byte[] buf = new byte[UDP_RECV_BUF_SIZE];
            while (running) {
                try {
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    udpSocket.receive(packet);
                    if (packet.getLength() <= 0) {
                        continue;
                    }
                    byte[] encrypted = new byte[packet.getLength()];
                    System.arraycopy(packet.getData(), packet.getOffset(), encrypted, 0, packet.getLength());
                    onUdpPacket(encrypted);
                } catch (SocketTimeoutException ignored) {
                } catch (IOException e) {
                    if (running) {
                        Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE UDP receive failed connectionId="
                                + connectionId + " error=" + e.getMessage());
                        close("CPP_SERVER_NO_RESPONSE");
                    }
                    break;
                }
            }
        }, "CPP-KCP-Recv-" + connectionId);
        recvThread.setDaemon(true);
        recvThread.start();
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
                Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE KCP raw -> TCP payload len=" + data.length
                        + " connectionId=" + connectionId);
                dataCallback.onData(data);
            }
        }
    }

    private void handleSocks5Response(byte[] data) {
        int responseLen = CppSocks5RequestBuilder.socks5ResponseLength(data);
        if (responseLen < 0) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE SOCKS5_RESPONSE_FAILED connectionId="
                    + connectionId + " len=" + data.length);
            close("SOCKS5_RESPONSE_FAILED");
            return;
        }
        int status = data[1] & 0xFF;
        Logger.info(LogConfig.MODULE_VPN, String.format(Locale.US,
                "CPP_REMOTE SOCKS5 response rep=0x%02X connectionId=%d", status, connectionId));
        if (status != 0) {
            close("SOCKS5_CONNECT_FAILED");
            return;
        }
        socks5Done = true;
        flushPendingClientData();
        if (data.length > responseLen) {
            byte[] extra = new byte[data.length - responseLen];
            System.arraycopy(data, responseLen, extra, 0, extra.length);
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
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE flush queued TCP payload len=" + data.length
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
        if (!running || udpSocket == null) {
            return;
        }
        try {
            byte[] plain = new byte[len];
            System.arraycopy(data, 0, plain, 0, len);
            byte[] encrypted = crypto.encrypt(plain);
            udpSocket.send(new DatagramPacket(encrypted, encrypted.length, serverAddr));
            Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE UDP send to "
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
        if (recvThread != null) {
            recvThread.interrupt();
            recvThread = null;
        }
        if (updateThread != null) {
            updateThread.interrupt();
            updateThread = null;
        }
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE connection closed reason=" + reason
                + " connectionId=" + connectionId);
        closeCallback.onClosed(reason);
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
}
