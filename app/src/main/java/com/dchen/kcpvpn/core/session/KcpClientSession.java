package com.dchen.kcpvpn.core.session;

import com.dchen.kcpvpn.core.crypto.Crypto;
import com.dchen.kcpvpn.core.kcp.Kcp;
import com.dchen.kcpvpn.core.kcp.KcpConfig;
import com.dchen.kcpvpn.core.kcp.KcpOutputCallback;
import com.dchen.kcpvpn.core.protocol.KcpFrame;
import com.dchen.kcpvpn.core.protocol.KcpFrameCodec;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * KCP 客户端会话 - 管理 UDP 连接、KCP 协议、加密解密和 frame 编解码。
 */
public class KcpClientSession {

    // 背压排队上限：ikcp_send 只是把数据切段追加进 snd_queue，本身不设界，
    // 链路停摆时会一路吃内存。超过即判定会话不可恢复，明确关闭而不是无限增长。
    // 与 CppRemoteKcpSession 的同类上限保持一致。
    private static final int SEND_QUEUE_LIMIT_BYTES = 2 * 1024 * 1024;

    private final String sessionId;
    private final InetSocketAddress serverAddr;
    private final Crypto crypto;
    private final Kcp kcp;
    private final Object kcpLock;
    private final Object outboundLock = new Object();
    private final Queue<byte[]> outboundQueue = new ArrayDeque<>();
    private int outboundBytes;
    private final KcpFrameCodec frameCodec;

    private DatagramSocket udpSocket;
    private volatile boolean running;
    private volatile boolean connected;
    private final Object handshakeLock = new Object();
    private final AtomicLong lastPingTime = new AtomicLong(0);
    private final AtomicLong lastPongTime = new AtomicLong(System.currentTimeMillis());

    private final AtomicLong lastActivityTime;

    private Thread updateThread;
    private Thread recvThread;

    private volatile Consumer<KcpFrame> onFrameReceived;
    private volatile SocketProtector socketProtector;

    public KcpClientSession(String serverHost, int serverPort, Crypto crypto) {
        this.sessionId = "client-" + System.currentTimeMillis();
        this.serverAddr = new InetSocketAddress(serverHost, serverPort);
        this.crypto = crypto;
        this.kcp = new Kcp(KcpConfig.DEFAULT_CONV);
        this.kcpLock = new Object();
        this.frameCodec = new KcpFrameCodec(LogConfig.MODULE_KCP_CLIENT);

        this.running = false;
        this.connected = false;
        this.lastActivityTime = new AtomicLong(System.currentTimeMillis());

        kcp.setNodelay(KcpConfig.NODELAY_ENABLED, KcpConfig.NODELAY_INTERVAL,
                KcpConfig.NODELAY_RESEND, KcpConfig.NODELAY_NOCWND);
        kcp.setWndSize(KcpConfig.KCP_SNDWND, KcpConfig.KCP_RCVWND);
        kcp.setMtu(KcpConfig.KCP_MTU);

        kcp.setOutputCallback(new KcpOutputCallback() {
            @Override
            public void onOutput(byte[] data, int len) {
                handleKcpOutput(data, len);
            }
        });

        Logger.info(LogConfig.MODULE_KCP_CLIENT, "Session created: " + sessionId
                + ", server=" + serverHost + ":" + serverPort);
    }

    public void setSocketProtector(SocketProtector protector) {
        this.socketProtector = protector;
    }

    public boolean connect() {
        Logger.info(LogConfig.MODULE_KCP_CLIENT, "KcpClientSession.connect() begin");

        try {
            udpSocket = new DatagramSocket();
            udpSocket.setSoTimeout(1000);
            try {
                udpSocket.setReceiveBufferSize(SessionConfig.UDP_SO_RCVBUF_BYTES);
                udpSocket.setSendBufferSize(SessionConfig.UDP_SO_SNDBUF_BYTES);
            } catch (Exception e) {
                Logger.warning(LogConfig.MODULE_KCP_CLIENT, "UDP buffer size request failed: " + e.getMessage());
            }

            SocketProtector protector = socketProtector;
            if (protector != null) {
                boolean protectedOk = protector.protect(udpSocket);
                Logger.info(LogConfig.MODULE_KCP_CLIENT, "protect kcp udp socket=" + protectedOk);
                if (!protectedOk) {
                    throw new IOException("protect kcp udp socket failed");
                }
            } else {
                throw new IOException("missing SocketProtector for kcp udp socket");
            }

            running = true;
            connected = false;
            touchActivity();

            startUpdateThread();
            startRecvThread();

            sendFrame(new KcpFrame(KcpFrame.TYPE_HELLO, 0, null));
            long deadline = System.currentTimeMillis() + 3000;
            synchronized (handshakeLock) {
                while (running && !connected && System.currentTimeMillis() < deadline) {
                    try {
                        handshakeLock.wait(200);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            if (!connected) {
                Logger.warning(LogConfig.MODULE_KCP_CLIENT, "HELLO_ACK timeout: " + serverAddr);
                close();
                return false;
            }

            Logger.info(LogConfig.MODULE_KCP_CLIENT, "Connected to " + serverAddr);
            return true;
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_CLIENT, "Connect error: " + e.getMessage());
            close();
            return false;
        }
    }

    private void startUpdateThread() {
        updateThread = new Thread(() -> {
            while (running) {
                try {
                    long nowMs = System.currentTimeMillis();
                    synchronized (kcpLock) {
                        kcp.update((int) (nowMs & 0xFFFFFFFFL));
                        kcp.flush();
                    }
                    drainOutboundQueue();
                    Thread.sleep(KcpConfig.KCP_INTERVAL_MS);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "KCP-Update-" + sessionId);
        updateThread.start();
    }

    private void startRecvThread() {
        recvThread = new Thread(() -> {
            byte[] recvBuf = new byte[SessionConfig.UDP_RECV_BUF_SIZE];
            while (running) {
                try {
                    DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
                    udpSocket.receive(packet);

                    if (packet.getLength() > 0) {
                        byte[] data = new byte[packet.getLength()];
                        System.arraycopy(recvBuf, 0, data, 0, packet.getLength());
                        onReceive(data);
                    }
                } catch (SocketTimeoutException e) {
                    // 正常超时
                } catch (IOException e) {
                    if (running) {
                        Logger.error(LogConfig.MODULE_KCP_CLIENT, "UDP receive error: " + e.getMessage());
                    }
                    break;
                }
            }
        }, "KCP-Recv-" + sessionId);
        recvThread.start();
    }

    private void onReceive(byte[] encryptedData) {
        try {
            byte[] decrypted = crypto.decrypt(encryptedData);
            touchActivity();

            int ret;
            synchronized (kcpLock) {
                ret = kcp.input(decrypted);
            }
            if (ret < 0) {
                Logger.warning(LogConfig.MODULE_KCP_CLIENT, "ikcp_input rejected packet, ret=" + ret);
                return;
            }

            tryDeliverFrames();
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_KCP_CLIENT, "Receive error: " + e.getMessage());
        }
    }

    private void tryDeliverFrames() {
        Consumer<KcpFrame> cb = onFrameReceived;
        if (cb == null) {
            return;
        }

        while (true) {
            byte[] data;
            synchronized (kcpLock) {
                int peekSize = kcp.peekSize();
                if (peekSize <= 0) {
                    break;
                }

                byte[] buf = new byte[peekSize];
                int len = kcp.recv(buf);
                if (len <= 0) {
                    break;
                }

                data = new byte[len];
                System.arraycopy(buf, 0, data, 0, len);
            }

            List<KcpFrame> frames = frameCodec.decode(data);
            for (KcpFrame frame : frames) {
                Logger.info(LogConfig.MODULE_KCP_CLIENT, "FRAME RECV type="
                        + KcpFrame.frameTypeName(frame.getFrameType())
                        + " connectionId=" + frame.getConnectionId()
                        + " len=" + frame.getPayloadLength());
                if (!handleControlFrame(frame)) {
                    cb.accept(frame);
                }
            }
        }
    }

    private boolean handleControlFrame(KcpFrame frame) {
        if (frame.getFrameType() == KcpFrame.TYPE_HELLO_ACK) {
            connected = true;
            synchronized (handshakeLock) {
                handshakeLock.notifyAll();
            }
            Logger.info(LogConfig.MODULE_KCP_CLIENT, "HELLO_ACK received");
            return true;
        }
        if (frame.getFrameType() == KcpFrame.TYPE_PING) {
            sendFrame(new KcpFrame(KcpFrame.TYPE_PONG, 0, null));
            return true;
        }
        if (frame.getFrameType() == KcpFrame.TYPE_PONG) {
            touchActivity();
            lastPongTime.set(System.currentTimeMillis());
            Logger.debug(LogConfig.MODULE_KCP_CLIENT, "PONG received");
            return true;
        }
        return frame.getFrameType() == KcpFrame.TYPE_HELLO;
    }

    private void handleKcpOutput(byte[] data, int len) {
        if (!running || udpSocket == null) {
            return;
        }

        try {
            byte[] encrypted = crypto.encrypt(data);
            DatagramPacket packet = new DatagramPacket(encrypted, encrypted.length, serverAddr);
            udpSocket.send(packet);
            Logger.debug(LogConfig.MODULE_KCP_CLIENT, "KCP encrypted UDP send len=" + encrypted.length
                    + " plainLen=" + len + " dst=" + serverAddr);
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_KCP_CLIENT, "Encrypt/send error: " + e.getMessage());
        }
    }

    public void sendFrame(KcpFrame frame) {
        if (!running) {
            return;
        }

        byte[] data = KcpFrameCodec.encode(frame);
        boolean overflow;
        int queuedBytes;
        synchronized (outboundLock) {
            // 只有队列为空且 KCP 尚有余量才能直接写入；队列非空时必须继续排队，
            // 否则新帧会插到已排队数据前面，打乱 KCP 字节流顺序。
            if (outboundQueue.isEmpty() && hasSendCapacity()) {
                writeThroughKcp(data);
                logFrameSent(frame);
                return;
            }
            overflow = outboundBytes + data.length > SEND_QUEUE_LIMIT_BYTES;
            queuedBytes = outboundBytes;
            if (!overflow) {
                outboundQueue.add(data);
                outboundBytes += data.length;
            }
        }

        if (overflow) {
            Logger.error(LogConfig.MODULE_KCP_CLIENT, "KCP_SEND_QUEUE_OVERFLOW connectionId="
                    + frame.getConnectionId() + " queuedBytes=" + queuedBytes
                    + " len=" + data.length);
            close();
            return;
        }
        Logger.debug(LogConfig.MODULE_KCP_CLIENT, "FRAME QUEUED by backpressure type="
                + KcpFrame.frameTypeName(frame.getFrameType())
                + " connectionId=" + frame.getConnectionId()
                + " len=" + frame.getPayloadLength() + " queuedBytes=" + outboundBytes);
    }

    private void logFrameSent(KcpFrame frame) {
        Logger.info(LogConfig.MODULE_KCP_CLIENT, "FRAME SEND type="
                + KcpFrame.frameTypeName(frame.getFrameType())
                + " connectionId=" + frame.getConnectionId()
                + " len=" + frame.getPayloadLength());
    }

    /** KCP 发送队列余量判据，与 C++ 的 wait_send &lt; KCP_BACKPRESSURE_THRESHOLD 同构。 */
    private boolean hasSendCapacity() {
        synchronized (kcpLock) {
            return kcp.waitSend() < KcpConfig.KCP_BACKPRESSURE_THRESHOLD;
        }
    }

    private void writeThroughKcp(byte[] data) {
        synchronized (kcpLock) {
            int ret = kcp.send(data);
            if (ret < 0) {
                Logger.warning(LogConfig.MODULE_KCP_CLIENT, "ikcp_send returned " + ret
                        + " (invalid argument), len=" + data.length);
                return;
            }
            kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
            kcp.flush();
        }
    }

    /**
     * 更新线程把排队的出站帧按序补进 KCP，直到重新触及阈值。
     * 取出元素后必须仍在 outboundLock 内写 KCP：若先释放锁再写，并发的 sendFrame
     * 会看到队列已空且有余量而直接写入，抢到它前面，打乱字节流顺序。
     * 锁序 outboundLock → kcpLock 与 sendFrame 一致，不会成环。
     */
    private void drainOutboundQueue() {
        while (running) {
            synchronized (outboundLock) {
                if (outboundQueue.isEmpty() || !hasSendCapacity()) {
                    return;
                }
                byte[] next = outboundQueue.remove();
                outboundBytes -= next.length;
                writeThroughKcp(next);
            }
        }
    }

    public void setOnFrameReceived(Consumer<KcpFrame> callback) {
        this.onFrameReceived = callback;
    }

    public boolean isConnected() {
        return connected && running;
    }

    public boolean isAlive() {
        if (!running) {
            return false;
        }
        long age = System.currentTimeMillis() - lastActivityTime.get();
        long pingAt = lastPingTime.get();
        long pongAt = lastPongTime.get();
        return age < SessionConfig.KCP_TIMEOUT_MS && (pingAt == 0 || pongAt >= pingAt
                || System.currentTimeMillis() - pingAt < 10_000);
    }

    public void sendPing() {
        lastPingTime.set(System.currentTimeMillis());
        sendFrame(new KcpFrame(KcpFrame.TYPE_PING, 0, null));
    }

    public int waitSend() {
        synchronized (kcpLock) {
            return kcp.waitSend();
        }
    }

    private void touchActivity() {
        lastActivityTime.set(System.currentTimeMillis());
    }

    public synchronized void close() {
        if (!running) {
            return;
        }
        running = false;
        connected = false;

        Logger.info(LogConfig.MODULE_KCP_CLIENT, "Closing session: " + sessionId);

        if (updateThread != null) {
            updateThread.interrupt();
            try {
                updateThread.join(1000);
            } catch (InterruptedException ignored) {
            }
            updateThread = null;
        }
        if (recvThread != null) {
            recvThread.interrupt();
            try {
                recvThread.join(1000);
            } catch (InterruptedException ignored) {
            }
            recvThread = null;
        }

        if (udpSocket != null) {
            udpSocket.close();
            udpSocket = null;
        }

        Logger.info(LogConfig.MODULE_KCP_CLIENT, "Session closed: " + sessionId);
    }

    public String getSessionId() {
        return sessionId;
    }

    public InetSocketAddress getServerAddr() {
        return serverAddr;
    }
}
