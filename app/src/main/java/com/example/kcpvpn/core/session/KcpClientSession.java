package com.example.kcpvpn.core.session;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.kcp.Kcp;
import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.kcp.KcpOutputCallback;
import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.protocol.KcpFrameCodec;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * KCP 客户端会话 - 与 C++ KCPClientSession 一致
 * 管理 UDP 连接、KCP 协议、加密解密
 */
public class KcpClientSession {

    private final String sessionId;
    private final InetSocketAddress serverAddr;
    private final Crypto crypto;
    private final Kcp kcp;
    private final Object kcpLock;
    private final KcpFrameCodec frameCodec;

    private DatagramSocket udpSocket;
    private volatile boolean running;
    private volatile boolean connected;

    private final AtomicLong lastActivityTime;

    private Thread updateThread;
    private Thread recvThread;

    private volatile Consumer<KcpFrame> onFrameReceived;

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

        // 配置 KCP
        kcp.setNodelay(KcpConfig.NODELAY_ENABLED, KcpConfig.NODELAY_INTERVAL,
                KcpConfig.NODELAY_RESEND, KcpConfig.NODELAY_NOCWND);
        kcp.setWndSize(KcpConfig.KCP_SNDWND, KcpConfig.KCP_RCVWND);
        kcp.setMtu(KcpConfig.KCP_MTU);

        // 设置输出回调
        kcp.setOutputCallback(new KcpOutputCallback() {
            @Override
            public void onOutput(byte[] data, int len) {
                handleKcpOutput(data, len);
            }
        });

        Logger.info("kcp_client", "Session created: " + sessionId
                + ", server=" + serverHost + ":" + serverPort);
    }

    /**
     * 连接到服务端
     */
    public boolean connect() {
        Logger.info(LogConfig.MODULE_KCP_CLIENT, "KcpClientSession.connect() begin");

        try {
            udpSocket = new DatagramSocket();
            udpSocket.setSoTimeout(1000);

            running = true;
            connected = true;
            touchActivity();

            startUpdateThread();
            startRecvThread();

            Logger.info(LogConfig.MODULE_KCP_CLIENT, "Connected to " + serverAddr);

            return true;
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_CLIENT, "Connect error: " + e.getMessage());
            close();
            return false;
        }
    }

    /**
     * 启动 KCP 更新线程
     */
    private void startUpdateThread() {
        updateThread = new Thread(() -> {
            while (running) {
                try {
                    long nowMs = System.currentTimeMillis();
                    synchronized (kcpLock) {
                        kcp.update((int) (nowMs & 0xFFFFFFFFL));
                    }
                    Thread.sleep(KcpConfig.KCP_INTERVAL_MS);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "KCP-Update-" + sessionId);
        updateThread.start();
    }

    /**
     * 启动 UDP 接收线程
     */
    private void startRecvThread() {
        recvThread = new Thread(() -> {
            byte[] recvBuf = new byte[SessionConfig.UDP_RECV_BUF_SIZE];
            while (running && connected) {
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
                    if (running && connected) {
                        Logger.error("kcp_client", "UDP receive error: " + e.getMessage());
                    }
                    break;
                }
            }
        }, "KCP-Recv-" + sessionId);
        recvThread.start();
    }

    /**
     * 处理接收到的 UDP 数据
     */
    private void onReceive(byte[] encryptedData) {
        try {
            byte[] decrypted = crypto.decrypt(encryptedData);
            touchActivity();

            int ret;
            synchronized (kcpLock) {
                ret = kcp.input(decrypted);
            }
            if (ret < 0) {
                Logger.warning("kcp_client", "ikcp_input rejected packet, ret=" + ret);
                return;
            }

            // 如果有数据接收回调且 KCP 中有数据，直接读取
            tryDeliverData();
        } catch (Exception e) {
            Logger.error("kcp_client", "Receive error: " + e.getMessage());
        }
    }

    /**
     * 尝试将 KCP 接收的数据直接交付给回调
     */
    private void tryDeliverData() {
        Consumer<KcpFrame> cb = onFrameReceived;
        if (cb == null) return;

        while (true) {
            byte[] data;
            synchronized (kcpLock) {
                int peekSize = kcp.peekSize();
                if (peekSize <= 0) break;

                byte[] buf = new byte[peekSize];
                int len = kcp.recv(buf);
                if (len <= 0) break;

                data = new byte[len];
                System.arraycopy(buf, 0, data, 0, len);
            }

            List<KcpFrame> frames = frameCodec.decode(data);
            for (KcpFrame frame : frames) {
                Logger.debug(LogConfig.MODULE_KCP_CLIENT, "Recv frame: connectionId="
                        + frame.getConnectionId() + ", frameType="
                        + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                        + frame.getPayloadLength());
                cb.accept(frame);
            }
        }
    }

    /**
     * 处理 KCP 输出（加密并发送）
     */
    private void handleKcpOutput(byte[] data, int len) {
        if (!running || !connected || udpSocket == null) {
            return;
        }

        try {
            byte[] encrypted = crypto.encrypt(data);
            DatagramPacket packet = new DatagramPacket(encrypted, encrypted.length, serverAddr);
            udpSocket.send(packet);
        } catch (Exception e) {
            Logger.error("kcp_client", "Encrypt/send error: " + e.getMessage());
        }
    }

    public void sendFrame(KcpFrame frame) {
        if (!running || !connected) {
            return;
        }

        byte[] data = KcpFrameCodec.encode(frame);
        synchronized (kcpLock) {
            int ret = kcp.send(data);
            if (ret < 0) {
                Logger.warning("kcp_client", "ikcp_send returned " + ret + " (queue may be full)");
                return;
            }

            kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
        }

        Logger.debug(LogConfig.MODULE_KCP_CLIENT, "Sent frame: connectionId="
                + frame.getConnectionId() + ", frameType="
                + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                + frame.getPayloadLength());
    }

    /**
     * 设置数据接收回调
     */
    public void setOnFrameReceived(Consumer<KcpFrame> callback) {
        this.onFrameReceived = callback;
    }

    /**
     * 检查是否连接
     */
    public boolean isConnected() {
        return connected && running;
    }

    /**
     * 检查是否存活
     */
    public boolean isAlive() {
        if (!running) return false;
        long age = System.currentTimeMillis() - lastActivityTime.get();
        return age < SessionConfig.KCP_TIMEOUT_MS;
    }

    public int waitSend() {
        return kcp.waitSend();
    }

    private void touchActivity() {
        lastActivityTime.set(System.currentTimeMillis());
    }

    /**
     * 关闭会话 — synchronized 防止双重关闭，join 线程确保安全
     */
    public synchronized void close() {
        if (!running) return;
        running = false;
        connected = false;

        Logger.info("kcp_client", "Closing session: " + sessionId);

        // 停止线程
        if (updateThread != null) {
            updateThread.interrupt();
            try { updateThread.join(1000); } catch (InterruptedException ignored) {}
            updateThread = null;
        }
        if (recvThread != null) {
            recvThread.interrupt();
            try { recvThread.join(1000); } catch (InterruptedException ignored) {}
            recvThread = null;
        }

        // 关闭 socket（会解除 recvThread 的 DatagramSocket.receive 阻塞）
        if (udpSocket != null) {
            udpSocket.close();
            udpSocket = null;
        }

        Logger.info("kcp_client", "Session closed: " + sessionId);
    }

    public String getSessionId() {
        return sessionId;
    }

    public InetSocketAddress getServerAddr() {
        return serverAddr;
    }
}
