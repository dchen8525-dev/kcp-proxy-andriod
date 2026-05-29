package com.example.kcpvpn.server;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.kcp.Kcp;
import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.kcp.KcpOutputCallback;
import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.protocol.KcpFrameCodec;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 服务端会话 - 与 C++ KCPSession 一致
 */
public class ServerSession {

    private final String sessionId;
    private final InetSocketAddress clientAddr;
    private final Crypto crypto;
    private final Kcp kcp;
    private final Object kcpLock;
    private final KcpFrameCodec frameCodec;

    private volatile boolean running;
    private final AtomicLong lastActivityTime;

    private Consumer<byte[]> sendCallback;
    private Consumer<KcpFrame> frameHandler;

    private Thread updateThread;

    /**
     * 创建服务端会话
     * @param clientAddr 客户端地址
     * @param crypto 加密实例（服务端方向）
     */
    public ServerSession(InetSocketAddress clientAddr, Crypto crypto) {
        this.sessionId = clientAddr.getAddress().getHostAddress() + ":" + clientAddr.getPort();
        this.clientAddr = clientAddr;
        this.crypto = crypto;
        this.kcp = new Kcp(KcpConfig.DEFAULT_CONV);
        this.kcpLock = new Object();
        this.frameCodec = new KcpFrameCodec(LogConfig.MODULE_KCP_SERVER);

        this.running = false;
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

        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession created: " + sessionId);
    }

    /**
     * 启动会话
     */
    public void start() {
        running = true;
        touchActivity();

        startUpdateThread();

        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession started: " + sessionId);
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
        }, "ServerKCP-Update-" + sessionId);
        updateThread.start();
    }

    /**
     * 处理接收到的数据（已解密）
     */
    public void receiveData(byte[] decryptedData) {
        if (!running) {
            return;
        }

        touchActivity();

        int ret;
        synchronized (kcpLock) {
            ret = kcp.input(decryptedData);
        }
        if (ret < 0) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "ikcp_input rejected packet, ret=" + ret);
            return;
        }

        deliverFrames();
    }

    /**
     * 处理 KCP 输出（加密并回调）
     */
    private void handleKcpOutput(byte[] data, int len) {
        if (!running || sendCallback == null) {
            return;
        }

        try {
            byte[] encrypted = crypto.encrypt(data);
            sendCallback.accept(encrypted);

            Logger.debug(LogConfig.MODULE_KCP_SERVER, "Output: " + data.length
                    + " plain -> " + encrypted.length + " encrypted");
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "Encrypt error: " + e.getMessage());
        }
    }

    public void sendFrame(KcpFrame frame) {
        if (!running) {
            return;
        }

        byte[] data = KcpFrameCodec.encode(frame);
        synchronized (kcpLock) {
            int ret = kcp.send(data);
            if (ret < 0) {
                Logger.error(LogConfig.MODULE_KCP_SERVER, "ikcp_send failed, ret=" + ret
                        + ", connectionId=" + frame.getConnectionId()
                        + ", frameType=" + KcpFrame.frameTypeName(frame.getFrameType())
                        + ", payloadLength=" + frame.getPayloadLength());
                return;
            }

            kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
        }

        Logger.debug(LogConfig.MODULE_KCP_SERVER, "Sent frame: connectionId="
                + frame.getConnectionId() + ", frameType="
                + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                + frame.getPayloadLength());
    }

    private void deliverFrames() {
        Consumer<KcpFrame> handler = frameHandler;
        if (handler == null) {
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
                Logger.debug(LogConfig.MODULE_KCP_SERVER, "Recv frame: connectionId="
                        + frame.getConnectionId() + ", frameType="
                        + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                        + frame.getPayloadLength());
                handler.accept(frame);
            }
        }
    }

    /**
     * 设置发送回调
     */
    public void setSendCallback(Consumer<byte[]> callback) {
        this.sendCallback = callback;
    }

    public void setFrameHandler(Consumer<KcpFrame> frameHandler) {
        this.frameHandler = frameHandler;
    }

    /**
     * 检查是否存活
     */
    public boolean isAlive() {
        if (!running) return false;
        long age = System.currentTimeMillis() - lastActivityTime.get();
        return age < ServerConfig.KCP_TIMEOUT_MS;
    }

    /**
     * 获取等待发送的数据大小
     */
    public int waitSend() {
        synchronized (kcpLock) {
            return kcp.waitSend();
        }
    }

    /**
     * 更新活动时间
     */
    private void touchActivity() {
        lastActivityTime.set(System.currentTimeMillis());
    }

    /**
     * 停止会话
     */
    public void stop() {
        if (!running) return;
        running = false;

        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession stopping: " + sessionId);

        if (updateThread != null) {
            updateThread.interrupt();
            updateThread = null;
        }

        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession stopped: " + sessionId);
    }

    /**
     * 获取会话 ID
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * 获取客户端地址
     */
    public InetSocketAddress getClientAddr() {
        return clientAddr;
    }
}
