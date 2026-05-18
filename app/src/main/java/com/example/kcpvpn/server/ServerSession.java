package com.example.kcpvpn.server;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.kcp.Kcp;
import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.kcp.KcpOutputCallback;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;
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

    private volatile boolean running;
    private volatile boolean handshakeDone;
    private final AtomicLong lastActivityTime;
    private final AtomicBoolean socks5ReadPending;
    private final AtomicBoolean forwardReadPending;

    private Consumer<byte[]> sendCallback;

    private Thread updateThread;

    private byte[] pendingReadBuffer;
    private Consumer<byte[]> pendingReadHandler;

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

        this.running = false;
        this.handshakeDone = false;
        this.lastActivityTime = new AtomicLong(System.currentTimeMillis());
        this.socks5ReadPending = new AtomicBoolean(false);
        this.forwardReadPending = new AtomicBoolean(false);

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
                    kcp.update((int) (nowMs & 0xFFFFFFFFL));

                    tryFulfillRead();

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

        int ret = kcp.input(decryptedData);
        if (ret < 0) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "ikcp_input rejected packet, ret=" + ret);
            return;
        }

        tryFulfillRead();
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

    /**
     * 发送数据
     */
    public void sendData(byte[] data) {
        if (!running) {
            return;
        }

        int ret = kcp.send(data);
        if (ret < 0) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "ikcp_send failed, ret=" + ret);
            return;
        }

        kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));

        Logger.debug(LogConfig.MODULE_KCP_SERVER, "Sent " + data.length + " bytes");
    }

    /**
     * 异步读取数据
     */
    public void asyncReadSome(byte[] buffer, Consumer<byte[]> handler) {
        if (!running) {
            handler.accept(null);
            return;
        }

        pendingReadBuffer = buffer;
        pendingReadHandler = handler;
        tryFulfillRead();
    }

    /**
     * 尝试读取数据
     */
    private synchronized void tryFulfillRead() {
        if (pendingReadBuffer == null || pendingReadHandler == null) {
            return;
        }

        int peekSize = kcp.peekSize();
        if (peekSize <= 0) {
            return;
        }

        byte[] buf = new byte[peekSize];
        int len = kcp.recv(buf);
        if (len <= 0) {
            return;
        }

        Consumer<byte[]> handler = pendingReadHandler;
        pendingReadBuffer = null;
        pendingReadHandler = null;

        byte[] data = new byte[len];
        System.arraycopy(buf, 0, data, 0, len);

        handler.accept(data);
    }

    /**
     * 设置发送回调
     */
    public void setSendCallback(Consumer<byte[]> callback) {
        this.sendCallback = callback;
    }

    /**
     * 标记握手完成
     */
    public void markHandshakeDone() {
        handshakeDone = true;
        Logger.info(LogConfig.MODULE_KCP_SERVER, "SOCKS5 handshake done: " + sessionId);
    }

    /**
     * 检查握手是否完成
     */
    public boolean isHandshakeDone() {
        return handshakeDone;
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
        return kcp.waitSend();
    }

    /**
     * 设置 SOCK5 读取等待状态
     */
    public void setSocks5ReadPending(boolean pending) {
        socks5ReadPending.set(pending);
    }

    /**
     * 检查是否 SOCKS5 读取等待
     */
    public boolean isSocks5ReadPending() {
        return socks5ReadPending.get();
    }

    /**
     * 设置转发读取等待状态
     */
    public void setForwardReadPending(boolean pending) {
        forwardReadPending.set(pending);
    }

    /**
     * 检查是否转发读取等待
     */
    public boolean isForwardReadPending() {
        return forwardReadPending.get();
    }

    /**
     * 尝试设置转发读取等待（原子操作）
     */
    public boolean trySetForwardReadPending() {
        return forwardReadPending.compareAndSet(false, true);
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

        // 清理等待的读取
        if (pendingReadHandler != null) {
            pendingReadHandler.accept(null);
            pendingReadHandler = null;
            pendingReadBuffer = null;
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