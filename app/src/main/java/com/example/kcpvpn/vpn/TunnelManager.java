package com.example.kcpvpn.vpn;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.session.KcpClientSession;
import com.example.kcpvpn.core.session.SessionConfig;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 阧道管理器 - 管理 KCP 连接生命周期和重连
 */
public class TunnelManager {

    private final String serverHost;
    private final int serverPort;
    private final String key;

    private volatile KcpClientSession session;
    private volatile Crypto crypto;

    private volatile boolean running;
    private final AtomicBoolean connecting = new AtomicBoolean(false);

    // 重连参数（指数退避）
    private final AtomicInteger reconnectAttempts;
    private final AtomicInteger reconnectDelayMs;
    private static final int INITIAL_DELAY_MS = 1000;
    private static final int MAX_DELAY_MS = 60000;
    private static final int DELAY_FACTOR = 2;

    // 重连定时器
    private final ScheduledExecutorService reconnectExecutor;

    // 流量统计
    private final AtomicLong uploadBytes;
    private final AtomicLong downloadBytes;
    private final AtomicLong connectionStartTime;

    // 状态回调
    private volatile Consumer<VpnConnectionState> stateCallback;
    private volatile Consumer<byte[]> dataReceivedCallback;

    public TunnelManager(String serverHost, int serverPort, String key) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.key = key;

        this.running = false;
        this.reconnectAttempts = new AtomicInteger(0);
        this.reconnectDelayMs = new AtomicInteger(INITIAL_DELAY_MS);
        this.uploadBytes = new AtomicLong(0);
        this.downloadBytes = new AtomicLong(0);
        this.connectionStartTime = new AtomicLong(0);
        this.reconnectExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ReconnectThread");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * 设置状态回调
     */
    public void setStateCallback(Consumer<VpnConnectionState> callback) {
        this.stateCallback = callback;
    }

    /**
     * 设置数据接收回调
     */
    public void setDataReceivedCallback(Consumer<byte[]> callback) {
        this.dataReceivedCallback = callback;
    }

    /**
     * 连接阧道
     * @return true 成功
     */
    public boolean connect() {
        Logger.info(LogConfig.MODULE_VPN, "TunnelManager.connect() begin");

        if (running || !connecting.compareAndSet(false, true)) {
            Logger.warning(LogConfig.MODULE_VPN, "Already connecting or connected, running=" + running);
            return false;
        }

        updateState(VpnConnectionState.CONNECTING);

        try {
            // 创建加密实例
            Logger.info(LogConfig.MODULE_VPN, "Creating Crypto instance with key length=" + key.length());
            crypto = new Crypto(key);
            Logger.info(LogConfig.MODULE_VPN, "Crypto instance created");

            // 创建 KCP 会话
            Logger.info(LogConfig.MODULE_VPN, "Creating KcpClientSession: " + serverHost + ":" + serverPort);
            session = new KcpClientSession(serverHost, serverPort, crypto);
            Logger.info(LogConfig.MODULE_VPN, "KcpClientSession created");

            session.setOnDataReceived(data -> {
                Consumer<byte[]> cb = dataReceivedCallback;
                if (cb != null) {
                    cb.accept(data);
                }
                downloadBytes.addAndGet(data.length);
            });

            // 连接
            Logger.info(LogConfig.MODULE_VPN, "Calling session.connect()...");
            if (!session.connect()) {
                Logger.error(LogConfig.MODULE_VPN, "KCP session.connect() returned false");
                connecting.set(false);
                updateState(VpnConnectionState.DISCONNECTED);
                return false;
            }

            Logger.info(LogConfig.MODULE_VPN, "KCP session connected");

            running = true;
            connecting.set(false);
            reconnectAttempts.set(0);
            reconnectDelayMs.set(INITIAL_DELAY_MS);
            connectionStartTime.set(System.currentTimeMillis());

            updateState(VpnConnectionState.CONNECTED);
            Logger.info(LogConfig.MODULE_VPN, "Tunnel connected: " + serverHost + ":" + serverPort);

            return true;

        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Connect error: " + e.getMessage());
            e.printStackTrace();
            connecting.set(false);
            updateState(VpnConnectionState.DISCONNECTED);
            return false;
        }
    }

    /**
     * 发送数据
     */
    public void sendData(byte[] data) {
        if (!running) {
            Logger.warning(LogConfig.MODULE_VPN, "Not connected, cannot send data");
            return;
        }

        KcpClientSession s = session;
        if (s == null) {
            Logger.warning(LogConfig.MODULE_VPN, "Session is null, cannot send data");
            return;
        }

        s.sendData(data);
        uploadBytes.addAndGet(data.length);

        Logger.debug(LogConfig.MODULE_VPN, "Sent " + data.length + " bytes");
    }

    /**
     * 发送 SOCKS5 请求
     */
    public void sendSocks5Request(String host, int port) {
        if (!running) {
            return;
        }

        KcpClientSession s = session;
        if (s == null) {
            return;
        }

        s.sendSocks5Request(host, port);
        Logger.info(LogConfig.MODULE_SOCKS5, "Sent SOCKS5 request: " + host + ":" + port);
    }

    /**
     * 检查连接状态
     */
    public void checkConnection() {
        KcpClientSession s = session;
        if (!running || s == null) {
            return;
        }

        if (!s.isAlive() || !s.isConnected()) {
            Logger.warning(LogConfig.MODULE_VPN, "Connection lost, triggering reconnect");
            reconnect();
        }
    }

    /**
     * 重新连接（指数退避）
     * 不在 disconnectInternal 中重置退避参数，保留指数退避状态
     */
    public void reconnect() {
        if (!connecting.compareAndSet(false, true)) {
            return;
        }

        updateState(VpnConnectionState.RECONNECTING);

        // 关闭旧连接（不重置退避参数）
        closeSession();

        // 计算重连延迟
        int attempts = reconnectAttempts.incrementAndGet();
        int delay = reconnectDelayMs.get();

        Logger.info(LogConfig.MODULE_RECONNECT, "Reconnect attempt " + attempts
                + ", delay " + delay + "ms");

        // 使用 ScheduledExecutorService 调度重连，避免无限创建线程
        reconnectExecutor.schedule(() -> {
            try {
                if (connect()) {
                    Logger.info(LogConfig.MODULE_RECONNECT, "Reconnect successful");
                } else {
                    // 更新延迟（指数退避）
                    int newDelay = Math.min(delay * DELAY_FACTOR, MAX_DELAY_MS);
                    reconnectDelayMs.set(newDelay);

                    Logger.warning(LogConfig.MODULE_RECONNECT, "Reconnect failed, next delay: " + newDelay + "ms");
                }
            } catch (Exception e) {
                Logger.error(LogConfig.MODULE_RECONNECT, "Reconnect error: " + e.getMessage());
            } finally {
                connecting.set(false);
            }
        }, delay, TimeUnit.MILLISECONDS);
    }

    /**
     * 断开连接
     */
    public void disconnect() {
        if (!running) {
            return;
        }

        updateState(VpnConnectionState.DISCONNECTING);
        closeSession();
        running = false;
        // 重置退避参数（仅在用户主动断开时重置）
        reconnectAttempts.set(0);
        reconnectDelayMs.set(INITIAL_DELAY_MS);
        updateState(VpnConnectionState.DISCONNECTED);

        Logger.info(LogConfig.MODULE_VPN, "Tunnel disconnected");
    }

    /**
     * 关闭会话（不重置退避参数）
     */
    private void closeSession() {
        if (session != null) {
            session.close();
            session = null;
        }

        if (crypto != null) {
            crypto.reset();
        }
    }

    /**
     * 更新状态
     */
    private void updateState(VpnConnectionState state) {
        Consumer<VpnConnectionState> cb = stateCallback;
        if (cb != null) {
            cb.accept(state);
        }
    }

    /**
     * 获取上传流量
     */
    public long getUploadBytes() {
        return uploadBytes.get();
    }

    /**
     * 获取下载流量
     */
    public long getDownloadBytes() {
        return downloadBytes.get();
    }

    /**
     * 获取连接时长（秒）
     */
    public long getConnectionDuration() {
        if (!running) {
            return 0;
        }
        return (System.currentTimeMillis() - connectionStartTime.get()) / 1000;
    }

    /**
     * 检查是否连接
     */
    public boolean isConnected() {
        return running && session != null && session.isConnected();
    }

    /**
     * 获取重连次数
     */
    public int getReconnectAttempts() {
        return reconnectAttempts.get();
    }

    /**
     * 重置流量统计
     */
    public void resetStats() {
        uploadBytes.set(0);
        downloadBytes.set(0);
    }
}