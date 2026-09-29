package com.dchen.kcpvpn.vpn;

import com.dchen.kcpvpn.core.crypto.Crypto;
import com.dchen.kcpvpn.core.protocol.KcpFrame;
import com.dchen.kcpvpn.core.session.KcpClientSession;
import com.dchen.kcpvpn.core.session.SocketProtector;
import com.dchen.kcpvpn.core.session.SessionConfig;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 隧道管理器 - 管理 KCP 连接生命周期和重连。
 */
public class TunnelManager {

    private final String serverHost;
    private final int serverPort;
    private final String key;

    private volatile KcpClientSession session;
    private volatile Crypto crypto;

    private volatile boolean running;
    private final AtomicBoolean connecting = new AtomicBoolean(false);

    // 用户已请求停止。running 只表示"隧道当前是通的"，重连退避期间它一直是 false，
    // 所以不能用它判断"是否已停止"——那样既拦不住退避结束后的自动重连，又会让
    // checkConnection 误判。停止语义单独用一个标志表达。
    private final AtomicBoolean stopped = new AtomicBoolean(false);
    private volatile Thread reconnectThread;

    private final AtomicInteger reconnectAttempts;
    private final AtomicInteger reconnectDelayMs;
    private static final int INITIAL_DELAY_MS = 1000;
    private static final int MAX_DELAY_MS = 60000;
    private static final int DELAY_FACTOR = 2;

    private final AtomicLong uploadBytes;
    private final AtomicLong downloadBytes;
    private final AtomicLong connectionStartTime;

    private volatile Consumer<VpnConnectionState> stateCallback;
    private volatile Consumer<KcpFrame> frameReceivedCallback;
    private volatile SocketProtector socketProtector;

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
    }

    public void setStateCallback(Consumer<VpnConnectionState> callback) {
        this.stateCallback = callback;
    }

    public void setFrameReceivedCallback(Consumer<KcpFrame> callback) {
        this.frameReceivedCallback = callback;
    }

    public void setSocketProtector(SocketProtector protector) {
        this.socketProtector = protector;
    }

    public boolean connect() {
        // 外部调用（用户重新发起连接）：清掉上一次 disconnect 留下的停止标志，
        // 否则 connectInternal 会直接拒绝。重连线程走 connectInternal，不清标志。
        stopped.set(false);
        return connectInternal();
    }

    private boolean connectInternal() {
        if (stopped.get()) {
            Logger.info(LogConfig.MODULE_VPN, "Connect skipped: tunnel stopped");
            return false;
        }

        Logger.info(LogConfig.MODULE_VPN, "TunnelManager.connect() begin");

        if (running || !connecting.compareAndSet(false, true)) {
            Logger.warning(LogConfig.MODULE_VPN, "Already connecting or connected, running=" + running);
            return false;
        }

        updateState(VpnConnectionState.CONNECTING);

        try {
            crypto = new Crypto(key);

            session = new KcpClientSession(serverHost, serverPort, crypto);
            SocketProtector protector = socketProtector;
            if (protector != null) {
                session.setSocketProtector(protector);
                Logger.info(LogConfig.MODULE_VPN, "SocketProtector set for KcpClientSession");
            }

            session.setOnFrameReceived(frame -> {
                Consumer<KcpFrame> cb = frameReceivedCallback;
                if (cb != null) {
                    cb.accept(frame);
                }
                downloadBytes.addAndGet(frame.getPayloadLength());
            });

            if (!session.connect()) {
                Logger.error(LogConfig.MODULE_VPN, "KCP session.connect() returned false");
                connecting.set(false);
                updateState(VpnConnectionState.DISCONNECTED);
                return false;
            }

            if (stopped.get()) {
                // disconnect() 在 connect 阻塞期间到达：这次连接已经不该存在，
                // 立刻拆掉，否则会话会带着 UDP socket 和线程活到进程结束。
                Logger.info(LogConfig.MODULE_VPN, "Connect aborted: tunnel stopped during handshake");
                closeSession();
                connecting.set(false);
                updateState(VpnConnectionState.DISCONNECTED);
                return false;
            }

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

    public void sendFrame(KcpFrame frame) {
        if (!running) {
            Logger.warning(LogConfig.MODULE_VPN, "Not connected, cannot send frame");
            return;
        }

        KcpClientSession s = session;
        if (s == null) {
            Logger.warning(LogConfig.MODULE_VPN, "Session is null, cannot send frame");
            return;
        }

        s.sendFrame(frame);
        uploadBytes.addAndGet(frame.getPayloadLength());

        Logger.info(LogConfig.MODULE_VPN, "FRAME SEND type="
                + KcpFrame.frameTypeName(frame.getFrameType())
                + " connectionId=" + frame.getConnectionId()
                + " len=" + frame.getPayloadLength());
    }

    public void checkConnection() {
        if (stopped.get()) {
            return;
        }
        if (connecting.get()) {
            // 重连退避中：下一次尝试由 ReconnectThread 负责，这里不重复触发
            return;
        }

        KcpClientSession s = session;
        if (!running || s == null) {
            // 上一次重连尝试失败后 running 一直是 false。旧实现在这里直接 return，
            // 于是健康检查再也触发不了重连，隧道一直死到用户手动断开重连为止。
            Logger.warning(LogConfig.MODULE_VPN, "Tunnel down, triggering reconnect");
            reconnect();
            return;
        }

        if (!s.isAlive() || !s.isConnected()) {
            Logger.warning(LogConfig.MODULE_VPN, "Connection lost, triggering reconnect");
            reconnect();
        } else {
            s.sendPing();
        }
    }

    public void reconnect() {
        if (stopped.get()) {
            return;
        }
        if (!connecting.compareAndSet(false, true)) {
            return;
        }

        updateState(VpnConnectionState.RECONNECTING);
        closeSession();
        running = false;

        int attempts = reconnectAttempts.incrementAndGet();
        int delay = reconnectDelayMs.get();

        Logger.info(LogConfig.MODULE_RECONNECT, "Reconnect attempt " + attempts
                + ", delay " + delay + "ms");

        Thread t = new Thread(() -> {
            try {
                Thread.sleep(delay);

                // connectInternal 自己会做 CAS，所以必须先释放 connecting
                connecting.set(false);
                if (stopped.get()) {
                    return;
                }

                if (connectInternal()) {
                    Logger.info(LogConfig.MODULE_RECONNECT, "Reconnect successful");
                } else {
                    int newDelay = Math.min(delay * DELAY_FACTOR, MAX_DELAY_MS);
                    reconnectDelayMs.set(newDelay);
                    Logger.warning(LogConfig.MODULE_RECONNECT, "Reconnect failed, next delay: " + newDelay + "ms");
                }
            } catch (InterruptedException e) {
                Logger.debug(LogConfig.MODULE_RECONNECT, "Reconnect interrupted");
            } finally {
                connecting.set(false);
            }
        }, "ReconnectThread");
        reconnectThread = t;
        t.start();
    }

    public void disconnect() {
        // 先置停止标志、唤醒退避中的重连线程，再做清理。旧实现在 !running 时直接
        // return：重连退避期间 running 已经是 false，disconnect 什么也没做，退避
        // 结束后 ReconnectThread 仍然会 connect()，隧道在用户关闭之后自己复活。
        stopped.set(true);

        Thread t = reconnectThread;
        reconnectThread = null;
        if (t != null) {
            t.interrupt();
        }

        updateState(VpnConnectionState.DISCONNECTING);
        closeSession();
        running = false;
        reconnectAttempts.set(0);
        reconnectDelayMs.set(INITIAL_DELAY_MS);
        updateState(VpnConnectionState.DISCONNECTED);

        Logger.info(LogConfig.MODULE_VPN, "Tunnel disconnected");
    }

    private void closeSession() {
        if (session != null) {
            session.close();
            session = null;
        }
        // 每会话一个全新 Crypto（新 salt、新计数器起点），不复用重置旧实例
        crypto = null;
    }

    private void updateState(VpnConnectionState state) {
        Consumer<VpnConnectionState> cb = stateCallback;
        if (cb != null) {
            cb.accept(state);
        }
    }

    public long getUploadBytes() {
        return uploadBytes.get();
    }

    public long getDownloadBytes() {
        return downloadBytes.get();
    }

    public long getConnectionDuration() {
        if (!running) {
            return 0;
        }
        return (System.currentTimeMillis() - connectionStartTime.get()) / 1000;
    }

    public boolean isConnected() {
        return running && session != null && session.isConnected();
    }

    public int getReconnectAttempts() {
        return reconnectAttempts.get();
    }

    public void resetStats() {
        uploadBytes.set(0);
        downloadBytes.set(0);
    }
}
