package com.example.kcpvpn.vpn;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.session.KcpClientSession;
import com.example.kcpvpn.core.session.SocketProtector;
import com.example.kcpvpn.core.session.SessionConfig;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

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

        Logger.debug(LogConfig.MODULE_VPN, "Sent frame: connectionId="
                + frame.getConnectionId() + ", frameType="
                + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                + frame.getPayloadLength());
    }

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

    public void reconnect() {
        if (!connecting.compareAndSet(false, true)) {
            return;
        }

        updateState(VpnConnectionState.RECONNECTING);
        closeSession();

        int attempts = reconnectAttempts.incrementAndGet();
        int delay = reconnectDelayMs.get();

        Logger.info(LogConfig.MODULE_RECONNECT, "Reconnect attempt " + attempts
                + ", delay " + delay + "ms");

        new Thread(() -> {
            try {
                Thread.sleep(delay);

                if (connect()) {
                    Logger.info(LogConfig.MODULE_RECONNECT, "Reconnect successful");
                } else {
                    int newDelay = Math.min(delay * DELAY_FACTOR, MAX_DELAY_MS);
                    reconnectDelayMs.set(newDelay);
                    Logger.warning(LogConfig.MODULE_RECONNECT, "Reconnect failed, next delay: " + newDelay + "ms");
                }
            } catch (InterruptedException e) {
                Logger.debug(LogConfig.MODULE_RECONNECT, "Reconnect interrupted");
            }
            connecting.set(false);
        }, "ReconnectThread").start();
    }

    public void disconnect() {
        if (!running) {
            return;
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

        if (crypto != null) {
            crypto.reset();
        }
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
