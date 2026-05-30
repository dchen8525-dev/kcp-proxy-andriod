package com.dchen.kcpvpn.vpn.cppremote;

import com.dchen.kcpvpn.core.session.SocketProtector;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class CppRemoteTunnelManager {
    public enum RemoteState {
        STARTED,
        REMOTE_REACHABLE,
        REMOTE_FAILED
    }

    private final String serverHost;
    private final int serverPort;
    private final String key;
    private final Map<Long, CppRemoteKcpSession> sessions = new ConcurrentHashMap<>();
    private final AtomicBoolean remoteReachable = new AtomicBoolean(false);
    private volatile SocketProtector socketProtector;
    private volatile StateCallback stateCallback;
    private volatile ScheduledExecutorService kcpScheduler;
    private volatile boolean running;

    public CppRemoteTunnelManager(String serverHost, int serverPort, String key) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.key = key;
    }

    public void setSocketProtector(SocketProtector socketProtector) {
        this.socketProtector = socketProtector;
    }

    public void setStateCallback(StateCallback stateCallback) {
        this.stateCallback = stateCallback;
    }

    public boolean start() {
        if (socketProtector == null) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE start failed: missing SocketProtector");
            return false;
        }
        kcpScheduler = Executors.newScheduledThreadPool(1,
                namedThreadFactory("CPP-KCP-Update"));
        running = true;
        Logger.info(LogConfig.MODULE_VPN, "mode=CPP_REMOTE server=" + serverHost + ":" + serverPort
                + " protocol=socks5-over-kcp-raw-stream socketProtected=true"
                + " keyLength=" + (key == null ? 0 : key.length())
                + " crypto=CPP_COMPATIBLE_AES_128_GCM");
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE KCP conv=1 nodelay=1 interval=10"
                + " resend=5 nc=1 sndWnd=256 rcvWnd=512 mtu=1400 timeout=60s");
        notifyState(RemoteState.STARTED, "local VPN/tunnel manager started");
        return true;
    }

    public void createConnection(long connectionId, byte[] dstAddr, int dstPort,
                                 CppRemoteKcpSession.DataCallback dataCallback,
                                 CppRemoteKcpSession.CloseCallback closeCallback) {
        if (!running) {
            Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE createConnection ignored, manager stopped");
            return;
        }
        CppRemoteKcpSession session = new CppRemoteKcpSession(connectionId, serverHost, serverPort,
                key, dstAddr, dstPort, socketProtector, dataCallback, reason -> {
            sessions.remove(connectionId);
            closeCallback.onClosed(reason);
        }, new CppRemoteKcpSession.RemoteStateCallback() {
            @Override
            public void onRemoteReachable() {
                if (remoteReachable.compareAndSet(false, true)) {
                    notifyState(RemoteState.REMOTE_REACHABLE, "valid SOCKS5 response received");
                }
            }

            @Override
            public void onRemoteFailed(String reason) {
                if (!remoteReachable.get()) {
                    notifyState(RemoteState.REMOTE_FAILED, reason);
                }
            }
        }, kcpScheduler);
        CppRemoteKcpSession existing = sessions.putIfAbsent(connectionId, session);
        if (existing != null) {
            session.close("duplicate_connection");
            return;
        }
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE session created connectionId=" + connectionId);
        if (!session.start()) {
            sessions.remove(connectionId);
            closeCallback.onClosed("KCP_SESSION_FAILED");
        }
    }

    public void sendData(long connectionId, byte[] data) {
        CppRemoteKcpSession session = sessions.get(connectionId);
        if (session == null) {
            Logger.warning(LogConfig.MODULE_VPN, "CPP_REMOTE DATA for unknown connectionId=" + connectionId);
            return;
        }
        session.sendTcpPayload(data);
    }

    public void closeConnection(long connectionId, String reason) {
        CppRemoteKcpSession session = sessions.remove(connectionId);
        if (session != null) {
            session.close(reason);
        }
    }

    public void stop() {
        running = false;
        for (Map.Entry<Long, CppRemoteKcpSession> entry : sessions.entrySet()) {
            entry.getValue().close("manager_stop");
        }
        sessions.clear();
        shutdownExecutors();
        remoteReachable.set(false);
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE manager stopped");
    }

    private void notifyState(RemoteState state, String detail) {
        StateCallback callback = stateCallback;
        if (callback != null) {
            callback.onStateChanged(state, detail);
        }
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE state=" + state + " detail=" + detail);
    }

    private void shutdownExecutors() {
        if (kcpScheduler != null) {
            kcpScheduler.shutdownNow();
            awaitTermination(kcpScheduler);
            kcpScheduler = null;
        }
    }

    private static void awaitTermination(ScheduledExecutorService executor) {
        try {
            executor.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static ThreadFactory namedThreadFactory(String prefix) {
        return new ThreadFactory() {
            private int index;

            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, prefix + "-" + (++index));
                thread.setDaemon(true);
                return thread;
            }
        };
    }

    public interface StateCallback {
        void onStateChanged(RemoteState state, String detail);
    }
}
