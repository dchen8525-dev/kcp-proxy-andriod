package com.example.kcpvpn.vpn.cppremote;

import com.example.kcpvpn.core.session.SocketProtector;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CppRemoteTunnelManager {
    private final String serverHost;
    private final int serverPort;
    private final String key;
    private final Map<Long, CppRemoteKcpSession> sessions = new ConcurrentHashMap<>();
    private volatile SocketProtector socketProtector;
    private volatile boolean running;

    public CppRemoteTunnelManager(String serverHost, int serverPort, String key) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.key = key;
    }

    public void setSocketProtector(SocketProtector socketProtector) {
        this.socketProtector = socketProtector;
    }

    public boolean start() {
        if (socketProtector == null) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE start failed: missing SocketProtector");
            return false;
        }
        running = true;
        Logger.info(LogConfig.MODULE_VPN, "mode=CPP_REMOTE server=" + serverHost + ":" + serverPort
                + " protocol=socks5-over-kcp-raw-stream socketProtected=true"
                + " keyLength=" + (key == null ? 0 : key.length())
                + " crypto=CPP_COMPATIBLE_AES_128_GCM");
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE KCP conv=1 nodelay=1 interval=10"
                + " resend=5 nc=1 sndWnd=256 rcvWnd=512 mtu=1400");
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
        });
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
        Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE manager stopped");
    }
}
