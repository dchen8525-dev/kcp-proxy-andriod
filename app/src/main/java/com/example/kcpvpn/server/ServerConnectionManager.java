package com.example.kcpvpn.server;

import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.Socket;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 服务端连接管理器 - 管理 TCP 连接
 * 支持每个会话多路复用（通过 connId 区分）
 */
public class ServerConnectionManager {

    private final Map<String, Socket> connections;

    public ServerConnectionManager() {
        this.connections = new ConcurrentHashMap<>();
    }

    private static String makeKey(String sessionId, int connId) {
        return sessionId + ":" + connId;
    }

    /**
     * 注册连接
     */
    public void registerConnection(String sessionId, int connId, Socket socket) {
        connections.put(makeKey(sessionId, connId), socket);
        Logger.debug(LogConfig.MODULE_KCP_SERVER, "Connection registered: " + sessionId + " connId=" + connId);
    }

    /**
     * 获取连接
     */
    public Socket getConnection(String sessionId, int connId) {
        return connections.get(makeKey(sessionId, connId));
    }

    /**
     * 关闭连接
     */
    public void closeConnection(String sessionId, int connId) {
        Socket socket = connections.remove(makeKey(sessionId, connId));
        if (socket != null) {
            try {
                if (!socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                Logger.warning(LogConfig.MODULE_KCP_SERVER, "Close socket error: " + e.getMessage());
            }
            Logger.info(LogConfig.MODULE_KCP_SERVER, "Connection closed: " + sessionId + " connId=" + connId);
        }
    }

    /**
     * 关闭指定会话的所有连接
     */
    public void closeAllForSession(String sessionId) {
        String prefix = sessionId + ":";
        Iterator<Map.Entry<String, Socket>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Socket> entry = it.next();
            if (entry.getKey().startsWith(prefix)) {
                try {
                    if (!entry.getValue().isClosed()) {
                        entry.getValue().close();
                    }
                } catch (IOException e) {
                    Logger.warning(LogConfig.MODULE_KCP_SERVER, "Close socket error: " + e.getMessage());
                }
                it.remove();
            }
        }
        Logger.info(LogConfig.MODULE_KCP_SERVER, "All connections closed for session: " + sessionId);
    }

    /**
     * 关闭所有连接
     */
    public void closeAll() {
        for (Iterator<Map.Entry<String, Socket>> it = connections.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Socket> entry = it.next();
            try {
                if (!entry.getValue().isClosed()) {
                    entry.getValue().close();
                }
            } catch (IOException e) {
                Logger.warning(LogConfig.MODULE_KCP_SERVER, "Close socket error: " + e.getMessage());
            }
            it.remove();
        }
        Logger.info(LogConfig.MODULE_KCP_SERVER, "All connections closed");
    }

    /**
     * 获取连接数量
     */
    public int getConnectionCount() {
        return connections.size();
    }
}
