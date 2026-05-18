package com.example.kcpvpn.server;

import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 服务端连接管理器 - 管理 TCP 连接
 */
public class ServerConnectionManager {

    private final Map<String, Socket> connections;

    public ServerConnectionManager() {
        this.connections = new ConcurrentHashMap<>();
    }

    /**
     * 注册连接
     */
    public void registerConnection(String sessionId, Socket socket) {
        connections.put(sessionId, socket);
        Logger.debug(LogConfig.MODULE_KCP_SERVER, "Connection registered: " + sessionId);
    }

    /**
     * 获取连接
     */
    public Socket getConnection(String sessionId) {
        return connections.get(sessionId);
    }

    /**
     * 关闭连接
     */
    public void closeConnection(String sessionId) {
        Socket socket = connections.remove(sessionId);
        if (socket != null) {
            try {
                if (!socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                Logger.warning(LogConfig.MODULE_KCP_SERVER, "Close socket error: " + e.getMessage());
            }
            Logger.info(LogConfig.MODULE_KCP_SERVER, "Connection closed: " + sessionId);
        }
    }

    /**
     * 关闭所有连接
     */
    public void closeAll() {
        for (String sessionId : connections.keySet()) {
            closeConnection(sessionId);
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