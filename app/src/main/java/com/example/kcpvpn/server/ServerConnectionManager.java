package com.example.kcpvpn.server;

import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 服务端连接管理器 - 每个 connectionId 对应一个远端 TCP 连接
 */
public class ServerConnectionManager {

    private final Map<Long, ServerConnection> connections;

    public ServerConnectionManager() {
        this.connections = new ConcurrentHashMap<>();
    }

    public boolean openConnection(long connectionId, String host, int port, ServerSession session) {
        if (connections.containsKey(connectionId)) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "OPEN ignored, connection exists: connectionId="
                    + connectionId + ", dst=" + host + ":" + port);
            return true;
        }

        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), ServerConfig.CONNECT_TIMEOUT_MS);
            ServerConnection conn = new ServerConnection(connectionId, session.getSessionId(), host, port, socket);
            connections.put(connectionId, conn);

            Logger.info(LogConfig.MODULE_KCP_SERVER, "Socket open: connectionId=" + connectionId
                    + ", dst=" + host + ":" + port + ", payloadLength=0");
            startRemoteRead(conn, session);
            return true;
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "Socket open failed: connectionId=" + connectionId
                    + ", dst=" + host + ":" + port + ", error=" + e.getMessage());
            closeQuietly(socket);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
            return false;
        }
    }

    public void writeData(long connectionId, byte[] data) {
        ServerConnection conn = connections.get(connectionId);
        if (conn == null) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "DATA for unknown connectionId="
                    + connectionId + ", payloadLength=" + (data == null ? 0 : data.length));
            return;
        }

        synchronized (conn.writeLock) {
            try {
                conn.outputStream.write(data);
                conn.outputStream.flush();
                Logger.debug(LogConfig.MODULE_KCP_SERVER, "KCP -> TCP DATA: connectionId=" + connectionId
                        + ", dst=" + conn.host + ":" + conn.port
                        + ", payloadLength=" + (data == null ? 0 : data.length));
            } catch (IOException e) {
                Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP write error: connectionId=" + connectionId
                        + ", dst=" + conn.host + ":" + conn.port + ", error=" + e.getMessage());
                closeConnection(connectionId, true);
            }
        }
    }

    public void closeConnection(long connectionId, boolean reset) {
        ServerConnection conn = connections.remove(connectionId);
        if (conn == null || !conn.closed.compareAndSet(false, true)) {
            return;
        }

        closeQuietly(conn.socket);
        Logger.info(LogConfig.MODULE_KCP_SERVER, (reset ? "Socket reset: " : "Socket close: ")
                + "connectionId=" + connectionId + ", dst=" + conn.host + ":" + conn.port
                + ", payloadLength=0");
    }

    public void closeAll() {
        for (Long connectionId : connections.keySet()) {
            closeConnection(connectionId, false);
        }
        Logger.info(LogConfig.MODULE_KCP_SERVER, "All connections closed");
    }

    public void closeSessionConnections(String sessionId) {
        for (ServerConnection conn : connections.values()) {
            if (conn.sessionId.equals(sessionId)) {
                closeConnection(conn.connectionId, false);
            }
        }
        Logger.info(LogConfig.MODULE_KCP_SERVER, "Session connections closed: sessionId=" + sessionId);
    }

    public int getConnectionCount() {
        return connections.size();
    }

    private void startRemoteRead(ServerConnection conn, ServerSession session) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[ServerConfig.FWD_BUF_SIZE];
            try {
                while (session.isAlive() && !conn.socket.isClosed()) {
                    if (session.waitSend() >= ServerConfig.BACKPRESSURE_THRESHOLD) {
                        Thread.sleep(KcpConfig.KCP_INTERVAL_MS * 4);
                        continue;
                    }

                    int len = conn.socket.getInputStream().read(buffer);
                    if (len <= 0) {
                        break;
                    }

                    byte[] data = new byte[len];
                    System.arraycopy(buffer, 0, data, 0, len);
                    session.sendFrame(new KcpFrame(KcpFrame.TYPE_DATA, conn.connectionId, data));
                    Logger.debug(LogConfig.MODULE_KCP_SERVER, "TCP -> KCP DATA: connectionId="
                            + conn.connectionId + ", dst=" + conn.host + ":" + conn.port
                            + ", payloadLength=" + len);
                }

                session.sendFrame(new KcpFrame(KcpFrame.TYPE_CLOSE, conn.connectionId, null));
            } catch (IOException | InterruptedException e) {
                Logger.debug(LogConfig.MODULE_KCP_SERVER, "TCP read ended: connectionId="
                        + conn.connectionId + ", dst=" + conn.host + ":" + conn.port
                        + ", error=" + e.getMessage());
                session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, conn.connectionId, null));
            } finally {
                closeConnection(conn.connectionId, false);
            }
        }, "TCP-to-KCP-" + conn.connectionId);
        thread.start();
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) {
            return;
        }
        try {
            if (!socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "Close socket error: " + e.getMessage());
        }
    }

    private static class ServerConnection {
        private final long connectionId;
        private final String sessionId;
        private final String host;
        private final int port;
        private final Socket socket;
        private final OutputStream outputStream;
        private final Object writeLock;
        private final AtomicBoolean closed;

        ServerConnection(long connectionId, String sessionId, String host, int port, Socket socket)
                throws IOException {
            this.connectionId = connectionId;
            this.sessionId = sessionId;
            this.host = host;
            this.port = port;
            this.socket = socket;
            this.outputStream = socket.getOutputStream();
            this.writeLock = new Object();
            this.closed = new AtomicBoolean(false);
        }
    }
}
