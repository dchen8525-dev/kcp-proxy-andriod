package com.example.kcpvpn.server;

import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.session.SocketProtector;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ServerConnectionManager {
    private static final int MAX_TCP_WORKERS = 64;
    private static final int MAX_TCP_QUEUE = 256;

    private final Map<Long, ServerConnection> connections = new ConcurrentHashMap<>();
    private final ThreadPoolExecutor connectExecutor;
    private final ThreadPoolExecutor readExecutor;

    public ServerConnectionManager() {
        this.connectExecutor = new ThreadPoolExecutor(
                0,
                MAX_TCP_WORKERS,
                30,
                TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                runnable -> {
                    Thread thread = new Thread(runnable, "ServerTCP-Connect");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
        this.readExecutor = new ThreadPoolExecutor(
                0,
                MAX_TCP_WORKERS,
                30,
                TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                runnable -> {
                    Thread thread = new Thread(runnable, "ServerTCP-Read");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    public void openConnection(long connectionId, String host, int port, ServerSession session,
                               SocketProtector socketProtector) {
        if (connections.containsKey(connectionId)) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "OPEN ignored, connection exists: connectionId="
                    + connectionId + ", dst=" + host + ":" + port);
            return;
        }

        ServerConnection pending = new ServerConnection(connectionId, session.getSessionId(), host, port);
        ServerConnection existing = connections.putIfAbsent(connectionId, pending);
        if (existing != null) {
            return;
        }

        try {
            connectExecutor.execute(() -> connectAndStart(connectionId, host, port, session, socketProtector));
        } catch (RuntimeException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP executor overloaded: connectionId="
                    + connectionId + ", dst=" + host + ":" + port);
            connections.remove(connectionId);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
        }
    }

    private void connectAndStart(long connectionId, String host, int port, ServerSession session,
                                 SocketProtector socketProtector) {
        Socket socket = new Socket();
        try {
            if (socketProtector != null) {
                socketProtector.bindToNetwork(socket);
                boolean protectedOk = socketProtector.protect(socket);
                Logger.info(LogConfig.MODULE_KCP_SERVER, "protect remote tcp socket=" + protectedOk);
                if (!protectedOk) {
                    throw new IOException("protect remote tcp socket failed");
                }
            } else {
                throw new IOException("missing SocketProtector for remote tcp socket");
            }
            Logger.info(LogConfig.MODULE_KCP_SERVER, "SERVER CONNECT connectionId=" + connectionId
                    + " dst=" + host + ":" + port + " result=START");
            socket.connect(new InetSocketAddress(host, port), ServerConfig.CONNECT_TIMEOUT_MS);
            ServerConnection conn = connections.get(connectionId);
            if (conn == null) {
                closeQuietly(socket);
                return;
            }
            conn.attach(socket);

            Logger.info(LogConfig.MODULE_KCP_SERVER, "Socket open: connectionId=" + connectionId
                    + ", dst=" + host + ":" + port + ", payloadLength=0");
            Logger.info(LogConfig.MODULE_KCP_SERVER, "SERVER CONNECT connectionId=" + connectionId
                    + " dst=" + host + ":" + port + " result=OK");
            conn.drainPendingWrites(session);
            startRemoteRead(conn, session);
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "Socket open failed: connectionId=" + connectionId
                    + ", dst=" + host + ":" + port + ", error=" + e.getMessage());
            Logger.error(LogConfig.MODULE_KCP_SERVER, "SERVER CONNECT connectionId=" + connectionId
                    + " dst=" + host + ":" + port + " result=FAIL error=" + e.getMessage());
            closeQuietly(socket);
            connections.remove(connectionId);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
        }
    }

    public void writeData(long connectionId, byte[] data, ServerSession session) {
        ServerConnection conn = connections.get(connectionId);
        if (conn == null) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "DATA for unknown connectionId="
                    + connectionId + ", payloadLength=" + (data == null ? 0 : data.length));
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
            return;
        }

        synchronized (conn.writeLock) {
            try {
                if (conn.outputStream == null) {
                    if (!conn.queuePendingWrite(data)) {
                        Logger.warning(LogConfig.MODULE_KCP_SERVER, "Pending write queue full: connectionId="
                                + connectionId);
                        closeConnection(connectionId, true);
                        session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
                    }
                    return;
                }
                conn.outputStream.write(data);
                conn.outputStream.flush();
                Logger.info(LogConfig.MODULE_KCP_SERVER, "remote TCP socket send connectionId=" + connectionId
                        + ", dst=" + conn.host + ":" + conn.port
                        + ", payloadLength=" + (data == null ? 0 : data.length));
            } catch (IOException e) {
                Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP write error: connectionId=" + connectionId
                        + ", dst=" + conn.host + ":" + conn.port + ", error=" + e.getMessage());
                closeConnection(connectionId, true);
                session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
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

    public void closeSessionConnections(String sessionId) {
        for (ServerConnection conn : connections.values()) {
            if (conn.sessionId.equals(sessionId)) {
                closeConnection(conn.connectionId, false);
            }
        }
        Logger.info(LogConfig.MODULE_KCP_SERVER, "Session connections closed: sessionId=" + sessionId);
    }

    public void closeAll() {
        for (Long connectionId : connections.keySet()) {
            closeConnection(connectionId, false);
        }
        connectExecutor.shutdownNow();
        readExecutor.shutdownNow();
        Logger.info(LogConfig.MODULE_KCP_SERVER, "All connections closed");
    }

    public int getConnectionCount() {
        return connections.size();
    }

    private void startRemoteRead(ServerConnection conn, ServerSession session) {
        try {
            readExecutor.execute(() -> readRemote(conn, session));
        } catch (RuntimeException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP read executor overloaded: connectionId="
                    + conn.connectionId);
            closeConnection(conn.connectionId, true);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, conn.connectionId, null));
        }
    }

    private void readRemote(ServerConnection conn, ServerSession session) {
        byte[] buffer = new byte[ServerConfig.FWD_BUF_SIZE];
        try {
            while (session.isAlive() && !conn.socket.isClosed()) {
                if (session.waitSend() >= ServerConfig.BACKPRESSURE_THRESHOLD) {
                    Thread.sleep(KcpConfig.KCP_INTERVAL_MS * 4L);
                    continue;
                }

                int len = conn.socket.getInputStream().read(buffer);
                if (len <= 0) {
                    break;
                }

                byte[] data = new byte[len];
                System.arraycopy(buffer, 0, data, 0, len);
                session.sendFrame(new KcpFrame(KcpFrame.TYPE_DATA, conn.connectionId, data));
                Logger.info(LogConfig.MODULE_KCP_SERVER, "remote response connectionId="
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
        private Socket socket;
        private OutputStream outputStream;
        private final Object writeLock;
        private final AtomicBoolean closed;
        private final Queue<byte[]> pendingWrites;
        private int pendingBytes;

        ServerConnection(long connectionId, String sessionId, String host, int port) {
            this.connectionId = connectionId;
            this.sessionId = sessionId;
            this.host = host;
            this.port = port;
            this.writeLock = new Object();
            this.closed = new AtomicBoolean(false);
            this.pendingWrites = new ArrayDeque<>();
            this.pendingBytes = 0;
        }

        void attach(Socket socket) throws IOException {
            synchronized (writeLock) {
                this.socket = socket;
                this.outputStream = socket.getOutputStream();
            }
        }

        boolean queuePendingWrite(byte[] data) {
            if (data == null) {
                return true;
            }
            if (pendingBytes + data.length > 256 * 1024) {
                return false;
            }
            byte[] copy = new byte[data.length];
            System.arraycopy(data, 0, copy, 0, data.length);
            pendingWrites.add(copy);
            pendingBytes += copy.length;
            return true;
        }

        void drainPendingWrites(ServerSession session) throws IOException {
            synchronized (writeLock) {
                while (!pendingWrites.isEmpty()) {
                    byte[] data = pendingWrites.remove();
                    pendingBytes -= data.length;
                    outputStream.write(data);
                    Logger.info(LogConfig.MODULE_KCP_SERVER, "remote TCP socket send connectionId="
                            + connectionId + ", dst=" + host + ":" + port
                            + ", payloadLength=" + data.length);
                }
                outputStream.flush();
            }
        }
    }
}
