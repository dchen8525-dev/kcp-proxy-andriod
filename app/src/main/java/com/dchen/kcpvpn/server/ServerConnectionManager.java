package com.dchen.kcpvpn.server;

import com.dchen.kcpvpn.core.kcp.KcpConfig;
import com.dchen.kcpvpn.core.protocol.KcpFrame;
import com.dchen.kcpvpn.core.session.SocketProtector;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;

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
    private static final int MAX_TCP_CONNECT_WORKERS = 64;
    private static final int MAX_TCP_READ_WORKERS = 256;
    private static final int REMOTE_READ_TIMEOUT_MS = 120 * 1000;

    private final Map<Long, ServerConnection> connections = new ConcurrentHashMap<>();
    private final ThreadPoolExecutor connectExecutor;
    private final ThreadPoolExecutor readExecutor;
    // TCP 写专用单线程：过去 DATA 帧在 LocalKcpServer 的唯一 recv 线程上做阻塞
    // 写，一个慢目标会把所有会话/所有连接全部卡死。写统一经此线程排队（FIFO 保
    // 序），recv 线程只做入队，KCP 处理不再被 TCP 阻塞。
    private final java.util.concurrent.ExecutorService writeExecutor;

    public ServerConnectionManager() {
        this.connectExecutor = new ThreadPoolExecutor(
                0,
                MAX_TCP_CONNECT_WORKERS,
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
                MAX_TCP_READ_WORKERS,
                30,
                TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                runnable -> {
                    Thread thread = new Thread(runnable, "ServerTCP-Read");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
        this.writeExecutor = new ThreadPoolExecutor(
                1,
                1,
                30,
                TimeUnit.SECONDS,
                new java.util.concurrent.LinkedBlockingQueue<>(),
                runnable -> {
                    Thread thread = new Thread(runnable, "ServerTCP-Write");
                    thread.setDaemon(true);
                    return thread;
                });
    }

    public void openConnection(long connectionId, String host, int port, ServerSession session,
                               SocketProtector socketProtector) {
        if (connections.containsKey(connectionId)) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "OPEN ignored, connection exists: connectionId="
                    + connectionId + ", dst=" + host + ":" + port);
            return;
        }

        ServerConnection pending = new ServerConnection(connectionId, session.getSessionId(),
                session, host, port);
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
            // SSRF 防护（与 C++ 服务器的 post-resolve 检查同位）：先解析再逐个
            // 校验解析结果，连接只用校验过的地址——否则 host 解析到内网/本机
            // loopback（Android 各应用共享 loopback）时 OPEN 帧能打到它们。
            java.net.InetAddress address = resolveAllowed(host);
            Logger.info(LogConfig.MODULE_KCP_SERVER, "SERVER CONNECT connectionId=" + connectionId
                    + " dst=" + host + ":" + port + " result=START");
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(REMOTE_READ_TIMEOUT_MS);
            socket.connect(new InetSocketAddress(address, port), ServerConfig.CONNECT_TIMEOUT_MS);
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
            // 待发数据排空也走写线程：与后续 writeData 的排队在同一 FIFO 上，
            // 保证连接建立前排队的字节先于新数据写出。
            scheduleDrain(conn);
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

    /** 解析 host 并校验全部解析结果；任一受限即拒绝（防 DNS rebinding 部分放行）。 */
    private java.net.InetAddress resolveAllowed(String host) throws IOException {
        java.net.InetAddress[] addresses = java.net.InetAddress.getAllByName(host);
        for (java.net.InetAddress address : addresses) {
            if (SsrfGuard.isRestricted(address)) {
                throw new IOException("SSRF_BLOCKED restricted target " + address.getHostAddress());
            }
        }
        return addresses[0];
    }

    public void writeData(long connectionId, byte[] data, ServerSession session) {
        ServerConnection conn = connections.get(connectionId);
        if (conn == null) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "DATA for unknown connectionId="
                    + connectionId + ", payloadLength=" + (data == null ? 0 : data.length));
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
            return;
        }

        boolean overflow = false;
        synchronized (conn.writeLock) {
            if (conn.closed.get()) {
                return;
            }
            // 只入队不写：真正的写出在 writeExecutor 上按 FIFO 进行，recv 线程
            // 不被慢目标阻塞。待发队列有 256KB 上限，超限判定连接不可恢复。
            if (!conn.queuePendingWrite(data)) {
                overflow = true;
            }
        }
        if (overflow) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "Pending write queue full: connectionId="
                    + connectionId);
            closeConnection(connectionId, true);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
            return;
        }
        conn.touch();
        scheduleDrain(conn);
    }

    /**
     * 在写线程上调度一次排空。每连接用 drainQueued 门控：已有排队任务时不再
     * 重复提交——否则每个 DATA 帧一个任务对象，帧洪水下无界堆积。任务排空的
     * 是整个待发队列，后到的入队要么被队尾之前的任务覆盖、要么触发新任务。
     */
    private void scheduleDrain(ServerConnection conn) {
        if (!conn.drainQueued.compareAndSet(false, true)) {
            return;
        }
        try {
            writeExecutor.execute(() -> {
                conn.drainQueued.set(false);
                drainConnection(conn);
            });
        } catch (RuntimeException e) {
            conn.drainQueued.set(false);
            Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP write executor overloaded: connectionId="
                    + conn.connectionId);
            closeConnection(conn.connectionId, true);
            conn.session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, conn.connectionId, null));
        }
    }

    /**
     * 写线程任务：排空待发队列；客户端已半关闭且尚未 shutdown 时，排空之后
     * （保证 FIN 排在所有排队数据之后，否则先发的 FIN 会挤掉排队数据、写还会
     * 以 IOException 失败）执行 shutdownOutput；两个方向都已结束时整体关闭并
     * 让客户端摘除映射。
     */
    private void drainConnection(ServerConnection conn) {
        try {
            boolean closeAfterDrain = false;
            synchronized (conn.writeLock) {
                if (conn.closed.get() || conn.outputStream == null) {
                    return;
                }
                conn.drainPendingWrites();
                if (conn.clientFinSeen.get() && !conn.outputShutdown) {
                    Socket socket = conn.socket;
                    if (socket != null && !socket.isClosed()) {
                        socket.shutdownOutput();
                    }
                    conn.outputShutdown = true;
                }
                closeAfterDrain = conn.clientFinSeen.get() && conn.targetEofSeen;
            }
            if (closeAfterDrain) {
                closeConnection(conn.connectionId, false);
                if (conn.finSentToClient.compareAndSet(false, true)) {
                    conn.session.sendFrame(new KcpFrame(KcpFrame.TYPE_FIN, conn.connectionId, null));
                }
            }
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP write error: connectionId=" + conn.connectionId
                    + ", dst=" + conn.host + ":" + conn.port + ", error=" + e.getMessage());
            // 已经被别人关闭的连接（写失败只是 close 的次生现象）不再回 RESET，
            // 否则正常关闭路径会多发一个 RESET。
            boolean alreadyClosed = conn.closed.get();
            closeConnection(conn.connectionId, true);
            if (!alreadyClosed) {
                conn.session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, conn.connectionId, null));
            }
        }
    }

    /**
     * 客户端方向半关闭（TYPE_FIN）：只关闭本地写侧，目标站的响应继续经读循环
     * 送回客户端——与 C++ 服务器的 shutdown_send 语义对齐。shutdown 由写线程
     * 在排空排队数据之后执行；connect 未完成时先记下 clientFinSeen，连接建立
     * 后的第一次排空会补上。两个方向都已结束时，排空任务负责整体关闭。
     */
    public void halfCloseConnection(long connectionId) {
        ServerConnection conn = connections.get(connectionId);
        if (conn == null) {
            return;
        }
        if (!conn.clientFinSeen.compareAndSet(false, true)) {
            return;
        }
        scheduleDrain(conn);
    }

    /**
     * 回收滞留的半关闭连接：目标已 EOF、FIN 已发给客户端，但客户端迟迟不 FIN。
     * 半关闭语义要求连接存活等待客户端收尾，但不能无限期占用目标 socket——
     * 由 LocalKcpServer 的 cleanup 周期调用，上限与 PacketRouter 的半关闭
     * 排空宽限一致（150s）。
     */
    public void closeIdleConnections(long idleMs) {
        long now = System.currentTimeMillis();
        for (ServerConnection conn : connections.values()) {
            if (conn.targetEofSeen && conn.finSentToClient.get()
                    && now - conn.lastActivityMs > idleMs) {
                Logger.info(LogConfig.MODULE_KCP_SERVER, "Idle half-closed connection reclaimed: "
                        + "connectionId=" + conn.connectionId + ", dst=" + conn.host + ":" + conn.port);
                closeConnection(conn.connectionId, false);
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
        writeExecutor.shutdownNow();
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
                conn.touch();
                session.sendFrame(new KcpFrame(KcpFrame.TYPE_DATA, conn.connectionId, data));
                Logger.info(LogConfig.MODULE_KCP_SERVER, "remote response connectionId="
                        + conn.connectionId + ", dst=" + conn.host + ":" + conn.port
                        + ", payloadLength=" + len);
            }

            handleTargetEof(conn, session);
        } catch (IOException | InterruptedException e) {
            Logger.debug(LogConfig.MODULE_KCP_SERVER, "TCP read ended: connectionId="
                    + conn.connectionId + ", dst=" + conn.host + ":" + conn.port
                    + ", error=" + e.getMessage());
            closeConnection(conn.connectionId, true);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, conn.connectionId, null));
        }
    }

    /**
     * 目标写侧关闭（read 返回 0/-1）：向客户端发 FIN（半关闭，只发一次），目标
     * 的在途响应仍会经 KCP 送达。旧实现在这里发 TYPE_CLOSE 并关闭 socket，把
     * 目标的响应一起截断。客户端方向也已 FIN 时交给写线程排空后整体关闭——
     * 不能在此直接关：排队中的数据仍要先送达目标。
     */
    private void handleTargetEof(ServerConnection conn, ServerSession session) {
        conn.targetEofSeen = true;
        if (conn.finSentToClient.compareAndSet(false, true)) {
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_FIN, conn.connectionId, null));
            Logger.info(LogConfig.MODULE_KCP_SERVER, "Target half-closed: connectionId="
                    + conn.connectionId + ", dst=" + conn.host + ":" + conn.port);
        }
        if (conn.clientFinSeen.get()) {
            scheduleDrain(conn);
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
        // 所属会话的引用：半关闭收尾（双方 FIN 后整体关闭）要向客户端发帧，
        // 会话若已死亡 sendFrame 自动变 no-op。
        private final ServerSession session;
        private final String host;
        private final int port;
        private Socket socket;
        private OutputStream outputStream;
        private final Object writeLock;
        private final AtomicBoolean closed;
        private final Queue<byte[]> pendingWrites;
        private int pendingBytes;
        // 半关闭状态：客户端方向已 FIN / 目标写侧已关闭 / 是否已向客户端发过
        // FIN（只发一次）。drainQueued 门控写线程上的重复排空任务；outputShutdown
        // 只在 writeLock 内读写。
        final AtomicBoolean clientFinSeen = new AtomicBoolean(false);
        volatile boolean targetEofSeen = false;
        final AtomicBoolean finSentToClient = new AtomicBoolean(false);
        final AtomicBoolean drainQueued = new AtomicBoolean(false);
        boolean outputShutdown = false;
        // 最近一次读/写活动的时刻（volatile：读循环/写线程/调度线程都会碰）
        volatile long lastActivityMs = System.currentTimeMillis();

        void touch() {
            lastActivityMs = System.currentTimeMillis();
        }

        ServerConnection(long connectionId, String sessionId, ServerSession session,
                         String host, int port) {
            this.connectionId = connectionId;
            this.sessionId = sessionId;
            this.session = session;
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

        /**
         * 把滞留队列写进目标 socket 并 flush。调用方必须持有 writeLock；
         * 写失败以 IOException 上抛，由调用方决定 RESET/关闭。
         */
        void drainPendingWrites() throws IOException {
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
