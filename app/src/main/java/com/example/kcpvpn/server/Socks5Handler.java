package com.example.kcpvpn.server;

import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.protocol.AddressParser;
import com.example.kcpvpn.core.protocol.Socks5;
import com.example.kcpvpn.core.protocol.Socks5Response;
import com.example.kcpvpn.core.session.SocketProtector;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SOCKS5 处理器 - 与 C++ handle_socks5_request 一致
 * 支持多路复用：每个连接带 1-byte connId 前缀
 */
public class Socks5Handler {

    // 连接线程池，避免阻塞 SOCKS5 读取循环
    private static final ExecutorService connectPool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "Socks5-Connect");
        t.setDaemon(true);
        return t;
    });

    /**
     * 处理 SOCKS5 请求
     */
    public static void handleRequest(ServerSession session, int connId, byte[] data,
                                     ServerConnectionManager connectionManager,
                                     SocketProtector socketProtector) {
        if (data == null || data.length < 4) {
            Logger.warning(LogConfig.MODULE_SOCKS5, "SOCKS5 request too short");
            sendReply(session, connId, Socks5.SOCKS5_REPLY_GENERAL_FAILURE);
            return;
        }

        ByteBuffer buf = ByteBuffer.wrap(data);

        byte ver = buf.get();
        byte cmd = buf.get();
        buf.get();  // RSV
        byte atyp = buf.get();

        if (ver != Socks5.SOCKS5_VERSION) {
            Logger.warning(LogConfig.MODULE_SOCKS5, "Invalid SOCKS5 version: " + ver);
            sendReply(session, connId, Socks5.SOCKS5_REPLY_GENERAL_FAILURE);
            return;
        }

        try {
            AddressParser.ParsedAddress addr = AddressParser.parse(data, 3, data.length);

            if (addr.host == null || addr.host.isEmpty()) {
                Logger.warning(LogConfig.MODULE_SOCKS5, "Empty host in SOCKS5 request");
                sendReply(session, connId, Socks5.SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
                return;
            }

            Logger.info(LogConfig.MODULE_SOCKS5, "SOCKS5 request: cmd=" + cmd
                    + ", host=" + addr.host + ", port=" + addr.port + ", connId=" + connId);

            if (cmd == Socks5.SOCKS5_CMD_CONNECT) {
                final ServerSession sess = session;
                final ServerConnectionManager mgr = connectionManager;
                final SocketProtector prot = socketProtector;
                final int cid = connId;
                connectPool.execute(() -> {
                    doConnect(sess, cid, addr.host, addr.port, mgr, prot);
                });
            } else if (cmd == Socks5.SOCKS5_CMD_UDP_ASSOCIATE) {
                Logger.warning(LogConfig.MODULE_SOCKS5, "UDP ASSOCIATE not supported");
                sendReply(session, connId, Socks5.SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
            } else {
                Logger.warning(LogConfig.MODULE_SOCKS5, "Unsupported command: " + cmd);
                sendReply(session, connId, Socks5.SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
            }

        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_SOCKS5, "Parse SOCKS5 request error: " + e.getMessage());
            sendReply(session, connId, Socks5.SOCKS5_REPLY_GENERAL_FAILURE);
        }
    }

    /**
     * 执行 TCP 连接（在线程池中运行）
     */
    private static void doConnect(ServerSession session, int connId, String host, int port,
                                  ServerConnectionManager connectionManager,
                                  SocketProtector socketProtector) {
        Logger.info(LogConfig.MODULE_SOCKS5, "Connecting to " + host + ":" + port + " connId=" + connId);

        Socket tcpSocket = new Socket();
        try {
            // addDisallowedApplication 已让本应用流量绕过 VPN，无需 protect()
            // emulator 中 bind() + protect() 组合会导致外部连接失败
            Logger.info(LogConfig.MODULE_SOCKS5, "Calling connect to " + host + ":" + port);

            tcpSocket.connect(new InetSocketAddress(host, port), ServerConfig.CONNECT_TIMEOUT_MS);
            Logger.info(LogConfig.MODULE_SOCKS5, "Connect to " + host + ":" + port + " succeeded");

            // 连接成功 → 注册并启动转发
            connectionManager.registerConnection(session.getSessionId(), connId, tcpSocket);
            sendSuccessReply(session, connId, host, port);
            session.markHandshakeDone();
            Logger.info(LogConfig.MODULE_SOCKS5, "Connected to " + host + ":" + port + " connId=" + connId);
            startForwarding(session, connId, tcpSocket, connectionManager, socketProtector);

        } catch (IOException e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.error(LogConfig.MODULE_SOCKS5, "Connect to target failed: " + e.getClass().getName()
                    + ": " + e.getMessage());
            byte replyCode = getErrorReplyCode(e);
            sendReply(session, connId, replyCode);
        }
    }

    /**
     * 开始双向转发
     */
    private static void startForwarding(ServerSession session, int connId, Socket tcpSocket,
                                         ServerConnectionManager connectionManager,
                                         SocketProtector socketProtector) {
        // TCP -> KCP 转发线程
        Thread tcpToKcpThread = new Thread(() -> {
            byte[] buffer = new byte[ServerConfig.FWD_BUF_SIZE];
            try {
                while (session.isAlive() && tcpSocket.isConnected() && !tcpSocket.isClosed()) {
                    if (session.waitSend() >= ServerConfig.BACKPRESSURE_THRESHOLD) {
                        Thread.sleep(KcpConfig.KCP_INTERVAL_MS * 4);
                        continue;
                    }

                    int len = tcpSocket.getInputStream().read(buffer);
                    if (len <= 0) {
                        break;
                    }

                    byte[] data = new byte[len];
                    System.arraycopy(buffer, 0, data, 0, len);
                    session.sendData(wrapWithConnId(connId, data));

                    Logger.debug(LogConfig.MODULE_KCP_SERVER, "TCP -> KCP: " + len + " bytes connId=" + connId);
                }
            } catch (IOException | InterruptedException e) {
                Logger.debug(LogConfig.MODULE_KCP_SERVER, "TCP read ended: " + e.getMessage());
            }

            connectionManager.closeConnection(session.getSessionId(), connId);
        }, "TCP-to-KCP-" + session.getSessionId() + "-" + connId);
        tcpToKcpThread.start();

        // 启动会话级 KCP 分发器（仅一次）
        if (session.trySetForwardReadPending()) {
            dispatchKcpToTcp(session, connectionManager, socketProtector);
        }
    }

    /**
     * 会话级 KCP 分发器：读取所有 KCP 数据并按 connId 路由
     */
    private static void dispatchKcpToTcp(ServerSession session,
                                          ServerConnectionManager connectionManager,
                                          SocketProtector socketProtector) {
        final byte[] buffer = new byte[ServerConfig.FWD_BUF_SIZE];
        session.asyncReadSome(buffer, data -> {
            if (data == null || data.length == 0) {
                connectionManager.closeAllForSession(session.getSessionId());
                return;
            }
            if (data.length < 1) {
                dispatchKcpToTcp(session, connectionManager, socketProtector);
                return;
            }

            int connId = data[0] & 0xFF;
            byte[] payload = new byte[data.length - 1];
            System.arraycopy(data, 1, payload, 0, payload.length);

            // 检测新的 SOCKS5 请求
            if (payload.length >= 4 && payload[0] == Socks5.SOCKS5_VERSION
                    && payload[1] == Socks5.SOCKS5_CMD_CONNECT) {
                Logger.info(LogConfig.MODULE_SOCKS5, "Detected new SOCKS5 CONNECT connId=" + connId);
                Socks5Handler.handleRequest(session, connId, payload, connectionManager, socketProtector);
            } else {
                Socket socket = connectionManager.getConnection(session.getSessionId(), connId);
                if (socket != null && !socket.isClosed()) {
                    try {
                        socket.getOutputStream().write(payload);
                        Logger.debug(LogConfig.MODULE_KCP_SERVER, "KCP -> TCP: " + payload.length + " bytes connId=" + connId);
                    } catch (IOException e) {
                        Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP write error connId=" + connId + ": " + e.getMessage());
                        connectionManager.closeConnection(session.getSessionId(), connId);
                    }
                } else {
                    Logger.warning(LogConfig.MODULE_KCP_SERVER, "No socket for connId=" + connId + ", dropping " + payload.length + " bytes");
                }
            }

            dispatchKcpToTcp(session, connectionManager, socketProtector);
        });
    }

    /**
     * 发送 SOCKS5 响应
     */
    private static void sendReply(ServerSession session, int connId, byte replyCode) {
        byte[] reply = Socks5Response.buildFailureResponse(replyCode);
        session.sendData(wrapWithConnId(connId, reply));
    }

    /**
     * 发送成功响应
     */
    private static void sendSuccessReply(ServerSession session, int connId, String host, int port) {
        byte[] reply = Socks5Response.buildSuccessResponse();
        session.sendData(wrapWithConnId(connId, reply));
    }

    /**
     * 为数据包添加 connId 前缀
     */
    private static byte[] wrapWithConnId(int connId, byte[] data) {
        byte[] wrapped = new byte[1 + data.length];
        wrapped[0] = (byte) connId;
        System.arraycopy(data, 0, wrapped, 1, data.length);
        return wrapped;
    }

    /**
     * 获取 Socket 的文件描述符（用于 VpnService.protect(int)）
     */
    private static int getSocketFd(Socket socket) {
        try {
            java.lang.reflect.Field implField = Socket.class.getDeclaredField("impl");
            implField.setAccessible(true);
            Object impl = implField.get(socket);
            if (impl == null) return -1;

            java.io.FileDescriptor fd = null;
            Class<?> clazz = impl.getClass();
            while (clazz != null && fd == null) {
                try {
                    java.lang.reflect.Field fdField = clazz.getDeclaredField("fd");
                    fdField.setAccessible(true);
                    fd = (java.io.FileDescriptor) fdField.get(impl);
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (fd == null) return -1;

            java.lang.reflect.Method getIntMethod = java.io.FileDescriptor.class.getDeclaredMethod("getInt$");
            getIntMethod.setAccessible(true);
            return (int) getIntMethod.invoke(fd);
        } catch (Exception e) {
            Logger.debug(LogConfig.MODULE_SOCKS5, "getSocketFd failed: " + e.getMessage());
            return -1;
        }
    }

    /**
     * 获取错误响应码
     */
    private static byte getErrorReplyCode(IOException e) {
        String message = e.getMessage();
        if (message != null) {
            if (message.contains("Connection refused")) {
                return Socks5.SOCKS5_REPLY_CONNECTION_REFUSED;
            }
            if (message.contains("Network unreachable")) {
                return Socks5.SOCKS5_REPLY_NETWORK_UNREACHABLE;
            }
            if (message.contains("Host unreachable") || message.contains("timeout")) {
                return Socks5.SOCKS5_REPLY_HOST_UNREACHABLE;
            }
        }
        return Socks5.SOCKS5_REPLY_GENERAL_FAILURE;
    }
}
