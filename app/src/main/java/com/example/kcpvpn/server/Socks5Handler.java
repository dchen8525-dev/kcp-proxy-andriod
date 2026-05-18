package com.example.kcpvpn.server;

import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.protocol.AddressParser;
import com.example.kcpvpn.core.protocol.Socks5;
import com.example.kcpvpn.core.protocol.Socks5Response;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

/**
 * SOCKS5 处理器 - 与 C++ handle_socks5_request 一致
 */
public class Socks5Handler {

    /**
     * 处理 SOCKS5 请求
     * @param session 服务端会话
     * @param data SOCKS5 请求数据
     * @param connectionManager 连接管理器
     */
    public static void handleRequest(ServerSession session, byte[] data,
                                     ServerConnectionManager connectionManager) {
        if (data == null || data.length < 4) {
            Logger.warning(LogConfig.MODULE_SOCKS5, "SOCKS5 request too short");
            sendReply(session, Socks5.SOCKS5_REPLY_GENERAL_FAILURE);
            return;
        }

        ByteBuffer buf = ByteBuffer.wrap(data);

        byte ver = buf.get();
        byte cmd = buf.get();
        buf.get();  // RSV
        byte atyp = buf.get();

        if (ver != Socks5.SOCKS5_VERSION) {
            Logger.warning(LogConfig.MODULE_SOCKS5, "Invalid SOCKS5 version: " + ver);
            sendReply(session, Socks5.SOCKS5_REPLY_GENERAL_FAILURE);
            return;
        }

        try {
            AddressParser.ParsedAddress addr = AddressParser.parse(data, 3, data.length - 3);

            if (addr.host == null || addr.host.isEmpty()) {
                Logger.warning(LogConfig.MODULE_SOCKS5, "Empty host in SOCKS5 request");
                sendReply(session, Socks5.SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
                return;
            }

            Logger.info(LogConfig.MODULE_SOCKS5, "SOCKS5 request: cmd=" + cmd
                    + ", host=" + addr.host + ", port=" + addr.port);

            if (cmd == Socks5.SOCKS5_CMD_CONNECT) {
                handleConnect(session, addr.host, addr.port, connectionManager);
            } else if (cmd == Socks5.SOCKS5_CMD_UDP_ASSOCIATE) {
                Logger.warning(LogConfig.MODULE_SOCKS5, "UDP ASSOCIATE not supported");
                sendReply(session, Socks5.SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
            } else {
                Logger.warning(LogConfig.MODULE_SOCKS5, "Unsupported command: " + cmd);
                sendReply(session, Socks5.SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
            }

        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_SOCKS5, "Parse SOCKS5 request error: " + e.getMessage());
            sendReply(session, Socks5.SOCKS5_REPLY_GENERAL_FAILURE);
        }
    }

    /**
     * 处理 CONNECT 命令
     */
    private static void handleConnect(ServerSession session, String host, int port,
                                      ServerConnectionManager connectionManager) {
        Logger.info(LogConfig.MODULE_SOCKS5, "Connecting to " + host + ":" + port);

        // 创建 TCP 连接
        Socket tcpSocket = new Socket();
        try {
            tcpSocket.connect(new InetSocketAddress(host, port), ServerConfig.CONNECT_TIMEOUT_MS);

            // 注册连接
            connectionManager.registerConnection(session.getSessionId(), tcpSocket);

            // 发送成功响应
            sendSuccessReply(session, host, port);

            session.markHandshakeDone();

            Logger.info(LogConfig.MODULE_SOCKS5, "Connected to " + host + ":" + port);

            // 开始双向转发
            startForwarding(session, tcpSocket, connectionManager);

        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_SOCKS5, "Connect to target failed: " + e.getMessage());
            byte replyCode = getErrorReplyCode(e);
            sendReply(session, replyCode);
        }
    }

    /**
     * 开始双向转发
     */
    private static void startForwarding(ServerSession session, Socket tcpSocket,
                                         ServerConnectionManager connectionManager) {
        // TCP -> KCP 转发线程
        Thread tcpToKcpThread = new Thread(() -> {
            byte[] buffer = new byte[ServerConfig.FWD_BUF_SIZE];
            try {
                while (session.isAlive() && tcpSocket.isConnected() && !tcpSocket.isClosed()) {
                    // 背压控制
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
                    session.sendData(data);

                    Logger.debug(LogConfig.MODULE_KCP_SERVER, "TCP -> KCP: " + len + " bytes");
                }
            } catch (IOException | InterruptedException e) {
                Logger.debug(LogConfig.MODULE_KCP_SERVER, "TCP read ended: " + e.getMessage());
            }

            connectionManager.closeConnection(session.getSessionId());
        }, "TCP-to-KCP-" + session.getSessionId());
        tcpToKcpThread.start();

        // KCP -> TCP 转发线程
        Thread kcpToTcpThread = new Thread(() -> {
            byte[] buffer = new byte[ServerConfig.FWD_BUF_SIZE];
            while (session.isAlive() && tcpSocket.isConnected() && !tcpSocket.isClosed()) {
                session.asyncReadSome(buffer, data -> {
                    if (data == null || data.length == 0) {
                        connectionManager.closeConnection(session.getSessionId());
                        return;
                    }

                    try {
                        tcpSocket.getOutputStream().write(data);
                        Logger.debug(LogConfig.MODULE_KCP_SERVER, "KCP -> TCP: " + data.length + " bytes");
                    } catch (IOException e) {
                        Logger.error(LogConfig.MODULE_KCP_SERVER, "TCP write error: " + e.getMessage());
                        connectionManager.closeConnection(session.getSessionId());
                    }
                });

                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "KCP-to-TCP-" + session.getSessionId());
        kcpToTcpThread.start();
    }

    /**
     * 发送 SOCKS5 响应
     */
    private static void sendReply(ServerSession session, byte replyCode) {
        byte[] reply = Socks5Response.buildFailureResponse(replyCode);
        session.sendData(reply);
    }

    /**
     * 发送成功响应
     */
    private static void sendSuccessReply(ServerSession session, String host, int port) {
        byte[] reply = Socks5Response.buildSuccessResponse();
        session.sendData(reply);
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