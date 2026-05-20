package com.example.kcpvpn.server;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.crypto.CryptoConfig;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地 KCP 服务端 - 用于本地自测模式
 * 与 C++ KCPServer 一致
 */
public class LocalKcpServer {

    private final String host;
    private final int port;
    private final String key;

    private DatagramSocket udpSocket;
    private volatile boolean running;

    private final Map<String, ServerSession> sessions;
    private final ServerConnectionManager connectionManager;

    private Thread recvThread;
    private Thread cleanupThread;

    /**
     * 创建本地服务端
     * @param port 监听端口
     * @param key 密钥
     */
    public LocalKcpServer(int port, String key) {
        this.host = ServerConfig.DEFAULT_HOST;
        this.port = port;
        this.key = key;

        this.sessions = new ConcurrentHashMap<>();
        this.connectionManager = new ServerConnectionManager();
        this.running = false;

        Logger.info(LogConfig.MODULE_KCP_SERVER, "LocalKcpServer created: " + host + ":" + port);
    }

    /**
     * 启动服务端
     * @return true 成功
     */
    public boolean start() {
        Logger.info(LogConfig.MODULE_KCP_SERVER, "LocalKcpServer.start() begin");

        try {
            Logger.info(LogConfig.MODULE_KCP_SERVER, "Creating UDP socket on " + host + ":" + port);
            udpSocket = new DatagramSocket(port, InetAddress.getByName(host));
            udpSocket.setSoTimeout(1000);

            Logger.info(LogConfig.MODULE_KCP_SERVER, "UDP socket created, local port=" + udpSocket.getLocalPort());

            running = true;

            Logger.info(LogConfig.MODULE_KCP_SERVER, "Starting recv thread");
            startRecvThread();

            Logger.info(LogConfig.MODULE_KCP_SERVER, "Starting cleanup thread");
            startCleanupThread();

            Logger.info(LogConfig.MODULE_KCP_SERVER, "Server started successfully on " + host + ":" + port);
            return true;

        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "Start server error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 启动接收线程
     */
    private void startRecvThread() {
        recvThread = new Thread(() -> {
            byte[] recvBuf = new byte[ServerConfig.UDP_RECV_BUF_SIZE];

            while (running) {
                try {
                    DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
                    udpSocket.receive(packet);

                    if (packet.getLength() > 0) {
                        byte[] data = new byte[packet.getLength()];
                        System.arraycopy(recvBuf, 0, data, 0, packet.getLength());

                        InetSocketAddress clientAddr = new InetSocketAddress(
                                packet.getAddress(), packet.getPort());

                        handleReceive(clientAddr, data);
                    }

                } catch (SocketTimeoutException e) {
                    // 正常超时，继续
                } catch (IOException e) {
                    if (running) {
                        Logger.error(LogConfig.MODULE_KCP_SERVER, "UDP receive error: " + e.getMessage());
                    }
                    break;
                }
            }
        }, "Server-Recv");
        recvThread.start();
    }

    /**
     * 处理接收到的数据
     */
    private void handleReceive(InetSocketAddress clientAddr, byte[] encryptedData) {
        String sessionId = clientAddr.getAddress().getHostAddress() + ":" + clientAddr.getPort();

        ServerSession session = sessions.get(sessionId);

        if (session == null) {
            // 新连接，尝试认证
            session = createSession(clientAddr, encryptedData);
            if (session == null) {
                // 认证失败，丢弃
                Logger.warning(LogConfig.MODULE_KCP_SERVER, "Auth failed for " + sessionId);
                return;
            }

            sessions.put(sessionId, session);
            Logger.info(LogConfig.MODULE_KCP_SERVER, "New session: " + sessionId
                    + " (total: " + sessions.size() + ")");
        } else {
            // 已有会话，使用会话绑定的 crypto 解密处理数据
            try {
                byte[] decrypted = session.getCrypto().decrypt(encryptedData);
                session.receiveData(decrypted);
            } catch (Exception e) {
                Logger.error(LogConfig.MODULE_KCP_SERVER, "Decrypt error: " + e.getMessage());
            }
        }

        // 处理 SOCKS5 请求（如果握手未完成）
        if (!session.isHandshakeDone() && !session.isSocks5ReadPending()) {
            handleSocks5(session);
        }
    }

    /**
     * 创建新会话（首包认证）
     */
    private ServerSession createSession(InetSocketAddress clientAddr, byte[] encryptedPacket) {
        // 检查会话数量限制
        if (sessions.size() >= ServerConfig.MAX_CONCURRENT_SESSIONS) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "Session cap reached: " + ServerConfig.MAX_CONCURRENT_SESSIONS);
            return null;
        }

        try {
            // 创建加密实例（服务端方向）
            Crypto crypto = new Crypto(key, CryptoConfig.NONCE_DIR_SERVER, "");

            // 尝试解密认证
            byte[] decrypted = crypto.decrypt(encryptedPacket);

            // 认证成功，创建会话
            ServerSession session = new ServerSession(clientAddr, crypto);

            // 设置发送回调
            session.setSendCallback(data -> {
                sendToClient(clientAddr, data);
            });

            session.start();

            // 注入已解密的数据
            session.receiveData(decrypted);

            return session;

        } catch (Exception e) {
            Logger.debug(LogConfig.MODULE_KCP_SERVER, "Auth failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * 处理 SOCKS5
     */
    private void handleSocks5(ServerSession session) {
        session.setSocks5ReadPending(true);

        byte[] buffer = new byte[ServerConfig.FWD_BUF_SIZE];
        session.asyncReadSome(buffer, data -> {
            session.setSocks5ReadPending(false);

            if (data == null || data.length == 0) {
                Logger.warning(LogConfig.MODULE_KCP_SERVER, "SOCKS5 read error");
                return;
            }

            Socks5Handler.handleRequest(session, data, connectionManager);
        });
    }

    /**
     * 发送数据给客户端
     */
    private void sendToClient(InetSocketAddress clientAddr, byte[] data) {
        if (!running || udpSocket == null) {
            return;
        }

        try {
            DatagramPacket packet = new DatagramPacket(data, data.length, clientAddr);
            udpSocket.send(packet);

            Logger.debug(LogConfig.MODULE_KCP_SERVER, "Sent " + data.length + " bytes to " + clientAddr);
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "Send to client error: " + e.getMessage());
        }
    }

    /**
     * 启动清理线程
     */
    private void startCleanupThread() {
        cleanupThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(ServerConfig.CLEANUP_INTERVAL_MS);

                    // 检查超时会话
                    for (Map.Entry<String, ServerSession> entry : sessions.entrySet()) {
                        ServerSession session = entry.getValue();
                        if (!session.isAlive()) {
                            Logger.info(LogConfig.MODULE_KCP_SERVER, "Cleaning up dead session: " + entry.getKey());
                            session.stop();
                            connectionManager.closeConnection(entry.getKey());
                            sessions.remove(entry.getKey());
                        }
                    }

                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "Server-Cleanup");
        cleanupThread.start();
    }

    /**
     * 停止服务端
     */
    public void stop() {
        if (!running) return;
        running = false;

        Logger.info(LogConfig.MODULE_KCP_SERVER, "Server stopping...");

        // 先关闭 socket，解除 recvThread 的 DatagramSocket.receive 阻塞
        if (udpSocket != null) {
            udpSocket.close();
            udpSocket = null;
        }

        // 再中断并等待线程
        if (recvThread != null) {
            recvThread.interrupt();
            try {
                recvThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            recvThread = null;
        }
        if (cleanupThread != null) {
            cleanupThread.interrupt();
            try {
                cleanupThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            cleanupThread = null;
        }

        // 关闭所有会话
        for (ServerSession session : sessions.values()) {
            session.stop();
        }
        sessions.clear();

        // 关闭所有连接
        connectionManager.closeAll();

        Logger.info(LogConfig.MODULE_KCP_SERVER, "Server stopped");
    }

    /**
     * 检查是否运行
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * 获取监听端口
     */
    public int getPort() {
        return port;
    }

    /**
     * 获取会话数量
     */
    public int getSessionCount() {
        return sessions.size();
    }
}