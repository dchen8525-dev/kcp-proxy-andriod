package com.example.kcpvpn.server;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.crypto.CryptoConfig;
import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.session.SocketProtector;
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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * 本地 KCP 服务端 - 用于本地自测模式。
 */
public class LocalKcpServer {

    private static volatile SocketProtector socketProtector;

    public static void setSocketProtector(SocketProtector protector) {
        socketProtector = protector;
    }

    private final String host;
    private final int port;
    private final String key;

    private DatagramSocket udpSocket;
    private volatile boolean running;

    private final Map<String, ServerSession> sessions;
    private final ServerConnectionManager connectionManager;
    private final ThreadPoolExecutor dnsExecutor;

    private Thread recvThread;
    private Thread cleanupThread;

    public LocalKcpServer(int port, String key) {
        this.host = ServerConfig.DEFAULT_HOST;
        this.port = port;
        this.key = key;

        this.sessions = new ConcurrentHashMap<>();
        this.connectionManager = new ServerConnectionManager();
        this.dnsExecutor = new ThreadPoolExecutor(
                2,
                8,
                30,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(128),
                runnable -> {
                    Thread thread = new Thread(runnable, "DNS-Relay");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
        this.running = false;

        Logger.info(LogConfig.MODULE_KCP_SERVER, "LocalKcpServer created: " + host + ":" + port);
    }

    public boolean start() {
        Logger.info(LogConfig.MODULE_KCP_SERVER, "LocalKcpServer.start() begin");

        try {
            Logger.info(LogConfig.MODULE_KCP_SERVER, "Creating UDP socket on " + host + ":" + port);
            udpSocket = new DatagramSocket(port, InetAddress.getByName(host));
            udpSocket.setSoTimeout(1000);

            Logger.info(LogConfig.MODULE_KCP_SERVER, "UDP socket created, local port=" + udpSocket.getLocalPort());

            running = true;
            startRecvThread();
            startCleanupThread();

            Logger.info(LogConfig.MODULE_KCP_SERVER, "Server started successfully on " + host + ":" + port);
            return true;
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "Start server error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

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
                    // 正常超时
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

    private void handleReceive(InetSocketAddress clientAddr, byte[] encryptedData) {
        String sessionId = clientAddr.getAddress().getHostAddress() + ":" + clientAddr.getPort();

        ServerSession session = sessions.get(sessionId);

        if (session == null) {
            session = createSession(clientAddr, encryptedData);
            if (session == null) {
                Logger.warning(LogConfig.MODULE_KCP_SERVER, "Auth failed for " + sessionId);
                return;
            }

            sessions.put(sessionId, session);
            Logger.info(LogConfig.MODULE_KCP_SERVER, "New session: " + sessionId
                    + " (total: " + sessions.size() + ")");
        } else {
            try {
                byte[] decrypted = session.getCrypto().decrypt(encryptedData);
                session.receiveData(decrypted);
            } catch (Exception e) {
                Logger.error(LogConfig.MODULE_KCP_SERVER, "Decrypt error: " + e.getMessage());
            }
        }
    }

    private ServerSession createSession(InetSocketAddress clientAddr, byte[] encryptedPacket) {
        if (sessions.size() >= ServerConfig.MAX_CONCURRENT_SESSIONS) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "Session cap reached: "
                    + ServerConfig.MAX_CONCURRENT_SESSIONS);
            return null;
        }

        try {
            Crypto crypto = new Crypto(key, CryptoConfig.NONCE_DIR_SERVER, "");
            byte[] decrypted = crypto.decrypt(encryptedPacket);

            ServerSession session = new ServerSession(clientAddr, crypto);
            session.setSendCallback(data -> sendToClient(clientAddr, data));
            session.setFrameHandler(frame -> handleFrame(session, frame));
            session.start();
            session.receiveData(decrypted);

            return session;
        } catch (Exception e) {
            Logger.debug(LogConfig.MODULE_KCP_SERVER, "Auth failed: " + e.getMessage());
            return null;
        }
    }

    private void handleFrame(ServerSession session, KcpFrame frame) {
        long connectionId = frame.getConnectionId();
        byte frameType = frame.getFrameType();

        if (frameType == KcpFrame.TYPE_OPEN) {
            Socks5Handler.handleOpenFrame(session, frame, connectionManager, socketProtector);
        } else if (frameType == KcpFrame.TYPE_DATA) {
            Logger.debug(LogConfig.MODULE_KCP_SERVER, "DATA frame: connectionId=" + connectionId
                    + ", payloadLength=" + frame.getPayloadLength());
            connectionManager.writeData(connectionId, frame.getPayload(), session);
        } else if (frameType == KcpFrame.TYPE_UDP_DATAGRAM) {
            handleUdpDatagram(session, frame);
        } else if (frameType == KcpFrame.TYPE_CLOSE) {
            Logger.info(LogConfig.MODULE_KCP_SERVER, "CLOSE frame: connectionId=" + connectionId
                    + ", payloadLength=" + frame.getPayloadLength());
            connectionManager.closeConnection(connectionId, false);
        } else if (frameType == KcpFrame.TYPE_RESET) {
            Logger.info(LogConfig.MODULE_KCP_SERVER, "RESET frame: connectionId=" + connectionId
                    + ", payloadLength=" + frame.getPayloadLength());
            connectionManager.closeConnection(connectionId, true);
        }
    }

    private void handleUdpDatagram(ServerSession session, KcpFrame frame) {
        try {
            dnsExecutor.execute(() -> relayDns(session, frame));
        } catch (RuntimeException e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "DNS relay executor overloaded: payloadLength="
                    + frame.getPayloadLength());
        }
    }

    private void relayDns(ServerSession session, KcpFrame frame) {
        DatagramSocket socket = null;
        try {
            com.example.kcpvpn.vpn.PacketRouter.UdpDatagram datagram =
                    com.example.kcpvpn.vpn.PacketRouter.parseUdpFramePayload(frame.getPayload());
            if (datagram.dstPort != 53) {
                Logger.debug(LogConfig.MODULE_KCP_SERVER, "Ignoring non-DNS UDP datagram, dstPort="
                        + datagram.dstPort);
                return;
            }

            socket = new DatagramSocket();
            socket.setSoTimeout(3000);
            InetAddress dnsServer = chooseDnsServer(datagram.dstAddr);
            DatagramPacket request = new DatagramPacket(datagram.payload, datagram.payload.length,
                    dnsServer, 53);
            socket.send(request);

            byte[] buf = new byte[1500];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            socket.receive(response);

            byte[] dnsPayload = new byte[response.getLength()];
            System.arraycopy(response.getData(), response.getOffset(), dnsPayload, 0, response.getLength());
            byte[] responsePayload = com.example.kcpvpn.vpn.PacketRouter.buildUdpFramePayload(
                    datagram.srcAddr, datagram.srcPort, datagram.dstAddr, datagram.dstPort, dnsPayload);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_UDP_DATAGRAM, 0, responsePayload));
            Logger.info(LogConfig.MODULE_KCP_SERVER, "UDP DNS relayed: server="
                    + dnsServer.getHostAddress() + ", payloadLength=" + dnsPayload.length);
        } catch (Exception e) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "DNS relay failed: " + e.getMessage());
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private InetAddress chooseDnsServer(byte[] requestedAddr) throws IOException {
        String requested = (requestedAddr[0] & 0xFF) + "." + (requestedAddr[1] & 0xFF) + "."
                + (requestedAddr[2] & 0xFF) + "." + (requestedAddr[3] & 0xFF);
        if (!requested.startsWith("10.0.2.") && !"0.0.0.0".equals(requested)) {
            return InetAddress.getByName(requested);
        }
        return InetAddress.getByName("1.1.1.1");
    }

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

    private void startCleanupThread() {
        cleanupThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(ServerConfig.CLEANUP_INTERVAL_MS);

                    for (Map.Entry<String, ServerSession> entry : sessions.entrySet()) {
                        ServerSession session = entry.getValue();
                        if (!session.isAlive()) {
                            Logger.info(LogConfig.MODULE_KCP_SERVER, "Cleaning up dead session: " + entry.getKey());
                            session.stop();
                            connectionManager.closeSessionConnections(entry.getKey());
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

    public void stop() {
        if (!running) {
            return;
        }
        running = false;

        Logger.info(LogConfig.MODULE_KCP_SERVER, "Server stopping...");

        if (recvThread != null) {
            recvThread.interrupt();
            recvThread = null;
        }
        if (cleanupThread != null) {
            cleanupThread.interrupt();
            cleanupThread = null;
        }

        for (ServerSession session : sessions.values()) {
            session.stop();
        }
        sessions.clear();

        connectionManager.closeAll();
        dnsExecutor.shutdownNow();

        if (udpSocket != null) {
            udpSocket.close();
            udpSocket = null;
        }

        Logger.info(LogConfig.MODULE_KCP_SERVER, "Server stopped");
    }

    public boolean isRunning() {
        return running;
    }

    public int getPort() {
        return port;
    }

    public int getSessionCount() {
        return sessions.size();
    }
}
