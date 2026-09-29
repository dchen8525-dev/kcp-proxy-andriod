package com.dchen.kcpvpn.vpn;

import com.dchen.kcpvpn.core.protocol.KcpFrame;
import com.dchen.kcpvpn.core.protocol.Socks5Request;
import com.dchen.kcpvpn.core.session.SocketProtector;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;
import com.dchen.kcpvpn.vpn.cppremote.CppRemoteKcpSession;
import com.dchen.kcpvpn.vpn.cppremote.CppRemoteTunnelManager;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class PacketRouter {
    private static final long ESTABLISHED_IDLE_TIMEOUT_MS = 3 * 60 * 1000L;
    // 半关闭排空上限：必须大于 CppRemoteKcpSession 的 120s 宽限，
    // 否则路由器会先于会话掐断仍在接收在途数据的连接。
    private static final long CLOSING_IDLE_TIMEOUT_MS = 150 * 1000L;
    private static final int TCP_IPV4_HEADER_LEN = 40;
    private static final int IPV4_HEADER_LEN = 20;
    private static final int IPV6_HEADER_LEN = 40;
    private static final int IPV6_ADDR_LEN = 16;
    private static final int TCP_HEADER_LEN = 20;
    private static final int MAX_TCP_PAYLOAD_PER_PACKET = VpnConfig.VPN_MTU - TCP_IPV4_HEADER_LEN;
    // IPv6 头比 IPv4 长 20 字节，同样的 MTU 下每个包要少装 20 字节负载，
    // 否则写进 TUN 的包会超过 MTU 被内核丢弃。
    private static final int MAX_TCP_PAYLOAD_PER_PACKET_IPV6 =
            VpnConfig.VPN_MTU - IPV6_HEADER_LEN - TCP_HEADER_LEN;
    private static final int UDP_TRACE_SAMPLE_RATE = 64;

    private final Map<String, TcpConnection> connectionsByKey = new ConcurrentHashMap<>();
    private final Map<Long, TcpConnection> connectionsById = new ConcurrentHashMap<>();
    private final AtomicLong nextConnectionId = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong nextTcpSequence = new AtomicLong(System.nanoTime());
    private final AtomicLong udpTraceCounter = new AtomicLong(0);
    private volatile boolean running;
    private volatile boolean localMode;
    private volatile SocketProtector socketProtector;
    private volatile CppRemoteTunnelManager cppRemoteTunnelManager;
    private volatile java.util.function.BooleanSupplier tunnelAliveSupplier;
    private Thread cleanupThread;

    public void setSocketProtector(SocketProtector protector) {
        this.socketProtector = protector;
    }

    public void setLocalMode(boolean localMode) {
        this.localMode = localMode;
    }

    public void setCppRemoteTunnelManager(CppRemoteTunnelManager cppRemoteTunnelManager) {
        this.cppRemoteTunnelManager = cppRemoteTunnelManager;
    }

    /** 本地模式的隧道存活判据（TunnelManager::isConnected）。 */
    public void setTunnelAliveSupplier(java.util.function.BooleanSupplier supplier) {
        this.tunnelAliveSupplier = supplier;
    }

    public void start() {
        running = true;
        startCleanupThread();
        Logger.info(LogConfig.MODULE_VPN, "PacketRouter started, localMode=" + localMode
                + ", socketProtectorSet=" + (socketProtector != null));
    }

    public void stop() {
        running = false;
        if (cleanupThread != null) {
            cleanupThread.interrupt();
            cleanupThread = null;
        }
        for (TcpConnection conn : connectionsById.values()) {
            conn.close();
        }
        connectionsByKey.clear();
        connectionsById.clear();
        Logger.info(LogConfig.MODULE_VPN, "PacketRouter stopped");
    }

    public void handleOutboundPacket(byte[] packet, OutboundCallback callback) {
        handleOutboundPacket(packet, callback::onSendFrame, callback::onWriteToVpn);
    }

    public void handleOutboundPacket(byte[] packet, SendFrameCallback sendFrameCallback,
                                     WritePacketCallback writePacketCallback) {
        if (!running || packet == null || packet.length < 20) {
            return;
        }

        try {
            ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
            int version = (buf.get(0) >> 4) & 0x0F;

            int ipHeaderLen;
            int totalLen;
            int protocol;
            byte[] srcAddr;
            byte[] dstAddr;

            if (version == 4) {
                ipHeaderLen = (buf.get(0) & 0x0F) * 4;
                if (packet.length < ipHeaderLen + 8) {
                    return;
                }

                totalLen = buf.getShort(2) & 0xFFFF;
                if (totalLen <= 0 || totalLen > packet.length) {
                    totalLen = packet.length;
                }

                int flagsAndFragment = buf.getShort(6) & 0xFFFF;
                if ((flagsAndFragment & 0x2000) != 0 || ((flagsAndFragment & 0x1FFF) << 3) != 0) {
                    Logger.debug(LogConfig.MODULE_VPN, "Ignoring fragmented IP packet");
                    return;
                }

                srcAddr = Arrays.copyOfRange(packet, 12, 16);
                dstAddr = Arrays.copyOfRange(packet, 16, 20);
                protocol = buf.get(9) & 0xFF;
            } else if (version == 6) {
                if (packet.length < IPV6_HEADER_LEN + 8) {
                    return;
                }

                // IPv6 固定 40 字节头：没有 IHL、没有头校验和；负载长度字段不含头本身。
                ipHeaderLen = IPV6_HEADER_LEN;
                int payloadLength = buf.getShort(4) & 0xFFFF;
                totalLen = payloadLength + IPV6_HEADER_LEN;
                if (totalLen > packet.length) {
                    totalLen = packet.length;
                }

                protocol = buf.get(6) & 0xFF;
                // 扩展头会把"上层协议"挤到后面的 next header 里，分片头则意味着我们
                // 手里只是一个片段。两者都直接丢弃——与 IPv4 路径丢弃分片的策略一致，
                // 也好过按错误偏移去解析 TCP。
                if (isIpv6ExtensionHeader(protocol)) {
                    Logger.debug(LogConfig.MODULE_VPN,
                            "Ignoring IPv6 packet with extension header nextHeader=" + protocol);
                    return;
                }

                srcAddr = Arrays.copyOfRange(packet, 8, 24);
                dstAddr = Arrays.copyOfRange(packet, 24, 40);
            } else {
                return;
            }

            Logger.debug(LogConfig.MODULE_VPN, "PacketRouter parse protocol=" + protocol
                    + " src=" + addressToString(srcAddr)
                    + " dst=" + addressToString(dstAddr)
                    + " len=" + totalLen);
            if (protocol == 6) {
                handleOutboundTcp(packet, buf, ipHeaderLen, totalLen, srcAddr, dstAddr,
                        sendFrameCallback, writePacketCallback);
            } else if (protocol == 17) {
                handleOutboundUdp(packet, buf, ipHeaderLen, totalLen, srcAddr, dstAddr,
                        sendFrameCallback, writePacketCallback);
            } else {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring non-TCP/UDP packet: protocol=" + protocol);
            }
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Handle outbound error: " + e.getMessage());
        }
    }

    private void handleOutboundTcp(byte[] packet, ByteBuffer buf, int ipHeaderLen, int totalLen,
                                   byte[] srcAddr, byte[] dstAddr, SendFrameCallback sendFrameCallback,
                                   WritePacketCallback writePacketCallback) {
        int tcpOffset = ipHeaderLen;
        if (totalLen < tcpOffset + 20) {
            return;
        }

        int srcPort = buf.getShort(tcpOffset) & 0xFFFF;
        int dstPort = buf.getShort(tcpOffset + 2) & 0xFFFF;
        int clientSeq = buf.getInt(tcpOffset + 4);
        int clientAck = buf.getInt(tcpOffset + 8);
        int tcpHeaderLen = ((buf.get(tcpOffset + 12) >> 4) & 0x0F) * 4;
        int flags = buf.get(tcpOffset + 13) & 0xFF;
        int payloadOffset = tcpOffset + tcpHeaderLen;
        int payloadLen = totalLen - payloadOffset;
        if (tcpHeaderLen < 20 || payloadLen < 0) {
            return;
        }

        boolean isSyn = (flags & 0x02) != 0;
        boolean isAck = (flags & 0x10) != 0;
        boolean isRst = (flags & 0x04) != 0;
        boolean isFin = (flags & 0x01) != 0;

        logTcpIn(srcAddr, srcPort, dstAddr, dstPort, flags, clientSeq, clientAck, payloadLen);

        String key = connectionKey(srcAddr, srcPort, dstAddr, dstPort);
        TcpConnection conn = connectionsByKey.get(key);
        if (conn == null) {
            if (!isSyn || isAck) {
                Logger.info(LogConfig.MODULE_VPN, "drop unknown non-SYN packet: src="
                        + addressToString(srcAddr) + ":" + srcPort
                        + ", dst=" + addressToString(dstAddr) + ":" + dstPort
                        + ", flags=" + flags + ", payloadLength=" + payloadLen);
                return;
            }
            conn = createConnection(key, srcAddr, srcPort, dstAddr, dstPort, clientSeq,
                    sendFrameCallback, writePacketCallback);
        }

        if (isSyn && !isAck) {
            synchronized (conn) {
                conn.clientNextSeq = clientSeq + 1;
                byte[] synAck = buildTcpPacket(conn, new byte[0], (byte) 0x12,
                        conn.serverInitialSeq, conn.clientNextSeq);
                writePacketCallback.onWritePacket(synAck);
                logTcpOut(conn, 0x12, conn.serverInitialSeq, conn.clientNextSeq, 0);
                if (!conn.synAckSent) {
                    conn.serverNextSeq = conn.serverInitialSeq + 1;
                    conn.synAckSent = true;
                }
                conn.state = TcpState.SYN_RECEIVED;
                conn.touch();
            }
            Logger.debug(LogConfig.MODULE_VPN, "TCP SYN-ACK: connectionId=" + conn.connectionId
                    + ", src=" + conn.dstHost + ":" + conn.dstPort
                    + ", dst=" + conn.srcHost + ":" + conn.srcPort + ", payloadLength=0");
            return;
        }

        if (isAck) {
            synchronized (conn) {
                conn.lastAckFromClient = clientAck;
                if (conn.state == TcpState.SYN_RECEIVED) {
                    conn.state = TcpState.ESTABLISHED;
                }
                conn.removeAckedServerSegments(clientAck);
                conn.touch();
            }
            if (!localMode && cppRemoteTunnelManager != null) {
                Logger.debug(LogConfig.MODULE_VPN, "Chrome ACK received connectionId=" + conn.connectionId
                        + " ack=" + (clientAck & 0xFFFFFFFFL));
            }
        }

        if (isRst) {
            sendCloseToOutbound(conn, sendFrameCallback, true);
            byte[] rstPacket = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                    conn.serverNextSeq, clientSeq + 1);
            writePacketCallback.onWritePacket(rstPacket);
            logTcpOut(conn, 0x14, conn.serverNextSeq, clientSeq + 1, 0);
            removeConnection(conn);
            Logger.info(LogConfig.MODULE_VPN, "RESET frame: connectionId=" + conn.connectionId
                    + ", src=" + conn.srcHost + ":" + conn.srcPort
                    + ", dst=" + conn.dstHost + ":" + conn.dstPort + ", payloadLength=0");
            return;
        }

        if (payloadLen > 0) {
            byte[] payload = new byte[payloadLen];
            System.arraycopy(packet, payloadOffset, payload, 0, payloadLen);
            synchronized (conn) {
                if (clientSeq < conn.clientNextSeq) {
                    byte[] ackPacket = buildTcpPacket(conn, new byte[0], (byte) 0x10,
                            conn.serverNextSeq, conn.clientNextSeq);
                    writePacketCallback.onWritePacket(ackPacket);
                    logTcpOut(conn, 0x10, conn.serverNextSeq, conn.clientNextSeq, 0);
                    Logger.debug(LogConfig.MODULE_VPN, "Ignoring duplicate TCP payload: connectionId="
                            + conn.connectionId + ", seq=" + clientSeq + ", expected=" + conn.clientNextSeq);
                    return;
                }
                if (clientSeq != conn.clientNextSeq) {
                    Logger.warning(LogConfig.MODULE_VPN, "Dropping out-of-order TCP payload: connectionId="
                            + conn.connectionId + ", seq=" + clientSeq + ", expected=" + conn.clientNextSeq
                            + ", payloadLength=" + payloadLen);
                    return;
                }
                conn.clientNextSeq += payloadLen;
                conn.touch();
            }

            sendOutboundTcpData(conn, payload, sendFrameCallback);
            byte[] ackPacket = buildTcpPacket(conn, new byte[0], (byte) 0x10,
                    conn.serverNextSeq, conn.clientNextSeq);
            writePacketCallback.onWritePacket(ackPacket);
            logTcpOut(conn, 0x10, conn.serverNextSeq, conn.clientNextSeq, 0);
            Logger.debug(LogConfig.MODULE_VPN, "DATA frame: connectionId=" + conn.connectionId
                    + ", src=" + conn.srcHost + ":" + conn.srcPort
                    + ", dst=" + conn.dstHost + ":" + conn.dstPort
                    + ", payloadLength=" + payloadLen);
        }

        if (isFin) {
            boolean firstFin;
            synchronized (conn) {
                firstFin = !conn.clientFinSeen;
                conn.clientFinSeen = true;
                conn.clientNextSeq = Math.max(conn.clientNextSeq, clientSeq + payloadLen + 1);
                conn.state = TcpState.CLOSING;
                conn.touch();
            }
            if (firstFin) {
                sendCloseToOutbound(conn, sendFrameCallback, false);
                Logger.info(LogConfig.MODULE_VPN, "CLOSE frame: connectionId=" + conn.connectionId
                        + ", src=" + conn.srcHost + ":" + conn.srcPort
                        + ", dst=" + conn.dstHost + ":" + conn.dstPort + ", payloadLength=0");
            }
            // 半关闭：本地 FIN 只回 ACK，会话保留至远端把在途数据排空；
            // 我们的 FIN 由远端关闭路径发出，避免重复 FIN 并丢弃尾部字节。
            int finAckSeq;
            int finAckAck;
            synchronized (conn) {
                finAckSeq = conn.serverNextSeq;
                finAckAck = conn.clientNextSeq;
            }
            byte[] ackPacket = buildTcpPacket(conn, new byte[0], (byte) 0x10, finAckSeq, finAckAck);
            writePacketCallback.onWritePacket(ackPacket);
            logTcpOut(conn, 0x10, finAckSeq, finAckAck, 0);
        }
    }

    private TcpConnection createConnection(String key, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                           int clientSeq, SendFrameCallback sendFrameCallback,
                                           WritePacketCallback writePacketCallback) {
        TcpConnection conn = new TcpConnection(nextConnectionId.incrementAndGet(), key, srcAddr, srcPort,
                dstAddr, dstPort, (int) nextTcpSequence.addAndGet(0x10000L), sendFrameCallback);
        conn.clientNextSeq = clientSeq + 1;
        connectionsByKey.put(key, conn);
        connectionsById.put(conn.connectionId, conn);

        CppRemoteTunnelManager remoteManager = cppRemoteTunnelManager;
        if (!localMode && remoteManager != null) {
            Logger.info(LogConfig.MODULE_VPN, "TCP SYN connectionId=" + conn.connectionId
                    + " mode=CPP_REMOTE dst=" + conn.dstHost + ":" + conn.dstPort);
            remoteManager.createConnection(conn.connectionId, conn.dstAddr, conn.dstPort,
                    data -> handleInboundRawTcpData(conn.connectionId, data, writePacketCallback),
                    reason -> handleRemoteConnectionClosed(conn.connectionId, reason, writePacketCallback));
        } else {
            byte[] openPayload = Socks5Request.buildConnectRequest(conn.dstHost, conn.dstPort);
            sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_OPEN, conn.connectionId, openPayload));
            Logger.info(LogConfig.MODULE_VPN, "OPEN connectionId=" + conn.connectionId
                    + " dst=" + conn.dstHost + ":" + conn.dstPort);
            Logger.info(LogConfig.MODULE_VPN, "OPEN frame: connectionId=" + conn.connectionId
                    + ", src=" + conn.srcHost + ":" + conn.srcPort
                    + ", dst=" + conn.dstHost + ":" + conn.dstPort
                    + ", payloadLength=" + openPayload.length);
        }
        return conn;
    }

    private void handleOutboundUdp(byte[] packet, ByteBuffer buf, int ipHeaderLen, int totalLen,
                                   byte[] srcAddr, byte[] dstAddr, SendFrameCallback sendFrameCallback,
                                   WritePacketCallback writePacketCallback) {
        int udpOffset = ipHeaderLen;
        if (totalLen < udpOffset + 8) {
            return;
        }
        // UDP 只走 IPv4：CPP_REMOTE 仅中继 DNS，且上游固定为 IPv4 的 1.1.1.1；
        // 本地模式的中继帧格式（buildUdpFramePayload）也按 4 字节地址编码。
        // IPv6 的 UDP（QUIC、mDNS 等）与既有的"非 DNS UDP"策略保持一致——直接丢弃。
        // DNS 不受影响：Builder 里通告的解析器是 IPv4 的 1.1.1.1 / 8.8.8.8。
        if (srcAddr.length != 4 || dstAddr.length != 4) {
            Logger.debug(LogConfig.MODULE_VPN, "Ignoring IPv6 UDP dst="
                    + addressToString(dstAddr) + ":" + (buf.getShort(udpOffset + 2) & 0xFFFF));
            return;
        }
        int srcPort = buf.getShort(udpOffset) & 0xFFFF;
        int dstPort = buf.getShort(udpOffset + 2) & 0xFFFF;
        int udpLen = buf.getShort(udpOffset + 4) & 0xFFFF;
        int payloadLen = udpLen - 8;
        if (payloadLen <= 0 || udpOffset + 8 + payloadLen > totalLen) {
            return;
        }
        logUdpTrace(() -> "UDP IN src=" + addressToString(srcAddr) + ":" + srcPort
                + " dst=" + addressToString(dstAddr) + ":" + dstPort
                + " dstPort=" + dstPort
                + " len=" + payloadLen, srcPort, dstPort);
        byte[] udpPayload = new byte[payloadLen];
        System.arraycopy(packet, udpOffset + 8, udpPayload, 0, payloadLen);
        if (!localMode && cppRemoteTunnelManager != null) {
            if (dstPort == 53) {
                relayDnsLocally(srcAddr, srcPort, dstAddr, dstPort, udpPayload, writePacketCallback);
            } else {
                Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE ignoring non-DNS UDP dst="
                        + addressToString(dstAddr) + ":" + dstPort + " len=" + payloadLen);
            }
            return;
        }
        sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_UDP_DATAGRAM, 0,
                buildUdpFramePayload(srcAddr, srcPort, dstAddr, dstPort, udpPayload)));
        String message = "UDP request: src=" + addressToString(srcAddr) + ":" + srcPort
                + ", dst=" + addressToString(dstAddr) + ":" + dstPort
                + ", payloadLength=" + payloadLen;
        if (dstPort == 53) {
            Logger.info(LogConfig.MODULE_VPN, message);
        } else {
            Logger.debug(LogConfig.MODULE_VPN, message);
        }
    }

    public void handleInboundFrame(KcpFrame frame, WritePacketCallback writePacketCallback) {
        if (!running || frame == null) {
            return;
        }

        if (frame.getFrameType() == KcpFrame.TYPE_UDP_DATAGRAM) {
            try {
                UdpDatagram datagram = parseUdpFramePayload(frame.getPayload());
                byte[] udpPacket = buildUdpPacket(datagram.payload, datagram.dstAddr,
                        datagram.dstPort, datagram.srcAddr, datagram.srcPort);
                writePacketCallback.onWritePacket(udpPacket);
                logUdpTrace(() -> "UDP OUT src=" + addressToString(datagram.dstAddr)
                        + ":" + datagram.dstPort
                        + " dst=" + addressToString(datagram.srcAddr) + ":" + datagram.srcPort
                        + " len=" + datagram.payload.length, datagram.dstPort, datagram.srcPort);
                String message = "UDP response: src="
                        + addressToString(datagram.dstAddr) + ":" + datagram.dstPort
                        + ", dst=" + addressToString(datagram.srcAddr) + ":" + datagram.srcPort
                        + ", payloadLength=" + datagram.payload.length;
                if (datagram.dstPort == 53) {
                    Logger.info(LogConfig.MODULE_VPN, message);
                } else {
                    Logger.debug(LogConfig.MODULE_VPN, message);
                }
            } catch (Exception e) {
                Logger.error(LogConfig.MODULE_VPN, "Build UDP response error: " + e.getMessage());
            }
            return;
        }

        TcpConnection conn = connectionsById.get(frame.getConnectionId());
        if (conn == null) {
            Logger.warning(LogConfig.MODULE_VPN, "Dropping frame for unknown connectionId="
                    + frame.getConnectionId() + ", frameType="
                    + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                    + frame.getPayloadLength());
            return;
        }

        try {
            if (frame.getFrameType() == KcpFrame.TYPE_DATA) {
                byte[] payload = frame.getPayload();
                if (payload == null) {
                    payload = new byte[0];
                }
                synchronized (conn) {
                    int offset = 0;
                    while (offset < payload.length) {
                        int segmentLen = Math.min(maxTcpPayload(conn), payload.length - offset);
                        byte[] segment = Arrays.copyOfRange(payload, offset, offset + segmentLen);
                        int seq = conn.serverNextSeq;
                        byte[] ipPacket = buildTcpPacket(conn, segment, (byte) 0x18,
                                seq, conn.clientNextSeq);
                        writePacketCallback.onWritePacket(ipPacket);
                        logTcpOut(conn, 0x18, seq, conn.clientNextSeq, segmentLen);
                        conn.addUnackedServerSegment(seq, segmentLen);
                        conn.serverNextSeq += segmentLen;
                        offset += segmentLen;
                    }
                    conn.touch();
                }
            } else if (frame.getFrameType() == KcpFrame.TYPE_CLOSE) {
                byte[] finAck;
                int seq;
                int ack;
                synchronized (conn) {
                    conn.state = TcpState.CLOSING;
                    seq = conn.serverNextSeq;
                    ack = conn.clientNextSeq;
                    finAck = buildTcpPacket(conn, new byte[0], (byte) 0x11,
                            seq, ack);
                    conn.serverNextSeq += 1;
                    conn.touch();
                }
                writePacketCallback.onWritePacket(finAck);
                logTcpOut(conn, 0x11, seq, ack, 0);
                removeConnection(conn);
            } else if (frame.getFrameType() == KcpFrame.TYPE_RESET) {
                byte[] rstPacket = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                        conn.serverNextSeq, conn.clientNextSeq);
                writePacketCallback.onWritePacket(rstPacket);
                logTcpOut(conn, 0x14, conn.serverNextSeq, conn.clientNextSeq, 0);
                removeConnection(conn);
            }
            Logger.debug(LogConfig.MODULE_VPN, "Inbound frame: connectionId=" + conn.connectionId
                    + ", frameType=" + KcpFrame.frameTypeName(frame.getFrameType())
                    + ", payloadLength=" + frame.getPayloadLength());
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Build inbound packet error: " + e.getMessage());
        }
    }

    public void handleInboundRawTcpData(long connectionId, byte[] payload,
                                        WritePacketCallback writePacketCallback) {
        TcpConnection conn = connectionsById.get(connectionId);
        if (!running || conn == null || payload == null) {
            return;
        }
        try {
            synchronized (conn) {
                int offset = 0;
                while (offset < payload.length) {
                    int segmentLen = Math.min(maxTcpPayload(conn), payload.length - offset);
                    byte[] segment = Arrays.copyOfRange(payload, offset, offset + segmentLen);
                    int seq = conn.serverNextSeq;
                    byte[] ipPacket = buildTcpPacket(conn, segment, (byte) 0x18,
                            seq, conn.clientNextSeq);
                    writePacketCallback.onWritePacket(ipPacket);
                    Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE TCP OUT to TUN len=" + ipPacket.length
                            + " connectionId=" + connectionId);
                    logTcpOut(conn, 0x18, seq, conn.clientNextSeq, segmentLen);
                    conn.addUnackedServerSegment(seq, segmentLen);
                    conn.serverNextSeq += segmentLen;
                    offset += segmentLen;
                }
                conn.touch();
            }
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE TUN_WRITE_FAILED connectionId="
                    + connectionId + " error=" + e.getMessage());
        }
    }

    private void handleRemoteConnectionClosed(long connectionId, String reason,
                                              WritePacketCallback writePacketCallback) {
        TcpConnection conn = connectionsById.get(connectionId);
        if (conn == null) {
            return;
        }
        try {
            byte[] packet;
            int flags;
            synchronized (conn) {
                conn.state = TcpState.CLOSING;
                // 用 CppRemoteKcpSession 的显式白名单判定，而不是在 reason 里找
                // "FAILED" 子串：SESSION_TIMEOUT / CPP_SERVER_NO_RESPONSE /
                // CRYPTO_MISMATCH / KCP_BACKPRESSURE_OVERFLOW 都是失败但不含
                // "FAILED"，旧写法会回 FIN，应用看到干净 EOF 而察觉不到截断。
                flags = CppRemoteKcpSession.isGracefulCloseReason(reason) ? 0x11 : 0x14;
                packet = buildTcpPacket(conn, new byte[0], (byte) flags,
                        conn.serverNextSeq, conn.clientNextSeq);
                if (flags == 0x11) {
                    conn.serverNextSeq += 1;
                }
            }
            writePacketCallback.onWritePacket(packet);
            logTcpOut(conn, flags, conn.serverNextSeq, conn.clientNextSeq, 0);
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE close write failed connectionId="
                    + connectionId + " error=" + e.getMessage());
        } finally {
            removeConnection(conn);
        }
    }

    private void sendOutboundTcpData(TcpConnection conn, byte[] payload,
                                     SendFrameCallback sendFrameCallback) {
        CppRemoteTunnelManager remoteManager = cppRemoteTunnelManager;
        if (!localMode && remoteManager != null) {
            remoteManager.sendData(conn.connectionId, payload);
            return;
        }
        sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_DATA, conn.connectionId, payload));
    }

    private void sendCloseToOutbound(TcpConnection conn, SendFrameCallback sendFrameCallback, boolean reset) {
        CppRemoteTunnelManager remoteManager = cppRemoteTunnelManager;
        if (!localMode && remoteManager != null) {
            if (reset) {
                remoteManager.closeConnection(conn.connectionId, "tcp_rst");
            } else {
                remoteManager.halfCloseConnection(conn.connectionId);
            }
            return;
        }
        sendFrameCallback.onSendFrame(new KcpFrame(reset ? KcpFrame.TYPE_RESET : KcpFrame.TYPE_CLOSE,
                conn.connectionId, null));
    }

    private void relayDnsLocally(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort, byte[] payload,
                                 WritePacketCallback writePacketCallback) {
        new Thread(() -> {
            try (DatagramSocket socket = new DatagramSocket()) {
                boolean protectedOk = socketProtector != null && socketProtector.protect(socket);
                Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE DNS UDP IN query="
                        + addressToString(dstAddr) + ":" + dstPort
                        + " src=" + addressToString(srcAddr) + ":" + srcPort);
                Logger.info(LogConfig.MODULE_VPN, "CPP_REMOTE DNS UDP socket protected=" + protectedOk);
                if (!protectedOk) {
                    Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE DNS_FAILED reason=protect_failed");
                    return;
                }
                socket.setSoTimeout(5000);
                InetAddress server = InetAddress.getByName("1.1.1.1");
                socket.send(new DatagramPacket(payload, payload.length, server, 53));
                byte[] buf = new byte[1500];
                DatagramPacket response = new DatagramPacket(buf, buf.length);
                socket.receive(response);
                byte[] dnsPayload = Arrays.copyOfRange(response.getData(), response.getOffset(),
                        response.getOffset() + response.getLength());
                Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE DNS response received len=" + dnsPayload.length);
                byte[] udpPacket = buildUdpPacket(dnsPayload, dstAddr, dstPort, srcAddr, srcPort);
                writePacketCallback.onWritePacket(udpPacket);
                Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE DNS UDP OUT written to TUN");
            } catch (Exception e) {
                Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE DNS_FAILED error=" + e.getMessage());
            }
        }, "CPP-DNS-Relay").start();
    }

    /**
     * 隧道侧是否还有活会话。用于把"空闲但健康"和"远端已消失、只剩本地映射"
     * 区分开：前者不该被空闲回收掐断。
     * CPP_REMOTE 走 manager 的会话表；本地模式走注入的存活判据（TunnelManager）。
     */
    private boolean isTunnelAlive(TcpConnection conn) {
        CppRemoteTunnelManager remoteManager = cppRemoteTunnelManager;
        if (!localMode && remoteManager != null) {
            return remoteManager.hasSession(conn.connectionId);
        }
        java.util.function.BooleanSupplier supplier = tunnelAliveSupplier;
        return supplier != null && supplier.getAsBoolean();
    }

    private void removeConnection(TcpConnection conn) {
        conn.close();
        connectionsByKey.remove(conn.key);
        connectionsById.remove(conn.connectionId);
    }

    /** 该连接的 IP 族对应的单包最大 TCP 负载（保证 头 + TCP头 + 负载 ≤ MTU）。 */
    private static int maxTcpPayload(TcpConnection conn) {
        return conn.dstAddr.length == IPV6_ADDR_LEN
                ? MAX_TCP_PAYLOAD_PER_PACKET_IPV6
                : MAX_TCP_PAYLOAD_PER_PACKET;
    }

    private byte[] buildTcpPacket(TcpConnection conn, byte[] payload, byte tcpFlags, int seq, int ack) {
        boolean ipv6 = conn.dstAddr.length == IPV6_ADDR_LEN;
        int ipHeaderLen = ipv6 ? IPV6_HEADER_LEN : IPV4_HEADER_LEN;
        int tcpLen = TCP_HEADER_LEN + payload.length;
        int totalLen = ipHeaderLen + tcpLen;
        byte[] packet = new byte[totalLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        if (ipv6) {
            // 版本(4) + traffic class(8) + flow label(20) = 前 4 字节
            buf.put((byte) 0x60);
            buf.put((byte) 0);
            buf.put((byte) 0);
            buf.put((byte) 0);
            buf.putShort((short) tcpLen);   // payload length：不含 40 字节头
            buf.put((byte) 6);              // next header = TCP
            buf.put((byte) 64);             // hop limit
            buf.put(conn.dstAddr);          // src = 远端目标
            buf.put(conn.srcAddr);          // dst = 本机
        } else {
            buf.put((byte) 0x45);
            buf.put((byte) 0);
            buf.putShort((short) totalLen);
            buf.putShort((short) 0);
            buf.putShort((short) 0x4000);
            buf.put((byte) 64);
            buf.put((byte) 6);
            buf.putShort((short) 0);
            buf.put(conn.dstAddr);
            buf.put(conn.srcAddr);
        }
        buf.putShort((short) conn.dstPort);
        buf.putShort((short) conn.srcPort);
        buf.putInt(seq);
        buf.putInt(ack);
        buf.put((byte) 0x50);
        buf.put(tcpFlags);
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.put(payload);
        if (!ipv6) {
            // IPv6 没有头部校验和，只有 TCP 伪首部校验和
            putChecksum(packet, 10, checksum(packet, 0, IPV4_HEADER_LEN));
        }
        putChecksum(packet, ipHeaderLen + 16,
                tcpChecksum(packet, ipHeaderLen, tcpLen, conn.dstAddr, conn.srcAddr));
        return packet;
    }

    private byte[] buildUdpPacket(byte[] payload, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort) {
        int udpLen = 8 + payload.length;
        int totalLen = 20 + udpLen;
        byte[] packet = new byte[totalLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 17);
        buf.putShort((short) 0);
        buf.put(srcAddr);
        buf.put(dstAddr);
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);
        buf.put(payload);
        putChecksum(packet, 10, checksum(packet, 0, 20));
        int udpChecksum = udpChecksum(packet, 20, udpLen, srcAddr, dstAddr);
        putChecksum(packet, 26, udpChecksum == 0 ? 0xFFFF : udpChecksum);
        return packet;
    }

    public static byte[] buildUdpFramePayload(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                              byte[] payload) {
        ByteBuffer buf = ByteBuffer.allocate(16 + payload.length).order(ByteOrder.BIG_ENDIAN);
        buf.put(srcAddr);
        buf.putShort((short) srcPort);
        buf.put(dstAddr);
        buf.putShort((short) dstPort);
        buf.putInt(payload.length);
        buf.put(payload);
        return buf.array();
    }

    public static UdpDatagram parseUdpFramePayload(byte[] payload) {
        if (payload == null || payload.length < 16) {
            throw new IllegalArgumentException("UDP frame payload too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        byte[] srcAddr = new byte[4];
        byte[] dstAddr = new byte[4];
        buf.get(srcAddr);
        int srcPort = buf.getShort() & 0xFFFF;
        buf.get(dstAddr);
        int dstPort = buf.getShort() & 0xFFFF;
        int payloadLen = buf.getInt();
        if (payloadLen < 0 || payloadLen > buf.remaining()) {
            throw new IllegalArgumentException("Invalid UDP payloadLength=" + payloadLen);
        }
        byte[] data = new byte[payloadLen];
        buf.get(data);
        return new UdpDatagram(srcAddr, srcPort, dstAddr, dstPort, data);
    }

    private static int tcpChecksum(byte[] packet, int offset, int len, byte[] srcAddr, byte[] dstAddr) {
        return protocolChecksum(packet, offset, len, srcAddr, dstAddr, 6);
    }

    private static int udpChecksum(byte[] packet, int offset, int len, byte[] srcAddr, byte[] dstAddr) {
        return protocolChecksum(packet, offset, len, srcAddr, dstAddr, 17);
    }

    private static int protocolChecksum(byte[] packet, int offset, int len, byte[] srcAddr, byte[] dstAddr,
                                        int protocol) {
        boolean ipv6 = srcAddr.length == IPV6_ADDR_LEN;
        int pseudoLen = ipv6 ? 40 : 12;
        byte[] pseudo = new byte[pseudoLen + len];
        if (ipv6) {
            // IPv6 伪首部：src(16) + dst(16) + 上层长度(4) + 三字节零(3) + next header(1)
            System.arraycopy(srcAddr, 0, pseudo, 0, IPV6_ADDR_LEN);
            System.arraycopy(dstAddr, 0, pseudo, IPV6_ADDR_LEN, IPV6_ADDR_LEN);
            pseudo[32] = (byte) ((len >> 24) & 0xFF);
            pseudo[33] = (byte) ((len >> 16) & 0xFF);
            pseudo[34] = (byte) ((len >> 8) & 0xFF);
            pseudo[35] = (byte) (len & 0xFF);
            pseudo[39] = (byte) protocol;   // pseudo[36..38] 保持 0
        } else {
            System.arraycopy(srcAddr, 0, pseudo, 0, 4);
            System.arraycopy(dstAddr, 0, pseudo, 4, 4);
            pseudo[8] = 0;
            pseudo[9] = (byte) protocol;
            pseudo[10] = (byte) ((len >> 8) & 0xFF);
            pseudo[11] = (byte) (len & 0xFF);
        }
        System.arraycopy(packet, offset, pseudo, pseudoLen, len);
        return checksum(pseudo, 0, pseudo.length);
    }

    private static int checksum(byte[] data, int offset, int len) {
        long sum = 0;
        int i = offset;
        while (len > 1) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
            len -= 2;
        }
        if (len > 0) {
            sum += (data[i] & 0xFF) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum) & 0xFFFF;
    }

    private static void putChecksum(byte[] packet, int offset, int checksum) {
        packet[offset] = (byte) ((checksum >> 8) & 0xFF);
        packet[offset + 1] = (byte) (checksum & 0xFF);
    }

    private static boolean seqAfterOrEqual(int a, int b) {
        return a == b || (a - b) > 0;
    }

    private static String connectionKey(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort) {
        return addressToString(srcAddr) + ":" + srcPort + "->" + addressToString(dstAddr) + ":" + dstPort;
    }

    /**
     * 是否是我们不解析的 IPv6 扩展头（next header 字段里的值）。
     * 逐跳(0)/路由(43)/分片(44)/AH(51)/目的地选项(60)：出现这些时真正的上层协议在
     * 更后面的 next header 里，或者我们只拿到一个分片——都按"不支持"丢弃。
     */
    private static boolean isIpv6ExtensionHeader(int nextHeader) {
        return nextHeader == 0 || nextHeader == 43 || nextHeader == 44
                || nextHeader == 51 || nextHeader == 60;
    }

    private static String addressToString(byte[] addr) {
        if (addr.length == IPV6_ADDR_LEN) {
            return formatIpv6(addr);
        }
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "."
                + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
    }

    /**
     * IPv6 文本形式。交给 InetAddress 做 RFC 5952 的 :: 压缩——getByAddress 只解析
     * 字面量、不发 DNS 查询。同一段字节永远得到同一个字符串，所以连接表 key 稳定。
     */
    private static String formatIpv6(byte[] addr) {
        try {
            return InetAddress.getByAddress(addr).getHostAddress();
        } catch (java.net.UnknownHostException e) {
            // 长度已由调用方保证为 16，理论不可达
            return "<ipv6:" + addr.length + "B>";
        }
    }

    private static void logTcpIn(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                 int flags, int seq, int ack, int len) {
        Logger.packetTrace(LogConfig.MODULE_VPN, () -> "TCP IN src=" + addressToString(srcAddr) + ":" + srcPort
                + " dst=" + addressToString(dstAddr) + ":" + dstPort
                + " flags=0x" + Integer.toHexString(flags)
                + " seq=" + (seq & 0xFFFFFFFFL)
                + " ack=" + (ack & 0xFFFFFFFFL)
                + " len=" + len);
    }

    private static void logTcpOut(TcpConnection conn, int flags, int seq, int ack, int len) {
        Logger.packetTrace(LogConfig.MODULE_VPN, () -> "TCP OUT src=" + conn.dstHost + ":" + conn.dstPort
                + " dst=" + conn.srcHost + ":" + conn.srcPort
                + " flags=0x" + Integer.toHexString(flags)
                + " seq=" + (seq & 0xFFFFFFFFL)
                + " ack=" + (ack & 0xFFFFFFFFL)
                + " len=" + len);
    }

    private void logUdpTrace(java.util.function.Supplier<String> message, int srcPort, int dstPort) {
        if (srcPort == 53 || dstPort == 53
                || udpTraceCounter.incrementAndGet() % UDP_TRACE_SAMPLE_RATE == 0) {
            Logger.packetTrace(LogConfig.MODULE_VPN, message);
        }
    }

    private void startCleanupThread() {
        cleanupThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(10_000);
                    long now = System.currentTimeMillis();
                    for (TcpConnection conn : connectionsById.values()) {
                        long age = now - conn.lastActivityTime;
                        if (conn.state == TcpState.ESTABLISHED) {
                            if (age <= ESTABLISHED_IDLE_TIMEOUT_MS) {
                                continue;
                            }
                            // 隧道侧仍有活会话 → 这是"长时间没数据"，不是死连接。
                            // 远端存活性由 KCP 保活 + dead_link 检测负责（见
                            // CppRemoteKcpSession 的更新循环），真死时会经 close 回调
                            // 走 handleRemoteConnectionClosed。旧实现只看空闲时长，
                            // 把 SSH / IMAP IDLE / 长轮询 / WebSocket 这类长时间静默
                            // 但完全健康的连接一起掐了。
                            if (isTunnelAlive(conn)) {
                                continue;
                            }
                        } else if (age <= CLOSING_IDLE_TIMEOUT_MS) {
                            continue;
                        }
                        Logger.info(LogConfig.MODULE_VPN, "Stale connection cleanup: connectionId="
                                + conn.connectionId + ", state=" + conn.state
                                + ", idleMs=" + age);
                        // 必须走 sendCloseToOutbound：CPP_REMOTE 模式下裸 KcpFrame 会被丢弃，
                        // 远端会话与 UDP socket 将一直泄漏。
                        sendCloseToOutbound(conn, conn.sendFrameCallback,
                                conn.state != TcpState.ESTABLISHED);
                        removeConnection(conn);
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "PacketRouter-Cleanup");
        cleanupThread.start();
    }

    public interface OutboundCallback {
        void onSendFrame(KcpFrame frame);
        void onWriteToVpn(byte[] packet);
    }

    public interface SendFrameCallback {
        void onSendFrame(KcpFrame frame);
    }

    public interface WritePacketCallback {
        void onWritePacket(byte[] packet);
    }

    public static class UdpDatagram {
        public final byte[] srcAddr;
        public final int srcPort;
        public final byte[] dstAddr;
        public final int dstPort;
        public final byte[] payload;

        UdpDatagram(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort, byte[] payload) {
            this.srcAddr = srcAddr;
            this.srcPort = srcPort;
            this.dstAddr = dstAddr;
            this.dstPort = dstPort;
            this.payload = payload;
        }
    }

    private enum TcpState {
        SYN_RECEIVED,
        ESTABLISHED,
        CLOSING
    }

    private static class TcpConnection {
        private final long connectionId;
        private final String key;
        private final byte[] srcAddr;
        private final byte[] dstAddr;
        private final int srcPort;
        private final int dstPort;
        private final String srcHost;
        private final String dstHost;
        private final int serverInitialSeq;
        private final SendFrameCallback sendFrameCallback;
        private int clientNextSeq;
        private int serverNextSeq;
        private int lastAckFromClient;
        private final Deque<UnackedSegment> unackedServerData;
        private long lastActivityTime;
        private TcpState state;
        private boolean synAckSent;
        private boolean clientFinSeen;
        private volatile boolean closed;

        TcpConnection(long connectionId, String key, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                      int initialServerSeq, SendFrameCallback sendFrameCallback) {
            this.connectionId = connectionId;
            this.key = key;
            this.srcAddr = Arrays.copyOf(srcAddr, srcAddr.length);
            this.dstAddr = Arrays.copyOf(dstAddr, dstAddr.length);
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.srcHost = addressToString(srcAddr);
            this.dstHost = addressToString(dstAddr);
            this.serverInitialSeq = initialServerSeq;
            this.sendFrameCallback = sendFrameCallback;
            this.clientNextSeq = 0;
            this.serverNextSeq = initialServerSeq;
            this.lastAckFromClient = 0;
            this.unackedServerData = new ArrayDeque<>();
            this.lastActivityTime = System.currentTimeMillis();
            this.state = TcpState.SYN_RECEIVED;
            this.synAckSent = false;
            this.closed = false;
        }

        void touch() {
            lastActivityTime = System.currentTimeMillis();
        }

        void addUnackedServerSegment(int seq, int length) {
            if (length > 0) {
                unackedServerData.addLast(new UnackedSegment(seq, length));
            }
        }

        void removeAckedServerSegments(int ack) {
            while (!unackedServerData.isEmpty()) {
                UnackedSegment segment = unackedServerData.peekFirst();
                if (seqAfterOrEqual(ack, segment.endSeq())) {
                    unackedServerData.removeFirst();
                } else {
                    break;
                }
            }
        }

        void close() {
            closed = true;
        }
    }

    private static class UnackedSegment {
        private final int seq;
        private final int length;

        UnackedSegment(int seq, int length) {
            this.seq = seq;
            this.length = length;
        }

        int endSeq() {
            return seq + length;
        }
    }
}
