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
    // server→app 方向的在途段重传。TUN 写丢失的段没有别的恢复途径（内核 TCP
    // 栈不会替我们重传我们发出的段）：应用对序号空洞回 dup-ACK，累计到阈值就
    // 快速重传最早的未确认段；尾部段丢失收不到 dup-ACK，由清理线程按停滞超时
    // 兜底重传。两者都依赖 addUnackedServerSegment 保留的段负载。
    private static final int DUP_ACK_RETRANSMIT_THRESHOLD = 3;
    private static final long RETRANSMIT_STALL_MS = 3000;
    // 连续多次兜底重传仍无任何 ACK 进展：连接不可恢复（对端内核彻底静默），
    // 放弃重传并回 RST，避免每 3s 无限重发。
    private static final int MAX_STALL_RETRANSMITS = 10;
    // 单连接滞留的未确认负载上限：应用长时间不 ACK（接收缓冲不再 drain 或进程
    // 已死）时，超过即判定连接不可恢复，回 RST 明确失败，而不是无界吃内存。
    private static final int MAX_UNACKED_RETAINED_BYTES = 256 * 1024;
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
    // DNS 中继线程池：每查询一个 new Thread 在页面加载（10-30 个查询）下是纯
    // 线程churn，故障/恶意应用刷 DNS 更会无上限地制造线程。固定小池排队即可，
    // 单个查询有 5s socket 超时，任务时长有界。
    private volatile java.util.concurrent.ExecutorService dnsRelayExecutor;
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
        dnsRelayExecutor = java.util.concurrent.Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "CPP-DNS-Relay");
            t.setDaemon(true);
            return t;
        });
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
        if (dnsRelayExecutor != null) {
            dnsRelayExecutor.shutdownNow();
            dnsRelayExecutor = null;
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
        // 应用通告的接收窗口（相对其 ack）：这是我们对应用方向的唯一流控信号。
        // 旧实现无视它（恒告 65535），应用内核缓冲填满后我们继续灌包，内核只能
        // 丢弃窗口外的段并回 dup-ACK——没有流控时是静默丢段，有重传后则变成
        // 无进展的重传循环。窗口耗尽即暂停转发（见 acceptOutboundSegment）。
        int peerWindow = buf.getShort(tcpOffset + 14) & 0xFFFF;
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
                // 窗口基准必须锚在我们自己的序列空间：应用期望我们的第一个数据
                // 字节落在 serverInitialSeq+1，SYN 的窗口字段是它对该方向的接收
                // 缓冲量。锚到 clientSeq+1（对端 ISN+1，另一个方向的序列空间）
                // 时，两个随机 ISN 的高低关系约五五开——错误基准会毒化窗口数学：
                // 过量发送被内核丢弃后反复重传，直到累计确认爬过错误基准。
                conn.setSendWindow(conn.serverInitialSeq + 1, peerWindow);
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
            UnackedSegment retransmit = null;
            synchronized (conn) {
                conn.lastAckFromClient = clientAck;
                // 窗口随每个应用报文按 RFC 793 规则刷新；窗口重新打开时要先
                // 冲刷滞留段，dup-ACK/快速重传逻辑才能看到完整的在途队列。
                conn.updateSendWindow(clientAck, peerWindow);
                if (conn.state == TcpState.SYN_RECEIVED) {
                    conn.state = TcpState.ESTABLISHED;
                }
                int removed = conn.removeAckedServerSegments(clientAck);
                flushPendingSegments(conn, writePacketCallback);
                if (removed > 0 || !conn.hasUnackedServerData()) {
                    conn.resetDupAcks();
                } else if (conn.tickDupAck()) {
                    UnackedSegment first = conn.peekFirstUnacked();
                    // 段已超出应用当前窗口时不白白重发（内核仍会丢弃）；窗口在
                    // 后续报文里重新打开后，这里的 dup-ACK 计数会立即命中发送。
                    if (first != null && conn.fitsInSendWindow(first.seq, first.length)) {
                        retransmit = first;
                        conn.markRetransmitted();
                    }
                }
                conn.touch();
            }
            if (retransmit != null) {
                byte[] retransmitPacket;
                int ack;
                synchronized (conn) {
                    ack = conn.clientNextSeq;
                    retransmitPacket = buildTcpPacket(conn, retransmit.payload, (byte) 0x18,
                            retransmit.seq, ack);
                }
                writePacketCallback.onWritePacket(retransmitPacket);
                logTcpOut(conn, 0x18, retransmit.seq, ack, retransmit.length);
                Logger.info(LogConfig.MODULE_VPN, "Fast retransmit: connectionId=" + conn.connectionId
                        + ", seq=" + (retransmit.seq & 0xFFFFFFFFL)
                        + ", len=" + retransmit.length);
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
            // 本地模式：远端已经先 FIN（serverFinSeen）而应用现在也 FIN——两个
            // 方向都结束，整体拆除；CPP_REMOTE 路径不设 serverFinSeen，不受影响。
            if (conn.serverFinSeen) {
                removeConnection(conn);
            }
        }
    }

    private TcpConnection createConnection(String key, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                           int clientSeq, SendFrameCallback sendFrameCallback,
                                           WritePacketCallback writePacketCallback) {
        TcpConnection conn = new TcpConnection(nextConnectionId.incrementAndGet(), key, srcAddr, srcPort,
                dstAddr, dstPort, (int) nextTcpSequence.addAndGet(0x10000L), sendFrameCallback,
                writePacketCallback);
        conn.clientNextSeq = clientSeq + 1;
        connectionsByKey.put(key, conn);
        connectionsById.put(conn.connectionId, conn);

        CppRemoteTunnelManager remoteManager = cppRemoteTunnelManager;
        if (!localMode && remoteManager != null) {
            Logger.info(LogConfig.MODULE_VPN, "TCP SYN connectionId=" + conn.connectionId
                    + " mode=CPP_REMOTE dst=" + conn.dstHost + ":" + conn.dstPort);
            remoteManager.createConnection(conn.connectionId, conn.dstAddr, conn.dstPort,
                    new CppRemoteKcpSession.DataCallback() {
                        @Override
                        public void onData(byte[] data) {
                            handleInboundRawTcpData(conn.connectionId, data, writePacketCallback);
                        }

                        @Override
                        public boolean hasSendCredit() {
                            return PacketRouter.this.hasSendCredit(conn);
                        }
                    },
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
                boolean unackedOverflow = false;
                synchronized (conn) {
                    int offset = 0;
                    while (offset < payload.length) {
                        int segmentLen = Math.min(maxTcpPayload(conn), payload.length - offset);
                        byte[] segment = Arrays.copyOfRange(payload, offset, offset + segmentLen);
                        int seq = conn.serverNextSeq;
                        // 窗口内 → 立即写 TUN；窗口耗尽 → 滞留 pending 等待窗口
                        // 重新打开（由应用报文触发的 flushPendingSegments 送出）。
                        // 登记失败（滞留总量超限）时这段绝不能已经写出去。
                        SegmentOutcome outcome =
                                conn.acceptOutboundSegment(seq, segment);
                        if (outcome == SegmentOutcome.OVERFLOW) {
                            unackedOverflow = true;
                            break;
                        }
                        if (outcome == SegmentOutcome.SEND_NOW) {
                            byte[] ipPacket = buildTcpPacket(conn, segment, (byte) 0x18,
                                    seq, conn.clientNextSeq);
                            writePacketCallback.onWritePacket(ipPacket);
                            logTcpOut(conn, 0x18, seq, conn.clientNextSeq, segmentLen);
                        }
                        conn.serverNextSeq += segmentLen;
                        offset += segmentLen;
                    }
                    if (!unackedOverflow) {
                        conn.touch();
                    }
                }
                if (unackedOverflow) {
                    // 应用长时间不 ACK（内核接收缓冲不再 drain 或进程已死），
                    // 继续转发只会无界吃内存。明确失败：回 RST 并拆除，
                    // 而不是丢段造成应用侧静默的流损坏。
                    abortConnection(conn, writePacketCallback);
                    return;
                }
            } else if (frame.getFrameType() == KcpFrame.TYPE_FIN) {
                // 本地模式：目标写侧已关闭。向应用回 FIN 但保留连接——应用的
                // 请求方向可能仍在途（TYPE_FIN 语义，与 CPP_REMOTE 的服务器 FIN
                // 处理一致）；应用也 FIN 后才整体拆除。
                byte[] finPacket;
                int seq;
                int ack;
                boolean bothDone;
                synchronized (conn) {
                    seq = conn.serverNextSeq;
                    ack = conn.clientNextSeq;
                    finPacket = buildTcpPacket(conn, new byte[0], (byte) 0x11, seq, ack);
                    conn.serverNextSeq += 1;
                    conn.serverFinSeen = true;
                    conn.state = TcpState.CLOSING;
                    conn.touch();
                    bothDone = conn.clientFinSeen;
                }
                writePacketCallback.onWritePacket(finPacket);
                logTcpOut(conn, 0x11, seq, ack, 0);
                if (bothDone) {
                    removeConnection(conn);
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
            boolean unackedOverflow = false;
            synchronized (conn) {
                int offset = 0;
                while (offset < payload.length) {
                    int segmentLen = Math.min(maxTcpPayload(conn), payload.length - offset);
                    byte[] segment = Arrays.copyOfRange(payload, offset, offset + segmentLen);
                    int seq = conn.serverNextSeq;
                    // 同 handleInboundFrame：窗口内立即写 TUN，窗口耗尽滞留 pending。
                    SegmentOutcome outcome =
                            conn.acceptOutboundSegment(seq, segment);
                    if (outcome == SegmentOutcome.OVERFLOW) {
                        unackedOverflow = true;
                        break;
                    }
                    if (outcome == SegmentOutcome.SEND_NOW) {
                        byte[] ipPacket = buildTcpPacket(conn, segment, (byte) 0x18,
                                seq, conn.clientNextSeq);
                        writePacketCallback.onWritePacket(ipPacket);
                        Logger.debug(LogConfig.MODULE_VPN, "CPP_REMOTE TCP OUT to TUN len=" + ipPacket.length
                                + " connectionId=" + connectionId);
                        logTcpOut(conn, 0x18, seq, conn.clientNextSeq, segmentLen);
                    }
                    conn.serverNextSeq += segmentLen;
                    offset += segmentLen;
                }
                if (!unackedOverflow) {
                    conn.touch();
                }
            }
            if (unackedOverflow) {
                abortConnection(conn, writePacketCallback);
            }
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "CPP_REMOTE TUN_WRITE_FAILED connectionId="
                    + connectionId + " error=" + e.getMessage());
        }
    }

    /**
     * 把滞留在 pending 的段按序送出：只要窗口装得下就从队首逐段转为在途并写
     * TUN。触发点是每个应用报文（isAck 分支先刷新窗口再走到这里）——窗口重新
     * 打开往往伴随一个不含新确认的 dup-ACK，所以必须在 dup-ACK 判定之前冲刷。
     */
    private void flushPendingSegments(TcpConnection conn, WritePacketCallback writePacketCallback) {
        while (conn.hasPendingSegments()) {
            UnackedSegment seg = conn.peekFirstPending();
            if (!conn.fitsInSendWindow(seg.seq, seg.length)) {
                return;
            }
            conn.promoteFirstPending();
            byte[] packet = buildTcpPacket(conn, seg.payload, (byte) 0x18,
                    seg.seq, conn.clientNextSeq);
            writePacketCallback.onWritePacket(packet);
            logTcpOut(conn, 0x18, seg.seq, conn.clientNextSeq, seg.length);
        }
    }

    /**
     * 不可恢复时强制拆链：关远端会话、向应用回 RST、摘除本地映射。
     * 应用看到的是明确的连接重置（可以立即重试），而不是静默丢段导致的挂死。
     */
    private void abortConnection(TcpConnection conn, WritePacketCallback writePacketCallback) {
        sendCloseToOutbound(conn, conn.sendFrameCallback, true);
        byte[] rst;
        synchronized (conn) {
            rst = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                    conn.serverNextSeq, conn.clientNextSeq);
        }
        try {
            writePacketCallback.onWritePacket(rst);
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Abort RST write failed: " + e.getMessage());
        }
        removeConnection(conn);
        Logger.info(LogConfig.MODULE_VPN, "ABORT connectionId=" + conn.connectionId
                + " reason=unacked_overflow");
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
            int sentSeq;
            int sentAck;
            synchronized (conn) {
                conn.state = TcpState.CLOSING;
                // 用 CppRemoteKcpSession 的显式白名单判定，而不是在 reason 里找
                // "FAILED" 子串：SESSION_TIMEOUT / CPP_SERVER_NO_RESPONSE /
                // CRYPTO_MISMATCH / KCP_BACKPRESSURE_OVERFLOW 都是失败但不含
                // "FAILED"，旧写法会回 FIN，应用看到干净 EOF 而察觉不到截断。
                flags = CppRemoteKcpSession.isGracefulCloseReason(reason) ? 0x11 : 0x14;
                // 日志 seq 必须在自增前取：FIN 的 seq 是发出值，serverNextSeq 随后
                // +1，旧写法在锁外用已自增的值打日志，与实际发出的差 1。
                sentSeq = conn.serverNextSeq;
                sentAck = conn.clientNextSeq;
                packet = buildTcpPacket(conn, new byte[0], (byte) flags,
                        sentSeq, sentAck);
                if (flags == 0x11) {
                    conn.serverNextSeq += 1;
                }
            }
            writePacketCallback.onWritePacket(packet);
            logTcpOut(conn, flags, sentSeq, sentAck, 0);
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
        // 本地模式：半关闭走 TYPE_FIN（服务器端 shutdownOutput，目标的在途响应
        // 不被截断）；TYPE_CLOSE 保留为整体关闭语义，只在双方都完成后由远端
        // 显式发出。
        sendFrameCallback.onSendFrame(new KcpFrame(reset ? KcpFrame.TYPE_RESET : KcpFrame.TYPE_FIN,
                conn.connectionId, null));
    }

    private void relayDnsLocally(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort, byte[] payload,
                                 WritePacketCallback writePacketCallback) {
        java.util.concurrent.ExecutorService relay = dnsRelayExecutor;
        if (relay == null) {
            return;  // 路由器已停止
        }
        relay.execute(() -> {
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
        });
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

    /**
     * 连接的应用方向是否仍有发送额度。false 时 CPP_REMOTE 会话停止从 KCP 取数，
     * 让 KCP 接收窗口收紧、把背压传回服务器（服务器侧 forward 循环随即停读目标
     * socket）。滞留 pending 只是"额度判断与窗口关闭"之间竞态的兜底，正常情况
     * 下数据应留在 KCP 而不是进入路由器。
     */
    private boolean hasSendCredit(TcpConnection conn) {
        synchronized (conn) {
            return conn.hasSendCredit();
        }
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
                    // 1s 粒度：驱动停滞重传兜底（3s 阈值），也让陈旧回收更及时。
                    Thread.sleep(1000);
                    long now = System.currentTimeMillis();
                    for (TcpConnection conn : connectionsById.values()) {
                        // 兜底重传先于回收判定：有未确认在途段时连接是"停滞"而非
                        // "陈旧"。尾部段丢失收不到 dup-ACK，只有这里能把流救回来。
                        UnackedSegment stalled =
                                conn.pollStalledRetransmit(now, RETRANSMIT_STALL_MS);
                        if (stalled != null) {
                            byte[] packet;
                            int ack;
                            synchronized (conn) {
                                ack = conn.clientNextSeq;
                                packet = buildTcpPacket(conn, stalled.payload, (byte) 0x18,
                                        stalled.seq, ack);
                            }
                            try {
                                conn.writePacketCallback.onWritePacket(packet);
                                logTcpOut(conn, 0x18, stalled.seq, ack, stalled.length);
                                Logger.info(LogConfig.MODULE_VPN, "Stall retransmit: connectionId="
                                        + conn.connectionId
                                        + ", seq=" + (stalled.seq & 0xFFFFFFFFL)
                                        + ", len=" + stalled.length
                                        + ", attempt=" + conn.stalledRetransmitCount());
                            } catch (Exception e) {
                                Logger.error(LogConfig.MODULE_VPN,
                                        "Stall retransmit write failed: " + e.getMessage());
                            }
                            if (conn.stalledRetransmitCount() > MAX_STALL_RETRANSMITS) {
                                // 多次兜底重传后仍无任何 ACK 进展：对端内核彻底静默，
                                // 连接不可恢复。回 RST 明确失败并回收，不再无限重发。
                                abortConnection(conn, conn.writePacketCallback);
                            }
                            continue;
                        }
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
                        // 回收时必须向应用回 RST：此时远端会话已关闭，缺了这个包
                        // 应用只会看到连接静默挂死，直到自己的超时才放弃。
                        byte[] rst;
                        synchronized (conn) {
                            rst = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                                    conn.serverNextSeq, conn.clientNextSeq);
                        }
                        try {
                            conn.writePacketCallback.onWritePacket(rst);
                        } catch (Exception e) {
                            Logger.error(LogConfig.MODULE_VPN,
                                    "Cleanup RST write failed: " + e.getMessage());
                        }
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
        // 写 TUN 的回调随连接保存：重传与回收路径在各自线程上也要能把包写进 TUN。
        private final WritePacketCallback writePacketCallback;
        private int clientNextSeq;
        private int serverNextSeq;
        private int lastAckFromClient;
        // server→app 方向的在途段登记（保留负载以备重传）。TUN 写丢失的段没有
        // 其他恢复途径：靠应用 dup-ACK（快速）或清理线程停滞兜底重传，直到确认。
        private final Deque<UnackedSegment> unackedServerData;
        private int unackedBytes;
        // 窗口耗尽时滞留的未发送段（应用报文刷新窗口后由 flushPendingSegments
        // 按序送出）。与 unacked 共享同一个滞留总量上限。
        private final Deque<UnackedSegment> pendingQueue = new ArrayDeque<>();
        private int pendingBytes;
        // 应用最近通告的接收窗口及其基准 ack：段 [ack, ack+window) 之内才允许
        // 写 TUN（无符号回绕比较见 fitsInSendWindow）。
        private int appWindowAck;
        private int appWindow;
        // 连续无进展的 dup-ACK 计数；达到阈值触发快速重传并复位。
        private int dupAckCount;
        // 上次 ACK 确认掉在途段的时刻（停滞重传的时间基准）。
        private long lastAckProgressMs;
        // 上次重传（快速或兜底）的时刻，避免两条重传路径对同一段背靠背重发。
        private long lastRetransmitMs;
        // 连续"无任何 ACK 进展"的兜底重传次数；超过上限判定连接不可恢复。
        private int stalledRetransmitCount;
        private long lastActivityTime;
        private TcpState state;
        private boolean synAckSent;
        private boolean clientFinSeen;
        // 本地模式：远端（frame 协议 TYPE_FIN）已声明不再发送。
        private boolean serverFinSeen;
        private volatile boolean closed;

        TcpConnection(long connectionId, String key, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                      int initialServerSeq, SendFrameCallback sendFrameCallback,
                      WritePacketCallback writePacketCallback) {
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
            this.writePacketCallback = writePacketCallback;
            this.clientNextSeq = 0;
            this.serverNextSeq = initialServerSeq;
            this.lastAckFromClient = 0;
            this.unackedServerData = new ArrayDeque<>();
            this.lastAckProgressMs = System.currentTimeMillis();
            this.lastActivityTime = System.currentTimeMillis();
            this.state = TcpState.SYN_RECEIVED;
            this.synAckSent = false;
            this.closed = false;
        }

        void touch() {
            lastActivityTime = System.currentTimeMillis();
        }

        /** 记录应用最近通告的接收窗口（相对其 ack）。仅用于连接初始化。 */
        void setSendWindow(int ack, int window) {
            appWindowAck = ack;
            appWindow = window;
        }

        /**
         * RFC 793 式窗口更新：确认推进时无条件采纳；确认不动时只在窗口扩大时
         * 采纳。窗口字段总是相对其 ack 的剩余量，ack 不动时窗口不会被合理地
         * 收缩（收缩只随新数据发生，而新数据会推进 ack）——采纳同确认上的收缩
         * 值会让发送端被陈旧值自缚、该发的数据发不出去。
         */
        void updateSendWindow(int ack, int window) {
            if (ack != appWindowAck
                    ? seqAfterOrEqual(ack, appWindowAck)
                    : window > appWindow) {
                appWindowAck = ack;
                appWindow = window;
            }
        }

        /**
         * 段是否完整落在应用当前通告的窗口内。窗口为 0（应用缓冲满）时一律
         * false——新段滞留、快速重传跳过，等待应用报文携带的新窗口。
         */
        boolean fitsInSendWindow(int seq, int len) {
            if (appWindow <= 0) {
                return false;
            }
            return seqAfterOrEqual(appWindowAck + appWindow, seq + len);
        }

        boolean hasUnackedServerData() {
            return !unackedServerData.isEmpty();
        }

        boolean hasPendingSegments() {
            return !pendingQueue.isEmpty();
        }

        /**
         * 是否可以继续从隧道取新数据写入本连接：窗口未耗尽、滞留未超限、且
         * 下一个字节能装进当前窗口。三者的组合保证"取数-写入"不越过应用通告
         * 的接收能力；false 时调用方（CPP_REMOTE 会话）停止从 KCP 取数。
         */
        boolean hasSendCredit() {
            return appWindow > 0
                    && unackedBytes + pendingBytes < MAX_UNACKED_RETAINED_BYTES
                    && fitsInSendWindow(serverNextSeq, 1);
        }

        UnackedSegment peekFirstPending() {
            return pendingQueue.peekFirst();
        }

        /** pending 队首转入在途（由调用方立刻写 TUN），保持与登记时相同的顺序。 */
        void promoteFirstPending() {
            UnackedSegment seg = pendingQueue.pollFirst();
            pendingBytes -= seg.length;
            unackedServerData.addLast(seg);
            unackedBytes += seg.length;
        }

        /**
         * 登记一个待发段。
         * @return SEND_NOW：已登记为在途，调用方须立即写 TUN；
         *         HELD：窗口耗尽，已滞留 pending，等窗口重新打开；
         *         OVERFLOW：滞留总量超过上限（应用长时间不确认），调用方应放弃连接。
         */
        SegmentOutcome acceptOutboundSegment(int seq, byte[] payload) {
            if (payload.length == 0) {
                return SegmentOutcome.SEND_NOW;
            }
            if (unackedBytes + pendingBytes + payload.length > MAX_UNACKED_RETAINED_BYTES) {
                return SegmentOutcome.OVERFLOW;
            }
            if (pendingQueue.isEmpty() && fitsInSendWindow(seq, payload.length)) {
                unackedServerData.addLast(new UnackedSegment(seq, payload));
                unackedBytes += payload.length;
                return SegmentOutcome.SEND_NOW;
            }
            pendingQueue.addLast(new UnackedSegment(seq, payload));
            pendingBytes += payload.length;
            return SegmentOutcome.HELD;
        }

        /** 移除被 ack 完全覆盖的段。返回移除数；任何进展都复位 dup-ACK 与兜底计数。 */
        int removeAckedServerSegments(int ack) {
            int removed = 0;
            while (!unackedServerData.isEmpty()) {
                UnackedSegment segment = unackedServerData.peekFirst();
                if (seqAfterOrEqual(ack, segment.endSeq())) {
                    unackedServerData.removeFirst();
                    unackedBytes -= segment.length;
                    removed++;
                } else {
                    break;
                }
            }
            if (removed > 0) {
                lastAckProgressMs = System.currentTimeMillis();
                dupAckCount = 0;
                stalledRetransmitCount = 0;
            }
            return removed;
        }

        /** 累计无进展 dup-ACK；达到阈值时复位计数并返回 true（触发快速重传）。 */
        boolean tickDupAck() {
            dupAckCount++;
            if (dupAckCount < DUP_ACK_RETRANSMIT_THRESHOLD) {
                return false;
            }
            dupAckCount = 0;
            return true;
        }

        void resetDupAcks() {
            dupAckCount = 0;
        }

        UnackedSegment peekFirstUnacked() {
            return unackedServerData.peekFirst();
        }

        void markRetransmitted() {
            lastRetransmitMs = System.currentTimeMillis();
        }

        int stalledRetransmitCount() {
            return stalledRetransmitCount;
        }

        /**
         * 清理线程的停滞兜底：没有任何 ACK 进展（典型是尾部段丢失，收不到
         * dup-ACK）超过 stallMs，就交回最早的待发/在途段。优先在途段（重传），
         * 在途为空而 pending 非空时交回队首 pending 段（兼作零窗口探测）——此时
         * 它从未被发出，转登记为在途。返回 null 表示本轮无需重传。
         */
        UnackedSegment pollStalledRetransmit(long now, long stallMs) {
            synchronized (this) {
                UnackedSegment candidate;
                boolean fromPending = false;
                if (!unackedServerData.isEmpty()) {
                    candidate = unackedServerData.peekFirst();
                } else if (!pendingQueue.isEmpty()) {
                    candidate = pendingQueue.peekFirst();
                    fromPending = true;
                } else {
                    return null;
                }
                long reference = Math.max(lastAckProgressMs, lastRetransmitMs);
                if (now - reference < stallMs) {
                    return null;
                }
                lastRetransmitMs = now;
                stalledRetransmitCount++;
                if (fromPending) {
                    pendingQueue.pollFirst();
                    pendingBytes -= candidate.length;
                    unackedServerData.addLast(candidate);
                    unackedBytes += candidate.length;
                }
                return candidate;
            }
        }

        void close() {
            closed = true;
        }
    }

    /** acceptOutboundSegment 的结果（见其注释）。 */
    private enum SegmentOutcome {
        SEND_NOW,
        HELD,
        OVERFLOW
    }

    private static class UnackedSegment {
        private final int seq;
        private final int length;
        private final byte[] payload;

        UnackedSegment(int seq, byte[] payload) {
            this.seq = seq;
            this.payload = payload;
            this.length = payload.length;
        }

        int endSeq() {
            return seq + length;
        }
    }
}
