package com.example.kcpvpn.vpn;

import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.protocol.Socks5Request;
import com.example.kcpvpn.core.session.SocketProtector;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

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
    private static final long CLOSING_IDLE_TIMEOUT_MS = 30 * 1000L;
    private static final int TCP_IPV4_HEADER_LEN = 40;
    private static final int MAX_TCP_PAYLOAD_PER_PACKET = VpnConfig.VPN_MTU - TCP_IPV4_HEADER_LEN;
    private static final int UDP_TRACE_SAMPLE_RATE = 64;

    private final Map<String, TcpConnection> connectionsByKey = new ConcurrentHashMap<>();
    private final Map<Long, TcpConnection> connectionsById = new ConcurrentHashMap<>();
    private final AtomicLong nextConnectionId = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong nextTcpSequence = new AtomicLong(System.nanoTime());
    private final AtomicLong udpTraceCounter = new AtomicLong(0);
    private volatile boolean running;
    private volatile boolean localMode;
    private volatile SocketProtector socketProtector;
    private Thread cleanupThread;

    public void setSocketProtector(SocketProtector protector) {
        this.socketProtector = protector;
    }

    public void setLocalMode(boolean localMode) {
        this.localMode = localMode;
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
            if (version != 4) {
                return;
            }

            int ipHeaderLen = (buf.get(0) & 0x0F) * 4;
            if (packet.length < ipHeaderLen + 8) {
                return;
            }

            int totalLen = buf.getShort(2) & 0xFFFF;
            if (totalLen <= 0 || totalLen > packet.length) {
                totalLen = packet.length;
            }

            int flagsAndFragment = buf.getShort(6) & 0xFFFF;
            if ((flagsAndFragment & 0x2000) != 0 || ((flagsAndFragment & 0x1FFF) << 3) != 0) {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring fragmented IP packet");
                return;
            }

            byte[] srcAddr = Arrays.copyOfRange(packet, 12, 16);
            byte[] dstAddr = Arrays.copyOfRange(packet, 16, 20);
            byte protocol = buf.get(9);
            Logger.info(LogConfig.MODULE_VPN, "PacketRouter parse protocol=" + (protocol & 0xFF)
                    + " src=" + addressToString(srcAddr)
                    + " dst=" + addressToString(dstAddr)
                    + " len=" + totalLen);
            if (protocol == 6) {
                handleOutboundTcp(packet, buf, ipHeaderLen, totalLen, srcAddr, dstAddr,
                        sendFrameCallback, writePacketCallback);
            } else if (protocol == 17) {
                handleOutboundUdp(packet, buf, ipHeaderLen, totalLen, srcAddr, dstAddr, sendFrameCallback);
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
            conn = createConnection(key, srcAddr, srcPort, dstAddr, dstPort, clientSeq, sendFrameCallback);
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
        }

        if (isRst) {
            sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_RESET, conn.connectionId, null));
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

            sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_DATA, conn.connectionId, payload));
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
            synchronized (conn) {
                conn.clientNextSeq = Math.max(conn.clientNextSeq, clientSeq + payloadLen + 1);
                conn.state = TcpState.CLOSING;
                conn.touch();
            }
            sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_CLOSE, conn.connectionId, null));
            byte[] finAck = buildTcpPacket(conn, new byte[0], (byte) 0x11,
                    conn.serverNextSeq, conn.clientNextSeq);
            writePacketCallback.onWritePacket(finAck);
            logTcpOut(conn, 0x11, conn.serverNextSeq, conn.clientNextSeq, 0);
            synchronized (conn) {
                conn.serverNextSeq += 1;
            }
            Logger.info(LogConfig.MODULE_VPN, "CLOSE frame: connectionId=" + conn.connectionId
                    + ", src=" + conn.srcHost + ":" + conn.srcPort
                    + ", dst=" + conn.dstHost + ":" + conn.dstPort + ", payloadLength=0");
        }
    }

    private TcpConnection createConnection(String key, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                           int clientSeq, SendFrameCallback sendFrameCallback) {
        TcpConnection conn = new TcpConnection(nextConnectionId.incrementAndGet(), key, srcAddr, srcPort,
                dstAddr, dstPort, (int) nextTcpSequence.addAndGet(0x10000L), sendFrameCallback);
        conn.clientNextSeq = clientSeq + 1;
        connectionsByKey.put(key, conn);
        connectionsById.put(conn.connectionId, conn);

        byte[] openPayload = Socks5Request.buildConnectRequest(conn.dstHost, conn.dstPort);
        sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_OPEN, conn.connectionId, openPayload));
        Logger.info(LogConfig.MODULE_VPN, "OPEN connectionId=" + conn.connectionId
                + " dst=" + conn.dstHost + ":" + conn.dstPort);
        Logger.info(LogConfig.MODULE_VPN, "OPEN frame: connectionId=" + conn.connectionId
                + ", src=" + conn.srcHost + ":" + conn.srcPort
                + ", dst=" + conn.dstHost + ":" + conn.dstPort
                + ", payloadLength=" + openPayload.length);
        return conn;
    }

    private void handleOutboundUdp(byte[] packet, ByteBuffer buf, int ipHeaderLen, int totalLen,
                                   byte[] srcAddr, byte[] dstAddr, SendFrameCallback sendFrameCallback) {
        int udpOffset = ipHeaderLen;
        if (totalLen < udpOffset + 8) {
            return;
        }
        int srcPort = buf.getShort(udpOffset) & 0xFFFF;
        int dstPort = buf.getShort(udpOffset + 2) & 0xFFFF;
        int udpLen = buf.getShort(udpOffset + 4) & 0xFFFF;
        int payloadLen = udpLen - 8;
        if (payloadLen <= 0 || udpOffset + 8 + payloadLen > totalLen) {
            return;
        }
        logUdpTrace("UDP IN src=" + addressToString(srcAddr) + ":" + srcPort
                + " dst=" + addressToString(dstAddr) + ":" + dstPort
                + " dstPort=" + dstPort
                + " len=" + payloadLen, srcPort, dstPort);
        byte[] udpPayload = new byte[payloadLen];
        System.arraycopy(packet, udpOffset + 8, udpPayload, 0, payloadLen);
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
                logUdpTrace("UDP OUT src=" + addressToString(datagram.dstAddr)
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
                        int segmentLen = Math.min(MAX_TCP_PAYLOAD_PER_PACKET, payload.length - offset);
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

    private void removeConnection(TcpConnection conn) {
        conn.close();
        connectionsByKey.remove(conn.key);
        connectionsById.remove(conn.connectionId);
    }

    private byte[] buildTcpPacket(TcpConnection conn, byte[] payload, byte tcpFlags, int seq, int ack) {
        int totalLen = 20 + 20 + payload.length;
        byte[] packet = new byte[totalLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
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
        putChecksum(packet, 10, checksum(packet, 0, 20));
        putChecksum(packet, 36, tcpChecksum(packet, 20, 20 + payload.length, conn.dstAddr, conn.srcAddr));
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
        byte[] pseudo = new byte[12 + len];
        System.arraycopy(srcAddr, 0, pseudo, 0, 4);
        System.arraycopy(dstAddr, 0, pseudo, 4, 4);
        pseudo[8] = 0;
        pseudo[9] = (byte) protocol;
        pseudo[10] = (byte) ((len >> 8) & 0xFF);
        pseudo[11] = (byte) (len & 0xFF);
        System.arraycopy(packet, offset, pseudo, 12, len);
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

    private static String addressToString(byte[] addr) {
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "."
                + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
    }

    private static void logTcpIn(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                 int flags, int seq, int ack, int len) {
        Logger.info(LogConfig.MODULE_VPN, "TCP IN src=" + addressToString(srcAddr) + ":" + srcPort
                + " dst=" + addressToString(dstAddr) + ":" + dstPort
                + " flags=0x" + Integer.toHexString(flags)
                + " seq=" + (seq & 0xFFFFFFFFL)
                + " ack=" + (ack & 0xFFFFFFFFL)
                + " len=" + len);
    }

    private static void logTcpOut(TcpConnection conn, int flags, int seq, int ack, int len) {
        Logger.info(LogConfig.MODULE_VPN, "TCP OUT src=" + conn.dstHost + ":" + conn.dstPort
                + " dst=" + conn.srcHost + ":" + conn.srcPort
                + " flags=0x" + Integer.toHexString(flags)
                + " seq=" + (seq & 0xFFFFFFFFL)
                + " ack=" + (ack & 0xFFFFFFFFL)
                + " len=" + len);
    }

    private void logUdpTrace(String message, int srcPort, int dstPort) {
        if (srcPort == 53 || dstPort == 53
                || udpTraceCounter.incrementAndGet() % UDP_TRACE_SAMPLE_RATE == 0) {
            Logger.info(LogConfig.MODULE_VPN, message);
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
                        long timeout = conn.state == TcpState.ESTABLISHED
                                ? ESTABLISHED_IDLE_TIMEOUT_MS : CLOSING_IDLE_TIMEOUT_MS;
                        if (age > timeout) {
                            Logger.info(LogConfig.MODULE_VPN, "Stale connection cleanup: connectionId="
                                    + conn.connectionId + ", state=" + conn.state
                                    + ", idleMs=" + age);
                            conn.sendFrameCallback.onSendFrame(new KcpFrame(
                                    conn.state == TcpState.ESTABLISHED
                                            ? KcpFrame.TYPE_CLOSE : KcpFrame.TYPE_RESET,
                                    conn.connectionId, null));
                            removeConnection(conn);
                        }
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
