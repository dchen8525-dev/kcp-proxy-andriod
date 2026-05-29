package com.example.kcpvpn.vpn;

import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.protocol.Socks5Request;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 数据包路由器 - 处理 VPN 数据包与 KCP frame 的转换
 */
public class PacketRouter {

    private final Map<String, TcpConnection> connectionsByKey;
    private final Map<Long, TcpConnection> connectionsById;
    private final AtomicLong nextConnectionId;
    private final AtomicLong nextTcpSequence;
    private volatile boolean running;

    public PacketRouter() {
        this.connectionsByKey = new ConcurrentHashMap<>();
        this.connectionsById = new ConcurrentHashMap<>();
        this.nextConnectionId = new AtomicLong(System.currentTimeMillis());
        this.nextTcpSequence = new AtomicLong(System.nanoTime());
        this.running = false;
    }

    public void start() {
        running = true;
        Logger.info(LogConfig.MODULE_VPN, "PacketRouter started");
    }

    public void stop() {
        running = false;

        for (TcpConnection conn : connectionsById.values()) {
            conn.close();
        }
        connectionsByKey.clear();
        connectionsById.clear();

        Logger.info(LogConfig.MODULE_VPN, "PacketRouter stopped");
    }

    private static String connectionKey(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort) {
        return addressToString(srcAddr) + ":" + srcPort + "->" + addressToString(dstAddr) + ":" + dstPort;
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
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring non-IPv4 packet");
                return;
            }

            int ihl = buf.get(0) & 0x0F;
            int ipHeaderLen = ihl * 4;
            if (packet.length < ipHeaderLen + 20) {
                return;
            }

            int totalLen = buf.getShort(2) & 0xFFFF;
            int flagsAndFragment = buf.getShort(6) & 0xFFFF;
            int moreFragments = flagsAndFragment & 0x2000;
            int fragmentOffset = (flagsAndFragment & 0x1FFF) << 3;
            if (moreFragments != 0 || fragmentOffset != 0) {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring fragmented IP packet");
                return;
            }

            byte protocol = buf.get(9);
            if (protocol != 6) {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring non-TCP packet: protocol=" + protocol);
                return;
            }

            if (totalLen <= 0 || totalLen > packet.length) {
                totalLen = packet.length;
            }

            byte[] srcAddr = Arrays.copyOfRange(packet, 12, 16);
            byte[] dstAddr = Arrays.copyOfRange(packet, 16, 20);
            int tcpOffset = ipHeaderLen;
            int srcPort = buf.getShort(tcpOffset) & 0xFFFF;
            int dstPort = buf.getShort(tcpOffset + 2) & 0xFFFF;
            int clientSeq = buf.getInt(tcpOffset + 4);
            int tcpHeaderLen = ((buf.get(tcpOffset + 12) >> 4) & 0x0F) * 4;
            int flags = buf.get(tcpOffset + 13) & 0xFF;
            int payloadOffset = tcpOffset + tcpHeaderLen;
            int payloadLen = totalLen - payloadOffset;
            if (payloadLen < 0) {
                return;
            }

            String key = connectionKey(srcAddr, srcPort, dstAddr, dstPort);
            TcpConnection conn = connectionsByKey.get(key);
            if (conn == null) {
                conn = new TcpConnection(nextConnectionId.incrementAndGet(), key, srcAddr, srcPort,
                        dstAddr, dstPort, (int) nextTcpSequence.addAndGet(0x10000L));
                connectionsByKey.put(key, conn);
                connectionsById.put(conn.connectionId, conn);

                byte[] openPayload = Socks5Request.buildConnectRequest(conn.dstHost, conn.dstPort);
                sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_OPEN, conn.connectionId, openPayload));
                Logger.info(LogConfig.MODULE_VPN, "OPEN frame: connectionId=" + conn.connectionId
                        + ", src=" + conn.srcHost + ":" + conn.srcPort
                        + ", dst=" + conn.dstHost + ":" + conn.dstPort
                        + ", payloadLength=" + openPayload.length);
            }

            if ((flags & 0x02) != 0) {
                synchronized (conn) {
                    conn.clientNextSeq = clientSeq + 1;
                    byte[] synAck = buildTcpPacket(conn, new byte[0], (byte) 0x12,
                            conn.serverInitialSeq, conn.clientNextSeq);
                    writePacketCallback.onWritePacket(synAck);
                    if (!conn.synAckSent) {
                        conn.serverNextSeq = conn.serverInitialSeq + 1;
                        conn.synAckSent = true;
                    }
                }
                Logger.debug(LogConfig.MODULE_VPN, "TCP SYN-ACK: connectionId=" + conn.connectionId
                        + ", src=" + conn.dstHost + ":" + conn.dstPort
                        + ", dst=" + conn.srcHost + ":" + conn.srcPort + ", payloadLength=0");
                return;
            }

            if ((flags & 0x04) != 0) {
                sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_RESET, conn.connectionId, null));
                byte[] rstAck = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                        conn.serverNextSeq, clientSeq + 1);
                writePacketCallback.onWritePacket(rstAck);
                Logger.info(LogConfig.MODULE_VPN, "RESET frame: connectionId=" + conn.connectionId
                        + ", src=" + conn.srcHost + ":" + conn.srcPort
                        + ", dst=" + conn.dstHost + ":" + conn.dstPort + ", payloadLength=0");
                removeConnection(conn);
                return;
            }

            if (payloadLen > 0) {
                byte[] payload = new byte[payloadLen];
                System.arraycopy(packet, payloadOffset, payload, 0, payloadLen);
                synchronized (conn) {
                    conn.clientNextSeq = clientSeq + payloadLen;
                }
                sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_DATA, conn.connectionId, payload));
                byte[] ack = buildTcpPacket(conn, new byte[0], (byte) 0x10,
                        conn.serverNextSeq, conn.clientNextSeq);
                writePacketCallback.onWritePacket(ack);
                Logger.debug(LogConfig.MODULE_VPN, "DATA frame: connectionId=" + conn.connectionId
                        + ", src=" + conn.srcHost + ":" + conn.srcPort
                        + ", dst=" + conn.dstHost + ":" + conn.dstPort
                        + ", payloadLength=" + payloadLen);
            }

            if ((flags & 0x01) != 0) {
                synchronized (conn) {
                    conn.clientNextSeq = clientSeq + payloadLen + 1;
                }
                sendFrameCallback.onSendFrame(new KcpFrame(KcpFrame.TYPE_CLOSE, conn.connectionId, null));
                byte[] finAck = buildTcpPacket(conn, new byte[0], (byte) 0x11,
                        conn.serverNextSeq, conn.clientNextSeq);
                writePacketCallback.onWritePacket(finAck);
                synchronized (conn) {
                    conn.serverNextSeq += 1;
                }
                Logger.info(LogConfig.MODULE_VPN, "CLOSE frame: connectionId=" + conn.connectionId
                        + ", src=" + conn.srcHost + ":" + conn.srcPort
                        + ", dst=" + conn.dstHost + ":" + conn.dstPort + ", payloadLength=0");
                removeConnection(conn);
            }
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Handle outbound error: " + e.getMessage());
        }
    }

    public void handleInboundFrame(KcpFrame frame, WritePacketCallback writePacketCallback) {
        if (!running || frame == null) {
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
                byte[] ipPacket;
                synchronized (conn) {
                    ipPacket = buildTcpPacket(conn, frame.getPayload(), (byte) 0x18,
                            conn.serverNextSeq, conn.clientNextSeq);
                    conn.serverNextSeq += frame.getPayloadLength();
                }
                writePacketCallback.onWritePacket(ipPacket);
                Logger.debug(LogConfig.MODULE_VPN, "Inbound DATA: connectionId=" + conn.connectionId
                        + ", src=" + conn.dstHost + ":" + conn.dstPort
                        + ", dst=" + conn.srcHost + ":" + conn.srcPort
                        + ", payloadLength=" + frame.getPayloadLength());
            } else if (frame.getFrameType() == KcpFrame.TYPE_CLOSE) {
                byte[] finAck;
                synchronized (conn) {
                    finAck = buildTcpPacket(conn, new byte[0], (byte) 0x11,
                            conn.serverNextSeq, conn.clientNextSeq);
                    conn.serverNextSeq += 1;
                }
                writePacketCallback.onWritePacket(finAck);
                Logger.info(LogConfig.MODULE_VPN, "Inbound CLOSE: connectionId=" + conn.connectionId
                        + ", src=" + conn.dstHost + ":" + conn.dstPort
                        + ", dst=" + conn.srcHost + ":" + conn.srcPort + ", payloadLength=0");
                removeConnection(conn);
            } else if (frame.getFrameType() == KcpFrame.TYPE_RESET) {
                byte[] rst;
                synchronized (conn) {
                    rst = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                            conn.serverNextSeq, conn.clientNextSeq);
                }
                writePacketCallback.onWritePacket(rst);
                Logger.info(LogConfig.MODULE_VPN, "Inbound RESET: connectionId=" + conn.connectionId
                        + ", src=" + conn.dstHost + ":" + conn.dstPort
                        + ", dst=" + conn.srcHost + ":" + conn.srcPort + ", payloadLength=0");
                removeConnection(conn);
            }
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

    private static int tcpChecksum(byte[] packet, int offset, int len, byte[] srcAddr, byte[] dstAddr) {
        byte[] pseudo = new byte[12 + len];
        System.arraycopy(srcAddr, 0, pseudo, 0, 4);
        System.arraycopy(dstAddr, 0, pseudo, 4, 4);
        pseudo[8] = 0;
        pseudo[9] = 6;
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

    private static String addressToString(byte[] addr) {
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "."
                + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
    }

    public interface SendFrameCallback {
        void onSendFrame(KcpFrame frame);
    }

    public interface WritePacketCallback {
        void onWritePacket(byte[] packet);
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
        private int clientNextSeq;
        private int serverNextSeq;
        private boolean synAckSent;
        private volatile boolean closed;

        TcpConnection(long connectionId, String key, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                      int initialServerSeq) {
            this.connectionId = connectionId;
            this.key = key;
            this.srcAddr = Arrays.copyOf(srcAddr, srcAddr.length);
            this.dstAddr = Arrays.copyOf(dstAddr, dstAddr.length);
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.srcHost = addressToString(srcAddr);
            this.dstHost = addressToString(dstAddr);
            this.serverInitialSeq = initialServerSeq;
            this.clientNextSeq = 0;
            this.serverNextSeq = initialServerSeq;
            this.synAckSent = false;
            this.closed = false;
        }

        void close() {
            closed = true;
        }
    }
}
