package com.example.kcpvpn.vpn;

import com.example.kcpvpn.core.protocol.AddressParser;
import com.example.kcpvpn.core.protocol.Socks5;
import com.example.kcpvpn.core.protocol.Socks5Request;
import com.example.kcpvpn.core.protocol.Socks5Response;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 数据包路由器 - 处理 VPN 数据包与 SOCKS5/KCP 的转换
 */
public class PacketRouter {

    private final Map<Integer, SocketConnection> connections;
    private final Queue<SocketConnection> pendingHandshakeQueue;
    private volatile boolean running;

    // TCP 序列号管理
    private int nextTcpSeq = 1000;

    // UDP DNS 转发 socket
    private DatagramSocket dnsSocket;

    public PacketRouter() {
        this.connections = new ConcurrentHashMap<>();
        this.pendingHandshakeQueue = new LinkedList<>();
        this.running = false;
    }

    /**
     * 启动路由器
     */
    public void start() {
        running = true;
        try {
            dnsSocket = new DatagramSocket();
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_VPN, "Failed to create DNS socket: " + e.getMessage());
        }
        Logger.info(LogConfig.MODULE_VPN, "PacketRouter started");
    }

    /**
     * 停止路由器
     */
    public void stop() {
        running = false;

        // 关闭所有连接
        for (SocketConnection conn : connections.values()) {
            conn.close();
        }
        connections.clear();
        pendingHandshakeQueue.clear();

        if (dnsSocket != null) {
            dnsSocket.close();
            dnsSocket = null;
        }

        Logger.info(LogConfig.MODULE_VPN, "PacketRouter stopped");
    }

    /**
     * 生成连接 key
     */
    private static int connectionKey(byte[] dstAddr, int dstPort) {
        int hash = Arrays.hashCode(dstAddr);
        hash = 31 * hash + dstPort;
        return hash;
    }

    /**
     * 处理出站数据包（从 VPN 接口读取）
     */
    public void handleOutboundPacket(byte[] packet, OutboundCallback callback) {
        if (!running || packet == null || packet.length < 20) {
            return;
        }

        try {
            ByteBuffer buf = ByteBuffer.wrap(packet);

            byte version = (byte) ((buf.get() >> 4) & 0x0F);
            if (version != 4) {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring non-IPv4 packet");
                return;
            }

            buf.position(0);

            byte ihl = (byte) (buf.get() & 0x0F);
            int headerLen = ihl * 4;

            buf.get();  // TOS
            int totalLen = buf.getShort() & 0xFFFF;
            buf.getShort();  // ID
            int flagsAndFragment = buf.getShort() & 0xFFFF;

            // 忽略分片包
            int moreFragments = flagsAndFragment & 0x2000;
            int fragmentOffset = (flagsAndFragment & 0x1FFF) << 3;
            if (moreFragments != 0 || fragmentOffset != 0) {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring fragmented IP packet");
                return;
            }

            buf.get();  // TTL
            byte protocol = buf.get();
            buf.getShort();  // Checksum

            byte[] srcAddr = new byte[4];
            buf.get(srcAddr);

            byte[] dstAddr = new byte[4];
            buf.get(dstAddr);

            if (totalLen > packet.length) {
                totalLen = packet.length;
            }

            String dstHost = String.format("%d.%d.%d.%d",
                    dstAddr[0] & 0xFF, dstAddr[1] & 0xFF,
                    dstAddr[2] & 0xFF, dstAddr[3] & 0xFF);

            if (protocol == 6) {  // TCP
                handleTcpPacket(buf, packet, headerLen, totalLen, srcAddr, dstAddr,
                        dstHost, callback);
            } else if (protocol == 17) {  // UDP
                handleUdpPacket(buf, packet, headerLen, totalLen, srcAddr, dstAddr,
                        dstHost, callback);
            } else {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring non-TCP/UDP packet: protocol=" + protocol);
            }

        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Handle outbound error: " + e.getMessage());
        }
    }

    /**
     * 处理 TCP 包
     */
    private void handleTcpPacket(ByteBuffer buf, byte[] packet, int headerLen, int totalLen,
                                  byte[] srcAddr, byte[] dstAddr, String dstHost,
                                  OutboundCallback callback) {
        buf.position(headerLen);
        int srcPort = buf.getShort() & 0xFFFF;
        int dstPort = buf.getShort() & 0xFFFF;

        // 读取 TCP seq
        int tcpSeq = buf.getInt();

        // 读取 TCP data offset 和 flags
        buf.position(headerLen + 12);
        byte dataOffsetByte = buf.get();
        int transportHeaderLen = ((dataOffsetByte >> 4) & 0x0F) * 4;
        byte tcpFlags = buf.get();

        boolean isSyn = (tcpFlags & 0x02) != 0;
        boolean isAck = (tcpFlags & 0x10) != 0;
        boolean isPsh = (tcpFlags & 0x08) != 0;
        boolean isRst = (tcpFlags & 0x04) != 0;
        boolean isFin = (tcpFlags & 0x01) != 0;

        int connKey = connectionKey(dstAddr, dstPort);
        SocketConnection conn = connections.get(connKey);

        if (conn == null) {
            if (isSyn && !isAck) {
                // 新连接 SYN
                int serverSeq = nextTcpSeq++;
                conn = new SocketConnection(srcAddr, srcPort, dstAddr, dstHost, dstPort,
                        tcpSeq, serverSeq, callback);
                connections.put(connKey, conn);

                // 发送 SYN-ACK 回客户端
                byte[] synAck = buildSynAckPacket(conn);
                callback.onWriteToVpn(synAck);
                // SYN 占用一个序列号
                conn.advanceAckNum(1);

                // 发送 SOCKS5 CONNECT
                byte[] socks5Request = Socks5Request.buildConnectRequest(dstHost, dstPort);
                callback.onSendToKcp(socks5Request);
                pendingHandshakeQueue.offer(conn);

                Logger.info(LogConfig.MODULE_SOCKS5, "New TCP connection: " + dstHost + ":" + dstPort
                        + " src=" + formatAddr(srcAddr) + ":" + srcPort
                        + " clientSeq=" + tcpSeq + " serverSeq=" + serverSeq);
            } else {
                // 非 SYN 包但连接不存在，发送 RST
                Logger.debug(LogConfig.MODULE_VPN, "TCP packet without connection, flags=" + tcpFlags);
            }
            return;
        }

        // 连接已存在
        if (isRst || isFin) {
            Logger.info(LogConfig.MODULE_VPN, "TCP RST/FIN received, closing: " + dstHost + ":" + dstPort);
            connections.remove(connKey);
            return;
        }

        if (isSyn && !isAck) {
            // 重复 SYN，重发 SYN-ACK
            byte[] synAck = buildSynAckPacket(conn);
            callback.onWriteToVpn(synAck);
            return;
        }

        // 提取数据部分
        int dataLen = totalLen - headerLen - transportHeaderLen;

        if (dataLen > 0) {
            if (conn.isHandshakeDone()) {
                byte[] data = new byte[dataLen];
                buf.position(headerLen + transportHeaderLen);
                buf.get(data);

                conn.advanceSeqNum(dataLen);
                callback.onSendToKcp(data);

                Logger.debug(LogConfig.MODULE_VPN, "TCP data: " + dataLen + " bytes to " + dstHost + ":" + dstPort);
            } else {
                Logger.debug(LogConfig.MODULE_VPN, "TCP data dropped: SOCKS5 handshake not done for " + dstHost);
            }
        }
    }

    /**
     * 处理 UDP 包
     */
    private void handleUdpPacket(ByteBuffer buf, byte[] packet, int headerLen, int totalLen,
                                  byte[] srcAddr, byte[] dstAddr, String dstHost,
                                  OutboundCallback callback) {
        buf.position(headerLen);
        int srcPort = buf.getShort() & 0xFFFF;
        int dstPort = buf.getShort() & 0xFFFF;

        int dataLen = totalLen - headerLen - 8;
        if (dataLen <= 0) {
            return;
        }

        byte[] data = new byte[dataLen];
        buf.position(headerLen + 8);
        buf.get(data);

        if (dstPort == 53) {
            // DNS 查询 - 同步转发
            handleDnsQuery(srcAddr, srcPort, dstAddr, dstPort, data, callback);
        } else {
            // 非 DNS UDP 暂时不处理
            Logger.debug(LogConfig.MODULE_VPN, "UDP non-DNS dropped: " + dstHost + ":" + dstPort);
        }
    }

    /**
     * 同步转发 DNS 查询
     */
    private void handleDnsQuery(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                 byte[] queryData, OutboundCallback callback) {
        if (dnsSocket == null) {
            Logger.warning(LogConfig.MODULE_VPN, "DNS socket not available");
            return;
        }

        try {
            DatagramPacket request = new DatagramPacket(queryData, queryData.length,
                    InetAddress.getByAddress(dstAddr), dstPort);
            dnsSocket.send(request);

            byte[] respBuf = new byte[512];
            DatagramPacket response = new DatagramPacket(respBuf, respBuf.length);
            dnsSocket.setSoTimeout(3000);
            dnsSocket.receive(response);

            byte[] dnsData = Arrays.copyOf(response.getData(), response.getLength());
            byte[] udpPacket = buildUdpPacket(dnsData, dstAddr, dstPort, srcAddr, srcPort);
            callback.onWriteToVpn(udpPacket);

            Logger.debug(LogConfig.MODULE_VPN, "DNS forwarded: " + dnsData.length + " bytes");

        } catch (IOException e) {
            Logger.warning(LogConfig.MODULE_VPN, "DNS query failed: " + e.getMessage());
        }
    }

    /**
     * 处理入站数据包（从 KCP 接收，写入 VPN 接口）
     */
    public void handleInboundData(byte[] data, WritePacketCallback writePacketCallback) {
        if (!running || data == null || data.length == 0) {
            return;
        }

        // 严格检查 SOCKS5 响应：必须以 0x05 开头且长度至少 10 字节
        if (data.length >= 10 && data[0] == Socks5.SOCKS5_VERSION) {
            // 进一步验证：REP 字段在有效范围内
            byte rep = data[1];
            if (rep >= 0 && rep <= 0x08) {
                Socks5Response response = Socks5Response.parse(data, 0, data.length);
                if (response.reply == Socks5.SOCKS5_REPLY_SUCCEEDED) {
                    Logger.info(LogConfig.MODULE_SOCKS5, "SOCKS5 handshake success");
                    SocketConnection conn = pendingHandshakeQueue.poll();
                    if (conn != null) {
                        conn.markHandshakeDone();
                    } else {
                        Logger.warning(LogConfig.MODULE_SOCKS5, "No pending connection for SOCKS5 response");
                    }
                } else {
                    Logger.warning(LogConfig.MODULE_SOCKS5, "SOCKS5 handshake failed: " + response.reply);
                    SocketConnection conn = pendingHandshakeQueue.poll();
                    if (conn != null) {
                        conn.markHandshakeFailed();
                        connections.values().remove(conn);
                    }
                }
                return;
            }
        }

        // 构建返回的 IP 数据包
        try {
            SocketConnection activeConn = findActiveConnection();
            if (activeConn == null) {
                Logger.warning(LogConfig.MODULE_VPN, "No active connection for inbound data, len=" + data.length);
                return;
            }

            byte[] ipPacket = buildIpPacket(data, activeConn);
            writePacketCallback.onWritePacket(ipPacket);
            Logger.debug(LogConfig.MODULE_VPN, "Inbound: " + data.length + " bytes -> VPN");
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Build IP packet error: " + e.getMessage());
        }
    }

    /**
     * 查找活跃连接
     */
    private SocketConnection findActiveConnection() {
        for (SocketConnection conn : connections.values()) {
            if (conn.isHandshakeDone()) {
                return conn;
            }
        }
        return null;
    }

    /**
     * 构建 TCP SYN-ACK 包
     */
    private byte[] buildSynAckPacket(SocketConnection conn) {
        int totalLen = 20 + 20;
        ByteBuffer buf = ByteBuffer.allocate(totalLen);

        // IP header
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 6);
        buf.putShort((short) 0);
        buf.put(conn.getDstAddr());
        buf.put(conn.getSrcAddr());

        // TCP header
        buf.putShort((short) conn.getDstPort());
        buf.putShort((short) conn.getSrcPort());
        buf.putInt(conn.getAckNum());         // Seq = server ISN
        buf.putInt(conn.getSeqNum() + 1);     // Ack = client ISN + 1
        buf.put((byte) 0x50);  // Data offset = 5
        buf.put((byte) 0x12);  // SYN + ACK
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);

        return buf.array();
    }

    /**
     * 构建 TCP 数据包（入站）
     */
    private byte[] buildIpPacket(byte[] payload, SocketConnection conn) {
        int totalLen = 20 + 20 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen);

        // IP header
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 6);
        buf.putShort((short) 0);
        buf.put(conn.getDstAddr());
        buf.put(conn.getSrcAddr());

        // TCP header
        buf.putShort((short) conn.getDstPort());
        buf.putShort((short) conn.getSrcPort());
        buf.putInt(conn.getAckNum());         // Sequence number
        buf.putInt(conn.getSeqNum() + 1);     // Ack number (account for SYN)
        buf.put((byte) 0x50);
        buf.put((byte) 0x18);  // PSH + ACK
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);

        // Payload
        buf.put(payload);

        conn.advanceAckNum(payload.length);

        return buf.array();
    }

    /**
     * 构建 UDP 数据包
     */
    private byte[] buildUdpPacket(byte[] payload, byte[] srcAddr, int srcPort,
                                   byte[] dstAddr, int dstPort) {
        int totalLen = 20 + 8 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen);

        // IP header
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 17);  // UDP
        buf.putShort((short) 0);
        buf.put(srcAddr);
        buf.put(dstAddr);

        // UDP header
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) (8 + payload.length));
        buf.putShort((short) 0);

        // Payload
        buf.put(payload);

        return buf.array();
    }

    private static String formatAddr(byte[] addr) {
        return String.format("%d.%d.%d.%d",
                addr[0] & 0xFF, addr[1] & 0xFF, addr[2] & 0xFF, addr[3] & 0xFF);
    }

    /**
     * 出站回调接口
     */
    public interface OutboundCallback {
        void onSendToKcp(byte[] data);
        void onWriteToVpn(byte[] packet);
    }

    /**
     * 写入数据包回调接口
     */
    public interface WritePacketCallback {
        void onWritePacket(byte[] packet);
    }

    /**
     * Socket 连接状态
     */
    private static class SocketConnection {
        private final byte[] srcAddr;
        private final int srcPort;
        private final byte[] dstAddr;
        private final String dstHost;
        private final int dstPort;
        private final OutboundCallback callback;

        // TCP 序列号管理
        private int seqNum;    // 客户端序列号（用于 ACK）
        private int ackNum;    // 服务器序列号（用于 SEQ）

        private volatile boolean handshakeDone;
        private volatile boolean handshakeFailed;

        public SocketConnection(byte[] srcAddr, int srcPort, byte[] dstAddr,
                                String dstHost, int dstPort,
                                int clientSeqNum, int serverSeqNum,
                                OutboundCallback callback) {
            this.srcAddr = srcAddr.clone();
            this.srcPort = srcPort;
            this.dstAddr = dstAddr.clone();
            this.dstHost = dstHost;
            this.dstPort = dstPort;
            this.seqNum = clientSeqNum;
            this.ackNum = serverSeqNum;
            this.callback = callback;
            this.handshakeDone = false;
            this.handshakeFailed = false;
        }

        public void markHandshakeDone() {
            handshakeDone = true;
        }

        public void markHandshakeFailed() {
            handshakeFailed = true;
        }

        public boolean isHandshakeDone() {
            return handshakeDone && !handshakeFailed;
        }

        public byte[] getSrcAddr() {
            return srcAddr;
        }

        public int getSrcPort() {
            return srcPort;
        }

        public byte[] getDstAddr() {
            return dstAddr;
        }

        public int getDstPort() {
            return dstPort;
        }

        public int getSeqNum() {
            return seqNum;
        }

        public int getAckNum() {
            return ackNum;
        }

        public void advanceSeqNum(int delta) {
            seqNum += delta;
        }

        public void advanceAckNum(int delta) {
            ackNum += delta;
        }

        public void close() {
        }
    }
}
