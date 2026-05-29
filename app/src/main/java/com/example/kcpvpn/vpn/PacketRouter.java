package com.example.kcpvpn.vpn;

import com.example.kcpvpn.core.protocol.AddressParser;
import com.example.kcpvpn.core.protocol.Socks5;
import com.example.kcpvpn.core.protocol.Socks5Request;
import com.example.kcpvpn.core.protocol.Socks5Response;
import com.example.kcpvpn.core.session.SocketProtector;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 数据包路由器 - 处理 VPN 数据包与 SOCKS5/KCP 的转换
 */
public class PacketRouter {

    private final Map<Integer, SocketConnection> connections;
    private final Map<Integer, SocketConnection> pendingHandshakes;
    private final Map<Integer, SocketConnection> connectionsById;
    private volatile boolean running;
    private volatile boolean localMode;

    // TCP 序列号管理
    private int nextTcpSeq = 1000;

    // 连接 ID 分配（1-255，循环使用）
    private int nextConnectionId = 1;

    // UDP DNS 转发 socket
    private DatagramSocket dnsSocket;
    private volatile SocketProtector socketProtector;

    // 异步 DNS 响应处理
    private final Map<Integer, PendingDnsQuery> pendingDnsQueries = new ConcurrentHashMap<>();
    private Thread dnsReceiveThread;
    private static final int DNS_TIMEOUT_MS = 10000;

    // 握手超时清理线程
    private Thread handshakeCleanupThread;
    private static final int HANDSHAKE_TIMEOUT_MS = 10000;

    public PacketRouter() {
        this.connections = new ConcurrentHashMap<>();
        this.pendingHandshakes = new ConcurrentHashMap<>();
        this.connectionsById = new ConcurrentHashMap<>();
        this.running = false;
    }

    /**
     * 待处理的 DNS 查询
     */
    private static class PendingDnsQuery {
        final int txId;
        final byte[] srcAddr;
        final int srcPort;
        final byte[] dstAddr;
        final int dstPort;
        final OutboundCallback callback;
        final long expireTime;
        volatile boolean completed;

        PendingDnsQuery(int txId, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                        OutboundCallback callback, long expireTime) {
            this.txId = txId;
            this.srcAddr = srcAddr.clone();
            this.srcPort = srcPort;
            this.dstAddr = dstAddr.clone();
            this.dstPort = dstPort;
            this.callback = callback;
            this.expireTime = expireTime;
            this.completed = false;
        }
    }

    /**
     * 设置 socket 保护器
     */
    public void setSocketProtector(SocketProtector protector) {
        this.socketProtector = protector;
    }

    public void setLocalMode(boolean localMode) {
        this.localMode = localMode;
    }

    /**
     * 启动路由器
     */
    public void start() {
        running = true;
        try {
            dnsSocket = new DatagramSocket();
            // 不保护 DNS socket：addDisallowedApplication 已让本应用流量绕过 VPN，
            // protect() 反而会把 socket 绑定到宿主物理网卡，导致 emulator 虚拟 DNS 10.0.2.3 不可达
            Logger.info(LogConfig.MODULE_VPN, "DNS socket created, port=" + dnsSocket.getLocalPort());

            startDnsReceiveThread();
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_VPN, "Failed to create DNS socket: " + e.getMessage());
        }

        startHandshakeCleanupThread();

        Logger.info(LogConfig.MODULE_VPN, "PacketRouter started");
    }

    /**
     * 启动 DNS 接收线程
     */
    private void startDnsReceiveThread() {
        dnsReceiveThread = new Thread(() -> {
            byte[] recvBuf = new byte[512];
            while (running && dnsSocket != null) {
                try {
                    DatagramPacket response = new DatagramPacket(recvBuf, recvBuf.length);
                    dnsSocket.receive(response);

                    if (response.getLength() >= 2) {
                        byte[] dnsData = Arrays.copyOf(response.getData(), response.getLength());
                        int respTxId = ((dnsData[0] & 0xFF) << 8) | (dnsData[1] & 0xFF);

                        PendingDnsQuery query = pendingDnsQueries.remove(respTxId);
                        if (query != null && !query.completed) {
                            query.completed = true;
                            byte[] udpPacket = buildUdpPacket(dnsData, query.dstAddr, query.dstPort,
                                    query.srcAddr, query.srcPort);
                            query.callback.onWriteToVpn(udpPacket);
                            Logger.info(LogConfig.MODULE_VPN, "DNS forwarded: " + dnsData.length + " bytes");
                        } else {
                            Logger.debug(LogConfig.MODULE_VPN, "DNS response with no pending query, txId=" + respTxId);
                        }
                    }
                } catch (SocketTimeoutException e) {
                    // 正常超时，继续循环
                } catch (IOException e) {
                    if (running) {
                        Logger.debug(LogConfig.MODULE_VPN, "DNS receive error: " + e.getMessage());
                    }
                }
            }
        }, "DNS-Recv");
        dnsReceiveThread.start();
    }

    /**
     * 启动握手超时清理线程
     */
    private void startHandshakeCleanupThread() {
        handshakeCleanupThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(2000);
                    long now = System.currentTimeMillis();
                    for (Iterator<Map.Entry<Integer, SocketConnection>> it = pendingHandshakes.entrySet().iterator(); it.hasNext(); ) {
                        Map.Entry<Integer, SocketConnection> entry = it.next();
                        SocketConnection conn = entry.getValue();
                        if (now - conn.lastActivityTime > HANDSHAKE_TIMEOUT_MS) {
                            byte[] rst = buildRstPacket(conn.srcAddr, conn.srcPort, conn.dstAddr, conn.dstPort, conn.seqNum);
                            conn.callback.onWriteToVpn(rst);
                            Logger.info(LogConfig.MODULE_SOCKS5, "Handshake timeout, sent RST: " + conn.getDstHost() + ":" + conn.getDstPort());

                            connections.remove(connectionKey(conn.srcAddr, conn.srcPort, conn.dstAddr, conn.dstPort));
                            connectionsById.remove(entry.getKey());
                            it.remove();
                        }
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "Handshake-Cleanup");
        handshakeCleanupThread.start();
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
        pendingHandshakes.clear();
        connectionsById.clear();
        pendingDnsQueries.clear();

        if (dnsSocket != null) {
            dnsSocket.close();
            dnsSocket = null;
        }

        if (dnsReceiveThread != null) {
            dnsReceiveThread.interrupt();
            try {
                dnsReceiveThread.join(1000);
            } catch (InterruptedException ignored) {}
            dnsReceiveThread = null;
        }

        if (handshakeCleanupThread != null) {
            handshakeCleanupThread.interrupt();
            try {
                handshakeCleanupThread.join(1000);
            } catch (InterruptedException ignored) {}
            handshakeCleanupThread = null;
        }

        Logger.info(LogConfig.MODULE_VPN, "PacketRouter stopped");
    }

    /**
     * 生成连接 key — 必须包含 srcAddr+srcPort+dstAddr+dstPort，
     * 否则同一目的地的多连接会冲突
     */
    private static int connectionKey(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort) {
        int hash = Arrays.hashCode(srcAddr);
        hash = 31 * hash + srcPort;
        hash = 31 * hash + Arrays.hashCode(dstAddr);
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

        int connKey = connectionKey(srcAddr, srcPort, dstAddr, dstPort);
        SocketConnection conn = connections.get(connKey);

        if (conn == null) {
            if (isSyn && !isAck) {
                // 快速拒绝 emulator 本地网络、已知被墙 IP、DoT，避免占用序列化槽
                if (shouldFastFail(dstHost, dstPort)) {
                    Logger.info(LogConfig.MODULE_VPN, "Fast-fail SYN to " + dstHost + ":" + dstPort);
                    byte[] rst = buildRstPacket(srcAddr, srcPort, dstAddr, dstPort, tcpSeq);
                    callback.onWriteToVpn(rst);
                    return;
                }

                // 新连接 SYN — 分配连接 ID
                int connId = nextConnectionId++;
                if (nextConnectionId > 255) {
                    nextConnectionId = 1;
                }
                int serverSeq = nextTcpSeq++;
                conn = new SocketConnection(connId, srcAddr, srcPort, dstAddr, dstHost, dstPort,
                        tcpSeq, serverSeq, callback);
                connections.put(connKey, conn);
                connectionsById.put(connId, conn);

                // 发送 SYN-ACK 回客户端
                byte[] synAck = buildSynAckPacket(conn);
                callback.onWriteToVpn(synAck);
                // SYN 占用一个序列号
                conn.advanceAckNum(1);

                // 发送 SOCKS5 CONNECT（带连接 ID 前缀）
                byte[] socks5Request = Socks5Request.buildConnectRequest(dstHost, dstPort);
                byte[] wrappedRequest = new byte[1 + socks5Request.length];
                wrappedRequest[0] = (byte) connId;
                System.arraycopy(socks5Request, 0, wrappedRequest, 1, socks5Request.length);
                callback.onSendToKcp(wrappedRequest);
                pendingHandshakes.put(connId, conn);

                Logger.info(LogConfig.MODULE_SOCKS5, "New TCP connection: " + dstHost + ":" + dstPort
                        + " src=" + formatAddr(srcAddr) + ":" + srcPort
                        + " clientSeq=" + tcpSeq + " serverSeq=" + serverSeq);
            } else {
                // 非 SYN 包但连接不存在，忽略
                Logger.debug(LogConfig.MODULE_VPN, "TCP packet without connection, flags=" + tcpFlags);
            }
            return;
        }

        // 连接已存在
        if (isRst || isFin) {
            Logger.info(LogConfig.MODULE_VPN, "TCP RST/FIN received, closing: " + dstHost + ":" + dstPort);
            conn.markClosed();
            connections.remove(connKey);
            connectionsById.remove(conn.connectionId);
            pendingHandshakes.remove(conn.connectionId);
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
                byte[] wrapped = new byte[1 + data.length];
                wrapped[0] = (byte) conn.connectionId;
                System.arraycopy(data, 0, wrapped, 1, data.length);
                callback.onSendToKcp(wrapped);

                // 立即发送 ACK，避免客户端重传
                byte[] ack = buildAckPacket(conn);
                callback.onWriteToVpn(ack);

                conn.touch();

                Logger.debug(LogConfig.MODULE_VPN, "TCP data: " + dataLen + " bytes to " + dstHost + ":" + dstPort + " connId=" + conn.connectionId);
            } else {
                Logger.debug(LogConfig.MODULE_VPN, "TCP data dropped: SOCKS5 handshake not done for " + dstHost);
                // 即使数据被丢弃，也发送 ACK，避免客户端超时重传占满窗口
                byte[] ack = buildAckPacket(conn);
                callback.onWriteToVpn(ack);
            }
        } else if (isAck) {
            // 空 ACK，保持连接活跃
            conn.touch();
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
            // DNS 查询 - 系统解析并合成响应（避免 emulator UDP 转发慢）
            handleDnsSynthesize(srcAddr, srcPort, dstAddr, dstPort, data, callback);
        } else {
            // 非 DNS UDP 暂时不处理
            Logger.debug(LogConfig.MODULE_VPN, "UDP non-DNS dropped: " + dstHost + ":" + dstPort);
        }
    }

    /**
     * 系统解析 DNS 并合成响应（绕过 emulator UDP 转发延迟）
     */
    private void handleDnsSynthesize(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                      byte[] queryData, OutboundCallback callback) {
        try {
            // 解析查询中的 hostname 和 QTYPE
            int offset = 12; // 跳过 DNS header
            StringBuilder hostname = new StringBuilder();
            while (offset < queryData.length) {
                int len = queryData[offset++] & 0xFF;
                if (len == 0) break;
                if (hostname.length() > 0) hostname.append('.');
                if (offset + len <= queryData.length) {
                    hostname.append(new String(queryData, offset, len, java.nio.charset.StandardCharsets.UTF_8));
                }
                offset += len;
            }
            if (offset + 4 > queryData.length) {
                Logger.warning(LogConfig.MODULE_VPN, "DNS query too short to parse QTYPE");
                return;
            }
            int qtype = ((queryData[offset] & 0xFF) << 8) | (queryData[offset + 1] & 0xFF);
            int qclass = ((queryData[offset + 2] & 0xFF) << 8) | (queryData[offset + 3] & 0xFF);

            String host = hostname.toString();
            if (host.isEmpty()) {
                Logger.warning(LogConfig.MODULE_VPN, "DNS query with empty hostname");
                return;
            }

            Logger.debug(LogConfig.MODULE_VPN, "DNS synthesize: " + host + " qtype=" + qtype);

            // 系统解析
            InetAddress[] addresses;
            try {
                addresses = InetAddress.getAllByName(host);
            } catch (UnknownHostException e) {
                // 返回 NXDOMAIN
                byte[] nxdomain = buildDnsResponse(queryData, qtype, new InetAddress[0], true);
                byte[] udpPacket = buildUdpPacket(nxdomain, srcAddr, srcPort, dstAddr, dstPort);
                callback.onWriteToVpn(udpPacket);
                Logger.info(LogConfig.MODULE_VPN, "DNS NXDOMAIN: " + host);
                return;
            }

            byte[] response = buildDnsResponse(queryData, qtype, addresses, false);
            byte[] udpPacket = buildUdpPacket(response, dstAddr, dstPort, srcAddr, srcPort);
            callback.onWriteToVpn(udpPacket);
            Logger.info(LogConfig.MODULE_VPN, "DNS synthesized: " + host + " answers=" + response.length + " bytes");

        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "DNS synthesize error: " + e.getMessage());
        }
    }

    /**
     * 构建 DNS 响应包（仅支持 A / AAAA）
     */
    private byte[] buildDnsResponse(byte[] queryData, int qtype, InetAddress[] addresses, boolean nxdomain) {
        ByteBuffer queryBuf = ByteBuffer.wrap(queryData);
        short txId = queryBuf.getShort();
        short flags = queryBuf.getShort();
        short qdcount = queryBuf.getShort();

        // 找到 question 末尾
        int offset = 12;
        while (offset < queryData.length) {
            int len = queryData[offset++] & 0xFF;
            if (len == 0) break;
            offset += len;
        }
        offset += 4; // QTYPE + QCLASS

        int answerCount = 0;
        for (InetAddress addr : addresses) {
            if (qtype == 1 && addr instanceof Inet4Address) answerCount++;
            else if (qtype == 28 && addr instanceof Inet6Address) answerCount++;
        }

        if (nxdomain) {
            answerCount = 0;
        }

        int responseLen = offset + answerCount * (qtype == 1 ? 16 : 28);
        ByteBuffer resp = ByteBuffer.allocate(responseLen);

        // Header
        resp.putShort(txId);
        resp.putShort((short) 0x8180); // QR=1, AA=0, TC=0, RD=1, RA=1
        resp.putShort(qdcount);
        resp.putShort((short) answerCount);
        resp.putShort((short) 0); // NSCOUNT
        resp.putShort((short) 0); // ARCOUNT

        // Question section (copy from query)
        resp.put(queryData, 12, offset - 12);

        // Answer RRs
        for (InetAddress addr : addresses) {
            if (qtype == 1 && addr instanceof Inet4Address) {
                resp.putShort((short) 0xC00C); // pointer to question name
                resp.putShort((short) 1); // A
                resp.putShort((short) 1); // IN
                resp.putInt(300); // TTL
                resp.putShort((short) 4); // RDLENGTH
                resp.put(addr.getAddress());
            } else if (qtype == 28 && addr instanceof Inet6Address) {
                resp.putShort((short) 0xC00C); // pointer to question name
                resp.putShort((short) 28); // AAAA
                resp.putShort((short) 1); // IN
                resp.putInt(300); // TTL
                resp.putShort((short) 16); // RDLENGTH
                resp.put(addr.getAddress());
            }
        }

        return Arrays.copyOf(resp.array(), resp.position());
    }

    /**
     * 异步转发 DNS 查询
     */
    private void handleDnsQuery(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                 byte[] queryData, OutboundCallback callback) {
        if (dnsSocket == null) {
            Logger.warning(LogConfig.MODULE_VPN, "DNS socket not available");
            return;
        }

        try {
            // 提取查询事务 ID（前 2 字节）
            int queryTxId = ((queryData[0] & 0xFF) << 8) | (queryData[1] & 0xFF);

            // 注册待处理查询
            PendingDnsQuery pending = new PendingDnsQuery(
                    queryTxId, srcAddr, srcPort, dstAddr, dstPort,
                    callback, System.currentTimeMillis() + DNS_TIMEOUT_MS);
            pendingDnsQueries.put(queryTxId, pending);

            // 发送查询
            DatagramPacket request = new DatagramPacket(queryData, queryData.length,
                    InetAddress.getByAddress(dstAddr), dstPort);
            dnsSocket.send(request);

            // 等待响应（由 DNS 接收线程处理）
            long remaining = DNS_TIMEOUT_MS;
            while (remaining > 0 && !pending.completed) {
                Thread.sleep(Math.min(remaining, 50));
                remaining = pending.expireTime - System.currentTimeMillis();
            }

            if (!pending.completed) {
                pendingDnsQueries.remove(queryTxId);
                Logger.warning(LogConfig.MODULE_VPN, "DNS query timeout, txId=" + queryTxId);
            }

        } catch (IOException e) {
            Logger.warning(LogConfig.MODULE_VPN, "DNS query send failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 处理入站数据包（从 KCP 接收，写入 VPN 接口）
     */
    public void handleInboundData(byte[] data, WritePacketCallback writePacketCallback) {
        if (!running || data == null || data.length == 0) {
            return;
        }

        Logger.debug(LogConfig.MODULE_VPN, "Inbound data: len=" + data.length + " firstByte=" + String.format("0x%02X", data[0]));

        if (data.length < 1) {
            Logger.warning(LogConfig.MODULE_VPN, "Inbound data too short, no connId");
            return;
        }

        int connId = data[0] & 0xFF;
        byte[] payload = Arrays.copyOfRange(data, 1, data.length);

        // 检查 SOCKS5 响应：payload 必须以 0x05 开头且长度至少 10 字节
        if (payload.length >= 10 && payload[0] == Socks5.SOCKS5_VERSION) {
            byte rep = payload[1];
            if (rep >= 0 && rep <= 0x08) {
                Socks5Response response = Socks5Response.parse(payload, 0, payload.length);
                if (response.reply == Socks5.SOCKS5_REPLY_SUCCEEDED) {
                    Logger.info(LogConfig.MODULE_SOCKS5, "SOCKS5 handshake success connId=" + connId);
                    SocketConnection conn = pendingHandshakes.remove(connId);
                    if (conn != null) {
                        conn.markHandshakeDone();
                        Logger.info(LogConfig.MODULE_SOCKS5, "Connection handshake done: " + conn.getDstHost() + ":" + conn.getDstPort());
                    } else {
                        Logger.warning(LogConfig.MODULE_SOCKS5, "No pending connection for SOCKS5 success response connId=" + connId);
                    }
                } else {
                    Logger.warning(LogConfig.MODULE_SOCKS5, "SOCKS5 handshake failed: reply=" + response.reply + " connId=" + connId);
                    SocketConnection conn = pendingHandshakes.remove(connId);
                    if (conn != null) {
                        // Send TCP RST so client knows connection failed
                        byte[] rst = buildRstPacket(conn.srcAddr, conn.srcPort, conn.dstAddr, conn.dstPort, conn.seqNum);
                        conn.callback.onWriteToVpn(rst);
                        Logger.info(LogConfig.MODULE_SOCKS5, "Sent TCP RST for failed handshake: " + conn.getDstHost() + ":" + conn.getDstPort());

                        conn.markHandshakeFailed();
                        conn.markClosed();
                        connections.remove(connectionKey(conn.srcAddr, conn.srcPort, conn.dstAddr, conn.dstPort));
                        connectionsById.remove(connId);
                        Logger.info(LogConfig.MODULE_SOCKS5, "Removed failed connection: " + conn.getDstHost() + ":" + conn.getDstPort());
                    } else {
                        Logger.warning(LogConfig.MODULE_SOCKS5, "No pending connection for SOCKS5 failure response connId=" + connId);
                    }
                }
                return;
            }
        }

        // 构建返回的 IP 数据包
        try {
            SocketConnection conn = connectionsById.get(connId);
            if (conn == null || !conn.isHandshakeDone()) {
                Logger.warning(LogConfig.MODULE_VPN, "No active connection for inbound data connId=" + connId + " payloadLen=" + payload.length);
                return;
            }

            byte[] ipPacket = buildIpPacket(payload, conn);
            writePacketCallback.onWritePacket(ipPacket);
            conn.touch();
            Logger.debug(LogConfig.MODULE_VPN, "Inbound: " + payload.length + " bytes -> VPN for " + conn.getDstHost() + ":" + conn.getDstPort() + " connId=" + connId);
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Build IP packet error: " + e.getMessage());
        }
    }

    /**
     * 快速拒绝 DoT / emulator 本地网络 / 已知被墙 IP，避免占用序列化槽。
     */
    private boolean shouldFastFail(String dstHost, int dstPort) {
        // DNS over TLS (DoT) - 让系统回退到 UDP DNS
        if (dstPort == 853) {
            return true;
        }
        // emulator 本地网络
        if (dstHost.startsWith("10.0.2.")) {
            return true;
        }
        // 已知被墙 Google IP 段（此网络环境下不可达），立即 RST 让 Chrome 回退
        if (dstHost.startsWith("142.250.") || dstHost.startsWith("216.239.")
                || dstHost.startsWith("172.217.") || dstHost.startsWith("74.125.")) {
            return true;
        }
        return false;
    }

    /**
     * 构建 TCP RST 包（响应被拒绝的 SYN）
     */
    private byte[] buildRstPacket(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort, int clientSeq) {
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
        buf.put(dstAddr);
        buf.put(srcAddr);

        // TCP header: RST + ACK
        buf.putShort((short) dstPort);
        buf.putShort((short) srcPort);
        buf.putInt(0);                 // Seq = 0
        buf.putInt(clientSeq + 1);     // Ack = client ISN + 1
        buf.put((byte) 0x50);          // Data offset = 5
        buf.put((byte) 0x14);          // RST + ACK
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.putShort((short) 0);

        byte[] packet = buf.array();
        short ipChecksum = calculateIpChecksum(packet, 0, 20);
        packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        packet[11] = (byte) (ipChecksum & 0xFF);

        return packet;
    }

    /**
     * 构建 TCP ACK 包（纯确认，无载荷）
     */
    private byte[] buildAckPacket(SocketConnection conn) {
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
        buf.putShort((short) 0);  // checksum placeholder
        buf.put(conn.getDstAddr());
        buf.put(conn.getSrcAddr());

        // TCP header
        buf.putShort((short) conn.getDstPort());
        buf.putShort((short) conn.getSrcPort());
        buf.putInt(conn.getAckNum());         // Sequence number
        buf.putInt(conn.getSeqNum() + 1);     // Ack number
        buf.put((byte) 0x50);  // Data offset = 5
        buf.put((byte) 0x10);  // ACK only
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);

        byte[] packet = buf.array();

        // 计算 IP 校验和
        short ipChecksum = calculateIpChecksum(packet, 0, 20);
        packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        packet[11] = (byte) (ipChecksum & 0xFF);

        return packet;
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
        buf.putShort((short) 0);  // checksum placeholder
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

        byte[] packet = buf.array();

        // 计算 IP 校验和
        short ipChecksum = calculateIpChecksum(packet, 0, 20);
        packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        packet[11] = (byte) (ipChecksum & 0xFF);

        return packet;
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
        buf.putShort((short) 0);  // checksum placeholder
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

        byte[] packet = buf.array();

        // 计算 IP 校验和
        short ipChecksum = calculateIpChecksum(packet, 0, 20);
        packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        packet[11] = (byte) (ipChecksum & 0xFF);

        conn.advanceAckNum(payload.length);

        return packet;
    }

    /**
     * 构建 UDP 数据包
     */
    private byte[] buildUdpPacket(byte[] payload, byte[] srcAddr, int srcPort,
                                   byte[] dstAddr, int dstPort) {
        int udpLen = 8 + payload.length;
        int totalLen = 20 + udpLen;
        ByteBuffer buf = ByteBuffer.allocate(totalLen);

        // IP header
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 17);  // UDP
        buf.putShort((short) 0);  // IP checksum placeholder
        buf.put(srcAddr);
        buf.put(dstAddr);

        // UDP header
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);  // UDP checksum placeholder

        // Payload
        buf.put(payload);

        byte[] packet = buf.array();

        // 计算 IP 校验和
        short ipChecksum = calculateIpChecksum(packet, 0, 20);
        packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        packet[11] = (byte) (ipChecksum & 0xFF);

        // 计算 UDP 校验和
        short udpChecksum = calculateUdpChecksum(packet, 0, 20, udpLen, srcAddr, dstAddr);
        packet[26] = (byte) ((udpChecksum >> 8) & 0xFF);
        packet[27] = (byte) (udpChecksum & 0xFF);

        return packet;
    }

    /**
     * 计算 IP 头部校验和
     */
    private static short calculateIpChecksum(byte[] packet, int offset, int length) {
        long sum = 0;
        int end = offset + length;
        for (int i = offset; i < end; i += 2) {
            sum += ((packet[i] & 0xFF) << 8) | (packet[i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

    /**
     * 计算 UDP 校验和（含伪头部）
     */
    private static short calculateUdpChecksum(byte[] packet, int ipOffset, int udpOffset, int udpLength,
                                               byte[] srcAddr, byte[] dstAddr) {
        long sum = 0;

        // 伪头部：源 IP
        for (int i = 0; i < 4; i += 2) {
            sum += ((srcAddr[i] & 0xFF) << 8) | (srcAddr[i + 1] & 0xFF);
        }

        // 伪头部：目的 IP
        for (int i = 0; i < 4; i += 2) {
            sum += ((dstAddr[i] & 0xFF) << 8) | (dstAddr[i + 1] & 0xFF);
        }

        // 伪头部：协议 + UDP 长度
        sum += 17;
        sum += udpLength;

        // UDP 头部和数据
        int end = udpOffset + udpLength;
        for (int i = udpOffset; i < end; i += 2) {
            if (i + 1 < end) {
                sum += ((packet[i] & 0xFF) << 8) | (packet[i + 1] & 0xFF);
            } else {
                sum += (packet[i] & 0xFF) << 8;
            }
        }

        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        short result = (short) ~sum;
        // 校验和为 0 时应返回 0xFFFF（UDP 特殊规则）
        return result == 0 ? (short) 0xFFFF : result;
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
        private static final long IDLE_TIMEOUT_MS = 5_000;

        final int connectionId;
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
        private volatile boolean closed;
        private volatile long lastActivityTime;

        public SocketConnection(int connectionId, byte[] srcAddr, int srcPort, byte[] dstAddr,
                                String dstHost, int dstPort,
                                int clientSeqNum, int serverSeqNum,
                                OutboundCallback callback) {
            this.connectionId = connectionId;
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
            this.closed = false;
            this.lastActivityTime = System.currentTimeMillis();
        }

        public void markHandshakeDone() {
            handshakeDone = true;
            touch();
        }

        public void markHandshakeFailed() {
            handshakeFailed = true;
        }

        public void markClosed() {
            closed = true;
        }

        public boolean isHandshakeDone() {
            return handshakeDone && !handshakeFailed && !closed;
        }

        public boolean isHandshakeFailed() {
            return handshakeFailed || closed;
        }

        public boolean isClosed() {
            return closed;
        }

        public void touch() {
            lastActivityTime = System.currentTimeMillis();
        }

        public boolean isIdle() {
            return System.currentTimeMillis() - lastActivityTime > IDLE_TIMEOUT_MS;
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

        public String getDstHost() {
            return dstHost;
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
            closed = true;
        }
    }
}
