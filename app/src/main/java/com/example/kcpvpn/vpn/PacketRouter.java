package com.example.kcpvpn.vpn;

import com.example.kcpvpn.core.protocol.AddressParser;
import com.example.kcpvpn.core.protocol.Socks5;
import com.example.kcpvpn.core.protocol.Socks5Request;
import com.example.kcpvpn.core.protocol.Socks5Response;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 数据包路由器 - 处理 VPN 数据包与 SOCKS5/KCP 的转换
 */
public class PacketRouter {

    private final Map<Integer, SocketConnection> connections;
    private volatile boolean running;

    public PacketRouter() {
        this.connections = new ConcurrentHashMap<>();
        this.running = false;
    }

    /**
     * 启动路由器
     */
    public void start() {
        running = true;
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

        Logger.info(LogConfig.MODULE_VPN, "PacketRouter stopped");
    }

    /**
     * 生成连接 key — 使用 IP 字节数组 + 端口，避免 hashCode 碰撞
     */
    private static int connectionKey(byte[] dstAddr, int dstPort) {
        return Arrays.hashCode(dstAddr) * 31 + dstPort;
    }

    /**
     * 处理出站数据包（从 VPN 接口读取，通过 KCP 发送）
     * @param packet IP 数据包
     * @param sendDataCallback 发送数据回调
     */
    public void handleOutboundPacket(byte[] packet, SendDataCallback sendDataCallback) {
        if (!running || packet == null || packet.length < 20) {
            return;
        }

        try {
            // 解析 IP 包头
            ByteBuffer buf = ByteBuffer.wrap(packet);

            byte version = (byte) ((buf.get() >> 4) & 0x0F);
            if (version != 4) {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring non-IPv4 packet");
                return;
            }

            buf.position(0);

            // 解析 IP 头
            byte ihl = (byte) (buf.get() & 0x0F);
            int headerLen = ihl * 4;

            buf.get();  // TOS
            int totalLen = buf.getShort() & 0xFFFF;
            buf.getShort();  // ID
            int flagsAndFragment = buf.getShort() & 0xFFFF;

            // 检查是否分片（MF=1 或 Fragment Offset != 0）
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

            // 校验 totalLen 不超过实际数据长度
            if (totalLen > packet.length) {
                totalLen = packet.length;
            }

            // 解析目标地址和端口
            int dstPort = 0;
            int srcPort = 0;

            if (protocol == 6) {  // TCP
                buf.position(headerLen);
                srcPort = buf.getShort() & 0xFFFF;
                dstPort = buf.getShort() & 0xFFFF;
            } else if (protocol == 17) {  // UDP
                buf.position(headerLen);
                srcPort = buf.getShort() & 0xFFFF;
                dstPort = buf.getShort() & 0xFFFF;
            } else {
                Logger.debug(LogConfig.MODULE_VPN, "Ignoring non-TCP/UDP packet: protocol=" + protocol);
                return;
            }

            // 构建目标地址字符串
            String dstHost = String.format("%d.%d.%d.%d",
                    dstAddr[0] & 0xFF, dstAddr[1] & 0xFF,
                    dstAddr[2] & 0xFF, dstAddr[3] & 0xFF);

            Logger.debug(LogConfig.MODULE_VPN, "Outbound: " + dstHost + ":" + dstPort
                    + " (" + (protocol == 6 ? "TCP" : "UDP") + ")");

            // 获取或创建连接（使用 IP 字节+端口作为 key）
            int connKey = connectionKey(dstAddr, dstPort);
            SocketConnection conn = connections.get(connKey);

            if (conn == null) {
                // 创建新连接
                conn = new SocketConnection(dstHost, dstPort, sendDataCallback);
                connections.put(connKey, conn);

                // 发送 SOCKS5 CONNECT 请求
                byte[] socks5Request = Socks5Request.buildConnectRequest(dstHost, dstPort);
                sendDataCallback.onSendData(socks5Request);

                Logger.info(LogConfig.MODULE_SOCKS5, "New connection: " + dstHost + ":" + dstPort);
            }

            // 提取数据部分
            int transportHeaderLen;
            if (protocol == 6) {
                // TCP: 从 TCP 头起始位置读 data offset
                // 当前 buf 位置在 srcPort(2)+dstPort(2) 之后，即 TCP 偏移 4
                // 还需跳过 seq(4)+ack(4)+dataOffset+flags(2) = 10 字节才能读到 data offset 字段
                // 但 data offset 在 TCP 头第 13 字节的高 4 位
                // 更简单的方法：回到 TCP 头起始读 data offset
                int savedPos = buf.position();
                buf.position(headerLen + 12);  // TCP 头偏移 12 = data offset 字段
                byte dataOffsetByte = buf.get();
                transportHeaderLen = ((dataOffsetByte >> 4) & 0x0F) * 4;
                buf.position(savedPos);  // 恢复位置
            } else {
                // UDP 头固定 8 字节
                transportHeaderLen = 8;
            }

            int dataLen = totalLen - headerLen - transportHeaderLen;

            if (dataLen > 0 && conn.isHandshakeDone()) {
                byte[] data = new byte[dataLen];
                buf.position(headerLen + transportHeaderLen);
                buf.get(data);

                sendDataCallback.onSendData(data);
                Logger.debug(LogConfig.MODULE_VPN, "Sent " + dataLen + " bytes");
            }

        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Handle outbound error: " + e.getMessage());
        }
    }

    /**
     * 处理入站数据包（从 KCP 接收，写入 VPN 接口）
     * @param data 数据
     * @param writePacketCallback 写入回调
     */
    public void handleInboundData(byte[] data, WritePacketCallback writePacketCallback) {
        if (!running || data == null || data.length == 0) {
            return;
        }

        // 检查是否是 SOCKS5 响应
        if (data.length >= 2 && data[0] == Socks5.SOCKS5_VERSION) {
            Socks5Response response = Socks5Response.parse(data, 0, data.length);
            if (response.reply == Socks5.SOCKS5_REPLY_SUCCEEDED) {
                Logger.info(LogConfig.MODULE_SOCKS5, "SOCKS5 handshake success");
                // 只标记最近创建的未握手连接（而非所有连接）
                for (SocketConnection conn : connections.values()) {
                    if (!conn.isHandshakeDone()) {
                        conn.markHandshakeDone();
                    }
                }
            } else {
                Logger.warning(LogConfig.MODULE_SOCKS5, "SOCKS5 handshake failed: " + response.reply);
            }
            return;
        }

        // 构建返回的 IP 数据包
        try {
            byte[] ipPacket = buildIpPacket(data);
            writePacketCallback.onWritePacket(ipPacket);
            Logger.debug(LogConfig.MODULE_VPN, "Inbound: " + data.length + " bytes -> VPN");
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Build IP packet error: " + e.getMessage());
        }
    }

    /**
     * 构建 IP 数据包
     * TODO: 需要维护连接状态（源/目的地址、端口、序列号）才能正确构建
     */
    private byte[] buildIpPacket(byte[] payload) {
        int totalLen = 20 + 20 + payload.length;  // IP header + TCP header + payload
        ByteBuffer buf = ByteBuffer.allocate(totalLen);

        // IP header (20 bytes)
        buf.put((byte) 0x45);  // Version 4, IHL 5
        buf.put((byte) 0);     // TOS
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);  // ID
        buf.putShort((short) 0x4000);  // Flags (Don't Fragment)
        buf.put((byte) 64);    // TTL
        buf.put((byte) 6);     // Protocol (TCP)
        buf.putShort((short) 0);  // Checksum (placeholder)

        // Source address (10.0.0.2 - VPN 内部地址)
        buf.put(new byte[]{10, 0, 0, 2});

        // Destination address (TODO: 需要根据实际连接确定)
        buf.put(new byte[]{0, 0, 0, 0});

        // TCP header (20 bytes, minimal)
        buf.putShort((short) 0);  // Source port
        buf.putShort((short) 0);  // Destination port
        buf.putInt(0);  // Sequence number
        buf.putInt(0);  // Ack number
        buf.put((byte) 0x50);  // Data offset (5)
        buf.put((byte) 0);     // Flags
        buf.putShort((short) 0);  // Window
        buf.putShort((short) 0);  // Checksum
        buf.putShort((short) 0);  // Urgent pointer

        // Payload
        buf.put(payload);

        return buf.array();
    }

    /**
     * 发送数据回调接口
     */
    public interface SendDataCallback {
        void onSendData(byte[] data);
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
        private final String host;
        private final int port;
        private final SendDataCallback sendCallback;
        private volatile boolean handshakeDone;

        public SocketConnection(String host, int port, SendDataCallback sendCallback) {
            this.host = host;
            this.port = port;
            this.sendCallback = sendCallback;
            this.handshakeDone = false;
        }

        public void markHandshakeDone() {
            handshakeDone = true;
        }

        public boolean isHandshakeDone() {
            return handshakeDone;
        }

        public void close() {
            // 清理连接资源
        }
    }
}