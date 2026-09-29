package com.dchen.kcpvpn.vpn;

import com.dchen.kcpvpn.core.protocol.KcpFrame;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * IPv6 转发：解析 40 字节头、合成 IPv6 SYN-ACK、TCP 伪首部校验和、扩展头/分片丢弃。
 * 校验和用独立实现重算，等于把 buildTcpPacket 的伪首部逐字节验证一遍。
 */
public class PacketRouterIpv6Test {
    private static final byte[] CLIENT_IP = ipv6("fd00::2");
    private static final byte[] SERVER_IP = ipv6("2001:db8::1");
    private static final int CLIENT_PORT = 41000;
    private static final int SERVER_PORT = 443;
    private static final int SYN_SEQ = 1000;

    private final List<byte[]> written = new ArrayList<>();
    private final List<KcpFrame> frames = new ArrayList<>();
    private PacketRouter router;
    private long connectionId;
    private int serverInitialSeq;

    @Before
    public void setUp() {
        router = new PacketRouter();
        router.setLocalMode(true);
        router.start();
    }

    @After
    public void tearDown() {
        router.stop();
    }

    @Test
    public void ipv6SynGetsIpv6SynAckWithValidChecksum() {
        sendTcp(0x02, SYN_SEQ, 0, new byte[0]);

        assertEquals("SYN 必须被解析并回 SYN-ACK", 1, written.size());
        byte[] packet = written.get(0);

        assertEquals("版本必须是 6", 6, (packet[0] >> 4) & 0x0F);
        assertEquals("next header 必须是 TCP", 6, packet[6] & 0xFF);
        assertEquals("payload length = TCP 头 20", 20, readShort(packet, 4));
        assertEquals("整包长度 = 40 + 20", 60, packet.length);
        assertArrayEquals("源地址应是远端目标", SERVER_IP, slice(packet, 8, 24));
        assertArrayEquals("目的地址应是本机", CLIENT_IP, slice(packet, 24, 40));
        assertEquals("SYN|ACK", 0x12, packet[40 + 13] & 0xFF);
        assertEquals(SERVER_PORT, readShort(packet, 40));
        assertEquals(CLIENT_PORT, readShort(packet, 42));
        assertTrue("IPv6 包不应有 IPv4 风格的头部校验和字段（版本/长度字段不可被改写）",
                packet[0] == (byte) 0x60 && packet[1] == 0);
        assertTrue("TCP 校验和必须通过 IPv6 伪首部重算", ipv6TcpChecksumValid(packet));
    }

    /** 防止上面的校验和断言变成恒真：改一个负载字节必须让验证失败。 */
    @Test
    public void checksumVerifierRejectsCorruptedPacket() {
        sendTcp(0x02, SYN_SEQ, 0, new byte[0]);
        byte[] packet = written.get(0);
        assertTrue(ipv6TcpChecksumValid(packet));

        packet[40 + 14] = (byte) (packet[40 + 14] ^ 0x01);   // 篡改 TCP 校验和本身
        assertTrue("被篡改的包不得通过校验", !ipv6TcpChecksumValid(packet));
    }

    @Test
    public void ipv6PayloadIsForwardedAndAcked() {
        establish();
        assertEquals(1, countFrames(KcpFrame.TYPE_OPEN));

        byte[] body = "GET / HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII);
        sendTcp(0x18, SYN_SEQ + 1, serverNextSeq(), body);

        KcpFrame data = lastFrame(KcpFrame.TYPE_DATA);
        assertArrayEquals("负载必须原样交给隧道", body, data.getPayload());

        byte[] ack = lastWritten();
        assertEquals("回 ACK", 0x10, ack[40 + 13] & 0xFF);
        assertTrue("ACK 的 TCP 校验和必须有效", ipv6TcpChecksumValid(ack));
    }

    @Test
    public void ipv6InboundDataSegmentsStayWithinMtu() {
        establish();
        byte[] big = new byte[3000];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) (i & 0xFF);
        }
        written.clear();
        router.handleInboundRawTcpData(connectionId, big, written::add);

        assertTrue("3000 字节至少要切成 3 个包", written.size() >= 3);
        int total = 0;
        for (byte[] packet : written) {
            assertTrue("写进 TUN 的包不得超过 MTU：" + packet.length, packet.length <= VpnConfig.VPN_MTU);
            assertEquals(6, (packet[0] >> 4) & 0x0F);
            assertTrue(ipv6TcpChecksumValid(packet));
            total += packet.length - 40 - 20;
        }
        assertEquals("切片不得丢字节或多字节", big.length, total);
    }

    @Test
    public void ipv6UdpIsDropped() {
        sendIpv6Packet(17, 40 + 8 + 4, buildUdpDatagram(4));
        assertTrue("IPv6 UDP 应被丢弃（与 IPv4 非 DNS UDP 策略一致）", written.isEmpty());
        assertTrue(frames.isEmpty());
    }

    @Test
    public void ipv6FragmentHeaderIsDropped() {
        // next header = 44（分片头）：我们只拿到一个片段，不能按 TCP 解析
        sendIpv6Packet(44, 40 + 8, buildUdpDatagram(0));
        assertTrue(written.isEmpty());
        assertTrue(frames.isEmpty());
    }

    @Test
    public void ipv4StillParsesAfterIpv6Support() {
        ByteBuffer buf = ByteBuffer.allocate(40).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) 40);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 6);
        buf.putShort((short) 0);
        buf.put(new byte[]{10, 0, 2, 15});
        buf.put(new byte[]{(byte) 93, (byte) 184, (byte) 216, 34});
        buf.putShort((short) CLIENT_PORT);
        buf.putShort((short) SERVER_PORT);
        buf.putInt(SYN_SEQ);
        buf.putInt(0);
        buf.put((byte) 0x50);
        buf.put((byte) 0x02);
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        router.handleOutboundPacket(buf.array(), frames::add, written::add);

        assertEquals(1, written.size());
        assertEquals("IPv4 路径不受影响", 0x45, written.get(0)[0] & 0xFF);
        assertEquals(0x12, written.get(0)[33] & 0xFF);
        assertTrue("IPv4 头部校验和必须有效", ipv4HeaderChecksumValid(written.get(0)));
        assertTrue("IPv4 TCP 校验和必须有效", ipv4TcpChecksumValid(written.get(0)));
    }

    private void establish() {
        sendTcp(0x02, SYN_SEQ, 0, new byte[0]);
        connectionId = frames.get(0).getConnectionId();
        serverInitialSeq = seqNumber(lastWritten());
        sendTcp(0x10, SYN_SEQ + 1, serverInitialSeq + 1, new byte[0]);
    }

    /** 服务端下一个待发序号：SYN-ACK 的 seq + 1。 */
    private int serverNextSeq() {
        return serverInitialSeq + 1;
    }

    private void sendTcp(int flags, int seq, int ack, byte[] payload) {
        int tcpLen = 20 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(40 + tcpLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x60);
        buf.put((byte) 0);
        buf.put((byte) 0);
        buf.put((byte) 0);
        buf.putShort((short) tcpLen);
        buf.put((byte) 6);
        buf.put((byte) 64);
        buf.put(CLIENT_IP);
        buf.put(SERVER_IP);
        buf.putShort((short) CLIENT_PORT);
        buf.putShort((short) SERVER_PORT);
        buf.putInt(seq);
        buf.putInt(ack);
        buf.put((byte) 0x50);
        buf.put((byte) flags);
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.put(payload);
        router.handleOutboundPacket(buf.array(), frames::add, written::add);
    }

    private static byte[] buildUdpDatagram(int payloadLen) {
        ByteBuffer udp = ByteBuffer.allocate(8 + payloadLen).order(ByteOrder.BIG_ENDIAN);
        udp.putShort((short) CLIENT_PORT);
        udp.putShort((short) 53);
        udp.putShort((short) (8 + payloadLen));
        udp.putShort((short) 0);
        udp.put(new byte[payloadLen]);
        return udp.array();
    }

    private void sendIpv6Packet(int nextHeader, int payloadLen, byte[] payload) {
        ByteBuffer buf = ByteBuffer.allocate(40 + payloadLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x60);
        buf.put((byte) 0);
        buf.put((byte) 0);
        buf.put((byte) 0);
        buf.putShort((short) payloadLen);
        buf.put((byte) nextHeader);
        buf.put((byte) 64);
        buf.put(CLIENT_IP);
        buf.put(SERVER_IP);
        buf.put(payload);
        router.handleOutboundPacket(buf.array(), frames::add, written::add);
    }

    private byte[] lastWritten() {
        return written.get(written.size() - 1);
    }

    private KcpFrame lastFrame(byte type) {
        for (int i = frames.size() - 1; i >= 0; i--) {
            if (frames.get(i).getFrameType() == type) {
                return frames.get(i);
            }
        }
        throw new AssertionError("no frame of type " + type);
    }

    private int countFrames(byte type) {
        int count = 0;
        for (KcpFrame frame : frames) {
            if (frame.getFrameType() == type) {
                count++;
            }
        }
        return count;
    }

    private static int seqNumber(byte[] packet) {
        return ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN).getInt(40 + 4);
    }

    private static int readShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static byte[] slice(byte[] data, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }

    private static byte[] ipv6(String literal) {
        try {
            byte[] addr = InetAddress.getByName(literal).getAddress();
            assertEquals("测试常量必须是 IPv6 字面量", 16, addr.length);
            return addr;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // ---- 独立的校验和实现（不复用被测代码）----

    /** 把伪首部 + TCP 段一起做反码求和，结果应为 0xFFFF。 */
    private static boolean ipv6TcpChecksumValid(byte[] packet) {
        int tcpLen = packet.length - 40;
        ByteBuffer pseudo = ByteBuffer.allocate(40 + tcpLen).order(ByteOrder.BIG_ENDIAN);
        pseudo.put(packet, 8, 16);      // src
        pseudo.put(packet, 24, 16);     // dst
        pseudo.putInt(tcpLen);          // 上层长度
        pseudo.put((byte) 0);
        pseudo.put((byte) 0);
        pseudo.put((byte) 0);
        pseudo.put((byte) 6);           // next header
        pseudo.put(packet, 40, tcpLen);
        return onesComplementSum(pseudo.array()) == 0xFFFF;
    }

    private static boolean ipv4HeaderChecksumValid(byte[] packet) {
        byte[] header = slice(packet, 0, 20);
        return onesComplementSum(header) == 0xFFFF;
    }

    private static boolean ipv4TcpChecksumValid(byte[] packet) {
        int tcpLen = packet.length - 20;
        ByteBuffer pseudo = ByteBuffer.allocate(12 + tcpLen).order(ByteOrder.BIG_ENDIAN);
        pseudo.put(packet, 12, 4);
        pseudo.put(packet, 16, 4);
        pseudo.put((byte) 0);
        pseudo.put((byte) 6);
        pseudo.putShort((short) tcpLen);
        pseudo.put(packet, 20, tcpLen);
        return onesComplementSum(pseudo.array()) == 0xFFFF;
    }

    private static int onesComplementSum(byte[] data) {
        long sum = 0;
        int i = 0;
        int len = data.length;
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
        return (int) (sum & 0xFFFF);
    }
}
