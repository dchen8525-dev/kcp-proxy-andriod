package com.dchen.kcpvpn.vpn;

import com.dchen.kcpvpn.core.protocol.KcpFrame;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * server→app 方向的在途段重传：TUN 写丢失的段由应用的 dup-ACK 敦促快速重传；
 * 未确认负载滞留超限时明确回 RST 拆除，而不是无界吃内存或静默丢段。
 */
public class PacketRouterRetransmitTest {
    private static final byte[] CLIENT_IP = {10, 0, 2, 15};
    private static final byte[] SERVER_IP = {(byte) 93, (byte) 184, (byte) 216, 34};
    private static final int CLIENT_PORT = 41000;
    private static final int SERVER_PORT = 443;
    private static final int SYN_SEQ = 1000;
    // IPv4 下单段上限 = VPN_MTU(1400) - 40；滞留上限 256KB / 1360 ≈ 192 段
    private static final int SEGMENT_SIZE = VpnConfig.VPN_MTU - 40;

    private final List<byte[]> written = new ArrayList<>();
    private final List<KcpFrame> frames = new ArrayList<>();
    private PacketRouter router;
    private long connectionId;
    private byte[] writtenSynAck;

    @Before
    public void setUp() {
        router = new PacketRouter();
        router.setLocalMode(true);
        router.start();
        establish();
    }

    @After
    public void tearDown() {
        router.stop();
    }

    private void establish() {
        sendTcp(0x02, SYN_SEQ, 0, new byte[0]);
        connectionId = frames.get(0).getConnectionId();
        writtenSynAck = lastWritten();
        int serverInitialSeq = seqNumber(writtenSynAck);
        sendTcp(0x10, SYN_SEQ + 1, serverInitialSeq + 1, new byte[0]);
        sendTcp(0x18, SYN_SEQ + 1, serverInitialSeq + 1, "GET".getBytes());
    }

    @Test
    public void duplicateAcksTriggerFastRetransmitOfFirstUnacked() {
        // 两个 server→app 段写入 TUN，均未确认
        byte[] seg1 = "aaaa".getBytes();
        byte[] seg2 = "bbbb".getBytes();
        written.clear();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, seg1), writer());
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, seg2), writer());
        assertEquals(2, written.size());
        int seq1 = seqNumber(written.get(0));
        int seq2 = seqNumber(written.get(1));
        assertEquals(seq1 + seg1.length, seq2);

        // 对第一段的确认是"进展"：不得触发重传
        written.clear();
        sendAck(seq1 + seg1.length);
        assertTrue("有进展的 ACK 不应触发重传", written.isEmpty());

        // 前两个 dup-ACK 只计数
        sendAck(seq1 + seg1.length);
        sendAck(seq1 + seg1.length);
        assertTrue("未达阈值的 dup-ACK 不应触发重传", written.isEmpty());

        // 第三个 dup-ACK 触发对最早未确认段（seg2）的快速重传
        sendAck(seq1 + seg1.length);
        assertEquals(1, written.size());
        assertEquals("重传段应为 PSH|ACK", 0x18, flags(written.get(0)));
        assertEquals("重传 seq 必须等于未确认段的 seq", seq2, seqNumber(written.get(0)));
        assertEquals("重传负载必须与原段一致", "bbbb",
                new String(payload(written.get(0))));
    }

    @Test
    public void progressAckResetsDupAckCount() {
        byte[] seg1 = "aaaa".getBytes();
        byte[] seg2 = "bbbb".getBytes();
        written.clear();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, seg1), writer());
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, seg2), writer());
        int seq1 = seqNumber(written.get(0));

        // 两个 dup-ACK 后出现进展 ACK：计数必须复位，其后还要再等满阈值才重传
        sendAck(seq1);
        sendAck(seq1);
        written.clear();
        sendAck(seq1 + seg1.length);
        sendAck(seq1 + seg1.length);
        assertTrue("进展后的两个 dup-ACK 不应触发重传", written.isEmpty());
    }

    @Test
    public void unackedOverflowAbortsConnectionWithRst() {
        written.clear();
        int overflowPayloads = 200;  // 192 段（滞留总量）后超过 256KB 上限
        for (int i = 0; i < overflowPayloads; i++) {
            byte[] payload = new byte[SEGMENT_SIZE];
            Arrays.fill(payload, (byte) ('a' + (i % 26)));
            router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, payload), writer());
        }
        // 窗口 65535 只装得下 48 段（65535/1360），其余滞留 pending；滞留总量
        // 在第 193 段越限 → RST。写出 = 48 段 + 1 个 RST。
        assertEquals(49, written.size());
        assertEquals(48, countWrittenFlags(0x18));
        assertEquals("滞留超限必须回 RST 明确失败", 0x14, flags(lastWritten()));
        assertEquals("本地模式同步发送 RESET 帧关闭本地会话", 1, countFrames(KcpFrame.TYPE_RESET));

        // 连接已拆除：后续数据不再写 TUN
        written.clear();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId,
                "late".getBytes()), writer());
        assertTrue("连接拆除后不应再有 TUN 写", written.isEmpty());
    }

    @Test
    public void windowExhaustionHoldsSegmentsUntilReopened() {
        written.clear();

        // 第一段正常送出；应用收下后内核缓冲满：ack 推进、窗口 0（零窗口的
        // 现实形态——内核已把数据收进缓冲，ack 前进而剩余窗口归零）
        byte[] seg1 = "aaaa".getBytes();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, seg1), writer());
        assertEquals(1, written.size());
        int seg1End = seqNumber(written.get(0)) + seg1.length;

        sendTcpWithWindow(0x10, SYN_SEQ + 5, seg1End, new byte[0], 0);
        written.clear();

        // 第二段：窗口为 0 → 滞留 pending，不写 TUN
        byte[] seg2 = "bbbb".getBytes();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, seg2), writer());
        assertTrue("窗口为 0 时不得写 TUN", written.isEmpty());

        // 窗口重新打开：同一确认上窗口扩大（RFC 793 采纳规则），滞留段按序送出
        sendTcpWithWindow(0x10, SYN_SEQ + 5, seg1End, new byte[0], 65535);
        assertEquals("窗口重开后滞留段必须冲刷", 1, written.size());
        assertEquals(0x18, flags(written.get(0)));
        assertEquals("滞留段的 seq 必须与登记时一致", seg1End, seqNumber(written.get(0)));
        assertEquals("bbbb", new String(payload(written.get(0))));
    }

    @Test
    public void windowShrinkAtSameAckIsIgnored() {
        written.clear();

        // 第一段送出前，应用在与当前基准相同的确认上通告收缩到 0：按 RFC 793
        // 不采纳（ack 不动时窗口不会被合理收缩），段照常可发
        byte[] seg1 = "aaaa".getBytes();
        sendTcpWithWindow(CLIENT_PORT, 0x10, SYN_SEQ + 5, serverInitialSeq() + 1, new byte[0], 0);
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId, seg1), writer());
        assertEquals("同一确认上的窗口收缩必须被忽略", 1, written.size());
        assertEquals(0x18, flags(written.get(0)));
    }

    @Test
    public void synWindowBaseIsAnchoredToServerSequenceSpace() {
        // 探测连接：读出当前服务器 ISN（每连接 +0x10000 递增），随后 RST 拆除
        sendTcpWithWindow(41001, 0x02, 555_000, 0, new byte[0], 65535);
        int s0 = seqNumber(lastWritten());
        sendTcpWithWindow(41001, 0x04, 555_001, s0 + 1, new byte[0], 65535);
        written.clear();
        frames.clear();

        // 目标连接：客户端 ISN 高于本连接服务器 ISN（s0+0x10000）128KB——
        // 若窗口基准被错误锚在客户端 ISN+1（另一序列空间的随机数），本连接
        // 的握手 ACK 会被判为"落后"而拒收，毒化的基准让 2000 字节窗口形同虚设
        int clientIsn = s0 + 0x30000;
        sendTcpWithWindow(41002, 0x02, clientIsn, 0, new byte[0], 2000);
        long targetId = frames.get(frames.size() - 1).getConnectionId();
        int s1 = seqNumber(lastWritten());
        assertEquals("第二个连接的服务器 ISN 应为探测连接 + 0x10000",
                s0 + 0x10000, s1);
        sendTcpWithWindow(41002, 0x10, clientIsn + 1, s1 + 1, new byte[0], 2000);
        written.clear();

        // 四段 1360 字节：2000 字节窗口只装得下第一段
        for (int i = 0; i < 4; i++) {
            router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, targetId,
                    new byte[SEGMENT_SIZE]), writer());
        }
        assertEquals("窗口基准必须锚在服务器序列空间：仅窗口内的第一段可发",
                1, written.size());
        assertEquals(0x18, flags(written.get(0)));
    }

    // ---- harness（与 PacketRouterHalfCloseTest 同构） ----

    private int serverInitialSeq() {
        // establish 的 SYN-ACK seq 即服务端初始序号
        return seqNumber(writtenSynAck);
    }

    private int countWrittenFlags(int expectedFlags) {
        int count = 0;
        for (byte[] packet : written) {
            if (flags(packet) == expectedFlags) {
                count++;
            }
        }
        return count;
    }

    private void sendAck(int ack) {
        sendTcp(0x10, SYN_SEQ + 5, ack, new byte[0]);
    }

    private void sendTcp(int flags, int seq, int ack, byte[] payload) {
        sendTcpWithWindow(CLIENT_PORT, flags, seq, ack, payload, 65535);
    }

    private void sendTcpWithWindow(int flags, int seq, int ack, byte[] payload, int window) {
        sendTcpWithWindow(CLIENT_PORT, flags, seq, ack, payload, window);
    }

    private void sendTcpWithWindow(int srcPort, int flags, int seq, int ack, byte[] payload, int window) {
        int totalLen = 40 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 6);
        buf.putShort((short) 0);
        buf.put(CLIENT_IP);
        buf.put(SERVER_IP);
        buf.putShort((short) srcPort);
        buf.putShort((short) SERVER_PORT);
        buf.putInt(seq);
        buf.putInt(ack);
        buf.put((byte) 0x50);
        buf.put((byte) flags);
        buf.putShort((short) window);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.put(payload);
        router.handleOutboundPacket(buf.array(), frames::add, writer());
    }

    private PacketRouter.WritePacketCallback writer() {
        return written::add;
    }

    private byte[] lastWritten() {
        return written.get(written.size() - 1);
    }

    private static int flags(byte[] packet) {
        return packet[33] & 0xFF;
    }

    private static int seqNumber(byte[] packet) {
        return ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN).getInt(24);
    }

    private static byte[] payload(byte[] packet) {
        return Arrays.copyOfRange(packet, 40, packet.length);
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
}
