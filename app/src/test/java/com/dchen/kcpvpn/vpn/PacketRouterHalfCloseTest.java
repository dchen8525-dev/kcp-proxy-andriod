package com.dchen.kcpvpn.vpn;

import com.dchen.kcpvpn.core.protocol.KcpFrame;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * 半关闭时序：本地 FIN 只回 ACK 并保留会话，我们的 FIN 只在远端关闭时发出一次。
 */
public class PacketRouterHalfCloseTest {
    private static final byte[] CLIENT_IP = {10, 0, 2, 15};
    private static final byte[] SERVER_IP = {(byte) 93, (byte) 184, (byte) 216, 34};
    private static final int CLIENT_PORT = 41000;
    private static final int SERVER_PORT = 443;
    private static final int SYN_SEQ = 1000;

    private final List<byte[]> written = new ArrayList<>();
    private final List<KcpFrame> frames = new ArrayList<>();
    private PacketRouter router;
    private long connectionId;

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
    public void localFinAcksAndDefersOurFinUntilRemoteClose() {
        establish();
        assertEquals(0x12, flags(written.get(0)));

        sendTcp(0x11, SYN_SEQ + 4, serverNextSeq(), new byte[0]);
        assertEquals("本地 FIN 之后只能回 ACK，FIN 必须延后", 0x10, flags(lastWritten()));
        assertEquals(SYN_SEQ + 5, ackNumber(lastWritten()));
        assertEquals("半关闭走 TYPE_FIN（服务器端 shutdownOutput 保留目标响应）",
                1, countFrames(KcpFrame.TYPE_FIN));
        assertEquals("半关闭前不得发出 FIN", 0, countWrittenFlags(0x11));

        written.clear();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId,
                "tail".getBytes(StandardCharsets.US_ASCII)), writer());
        assertEquals("排空期间的远端数据必须写入 TUN", 1, written.size());
        assertEquals(0x18, flags(written.get(0)));

        written.clear();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_CLOSE, connectionId, null), writer());
        assertEquals(1, written.size());
        assertEquals("远端关闭时才发出唯一的 FIN", 0x11, flags(written.get(0)));

        written.clear();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_CLOSE, connectionId, null), writer());
        assertTrue("连接已回收，不应有第二个 FIN", written.isEmpty());
    }

    @Test
    public void repeatedLocalFinSendsCloseFrameOnlyOnce() {
        establish();
        sendTcp(0x11, SYN_SEQ + 4, serverNextSeq(), new byte[0]);
        sendTcp(0x11, SYN_SEQ + 4, serverNextSeq(), new byte[0]);

        assertEquals(1, countFrames(KcpFrame.TYPE_FIN));
        assertEquals(0x10, flags(lastWritten()));
    }

    @Test
    public void serverFinWritesAppFinAndKeepsConnectionUntilAppFin() {
        establish();
        int expectedServerNextSeq = serverNextSeq();
        written.clear();

        // 远端先 FIN：应用收到 FIN（0x11），连接保留等待应用方向收尾
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_FIN, connectionId, null), writer());
        assertEquals(1, written.size());
        assertEquals("远端 FIN 必须以 FIN|ACK 写给应用", 0x11, flags(written.get(0)));

        // 应用随后 FIN：回 ACK 并把 FIN 转告远端，双方都完成后整体拆除
        sendTcp(0x11, SYN_SEQ + 4, expectedServerNextSeq, new byte[0]);
        assertEquals(1, countFrames(KcpFrame.TYPE_FIN));

        written.clear();
        router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId,
                "late".getBytes(StandardCharsets.US_ASCII)), writer());
        assertTrue("双方 FIN 完成后连接已回收", written.isEmpty());
    }

    private void establish() {
        sendTcp(0x02, SYN_SEQ, 0, new byte[0]);
        connectionId = frames.get(0).getConnectionId();
        int serverInitialSeq = seqNumber(lastWritten());
        sendTcp(0x10, SYN_SEQ + 1, serverInitialSeq + 1, new byte[0]);
        sendTcp(0x18, SYN_SEQ + 1, serverInitialSeq + 1, "GET".getBytes(StandardCharsets.US_ASCII));
    }

    private int serverNextSeq() {
        // written[1] 是数据段的 ACK，其 seq 即服务端的下一个序号
        return seqNumber(written.get(1));
    }

    private void sendTcp(int flags, int seq, int ack, byte[] payload) {
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

    private static int ackNumber(byte[] packet) {
        return ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN).getInt(28);
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
