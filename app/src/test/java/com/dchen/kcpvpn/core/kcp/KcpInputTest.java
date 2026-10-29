package com.dchen.kcpvpn.core.kcp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

public class KcpInputTest {

    @Test
    public void inputConsumesPayloadForOutOfWindowPush() {
        byte[] skippedPayload = new byte[]{0x45, 0x46, 0x47, 0x48};
        byte[] validPayload = new byte[]{1, 2, 3};

        ByteBuffer packet = ByteBuffer.allocate(
                Segment.HEADER_SIZE + skippedPayload.length
                        + Segment.HEADER_SIZE + validPayload.length);
        packet.order(ByteOrder.LITTLE_ENDIAN);
        putPush(packet, KcpConfig.DEFAULT_CONV, 512, 0, skippedPayload);
        putPush(packet, KcpConfig.DEFAULT_CONV, 0, 0, validPayload);

        Kcp kcp = new Kcp(KcpConfig.DEFAULT_CONV);
        assertEquals(0, kcp.input(packet.array()));

        byte[] received = new byte[validPayload.length];
        assertEquals(validPayload.length, kcp.recv(received));
        assertArrayEquals(validPayload, received);
    }

    /**
     * 零长度 PUSH（只能来自异常/恶意对端）必须被 ACK 后丢弃、绝不入队：
     * 若入队，peekSize()==0 会被投递循环当"没有数据"，该段永远无法消费，
     * 接收队列涨满后会话无声死锁。
     */
    @Test
    public void zeroLengthPushIsAckedButNotQueued() {
        byte[] validPayload = new byte[]{7, 8, 9};

        ByteBuffer packet = ByteBuffer.allocate(
                Segment.HEADER_SIZE + Segment.HEADER_SIZE + validPayload.length);
        packet.order(ByteOrder.LITTLE_ENDIAN);
        putPush(packet, KcpConfig.DEFAULT_CONV, 0, 0, new byte[0]);
        putPush(packet, KcpConfig.DEFAULT_CONV, 1, 0, validPayload);

        Kcp kcp = new Kcp(KcpConfig.DEFAULT_CONV);
        assertEquals(0, kcp.input(packet.array()));

        // 唯一可消费的数据是 sn=1 的正常段；sn=0 的零长度段没有堵住接收路径
        byte[] received = new byte[validPayload.length];
        assertEquals(validPayload.length, kcp.recv(received));
        assertArrayEquals(validPayload, received);
        assertEquals(-1, kcp.recv(received));
    }

    /**
     * 超前（sn &gt; rcv_nxt）的零长度 PUSH 不能被 ACK，也不能被当作已消费：
     * ACK 会让对端停止重传该 sn，序号空洞永远填不上；必须等它按序到达时
     * 消费并推进 rcv_nxt，其后的数据才能继续交付。
     */
    @Test
    public void aheadZeroLengthPushDoesNotConsumeSequenceSpace() {
        byte[] payload2 = new byte[]{10, 11, 12};

        Kcp kcp = new Kcp(KcpConfig.DEFAULT_CONV);

        // 超前的零长度 sn=1：不入队、不推进
        ByteBuffer zero = onePush(1, new byte[0]);
        assertEquals(0, kcp.input(zero.array()));
        // 数据 sn=2：因 sn=1 未消费而滞留
        ByteBuffer data2 = onePush(2, payload2);
        assertEquals(0, kcp.input(data2.array()));

        byte[] scratch = new byte[16];
        assertEquals(-1, kcp.recv(scratch));

        // 按序的零长度 sn=0：消费，rcv_nxt 推进到 1
        assertEquals(0, kcp.input(onePush(0, new byte[0]).array()));
        // 此刻 sn=1 仍是空洞：sn=2 仍不可交付
        assertEquals(-1, kcp.recv(scratch));

        // 对端重传的零长度 sn=1：按序消费，rcv_nxt 推进到 2，sn=2 解锁
        assertEquals(0, kcp.input(onePush(1, new byte[0]).array()));
        assertEquals(payload2.length, kcp.recv(scratch));
        assertArrayEquals(payload2, java.util.Arrays.copyOf(scratch, payload2.length));
        assertEquals(-1, kcp.recv(scratch));
    }

    private static ByteBuffer onePush(int sn, byte[] payload) {
        ByteBuffer packet = ByteBuffer.allocate(Segment.HEADER_SIZE + payload.length);
        packet.order(ByteOrder.LITTLE_ENDIAN);
        putPush(packet, KcpConfig.DEFAULT_CONV, sn, 0, payload);
        packet.flip();
        return packet;
    }

    private static void putPush(ByteBuffer packet, int conv, int sn, int una, byte[] payload) {
        packet.putInt(conv);
        packet.put((byte) Segment.IKCP_CMD_PUSH);
        packet.put((byte) 0);
        packet.putShort((short) KcpConfig.KCP_RCVWND);
        packet.putInt(1234);
        packet.putInt(sn);
        packet.putInt(una);
        packet.putInt(payload.length);
        packet.put(payload);
    }
}
