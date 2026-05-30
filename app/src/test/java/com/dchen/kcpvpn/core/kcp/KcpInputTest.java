package com.dchen.kcpvpn.core.kcp;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

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
