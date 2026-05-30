package com.dchen.kcpvpn.core.protocol;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KcpFrameCodecTest {
    @Test
    public void decodesOneCompleteFrame() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] encoded = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_DATA, 7L, new byte[]{1, 2, 3}));

        List<KcpFrame> frames = codec.decode(encoded);

        assertEquals(1, frames.size());
        assertEquals(KcpFrame.TYPE_DATA, frames.get(0).getFrameType());
        assertEquals(7L, frames.get(0).getConnectionId());
        assertEquals(3, frames.get(0).getPayloadLength());
    }

    @Test
    public void decodesTwoFramesInOneBuffer() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] first = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_OPEN, 1L, new byte[]{1}));
        byte[] second = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_CLOSE, 2L, new byte[0]));
        byte[] both = new byte[first.length + second.length];
        System.arraycopy(first, 0, both, 0, first.length);
        System.arraycopy(second, 0, both, first.length, second.length);

        List<KcpFrame> frames = codec.decode(both);

        assertEquals(2, frames.size());
        assertEquals(1L, frames.get(0).getConnectionId());
        assertEquals(2L, frames.get(1).getConnectionId());
    }

    @Test
    public void decodesSplitFrame() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] encoded = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_DATA, 9L, new byte[]{4, 5}));
        byte[] part1 = new byte[10];
        byte[] part2 = new byte[encoded.length - part1.length];
        System.arraycopy(encoded, 0, part1, 0, part1.length);
        System.arraycopy(encoded, part1.length, part2, 0, part2.length);

        assertTrue(codec.decode(part1).isEmpty());
        assertEquals(1, codec.decode(part2).size());
    }

    @Test
    public void dropsInvalidMagicAndRecovers() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] invalid = new byte[]{0, 1, 2, 3};
        byte[] valid = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_RESET, 3L, new byte[0]));
        byte[] combined = new byte[invalid.length + valid.length];
        System.arraycopy(invalid, 0, combined, 0, invalid.length);
        System.arraycopy(valid, 0, combined, invalid.length, valid.length);

        assertEquals(1, codec.decode(combined).size());
    }

    @Test
    public void rejectsInvalidVersion() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] encoded = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_DATA, 1L, new byte[0]));
        encoded[2] = 99;

        assertTrue(codec.decode(encoded).isEmpty());
    }

    @Test
    public void rejectsInvalidFrameType() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] encoded = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_DATA, 1L, new byte[0]));
        encoded[3] = 42;

        assertTrue(codec.decode(encoded).isEmpty());
    }

    @Test
    public void rejectsOversizedPayloadLength() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x4B);
        buf.put((byte) 0x50);
        buf.put((byte) 1);
        buf.put(KcpFrame.TYPE_DATA);
        buf.putLong(1L);
        buf.putInt(1024 * 1024 + 1);

        assertTrue(codec.decode(buf.array()).isEmpty());
    }

    @Test
    public void keepsTruncatedPayloadPending() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] encoded = KcpFrameCodec.encode(new KcpFrame(KcpFrame.TYPE_DATA, 1L, new byte[]{1, 2, 3}));
        byte[] truncated = new byte[encoded.length - 1];
        System.arraycopy(encoded, 0, truncated, 0, truncated.length);

        assertTrue(codec.decode(truncated).isEmpty());
        assertEquals(1, codec.decode(new byte[]{3}).size());
    }

    @Test
    public void randomBytesDoNotCrash() {
        KcpFrameCodec codec = new KcpFrameCodec("test");
        byte[] random = new byte[4096];
        for (int i = 0; i < random.length; i++) {
            random[i] = (byte) (i * 31);
        }

        assertTrue(codec.decode(random).isEmpty());
    }
}
