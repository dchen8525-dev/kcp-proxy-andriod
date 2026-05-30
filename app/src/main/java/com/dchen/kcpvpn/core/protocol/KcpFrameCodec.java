package com.dchen.kcpvpn.core.protocol;

import com.dchen.kcpvpn.log.Logger;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Big-endian KCP frame encoder/decoder. Decoder keeps partial data between calls.
 */
public class KcpFrameCodec {
    private static final byte MAGIC_1 = 0x4B;
    private static final byte MAGIC_2 = 0x50;
    private static final byte VERSION = 1;
    private static final int HEADER_LEN = 16;
    private static final int MAX_PAYLOAD_LEN = 1024 * 1024;
    private static final int MAX_PENDING_LEN = MAX_PAYLOAD_LEN + HEADER_LEN;

    private final String logModule;
    private final ByteArrayOutputStream pending = new ByteArrayOutputStream();

    public KcpFrameCodec(String logModule) {
        this.logModule = logModule;
    }

    public static byte[] encode(KcpFrame frame) {
        byte[] payload = frame.getPayload();
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_LEN + payload.length);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.put(MAGIC_1);
        buffer.put(MAGIC_2);
        buffer.put(VERSION);
        buffer.put(frame.getFrameType());
        buffer.putLong(frame.getConnectionId());
        buffer.putInt(payload.length);
        buffer.put(payload);
        return buffer.array();
    }

    public synchronized List<KcpFrame> decode(byte[] data) {
        List<KcpFrame> frames = new ArrayList<>();
        if (data == null || data.length == 0) {
            return frames;
        }

        if (pending.size() + data.length > MAX_PENDING_LEN) {
            int dropped = pending.size() + data.length;
            pending.reset();
            Logger.warning(logModule, "KCP frame decode error: pending buffer overflow, dropped="
                    + dropped);
            return frames;
        }

        pending.write(data, 0, data.length);
        byte[] buf = pending.toByteArray();
        int pos = 0;

        while (buf.length - pos >= HEADER_LEN) {
            if (buf[pos] != MAGIC_1 || buf[pos + 1] != MAGIC_2) {
                int next = findNextMagic(buf, pos + 1);
                Logger.warning(logModule, "KCP frame decode error: invalid magic, dropped="
                        + ((next >= 0 ? next : buf.length) - pos));
                if (next < 0) {
                    pos = buf.length;
                    break;
                }
                pos = next;
                continue;
            }

            byte version = buf[pos + 2];
            if (version != VERSION) {
                Logger.warning(logModule, "KCP frame decode error: invalid version=" + (version & 0xFF));
                pos += 2;
                continue;
            }

            byte frameType = buf[pos + 3];
            if (!isValidFrameType(frameType)) {
                Logger.warning(logModule, "KCP frame decode error: invalid frameType=" + (frameType & 0xFF));
                pos += 2;
                continue;
            }

            ByteBuffer header = ByteBuffer.wrap(buf, pos + 4, 12).order(ByteOrder.BIG_ENDIAN);
            long connectionId = header.getLong();
            int payloadLength = header.getInt();
            if (payloadLength < 0 || payloadLength > MAX_PAYLOAD_LEN) {
                Logger.warning(logModule, "KCP frame decode error: invalid payloadLength="
                        + payloadLength + ", connectionId=" + connectionId);
                pos += 2;
                continue;
            }

            int frameLen = HEADER_LEN + payloadLength;
            if (buf.length - pos < frameLen) {
                break;
            }

            byte[] payload = new byte[payloadLength];
            if (payloadLength > 0) {
                System.arraycopy(buf, pos + HEADER_LEN, payload, 0, payloadLength);
            }

            frames.add(new KcpFrame(frameType, connectionId, payload));
            pos += frameLen;
        }

        pending.reset();
        if (pos < buf.length) {
            pending.write(buf, pos, buf.length - pos);
        }

        return frames;
    }

    private static int findNextMagic(byte[] buf, int start) {
        for (int i = start; i < buf.length - 1; i++) {
            if (buf[i] == MAGIC_1 && buf[i + 1] == MAGIC_2) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isValidFrameType(byte frameType) {
        return frameType == KcpFrame.TYPE_OPEN
                || frameType == KcpFrame.TYPE_DATA
                || frameType == KcpFrame.TYPE_CLOSE
                || frameType == KcpFrame.TYPE_RESET
                || frameType == KcpFrame.TYPE_UDP_DATAGRAM
                || frameType == KcpFrame.TYPE_HELLO
                || frameType == KcpFrame.TYPE_HELLO_ACK
                || frameType == KcpFrame.TYPE_PING
                || frameType == KcpFrame.TYPE_PONG;
    }
}
