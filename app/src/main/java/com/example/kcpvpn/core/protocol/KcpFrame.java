package com.example.kcpvpn.core.protocol;

/**
 * Application frame carried inside KCP payloads.
 */
public class KcpFrame {
    public static final byte TYPE_OPEN = 1;
    public static final byte TYPE_DATA = 2;
    public static final byte TYPE_CLOSE = 3;
    public static final byte TYPE_RESET = 4;
    public static final byte TYPE_UDP_DATAGRAM = 5;
    public static final byte TYPE_HELLO = 100;
    public static final byte TYPE_HELLO_ACK = 101;
    public static final byte TYPE_PING = 102;
    public static final byte TYPE_PONG = 103;

    private final byte frameType;
    private final long connectionId;
    private final byte[] payload;

    public KcpFrame(byte frameType, long connectionId, byte[] payload) {
        this.frameType = frameType;
        this.connectionId = connectionId;
        this.payload = payload == null ? new byte[0] : payload;
    }

    public byte getFrameType() {
        return frameType;
    }

    public long getConnectionId() {
        return connectionId;
    }

    public byte[] getPayload() {
        return payload;
    }

    public int getPayloadLength() {
        return payload.length;
    }

    public static String frameTypeName(byte frameType) {
        switch (frameType) {
            case TYPE_OPEN:
                return "OPEN";
            case TYPE_DATA:
                return "DATA";
            case TYPE_CLOSE:
                return "CLOSE";
            case TYPE_RESET:
                return "RESET";
            case TYPE_UDP_DATAGRAM:
                return "UDP_DATAGRAM";
            case TYPE_HELLO:
                return "HELLO";
            case TYPE_HELLO_ACK:
                return "HELLO_ACK";
            case TYPE_PING:
                return "PING";
            case TYPE_PONG:
                return "PONG";
            default:
                return "UNKNOWN(" + (frameType & 0xFF) + ")";
        }
    }
}
