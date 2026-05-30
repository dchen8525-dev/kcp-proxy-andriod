package com.dchen.kcpvpn.vpn.cppremote;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class CppSocks5RequestBuilder {
    public static final int SOCKS5_RESPONSE_INVALID = -1;
    public static final int SOCKS5_RESPONSE_INCOMPLETE = -2;

    private CppSocks5RequestBuilder() {
    }

    public static byte[] buildIpv4Connect(byte[] dstAddr, int dstPort) {
        if (dstAddr == null || dstAddr.length != 4) {
            throw new IllegalArgumentException("CPP_REMOTE only supports IPv4 SOCKS5 CONNECT");
        }
        ByteBuffer buf = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x05);
        buf.put((byte) 0x01);
        buf.put((byte) 0x00);
        buf.put((byte) 0x01);
        buf.put(dstAddr);
        buf.putShort((short) dstPort);
        return buf.array();
    }

    public static int socks5ResponseLength(byte[] data) {
        if (data == null || data.length == 0) {
            return SOCKS5_RESPONSE_INCOMPLETE;
        }
        if (data[0] != 0x05) {
            return SOCKS5_RESPONSE_INVALID;
        }
        if (data.length < 4) {
            return SOCKS5_RESPONSE_INCOMPLETE;
        }
        int atyp = data[3] & 0xFF;
        if (atyp == 0x01) {
            return data.length >= 10 ? 10 : SOCKS5_RESPONSE_INCOMPLETE;
        }
        if (atyp == 0x04) {
            return data.length >= 22 ? 22 : SOCKS5_RESPONSE_INCOMPLETE;
        }
        if (atyp == 0x03) {
            if (data.length < 5) {
                return SOCKS5_RESPONSE_INCOMPLETE;
            }
            int domainLen = data[4] & 0xFF;
            int total = 5 + domainLen + 2;
            return data.length >= total ? total : SOCKS5_RESPONSE_INCOMPLETE;
        }
        return SOCKS5_RESPONSE_INVALID;
    }
}
