package com.dchen.kcpvpn.vpn.cppremote;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class CppSocks5RequestBuilder {
    public static final int SOCKS5_RESPONSE_INVALID = -1;
    public static final int SOCKS5_RESPONSE_INCOMPLETE = -2;

    private CppSocks5RequestBuilder() {
    }

    /**
     * 按目标地址长度选择 ATYP：4 字节 → 0x01（IPv4），16 字节 → 0x04（IPv6）。
     * 服务端 address.cpp / socks5.cpp 两条分支都支持，所以调用方不必关心地址族。
     */
    public static byte[] buildConnect(byte[] dstAddr, int dstPort) {
        if (dstAddr == null) {
            throw new IllegalArgumentException("missing SOCKS5 CONNECT destination address");
        }
        if (dstAddr.length == 4) {
            return buildIpv4Connect(dstAddr, dstPort);
        }
        if (dstAddr.length == 16) {
            return buildIpv6Connect(dstAddr, dstPort);
        }
        throw new IllegalArgumentException("unsupported SOCKS5 CONNECT address length: " + dstAddr.length);
    }

    public static byte[] buildIpv4Connect(byte[] dstAddr, int dstPort) {
        if (dstAddr == null || dstAddr.length != 4) {
            throw new IllegalArgumentException("IPv4 SOCKS5 CONNECT requires a 4-byte address");
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

    public static byte[] buildIpv6Connect(byte[] dstAddr, int dstPort) {
        if (dstAddr == null || dstAddr.length != 16) {
            throw new IllegalArgumentException("IPv6 SOCKS5 CONNECT requires a 16-byte address");
        }
        ByteBuffer buf = ByteBuffer.allocate(22).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x05);
        buf.put((byte) 0x01);
        buf.put((byte) 0x00);
        buf.put((byte) 0x04);
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
