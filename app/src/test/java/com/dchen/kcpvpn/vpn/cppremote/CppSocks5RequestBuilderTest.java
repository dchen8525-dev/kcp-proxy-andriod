package com.dchen.kcpvpn.vpn.cppremote;

import org.junit.Test;

import java.net.InetAddress;

import static org.junit.Assert.assertEquals;

/**
 * SOCKS5 CONNECT 请求的 ATYP 选择：4 字节 → 0x01，16 字节 → 0x04。
 * 服务端 address.cpp 对两种 ATYP 都有解析分支，这里只保证客户端把字节摆对。
 */
public class CppSocks5RequestBuilderTest {

    @Test
    public void ipv4ConnectUsesAtyp01() {
        byte[] request = CppSocks5RequestBuilder.buildConnect(new byte[]{10, 0, 0, 5}, 443);

        assertEquals(10, request.length);
        assertEquals(0x05, request[0] & 0xFF);
        assertEquals(0x01, request[1] & 0xFF);
        assertEquals(0x00, request[2] & 0xFF);
        assertEquals(0x01, request[3] & 0xFF);
        assertEquals(10, request[4] & 0xFF);
        assertEquals(0, request[5] & 0xFF);
        assertEquals(0, request[6] & 0xFF);
        assertEquals(5, request[7] & 0xFF);
        assertEquals(443, ((request[8] & 0xFF) << 8) | (request[9] & 0xFF));
    }

    @Test
    public void ipv6ConnectUsesAtyp04() throws Exception {
        byte[] addr = InetAddress.getByName("2001:db8::1").getAddress();
        assertEquals(16, addr.length);

        byte[] request = CppSocks5RequestBuilder.buildConnect(addr, 8443);

        assertEquals("ATYP=0x04 的请求是 4 + 16 + 2", 22, request.length);
        assertEquals(0x05, request[0] & 0xFF);
        assertEquals(0x01, request[1] & 0xFF);
        assertEquals(0x00, request[2] & 0xFF);
        assertEquals(0x04, request[3] & 0xFF);
        for (int i = 0; i < 16; i++) {
            assertEquals("地址字节必须原样搬运 offset=" + i, addr[i], request[4 + i]);
        }
        assertEquals(8443, ((request[20] & 0xFF) << 8) | (request[21] & 0xFF));
    }

    @Test(expected = IllegalArgumentException.class)
    public void unknownAddressLengthIsRejected() {
        CppSocks5RequestBuilder.buildConnect(new byte[8], 80);
    }

    @Test(expected = IllegalArgumentException.class)
    public void missingAddressIsRejected() {
        CppSocks5RequestBuilder.buildConnect(null, 80);
    }
}
