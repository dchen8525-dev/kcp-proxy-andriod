package com.dchen.kcpvpn.core.protocol;

/**
 * SOCKS5 请求结构 - 与 C++ socks5.hpp SOCKS5Request 一致
 */
public class Socks5Request {
    public byte cmd;
    public String host;
    public int port;
    public byte atyp;

    public Socks5Request() {
        this.cmd = Socks5.SOCKS5_CMD_CONNECT;
        this.host = "";
        this.port = 0;
        this.atyp = Socks5.SOCKS5_ATYP_DOMAIN;
    }

    public Socks5Request(byte cmd, String host, int port) {
        this.cmd = cmd;
        this.host = host;
        this.port = port;
        this.atyp = AddressEncoder.getAddressType(host);
    }

    /**
     * 构建请求字节数组
     * 格式: [VER] + [CMD] + [RSV] + [ATYP] + [ADDR] + [PORT]
     */
    public byte[] build() {
        byte[] addr = AddressEncoder.encode(host, port);
        byte[] result = new byte[3 + addr.length];

        result[0] = Socks5.SOCKS5_VERSION;
        result[1] = cmd;
        result[2] = 0x00;  // RSV

        System.arraycopy(addr, 0, result, 3, addr.length);

        return result;
    }

    /**
     * 构建 CONNECT 请求
     */
    public static byte[] buildConnectRequest(String host, int port) {
        return new Socks5Request(Socks5.SOCKS5_CMD_CONNECT, host, port).build();
    }
}