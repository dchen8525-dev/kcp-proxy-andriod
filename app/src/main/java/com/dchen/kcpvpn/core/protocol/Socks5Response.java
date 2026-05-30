package com.dchen.kcpvpn.core.protocol;

/**
 * SOCKS5 响应结构 - 与 C++ socks5.hpp SOCKS5Response 一致
 */
public class Socks5Response {
    public byte reply;
    public String host;
    public int port;

    public Socks5Response() {
        this.reply = Socks5.SOCKS5_REPLY_GENERAL_FAILURE;
        this.host = "";
        this.port = 0;
    }

    public Socks5Response(byte reply, String host, int port) {
        this.reply = reply;
        this.host = host;
        this.port = port;
    }

    /**
     * 构建响应字节数组
     * 格式: [VER] + [REP] + [RSV] + [ATYP] + [BND.ADDR] + [BND.PORT]
     */
    public byte[] build() {
        byte[] result;

        if (host == null || host.isEmpty()) {
            // RFC 1928 §6: 错误时使用 0.0.0.0:0
            result = new byte[10];
            result[0] = Socks5.SOCKS5_VERSION;
            result[1] = reply;
            result[2] = 0x00;  // RSV
            result[3] = Socks5.SOCKS5_ATYP_IPV4;
            // 4字节 IPv4 地址 (0.0.0.0)
            result[4] = 0;
            result[5] = 0;
            result[6] = 0;
            result[7] = 0;
            // 2字节端口 (0)
            result[8] = 0;
            result[9] = 0;
        } else {
            byte[] addr = AddressEncoder.encode(host, port);
            result = new byte[3 + addr.length];
            result[0] = Socks5.SOCKS5_VERSION;
            result[1] = reply;
            result[2] = 0x00;  // RSV
            System.arraycopy(addr, 0, result, 3, addr.length);
        }

        return result;
    }

    /**
     * 解析响应
     * @param data 响应数据
     * @param offset 起始偏移（VER 位置）
     * @param len 数据总长度
     */
    public static Socks5Response parse(byte[] data, int offset, int len) {
        if (len < 10) {
            return new Socks5Response(Socks5.SOCKS5_REPLY_GENERAL_FAILURE, "", 0);
        }

        // 验证 VER 字节
        if (data[offset] != Socks5.SOCKS5_VERSION) {
            return new Socks5Response(Socks5.SOCKS5_REPLY_GENERAL_FAILURE, "", 0);
        }

        Socks5Response resp = new Socks5Response();
        resp.reply = data[offset + 1];

        // 传完整 len 给 AddressParser，让它从 offset+3 开始解析
        // AddressParser 内部会用 offset+3 与 len 做比较
        AddressParser.ParsedAddress addr = AddressParser.parse(data, offset + 3, len);
        resp.host = addr.host;
        resp.port = addr.port;

        return resp;
    }

    /**
     * 构建成功响应
     */
    public static byte[] buildSuccessResponse() {
        return new Socks5Response(Socks5.SOCKS5_REPLY_SUCCEEDED, "0.0.0.0", 0).build();
    }

    /**
     * 构建失败响应
     */
    public static byte[] buildFailureResponse(byte replyCode) {
        return new Socks5Response(replyCode, "", 0).build();
    }
}