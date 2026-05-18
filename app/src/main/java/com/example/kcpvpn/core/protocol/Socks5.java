package com.example.kcpvpn.core.protocol;

/**
 * SOCKS5 常量定义 - 与 C++ config.hpp SOCKS5 常量一致
 */
public class Socks5 {
    // SOCKS5 版本
    public static final byte SOCKS5_VERSION = 0x05;

    // 认证方法
    public static final byte SOCKS5_AUTH_NONE = 0x00;
    public static final byte SOCKS5_AUTH_NO_ACCEPTABLE = (byte) 0xFF;

    // 命令类型
    public static final byte SOCKS5_CMD_CONNECT = 0x01;
    public static final byte SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

    // 地址类型
    public static final byte SOCKS5_ATYP_IPV4 = 0x01;
    public static final byte SOCKS5_ATYP_DOMAIN = 0x03;
    public static final byte SOCKS5_ATYP_IPV6 = 0x04;

    // 响应码
    public static final byte SOCKS5_REPLY_SUCCEEDED = 0x00;
    public static final byte SOCKS5_REPLY_GENERAL_FAILURE = 0x01;
    public static final byte SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03;
    public static final byte SOCKS5_REPLY_HOST_UNREACHABLE = 0x04;
    public static final byte SOCKS5_REPLY_CONNECTION_REFUSED = 0x05;
    public static final byte SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07;
    public static final byte SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
}