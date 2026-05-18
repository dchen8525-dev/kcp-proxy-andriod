package com.example.kcpvpn.core.protocol;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * 地址编码器 - 与 C++ address.cpp encode_address 一致
 * 支持 IPv4、IPv6、Domain 三种地址类型
 * 注意：域名不做 DNS 解析，直接编码为 ATYP_DOMAIN，让代理服务器解析
 */
public class AddressEncoder {

    /**
     * 判断字符串是否是合法的 IPv4 字面地址
     */
    private static boolean isIPv4Literal(String host) {
        if (host == null || host.isEmpty()) return false;
        String[] parts = host.split("\\.");
        if (parts.length != 4) return false;
        for (String part : parts) {
            try {
                int val = Integer.parseInt(part);
                if (val < 0 || val > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /**
     * 判断字符串是否是合法的 IPv6 字面地址
     */
    private static boolean isIPv6Literal(String host) {
        return host != null && host.contains(":");
    }

    /**
     * 编码地址
     * @param host 主机名或 IP 地址
     * @param port 端口号
     * @return 编码后的字节数组
     */
    public static byte[] encode(String host, int port) {
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Host cannot be empty");
        }

        byte[] result;

        // 只对字面 IP 地址编码为 ATYP_IPV4/ATYP_IPV6
        // 域名不做 DNS 解析，直接编码为 ATYP_DOMAIN
        if (isIPv4Literal(host)) {
            // IPv4 编码
            try {
                InetAddress addr = InetAddress.getByName(host);
                result = new byte[7];  // ATYP(1) + IPv4(4) + PORT(2)
                result[0] = Socks5.SOCKS5_ATYP_IPV4;
                byte[] ipBytes = addr.getAddress();
                System.arraycopy(ipBytes, 0, result, 1, 4);
                result[5] = (byte) ((port >> 8) & 0xFF);
                result[6] = (byte) (port & 0xFF);
            } catch (UnknownHostException e) {
                result = encodeDomain(host, port);
            }
        } else if (isIPv6Literal(host)) {
            // IPv6 编码
            try {
                InetAddress addr = InetAddress.getByName(host);
                if (addr instanceof Inet6Address) {
                    result = new byte[19];  // ATYP(1) + IPv6(16) + PORT(2)
                    result[0] = Socks5.SOCKS5_ATYP_IPV6;
                    byte[] ipBytes = addr.getAddress();
                    System.arraycopy(ipBytes, 0, result, 1, 16);
                    result[17] = (byte) ((port >> 8) & 0xFF);
                    result[18] = (byte) (port & 0xFF);
                } else {
                    result = encodeDomain(host, port);
                }
            } catch (UnknownHostException e) {
                result = encodeDomain(host, port);
            }
        } else {
            // 域名编码 — 不做 DNS 解析
            result = encodeDomain(host, port);
        }

        return result;
    }

    /**
     * 编码域名 — 使用 byte 长度而非 char 长度
     */
    private static byte[] encodeDomain(String host, int port) {
        byte[] domainBytes = host.getBytes(StandardCharsets.US_ASCII);
        if (domainBytes.length > 255) {
            throw new IllegalArgumentException("Domain name too long");
        }

        byte[] result = new byte[4 + domainBytes.length];  // ATYP(1) + LEN(1) + DOMAIN + PORT(2)
        result[0] = Socks5.SOCKS5_ATYP_DOMAIN;
        result[1] = (byte) domainBytes.length;  // 用 byte 长度而非 char 长度
        System.arraycopy(domainBytes, 0, result, 2, domainBytes.length);
        result[2 + domainBytes.length] = (byte) ((port >> 8) & 0xFF);
        result[3 + domainBytes.length] = (byte) (port & 0xFF);

        return result;
    }

    /**
     * 获取地址类型 — 不做 DNS 解析
     */
    public static byte getAddressType(String host) {
        if (isIPv4Literal(host)) {
            return Socks5.SOCKS5_ATYP_IPV4;
        } else if (isIPv6Literal(host)) {
            return Socks5.SOCKS5_ATYP_IPV6;
        }
        return Socks5.SOCKS5_ATYP_DOMAIN;
    }
}