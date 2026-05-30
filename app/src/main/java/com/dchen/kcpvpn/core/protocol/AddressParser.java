package com.dchen.kcpvpn.core.protocol;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

/**
 * 地址解析器 - 与 C++ address.cpp parse_address 一致
 * 从 SOCKS5 数据中解析地址和端口
 */
public class AddressParser {

    /**
     * 解析结果结构
     */
    public static class ParsedAddress {
        public String host;
        public int port;
        public int bytesConsumed;

        public ParsedAddress() {
            this.host = "";
            this.port = 0;
            this.bytesConsumed = 0;
        }

        public ParsedAddress(String host, int port, int bytesConsumed) {
            this.host = host;
            this.port = port;
            this.bytesConsumed = bytesConsumed;
        }
    }

    /**
     * 解析地址
     * @param data SOCKS5 数据
     * @param offset 起始偏移（ATYP 位置）
     * @param len 数据总长度（整个缓冲区的长度，不是减去 offset 后的长度）
     * @return 解析结果
     */
    public static ParsedAddress parse(byte[] data, int offset, int len) {
        if (data == null) {
            throw new IllegalArgumentException("Address data is null");
        }
        if (offset < 0 || len < 0 || len > data.length || offset >= len) {
            throw new IllegalArgumentException("Insufficient data for address type");
        }

        byte atyp = data[offset];
        ParsedAddress result = new ParsedAddress();

        switch (atyp) {
            case Socks5.SOCKS5_ATYP_IPV4:
                if (len < offset + 7) {
                    throw new IllegalArgumentException("Insufficient data for IPv4 address");
                }
                // & 0xFF 防止有符号字节产生负数
                result.host = String.format(Locale.US, "%d.%d.%d.%d",
                        data[offset + 1] & 0xFF, data[offset + 2] & 0xFF,
                        data[offset + 3] & 0xFF, data[offset + 4] & 0xFF);
                result.port = ((data[offset + 5] & 0xFF) << 8) | (data[offset + 6] & 0xFF);
                result.bytesConsumed = 7;
                break;

            case Socks5.SOCKS5_ATYP_DOMAIN:
                if (offset + 1 >= len) {
                    throw new IllegalArgumentException("Insufficient data for domain length");
                }
                int domainLen = data[offset + 1] & 0xFF;
                if (domainLen <= 0) {
                    throw new IllegalArgumentException("Invalid domain length: " + domainLen);
                }
                if (offset + 2 + domainLen + 2 > len) {
                    throw new IllegalArgumentException("Insufficient data for domain address");
                }
                result.host = new String(data, offset + 2, domainLen, StandardCharsets.UTF_8);
                int portOffset = offset + 2 + domainLen;
                result.port = ((data[portOffset] & 0xFF) << 8) | (data[portOffset + 1] & 0xFF);
                result.bytesConsumed = 4 + domainLen;
                break;

            case Socks5.SOCKS5_ATYP_IPV6:
                if (len < offset + 19) {
                    throw new IllegalArgumentException("Insufficient data for IPv6 address");
                }
                byte[] ipv6Bytes = Arrays.copyOfRange(data, offset + 1, offset + 17);
                result.host = formatIPv6(ipv6Bytes);
                result.port = ((data[offset + 17] & 0xFF) << 8) | (data[offset + 18] & 0xFF);
                result.bytesConsumed = 19;
                break;

            default:
                throw new IllegalArgumentException("Unsupported address type: " + atyp);
        }

        return result;
    }

    /**
     * 格式化 IPv6 地址（RFC-compliant 压缩）
     */
    private static String formatIPv6(byte[] bytes) {
        int[] segments = new int[8];
        for (int i = 0; i < 8; i++) {
            segments[i] = ((bytes[i * 2] & 0xFF) << 8) | (bytes[i * 2 + 1] & 0xFF);
        }

        // 找最长连续零段
        int bestStart = -1, bestLen = 0;
        int curStart = -1, curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (segments[i] == 0) {
                if (curStart == -1) curStart = i;
                curLen++;
                if (curLen > bestLen) {
                    bestStart = curStart;
                    bestLen = curLen;
                }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (bestLen >= 2 && i == bestStart) {
                sb.append(":");
                i += bestLen - 1;
                if (i == 7) sb.append(":");
                continue;
            }
            if (sb.length() > 0) sb.append(":");
            sb.append(Integer.toHexString(segments[i]));
        }

        return sb.toString();
    }

    /**
     * 从 ByteBuffer 解析地址
     */
    public static ParsedAddress parse(ByteBuffer buf) {
        if (buf == null || buf.remaining() < 1) {
            throw new IllegalArgumentException("Insufficient data for address type");
        }
        byte atyp = buf.get();

        ParsedAddress result = new ParsedAddress();

        switch (atyp) {
            case Socks5.SOCKS5_ATYP_IPV4:
                if (buf.remaining() < 6) {
                    throw new IllegalArgumentException("Insufficient data for IPv4 address");
                }
                byte[] ipv4Bytes = new byte[4];
                buf.get(ipv4Bytes);
                // & 0xFF 防止有符号字节产生负数
                result.host = String.format(Locale.US, "%d.%d.%d.%d",
                        ipv4Bytes[0] & 0xFF, ipv4Bytes[1] & 0xFF,
                        ipv4Bytes[2] & 0xFF, ipv4Bytes[3] & 0xFF);
                result.port = buf.getShort() & 0xFFFF;
                result.bytesConsumed = 7;
                break;

            case Socks5.SOCKS5_ATYP_DOMAIN:
                if (buf.remaining() < 1) {
                    throw new IllegalArgumentException("Insufficient data for domain length");
                }
                int domainLen = buf.get() & 0xFF;
                if (domainLen <= 0 || buf.remaining() < domainLen + 2) {
                    throw new IllegalArgumentException("Invalid or truncated domain address");
                }
                byte[] domainBytes = new byte[domainLen];
                buf.get(domainBytes);
                result.host = new String(domainBytes, StandardCharsets.US_ASCII);
                result.port = buf.getShort() & 0xFFFF;
                result.bytesConsumed = 4 + domainLen;
                break;

            case Socks5.SOCKS5_ATYP_IPV6:
                if (buf.remaining() < 18) {
                    throw new IllegalArgumentException("Insufficient data for IPv6 address");
                }
                byte[] ipv6Bytes = new byte[16];
                buf.get(ipv6Bytes);
                result.host = formatIPv6(ipv6Bytes);
                result.port = buf.getShort() & 0xFFFF;
                result.bytesConsumed = 19;
                break;

            default:
                throw new IllegalArgumentException("Unsupported address type: " + atyp);
        }

        return result;
    }
}
