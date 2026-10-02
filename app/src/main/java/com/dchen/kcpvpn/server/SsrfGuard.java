package com.dchen.kcpvpn.server;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;

/**
 * SSRF 目标防护 - C++ address.cpp is_restricted_target 的 Java 移植。
 *
 * 本地模式服务器的 OPEN 帧过去可以指向任意地址（包括 127.0.0.1 上的其它应用
 * 服务与内网）——Android 各应用共享 loopback，拿到 PSK 的应用能借这条路径探测
 * 本机/内网端口。与 C++ 服务器同规则拒绝受限目标。
 *
 * IPv4 各段的边界与 C++ 逐条对齐（含 192.0.0.0/24 与 192.0.2.0/24 的精确匹配，
 * 以及 v6 过渡机制内嵌 v4 的还原检查）。本地自测需要放行受限目标时，由测试
 * 环境直接选择公网地址，不设 allowlist。
 */
public final class SsrfGuard {

    private SsrfGuard() {
    }

    public static boolean isRestricted(InetAddress address) {
        if (address instanceof Inet4Address) {
            return isRestrictedV4(address.getAddress());
        }
        if (address instanceof Inet6Address) {
            return isRestrictedV6(address.getAddress());
        }
        return false;
    }

    static boolean isRestrictedV4(byte[] b) {
        int o0 = b[0] & 0xFF;
        int o1 = b[1] & 0xFF;
        int o2 = b[2] & 0xFF;
        if (isZeroBytes(b, 0, 4)) return true;                 // 0.0.0.0 (unspecified)
        if (o0 == 127) return true;                            // loopback
        if (o0 >= 224 && o0 <= 239) return true;               // multicast
        if (o0 == 0) return true;                              // 0.0.0.0/8
        if (o0 == 10) return true;                             // 10.0.0.0/8
        if (o0 == 100 && (o1 & 0xC0) == 64) return true;       // 100.64.0.0/10 CGN
        if (o0 == 169 && o1 == 254) return true;               // 169.254.0.0/16
        if (o0 == 172 && (o1 & 0xF0) == 16) return true;       // 172.16.0.0/12
        if (o0 == 192 && o1 == 168) return true;               // 192.168.0.0/16
        // 192.0.0.0/24（IETF 协议分配）与 192.0.2.0/24（TEST-NET-1）。o2 必须
        // 精确等于 0 或 2——宽松的 <= 2 会误吞全局可路由的 192.0.1.0/24（C++ 侧修过）。
        if (o0 == 192 && o1 == 0 && (o2 == 0 || o2 == 2)) return true;
        if (o0 == 192 && o1 == 88 && o2 == 99) return true;    // 192.88.99.0/24 6to4 relay
        if (o0 == 198 && (o1 == 18 || o1 == 19)) return true;  // 198.18.0.0/15
        if (o0 == 198 && o1 == 51 && o2 == 100) return true;   // 198.51.100.0/24
        if (o0 == 203 && o1 == 0 && o2 == 113) return true;    // 203.0.113.0/24
        if (o0 >= 240) return true;                            // 240.0.0.0/4 reserved
        if (o0 == 255) return true;                            // 255.255.255.255 broadcast
        return false;
    }

    private static boolean isRestrictedV6(byte[] b) {
        // IPv4-mapped ::ffff:a.b.c.d —— 按 v4 规则判定
        if (isZeroBytes(b, 0, 10) && b[10] == (byte) 0xFF && b[11] == (byte) 0xFF) {
            byte[] v4 = new byte[]{b[12], b[13], b[14], b[15]};
            return isRestrictedV4(v4);
        }
        // 6to4 (2002::/16)：内嵌 v4 在字节 2-5
        if (b[0] == 0x20 && b[1] == 0x02
                && isRestrictedV4(new byte[]{b[2], b[3], b[4], b[5]})) {
            return true;
        }
        // Teredo (2001:0000::/32)：服务器 v4 在 4-7，客户端 v4（按位取反）在 12-15
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) {
            if (isRestrictedV4(new byte[]{b[4], b[5], b[6], b[7]})) {
                return true;
            }
            byte[] client = new byte[]{
                    (byte) ~b[12], (byte) ~b[13], (byte) ~b[14], (byte) ~b[15]};
            if (isRestrictedV4(client)) {
                return true;
            }
        }
        // NAT64 64:ff9b::/96 与 64:ff9b:1::/48：内嵌 v4 在字节 12-15
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == (byte) 0xFF && b[3] == (byte) 0x9B
                && b[4] == 0x00 && (b[5] == 0x00 || b[5] == 0x01)
                && isRestrictedV4(new byte[]{b[12], b[13], b[14], b[15]})) {
            return true;
        }
        // IPv4-compatible ::a.b.c.d（::/96，:: 与 ::1 由下面覆盖）
        if (isZeroBytes(b, 0, 12) && isRestrictedV4(new byte[]{b[12], b[13], b[14], b[15]})) {
            return true;
        }
        if (isZeroBytes(b, 0, 16)) return true;                // :: (unspecified)
        if (isZeroBytes(b, 0, 15) && b[15] == 1) return true;  // ::1 loopback
        if (b[0] == (byte) 0xFE && (b[1] & 0xC0) == 0x80) return true;  // fe80::/10 link-local
        if (b[0] == (byte) 0xFE && (b[1] & 0xC0) == 0xC0) return true;  // fec0::/10 site-local
        if ((b[0] & 0xFE) == 0xFC) return true;                // fc00::/7 unique-local
        if (b[0] == (byte) 0xFF) return true;                  // multicast
        // 2001:db8::/32 documentation
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == (byte) 0xB8) {
            return true;
        }
        return false;
    }

    private static boolean isZeroBytes(byte[] b, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return true;
    }
}
