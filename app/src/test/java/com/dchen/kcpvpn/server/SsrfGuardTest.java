package com.dchen.kcpvpn.server;

import org.junit.Test;

import java.net.InetAddress;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * SsrfGuard 与 C++ address.cpp is_restricted_target 的判定对齐测试，
 * 用例镜像 C++ 侧 test_restricted_targets。
 */
public class SsrfGuardTest {

    private static boolean v4(String addr) throws Exception {
        return SsrfGuard.isRestricted(InetAddress.getByName(addr));
    }

    private static boolean v6(String addr) throws Exception {
        return SsrfGuard.isRestricted(InetAddress.getByName(addr));
    }

    @Test
    public void publicIpv4IsAllowed() throws Exception {
        assertFalse(v4("8.8.8.8"));
        assertFalse(v4("1.1.1.1"));
        assertFalse(v4("93.184.216.34"));
        assertFalse(v4("172.32.0.1"));    // 172.16/12 之外
        assertFalse(v4("192.0.1.1"));     // 全局可路由；宽松的 <=2 会误吞（C++ 修过的 bug）
        assertFalse(v4("192.1.0.1"));
        assertFalse(v4("198.20.0.1"));
    }

    @Test
    public void restrictedIpv4IsBlocked() throws Exception {
        assertTrue(v4("0.0.0.0"));
        assertTrue(v4("127.0.0.1"));
        assertTrue(v4("10.0.0.1"));
        assertTrue(v4("100.64.0.1"));     // CGNAT
        assertTrue(v4("169.254.1.1"));    // link-local
        assertTrue(v4("172.16.0.1"));
        assertTrue(v4("172.31.255.255"));
        assertTrue(v4("192.168.1.1"));
        assertTrue(v4("192.0.0.1"));      // IETF protocol assignments
        assertTrue(v4("192.0.2.1"));      // TEST-NET-1
        assertTrue(v4("192.88.99.1"));    // 6to4 relay anycast
        assertTrue(v4("198.18.0.1"));     // benchmarking
        assertTrue(v4("198.51.100.1"));   // TEST-NET-2
        assertTrue(v4("203.0.113.1"));    // TEST-NET-3
        assertTrue(v4("224.0.0.1"));      // multicast
        assertTrue(v4("240.0.0.1"));      // reserved
        assertTrue(v4("255.255.255.255"));
    }

    @Test
    public void publicIpv6IsAllowed() throws Exception {
        assertFalse(v6("2606:4700::1111"));
        assertFalse(v6("2001:4860:4860::8888"));
    }

    @Test
    public void restrictedIpv6IsBlocked() throws Exception {
        assertTrue(v6("::1"));
        assertTrue(v6("::"));
        assertTrue(v6("fe80::1"));        // link-local
        assertTrue(v6("fec0::1"));        // site-local（C++ 侧补的缺口）
        assertTrue(v6("fd00::1"));        // unique-local
        assertTrue(v6("ff02::1"));        // multicast
        assertTrue(v6("2001:db8::1"));    // documentation
    }

    @Test
    public void ipv4MappedIpv6InheritsV4Rules() throws Exception {
        assertTrue(v6("::ffff:127.0.0.1"));
        assertTrue(v6("::ffff:10.0.0.1"));
        assertFalse(v6("::ffff:8.8.8.8"));
    }

    @Test
    public void v6TransitionMechanismsAreCheckedByEmbeddedV4() throws Exception {
        // 6to4 2002::/16：内嵌 127.0.0.1 / 8.8.8.8
        assertTrue(v6("2002:7f00:1::"));
        assertFalse(v6("2002:808:808::"));
        // NAT64 64:ff9b::/96：内嵌 127.0.0.1
        assertTrue(v6("64:ff9b::7f00:1"));
        // IPv4-compatible ::/96：尾部即 v4
        assertTrue(v6("::127.0.0.1"));
        // Teredo 2001:0000::/32：客户端 v4 按位取反藏在 12-15 字节
        assertTrue(v6("2001:0:4141:4141:4141:4141:8080:8080"));    // 还原为 127.127.127.127
        assertFalse(v6("2001:0:4141:4141:4141:4141:f7f7:f7f7"));   // 还原为 8.8.8.8
    }
}
