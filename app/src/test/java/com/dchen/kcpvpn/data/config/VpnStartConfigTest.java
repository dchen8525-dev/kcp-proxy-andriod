package com.dchen.kcpvpn.data.config;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class VpnStartConfigTest {
    @Test
    public void validateAcceptsRemoteEmulatorHost() {
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("10.0.2.2", 8388, "remote_test_key_123456", false);

        assertTrue(result.valid);
    }

    @Test
    public void validateRejectsInvalidPort() {
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("10.0.2.2", 70000, "remote_test_key_123456", false);

        assertFalse(result.valid);
        assertTrue(result.toUserMessage().contains("CONFIG_INVALID"));
    }

    @Test
    public void validateRejectsShortRemoteKey() {
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("vpn.example.com", 8388, "short", false);

        assertFalse(result.valid);
    }

    @Test
    public void validateRejectsRemoteKeyBelowServerMinimum() {
        // C++ main_server.cpp / main_client.cpp 要求 key.size() >= 16
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("vpn.example.com", 8388, "123456789012345", false);

        assertFalse(result.valid);
    }

    @Test
    public void validateAcceptsRemoteKeyAtServerMinimum() {
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("vpn.example.com", 8388, "1234567890123456", false);

        assertTrue(result.valid);
    }

    @Test
    public void validateAcceptsLocalModeTestKey() {
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("127.0.0.1", 8443, "test-key", true);

        assertTrue(result.valid);
    }

    // ---- IPv6 字面地址：隧道栈全链路支持，主机名校验不得成为唯一的拦路虎 ----

    @Test
    public void validateAcceptsIpv6LiteralHost() {
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("2001:db8::1", 8388, "remote_test_key_123456", false);

        assertTrue(result.valid);
    }

    @Test
    public void isValidHostAcceptsCanonicalIpv6Forms() {
        assertTrue(VpnStartConfig.isValidHost("::1"));
        assertTrue(VpnStartConfig.isValidHost("::"));
        assertTrue(VpnStartConfig.isValidHost("2001:db8::1"));
        assertTrue(VpnStartConfig.isValidHost("fe80::1"));
        assertTrue(VpnStartConfig.isValidHost("1:2:3:4:5:6:7:8"));          // 完整形式
        assertTrue(VpnStartConfig.isValidHost("1:2:3:4:5:6:7::"));          // 压缩最后一组
        assertTrue(VpnStartConfig.isValidHost("::ffff:192.168.1.1"));       // 内嵌 IPv4
    }

    @Test
    public void isValidHostRejectsMalformedIpv6() {
        assertTrue(!VpnStartConfig.isValidHost("1:2:3:4:5:6:7:8:9"));   // 9 组
        assertTrue(!VpnStartConfig.isValidHost("1::2::3"));             // :: 两次
        assertTrue(!VpnStartConfig.isValidHost(":1:2"));                // 单冒号开头
        assertTrue(!VpnStartConfig.isValidHost("1:2:"));                // 单冒号结尾
        assertTrue(!VpnStartConfig.isValidHost("12345::"));             // 段超 4 位
        assertTrue(!VpnStartConfig.isValidHost("::1:2:3:4:5:6:7:8"));   // :: 未压缩任何内容
        assertTrue(!VpnStartConfig.isValidHost("g::1"));                // 非十六进制
        assertTrue(!VpnStartConfig.isValidHost("fe80::1%eth0"));        // zone id 不支持
        assertTrue(!VpnStartConfig.isValidHost(":"));                   // 纯冒号
    }

    // ---- 前导零八位组：校验(十进制)与解析(历史八进制语义)必须同律 ----

    @Test
    public void validateRejectsLeadingZeroIpv4Octets() {
        // "010" 按十进制校验是 10,但 InetAddress 的历史语义可能按八进制解析成 8
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("010.0.2.2", 8388, "remote_test_key_123456", false);

        assertFalse(result.valid);
        assertFalse(VpnStartConfig.isValidHost("01.2.3.4"));
    }

    @Test
    public void isValidHostStillAcceptsLegitimateZeroOctets() {
        assertTrue(VpnStartConfig.isValidHost("0.0.0.0"));
        assertTrue(VpnStartConfig.isValidHost("10.0.2.2"));
        assertTrue(VpnStartConfig.isValidHost("192.168.1.1"));
    }
}
