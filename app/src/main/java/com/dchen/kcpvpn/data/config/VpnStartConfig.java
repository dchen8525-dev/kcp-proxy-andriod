package com.dchen.kcpvpn.data.config;

import java.util.regex.Pattern;

public final class VpnStartConfig {
    private static final Pattern IPV4_PATTERN = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$");

    private VpnStartConfig() {
    }

    public static ValidationResult validate(String host, int port, String key, boolean localMode) {
        if (host == null || host.trim().isEmpty()) {
            return ValidationResult.invalid("CONFIG_INVALID", "服务器地址不能为空", "填写服务器地址，例如 10.0.2.2。");
        }
        String normalizedHost = host.trim();
        if (!isValidHost(normalizedHost)) {
            return ValidationResult.invalid("CONFIG_INVALID", "服务器地址格式不正确",
                    "使用 IPv4/IPv6 地址或有效域名。");
        }
        if (port < 1 || port > 65535) {
            return ValidationResult.invalid("CONFIG_INVALID", "端口范围应为 1-65535", "检查服务端监听端口。");
        }
        if (key == null || key.trim().isEmpty()) {
            return ValidationResult.invalid("CONFIG_INVALID", "密钥不能为空", "填写与服务端一致的密钥。");
        }
        // 与 C++ 服务端/客户端一致：main_server.cpp / main_client.cpp 都要求
        // key.size() >= 16，短于 16 的密钥在服务端启动阶段就会被拒绝。这里放行
        // 只会让用户在隧道建不起来之后才去翻日志。
        if (!localMode && key.trim().length() < 16) {
            return ValidationResult.invalid("CONFIG_INVALID", "远程模式密钥过短", "使用至少 16 个字符的远程密钥。");
        }
        return ValidationResult.valid();
    }

    public static boolean isValidHost(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        // IPv6 字面地址：隧道栈（InetSocketAddress / DatagramChannel / C++ 侧
        // make_address）全链路支持，过去仅因主机名校验不含冒号而无法从 GUI 配置。
        if (host.indexOf(':') >= 0) {
            return isValidIpv6Literal(host);
        }
        if (IPV4_PATTERN.matcher(host).matches()) {
            String[] parts = host.split("\\.");
            for (String part : parts) {
                if (!isValidIpv4Octet(part)) {
                    return false;
                }
            }
            return true;
        }
        return host.contains(".") && !host.startsWith(".") && !host.endsWith(".")
                && HOST_PATTERN.matcher(host).matches();
    }

    /**
     * 单个 IPv4 八位组：0-255 的十进制数，且拒绝前导零。前导零曾按八进制解析
     * （Java 的 InetAddress 有历史八进制语义），"010.0.0.1" 校验时按十进制算 10
     * 而实际可能连到 8.0.0.1——校验与解析必须同律，这里直接拒绝歧义写法。
     * 单个 "0" 本身合法（0.0.0.0、10.0.0.0 都需要它）。
     */
    private static boolean isValidIpv4Octet(String part) {
        if (part.isEmpty()) {
            return false;
        }
        if (part.length() > 1 && part.charAt(0) == '0') {
            return false;  // 前导零歧义
        }
        int value;
        try {
            value = Integer.parseInt(part);
        } catch (NumberFormatException e) {
            return false;
        }
        return value >= 0 && value <= 255;
    }

    /**
     * 结构化校验 IPv6 字面地址（纯解析，不做 DNS）。规则：:: 至多出现一次且
     * 必须真的压缩内容；每段 1-4 位十六进制；支持末尾内嵌 IPv4（计 2 组）；
     * 不接受 zone id（%eth0）。
     */
    static boolean isValidIpv6Literal(String host) {
        if (host.isEmpty() || host.indexOf(':') < 0 || host.indexOf('%') >= 0) {
            return false;
        }

        int doubleColon = host.indexOf("::");
        if (doubleColon >= 0) {
            if (host.indexOf("::", doubleColon + 1) >= 0) {
                return false;  // "::" 至多一次
            }
            int leftGroups = countIpv6Groups(host.substring(0, doubleColon));
            int rightGroups = countIpv6Groups(host.substring(doubleColon + 2));
            if (leftGroups < 0 || rightGroups < 0) {
                return false;
            }
            // "::" 必须压缩至少一个全零组（8 组全写出来的地址不该带 ::）
            return leftGroups + rightGroups <= 7;
        }
        return countIpv6Groups(host) == 8;
    }

    /**
     * 校验一段冒号分隔的十六进制组（不含 "::"），末组允许是内嵌 IPv4（计 2 组）。
     * 返回组数；格式非法返回 -1。
     */
    private static int countIpv6Groups(String segment) {
        if (segment.isEmpty()) {
            return 0;
        }
        String[] parts = segment.split(":", -1);
        int groups = 0;
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            boolean last = i == parts.length - 1;
            if (last && part.indexOf('.') >= 0) {
                // 内嵌 IPv4：4 个无前导零的严格十进制八位组
                if (!IPV4_PATTERN.matcher(part).matches()) {
                    return -1;
                }
                String[] octets = part.split("\\.");
                for (String octet : octets) {
                    if (!isValidIpv4Octet(octet)) {
                        return -1;
                    }
                }
                groups += 2;
                continue;
            }
            if (part.isEmpty() || part.length() > 4) {
                return -1;
            }
            for (int j = 0; j < part.length(); j++) {
                if (Character.digit(part.charAt(j), 16) < 0) {
                    return -1;
                }
            }
            groups++;
        }
        return groups;
    }

    public static final class ValidationResult {
        public final boolean valid;
        public final String stage;
        public final String reason;
        public final String suggestedFix;

        private ValidationResult(boolean valid, String stage, String reason, String suggestedFix) {
            this.valid = valid;
            this.stage = stage;
            this.reason = reason;
            this.suggestedFix = suggestedFix;
        }

        static ValidationResult valid() {
            return new ValidationResult(true, "", "", "");
        }

        static ValidationResult invalid(String stage, String reason, String suggestedFix) {
            return new ValidationResult(false, stage, reason, suggestedFix);
        }

        public String toUserMessage() {
            if (valid) {
                return "";
            }
            return stage + ": " + reason + "。建议：" + suggestedFix;
        }
    }
}
