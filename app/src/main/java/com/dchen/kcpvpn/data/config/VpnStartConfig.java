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
            return ValidationResult.invalid("CONFIG_INVALID", "服务器地址格式不正确", "使用 IPv4 地址或有效域名。");
        }
        if (port < 1 || port > 65535) {
            return ValidationResult.invalid("CONFIG_INVALID", "端口范围应为 1-65535", "检查服务端监听端口。");
        }
        if (key == null || key.trim().isEmpty()) {
            return ValidationResult.invalid("CONFIG_INVALID", "密钥不能为空", "填写与服务端一致的密钥。");
        }
        if (!localMode && key.trim().length() < 8) {
            return ValidationResult.invalid("CONFIG_INVALID", "远程模式密钥过短", "使用至少 8 个字符的远程密钥。");
        }
        return ValidationResult.valid();
    }

    public static boolean isValidHost(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        if (IPV4_PATTERN.matcher(host).matches()) {
            String[] parts = host.split("\\.");
            for (String part : parts) {
                int value;
                try {
                    value = Integer.parseInt(part);
                } catch (NumberFormatException e) {
                    return false;
                }
                if (value < 0 || value > 255) {
                    return false;
                }
            }
            return true;
        }
        return host.contains(".") && !host.startsWith(".") && !host.endsWith(".")
                && HOST_PATTERN.matcher(host).matches();
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
