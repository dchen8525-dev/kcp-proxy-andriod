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
    public void validateAcceptsLocalModeTestKey() {
        VpnStartConfig.ValidationResult result =
                VpnStartConfig.validate("127.0.0.1", 8443, "test-key", true);

        assertTrue(result.valid);
    }
}
