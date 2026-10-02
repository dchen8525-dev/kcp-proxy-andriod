package com.dchen.kcpvpn.core.crypto;

import com.dchen.kcpvpn.log.Logger;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 加密主类 - 与 C++ crypto.cpp 完全一致（V2 线格式）。
 * 线格式: session_salt(16) + nonce(12) + ciphertext + tag(16)。
 * per-session 密钥 = HKDF-SHA256(PSK, APP_SALT || session_salt, info=方向标签)，
 * 加密计数器起点 = session_salt 前 6 字节大端。客户端在构造时生成 salt 立即派生；
 * 服务端（serverMode）从首个报文学到 salt 后懒派生，并要求后续报文携带同一 salt。
 */
public class Crypto {

    private final byte localDirection;
    private final byte peerDirection;
    private final boolean serverMode;

    private final ReplayWindow replayWindow = new ReplayWindow();

    private final Object stateLock = new Object();
    private AesGcmCipher encryptCipher;
    private AesGcmCipher decryptCipher;
    private byte[] sessionSalt;
    private boolean saltSet;
    private long encryptCounter;

    /** PSK 的 UTF-8 字节，仅在服务端懒派生期间保留，派生完成后擦除。 */
    private byte[] pendingPsk;

    /**
     * 客户端构造：生成新的 per-session 随机盐并立即派生密钥。
     */
    public Crypto(String key) {
        this(key, CryptoConfig.NONCE_DIR_CLIENT, generateSessionSalt());
    }

    /**
     * 显式盐构造（客户端语义）：立即派生 per-session 密钥。
     *
     * @param key         PSK
     * @param direction   本端方向（CLIENT 或 SERVER）
     * @param sessionSalt 16 字节 per-session 随机盐
     */
    public Crypto(String key, byte direction, byte[] sessionSalt) {
        this.localDirection = direction;
        this.peerDirection = (direction == CryptoConfig.NONCE_DIR_CLIENT)
                ? CryptoConfig.NONCE_DIR_SERVER
                : CryptoConfig.NONCE_DIR_CLIENT;
        this.serverMode = false;
        if (sessionSalt == null || sessionSalt.length != CryptoConfig.SESSION_SALT_SIZE) {
            throw new IllegalArgumentException("session salt must be exactly 16 bytes");
        }
        deriveSessionKeys(key.getBytes(StandardCharsets.UTF_8), sessionSalt);
        Logger.debug("crypto", "Crypto initialized: direction=" + direction
                + ", per-session key derived via HKDF(PSK, APP_SALT||session_salt)");
    }

    /**
     * 服务端构造：salt 未知，密钥在首个成功解密的报文上懒派生；
     * 首包旁路重放窗口（与 C++ server_mode 一致）。
     */
    public static Crypto createServerCrypto(String key) {
        return new Crypto(key, true);
    }

    private Crypto(String key, boolean serverMode) {
        this.localDirection = CryptoConfig.NONCE_DIR_SERVER;
        this.peerDirection = CryptoConfig.NONCE_DIR_CLIENT;
        this.serverMode = serverMode;
        this.pendingPsk = key.getBytes(StandardCharsets.UTF_8);
    }

    /** 生成 16 字节密码学随机的 per-session 盐。 */
    public static byte[] generateSessionSalt() {
        byte[] salt = new byte[CryptoConfig.SESSION_SALT_SIZE];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private void deriveSessionKeys(byte[] psk, byte[] salt) {
        byte[] appSalt = CryptoConfig.APP_SALT.getBytes(StandardCharsets.UTF_8);
        byte[] hkdfSalt = new byte[appSalt.length + salt.length];
        System.arraycopy(appSalt, 0, hkdfSalt, 0, appSalt.length);
        System.arraycopy(salt, 0, hkdfSalt, appSalt.length, salt.length);

        byte[] encInfo = (localDirection == CryptoConfig.NONCE_DIR_CLIENT)
                ? CryptoConfig.INFO_C2S.getBytes(StandardCharsets.UTF_8)
                : CryptoConfig.INFO_S2C.getBytes(StandardCharsets.UTF_8);
        byte[] decInfo = (peerDirection == CryptoConfig.NONCE_DIR_CLIENT)
                ? CryptoConfig.INFO_C2S.getBytes(StandardCharsets.UTF_8)
                : CryptoConfig.INFO_S2C.getBytes(StandardCharsets.UTF_8);

        byte[] encryptKey = HkdfSha256.derive(psk, hkdfSalt, encInfo, CryptoConfig.AES_KEY_SIZE);
        byte[] decryptKey = HkdfSha256.derive(psk, hkdfSalt, decInfo, CryptoConfig.AES_KEY_SIZE);
        Arrays.fill(hkdfSalt, (byte) 0);

        this.encryptCipher = new AesGcmCipher(encryptKey);
        this.decryptCipher = new AesGcmCipher(decryptKey);
        Arrays.fill(encryptKey, (byte) 0);
        Arrays.fill(decryptKey, (byte) 0);
        if (pendingPsk != null) {
            Arrays.fill(pendingPsk, (byte) 0);
            pendingPsk = null;
        }

        // 计数器起点 = salt 前 6 字节大端（< 2^48），与 C++ derive_session_keys 一致
        this.encryptCounter = startCounterOf(salt);
        this.sessionSalt = salt.clone();
        this.saltSet = true;
    }

    /**
     * 加密数据。
     *
     * @return 线格式: session_salt(16) + nonce(12) + ciphertext + tag(16)
     */
    public byte[] encrypt(byte[] plaintext) {
        synchronized (stateLock) {
            if (!saltSet) {
                throw new IllegalStateException("encrypt called before the session salt was established");
            }
            if (encryptCounter >= CryptoConfig.MAX_COUNTER) {
                // 专用类型：调用方能区分"计数器耗尽（会话必须重建）"和普通 IO 失败，
                // 关闭原因才不会误标成 UDP_SEND_FAILED。
                throw new CounterOverflowException(
                        "Encryption counter overflow - session must be rekeyed");
            }

            long counter = encryptCounter++;
            byte[] nonce = NonceGenerator.generate(counter, localDirection);
            byte[] ciphertextWithTag = encryptCipher.encrypt(plaintext, nonce);

            byte[] result = new byte[CryptoConfig.SESSION_SALT_SIZE + nonce.length + ciphertextWithTag.length];
            System.arraycopy(sessionSalt, 0, result, 0, CryptoConfig.SESSION_SALT_SIZE);
            System.arraycopy(nonce, 0, result, CryptoConfig.SESSION_SALT_SIZE, nonce.length);
            System.arraycopy(ciphertextWithTag, 0, result,
                    CryptoConfig.SESSION_SALT_SIZE + nonce.length, ciphertextWithTag.length);

            Logger.debug("crypto", "Encrypt: " + plaintext.length + " bytes -> " + result.length
                    + " bytes, counter=" + counter);
            return result;
        }
    }

    /**
     * 解密线格式报文: session_salt(16) + nonce(12) + ciphertext + tag(16)。
     *
     * @throws ReplayRejectedException   重放/过期计数器（正常乱序，丢包即可，勿拆会话）
     * @throws AEADBadTagException       认证失败（密钥错误/数据损坏）
     */
    public byte[] decrypt(byte[] packet) throws Exception {
        synchronized (stateLock) {
            if (packet == null || packet.length
                    < CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE + CryptoConfig.TAG_SIZE) {
                throw new IllegalArgumentException("Packet too short");
            }

            byte[] salt = Arrays.copyOfRange(packet, 0, CryptoConfig.SESSION_SALT_SIZE);
            if (!saltSet) {
                if (!serverMode || pendingPsk == null) {
                    throw new IllegalStateException("decrypt called before key material was available");
                }
                // 服务端：从线上首个报文学习 salt 并派生 per-session 密钥
                deriveSessionKeys(pendingPsk, salt);
            } else if (!matchesSalt(packet)) {
                throw new RuntimeException("session salt mismatch (possible cross-session injection)");
            }

            byte[] nonce = Arrays.copyOfRange(packet,
                    CryptoConfig.SESSION_SALT_SIZE,
                    CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE);

            byte direction = NonceGenerator.parseDirection(nonce);
            if (direction != peerDirection) {
                throw new RuntimeException("Decryption rejected: wrong direction byte");
            }

            long counter = NonceGenerator.parseCounter(nonce);

            // 服务端首包旁路重放窗口（其计数器即窗口种子）；其余情况先查窗口。
            // 仅检查，不提交：counter 必须在 AEAD 校验通过后才进入窗口，
            // 否则伪造的高计数器包会永久污染会话（与 C++ 同序）。
            boolean firstPacket = serverMode && !replayWindow.hasReceivedAny();
            if (!firstPacket && !replayWindow.check(counter)) {
                throw new ReplayRejectedException("replay or stale counter, counter=" + counter
                        + ", highest=" + replayWindow.getHighestReceived());
            }

            byte[] cipherData = Arrays.copyOfRange(packet,
                    CryptoConfig.SESSION_SALT_SIZE + CryptoConfig.NONCE_SIZE, packet.length);

            byte[] plaintext;
            try {
                plaintext = decryptCipher.decrypt(cipherData, nonce);
            } catch (RuntimeException e) {
                if (e.getCause() instanceof AEADBadTagException) {
                    throw new AEADBadTagException("AEAD tag verification failed");
                }
                throw e;
            }
            replayWindow.commit(counter);

            Logger.debug("crypto", "Decrypt: " + packet.length + " bytes -> " + plaintext.length
                    + " bytes, counter=" + counter);
            return plaintext;
        }
    }

    /**
     * 报文的起始 16 字节是否为本会话的 salt（服务端检测同源端口的重连新会话）。
     */
    public boolean matchesSalt(byte[] packet) {
        synchronized (stateLock) {
            if (!saltSet || packet == null || packet.length < CryptoConfig.SESSION_SALT_SIZE) {
                return false;
            }
            return constantTimeEquals(packet, sessionSalt);
        }
    }

    /** 本会话 16 字节 salt 的副本（线上明文携带，非机密，但每会话唯一）。 */
    public byte[] sessionSalt() {
        synchronized (stateLock) {
            return saltSet ? sessionSalt.clone() : new byte[0];
        }
    }

    private static long startCounterOf(byte[] salt) {
        long startCounter = 0;
        for (int i = 0; i < 6; i++) {
            startCounter = (startCounter << 8) | (salt[i] & 0xFFL);
        }
        return startCounter;
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        int diff = 0;
        for (int i = 0; i < b.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    public byte getLocalDirection() {
        return localDirection;
    }

    public byte getPeerDirection() {
        return peerDirection;
    }

    /** 重放/过期计数器拒绝：正常 UDP 乱序现象，不是会话错误。 */
    public static class ReplayRejectedException extends Exception {
        public ReplayRejectedException(String message) {
            super(message);
        }
    }

    /** 加密计数器达到 MAX_COUNTER(2^48)：本会话的 nonce 空间已耗尽，必须重建会话。 */
    public static class CounterOverflowException extends RuntimeException {
        public CounterOverflowException(String message) {
            super(message);
        }
    }
}
