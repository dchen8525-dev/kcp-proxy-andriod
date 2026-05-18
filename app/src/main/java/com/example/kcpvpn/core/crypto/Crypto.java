package com.example.kcpvpn.core.crypto;

import com.example.kcpvpn.log.Logger;

import java.nio.charset.StandardCharsets;

/**
 * 加密主类 - 与 C++ crypto.cpp 完全一致
 * 集成 HKDF 密钥派生、AES-GCM 加密、重放保护
 */
public class Crypto {

    private final byte[] encryptKey;
    private final byte[] decryptKey;
    private final byte localDirection;
    private final byte peerDirection;

    private long encryptCounter;
    private final ReplayWindow replayWindow;

    private final AesGcmCipher encryptCipher;
    private final AesGcmCipher decryptCipher;

    /**
     * 创建加密实例
     * @param key 用户密钥
     * @param direction 本端方向（CLIENT 或 SERVER）
     * @param userSalt 用户盐值（可选）
     */
    public Crypto(String key, byte direction, String userSalt) {
        this.localDirection = direction;
        this.peerDirection = (direction == CryptoConfig.NONCE_DIR_CLIENT)
                ? CryptoConfig.NONCE_DIR_SERVER
                : CryptoConfig.NONCE_DIR_CLIENT;

        // 构建 HKDF 盐值：应用固定盐 + 用户盐
        String hkdfSalt = CryptoConfig.APP_SALT;
        if (userSalt != null && !userSalt.isEmpty()) {
            hkdfSalt += userSalt;
        }

        // 派生加密密钥（本端方向）— 使用 UTF-8 编码保证与 C++ 一致
        String encInfo = (localDirection == CryptoConfig.NONCE_DIR_CLIENT)
                ? CryptoConfig.INFO_C2S
                : CryptoConfig.INFO_S2C;
        encryptKey = HkdfSha256.derive(
                key.getBytes(StandardCharsets.UTF_8),
                hkdfSalt.getBytes(StandardCharsets.UTF_8),
                encInfo.getBytes(StandardCharsets.UTF_8),
                CryptoConfig.AES_KEY_SIZE
        );

        // 派生解密密钥（对端方向）
        String decInfo = (peerDirection == CryptoConfig.NONCE_DIR_CLIENT)
                ? CryptoConfig.INFO_C2S
                : CryptoConfig.INFO_S2C;
        decryptKey = HkdfSha256.derive(
                key.getBytes(StandardCharsets.UTF_8),
                hkdfSalt.getBytes(StandardCharsets.UTF_8),
                decInfo.getBytes(StandardCharsets.UTF_8),
                CryptoConfig.AES_KEY_SIZE
        );

        // 创建加密器
        encryptCipher = new AesGcmCipher(encryptKey);
        decryptCipher = new AesGcmCipher(decryptKey);

        // 初始化计数器和重放窗口
        encryptCounter = 0;
        replayWindow = new ReplayWindow();

        Logger.debug("crypto", "Crypto initialized: direction=" + direction
                + ", encKey derived from HKDF, decKey derived from HKDF");
    }

    /**
     * 创建客户端加密实例
     */
    public Crypto(String key) {
        this(key, CryptoConfig.NONCE_DIR_CLIENT, "");
    }

    /**
     * 创建服务端加密实例
     */
    public static Crypto createServerCrypto(String key, String userSalt) {
        return new Crypto(key, CryptoConfig.NONCE_DIR_SERVER, userSalt);
    }

    /**
     * 加密数据
     * @param plaintext 明文数据
     * @return 加密后的数据：[nonce(12)] + [ciphertext] + [tag(16)]
     */
    public synchronized byte[] encrypt(byte[] plaintext) {
        // 检查计数器溢出
        if (encryptCounter >= CryptoConfig.MAX_COUNTER) {
            throw new RuntimeException("Encryption counter overflow - session must be rekeyed");
        }

        // 生成 Nonce
        long counter = encryptCounter++;
        byte[] nonce = NonceGenerator.generate(counter, localDirection);

        // 加密
        byte[] ciphertextWithTag = encryptCipher.encrypt(plaintext, nonce);

        // 组合输出：nonce + ciphertext + tag
        byte[] result = new byte[CryptoConfig.NONCE_SIZE + ciphertextWithTag.length];
        System.arraycopy(nonce, 0, result, 0, CryptoConfig.NONCE_SIZE);
        System.arraycopy(ciphertextWithTag, 0, result, CryptoConfig.NONCE_SIZE, ciphertextWithTag.length);

        Logger.debug("crypto", "Encrypt: " + plaintext.length + " bytes -> " + result.length
                + " bytes, counter=" + counter);

        return result;
    }

    /**
     * 解密数据
     * @param ciphertext 加密数据：[nonce(12)] + [ciphertext] + [tag(16)]
     * @return 明文数据
     */
    public synchronized byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null || ciphertext.length < CryptoConfig.NONCE_SIZE + CryptoConfig.TAG_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        // 解析 Nonce
        byte[] nonce = new byte[CryptoConfig.NONCE_SIZE];
        System.arraycopy(ciphertext, 0, nonce, 0, CryptoConfig.NONCE_SIZE);

        // 检查方向标识
        byte direction = NonceGenerator.parseDirection(nonce);
        if (direction != peerDirection) {
            throw new RuntimeException("Decryption rejected: wrong direction byte");
        }

        // 解析计数器
        long counter = NonceGenerator.parseCounter(nonce);

        // 重放检查（在解密之前，避免无效包消耗解密资源）
        if (!replayWindow.checkAndUpdate(counter)) {
            throw new RuntimeException("Decryption rejected: replay or stale counter");
        }

        // 解密
        int cipherDataLen = ciphertext.length - CryptoConfig.NONCE_SIZE;
        byte[] cipherData = new byte[cipherDataLen];
        System.arraycopy(ciphertext, CryptoConfig.NONCE_SIZE, cipherData, 0, cipherDataLen);

        byte[] plaintext = decryptCipher.decrypt(cipherData, nonce);

        Logger.debug("crypto", "Decrypt: " + ciphertext.length + " bytes -> " + plaintext.length
                + " bytes, counter=" + counter);

        return plaintext;
    }

    /**
     * 重置加密状态
     */
    public synchronized void reset() {
        encryptCounter = 0;
        replayWindow.reset();
        Logger.debug("crypto", "Crypto reset");
    }

    /**
     * 获取本端方向
     */
    public byte getLocalDirection() {
        return localDirection;
    }

    /**
     * 获取对端方向
     */
    public byte getPeerDirection() {
        return peerDirection;
    }
}