package com.dchen.kcpvpn.core.crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * AES-128-GCM 加密器 - 与 C++ crypto.cpp 一致
 * 提供 AEAD（Authenticated Encryption with Associated Data）加密
 */
public class AesGcmCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = CryptoConfig.TAG_SIZE * 8; // 位

    private SecretKeySpec keySpec;
    private Cipher cipher;

    /**
     * 创建 AES-GCM 加密器
     * @param key 16字节 AES 密钥
     */
    public AesGcmCipher(byte[] key) {
        if (key == null || key.length != CryptoConfig.AES_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be 16 bytes");
        }
        this.keySpec = new SecretKeySpec(key, "AES");

        try {
            this.cipher = Cipher.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("AES-GCM cipher not available", e);
        }
    }

    /**
     * 加密数据
     * @param plaintext 明文数据
     * @param nonce 12字节 Nonce
     * @return 密文 + 16字节认证标签
     */
    public byte[] encrypt(byte[] plaintext, byte[] nonce) {
        if (nonce == null || nonce.length != CryptoConfig.NONCE_SIZE) {
            throw new IllegalArgumentException("Nonce must be 12 bytes");
        }

        try {
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    /**
     * 解密数据
     * @param ciphertext 密文 + 16字节认证标签
     * @param nonce 12字节 Nonce
     * @return 明文数据
     */
    public byte[] decrypt(byte[] ciphertext, byte[] nonce) {
        if (nonce == null || nonce.length != CryptoConfig.NONCE_SIZE) {
            throw new IllegalArgumentException("Nonce must be 12 bytes");
        }
        if (ciphertext == null || ciphertext.length < CryptoConfig.TAG_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        try {
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }
}