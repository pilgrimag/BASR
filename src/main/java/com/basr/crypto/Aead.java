package com.basr.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * BASR AEAD 实现。
 *
 * 具体实例：
 *
 *      AES-256-GCM
 *
 * D_i 的本地编码：
 *
 *      nonce || ciphertext || authenticationTag
 *
 * nonce 长度由 pp_AEAD 指定，当前为 12 字节。
 */
public final class Aead {

    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    private Aead() {
    }

    public static byte[] encrypt(
            PublicParams pp,
            byte[] key,
            byte[] plaintext,
            byte[] associatedData) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(
                plaintext,
                "plaintext");
        Objects.requireNonNull(
                associatedData,
                "associatedData");

        validateConfiguration(
                pp.getAeadParameters(),
                key);

        PublicParams.AeadParameters parameters =
                pp.getAeadParameters();

        byte[] nonce =
                new byte[
                        parameters
                                .nonceLengthBytes()];

        SECURE_RANDOM.nextBytes(nonce);

        try {
            Cipher cipher =
                    Cipher.getInstance(
                            parameters
                                    .transformation());

            GCMParameterSpec parameterSpec =
                    new GCMParameterSpec(
                            parameters
                                    .tagLengthBits(),
                            nonce);

            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    parameterSpec);

            cipher.updateAAD(associatedData);

            byte[] ciphertextAndTag =
                    cipher.doFinal(plaintext);

            return TranscriptEncoder.concat(
                    nonce,
                    ciphertextAndTag);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "AEAD encryption failed",
                    exception);
        }
    }

    public static byte[] decrypt(
            PublicParams pp,
            byte[] key,
            byte[] encodedCiphertext,
            byte[] associatedData) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(
                encodedCiphertext,
                "encodedCiphertext");
        Objects.requireNonNull(
                associatedData,
                "associatedData");

        validateConfiguration(
                pp.getAeadParameters(),
                key);

        PublicParams.AeadParameters parameters =
                pp.getAeadParameters();

        int nonceLength =
                parameters.nonceLengthBytes();

        int tagLengthBytes =
                parameters.tagLengthBits() / 8;

        if (encodedCiphertext.length
                < nonceLength + tagLengthBytes) {

            throw new IllegalArgumentException(
                    "AEAD ciphertext is too short");
        }

        byte[] nonce =
                new byte[nonceLength];

        System.arraycopy(
                encodedCiphertext,
                0,
                nonce,
                0,
                nonceLength);

        byte[] ciphertextAndTag =
                new byte[
                        encodedCiphertext.length
                                - nonceLength];

        System.arraycopy(
                encodedCiphertext,
                nonceLength,
                ciphertextAndTag,
                0,
                ciphertextAndTag.length);

        try {
            Cipher cipher =
                    Cipher.getInstance(
                            parameters
                                    .transformation());

            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(
                            parameters
                                    .tagLengthBits(),
                            nonce));

            cipher.updateAAD(associatedData);

            return cipher.doFinal(
                    ciphertextAndTag);

        } catch (AEADBadTagException exception) {
            throw new SecurityException(
                    "AEAD authentication failed",
                    exception);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "AEAD decryption failed",
                    exception);
        }
    }

    private static void validateConfiguration(
            PublicParams.AeadParameters parameters,
            byte[] key) {

        Objects.requireNonNull(
                parameters,
                "aeadParameters");

        if (!"AES/GCM/NoPadding"
                .equalsIgnoreCase(
                        parameters.transformation())) {

            throw new IllegalArgumentException(
                    "Unsupported AEAD transformation: "
                            + parameters
                                    .transformation());
        }

        if (parameters.keyLengthBytes() != 32
                || key.length != 32) {

            throw new IllegalArgumentException(
                    "AES-256-GCM requires a 32-byte key");
        }

        if (parameters.nonceLengthBytes() != 12) {
            throw new IllegalArgumentException(
                    "This implementation requires a 12-byte GCM nonce");
        }

        if (parameters.tagLengthBits() != 128) {
            throw new IllegalArgumentException(
                    "This implementation requires a 128-bit GCM tag");
        }
    }
}