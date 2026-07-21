package com.basr.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Objects;

/**
 * X25519 公钥的规范 32 字节编码工具。
 *
 * RFC 7748 使用固定 32 字节、小端序 u 坐标。
 */
public final class X25519Codec {

    public static final int ENCODED_PUBLIC_KEY_LENGTH = 32;

    private X25519Codec() {
    }

    /**
     * 将 X25519 公钥编码为固定 32 字节小端格式。
     */
    public static byte[] encodePublicKey(
            XECPublicKey publicKey) {

        Objects.requireNonNull(publicKey, "publicKey");

        requireX25519(publicKey);

        BigInteger u = publicKey.getU();

        if (u.signum() < 0) {
            throw new IllegalArgumentException(
                    "X25519 u-coordinate cannot be negative");
        }

        byte[] bigEndian = u.toByteArray();

        int sourceOffset =
                bigEndian.length > 1
                        && bigEndian[0] == 0
                        ? 1
                        : 0;

        int sourceLength =
                bigEndian.length - sourceOffset;

        if (sourceLength
                > ENCODED_PUBLIC_KEY_LENGTH) {

            throw new IllegalArgumentException(
                    "X25519 public key exceeds 32 bytes");
        }

        byte[] littleEndian =
                new byte[ENCODED_PUBLIC_KEY_LENGTH];

        for (int index = 0;
             index < sourceLength;
             index++) {

            littleEndian[index] =
                    bigEndian[
                            bigEndian.length
                                    - 1
                                    - index];
        }

        return littleEndian;
    }

    /**
     * 从规范 32 字节小端格式恢复 X25519 公钥。
     */
    public static XECPublicKey decodePublicKey(
            byte[] encoded) {

        Objects.requireNonNull(encoded, "encoded");

        if (encoded.length
                != ENCODED_PUBLIC_KEY_LENGTH) {

            throw new IllegalArgumentException(
                    "X25519 public key must contain exactly 32 bytes");
        }

        /*
         * 本地协议只接受规范编码。
         * X25519 u 坐标最高有效位必须为零。
         */
        if ((encoded[31] & 0x80) != 0) {
            throw new IllegalArgumentException(
                    "Non-canonical X25519 public-key encoding");
        }

        byte[] bigEndian =
                new byte[
                        ENCODED_PUBLIC_KEY_LENGTH];

        for (int index = 0;
             index < encoded.length;
             index++) {

            bigEndian[
                    encoded.length - 1 - index]
                    = encoded[index];
        }

        BigInteger u =
                new BigInteger(1, bigEndian);

        try {
            KeyFactory keyFactory =
                    KeyFactory.getInstance(
                            "X25519");

            return (XECPublicKey)
                    keyFactory.generatePublic(
                            new XECPublicKeySpec(
                                    NamedParameterSpec.X25519,
                                    u));

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Unable to decode X25519 public key",
                    exception);
        }
    }

    /**
     * 验证密钥使用 X25519 参数集。
     */
    public static void requireX25519(
            XECKey key) {

        Objects.requireNonNull(key, "key");

        if (!(key.getParams()
                instanceof NamedParameterSpec parameters)) {

            throw new IllegalArgumentException(
                    "Key does not use named XEC parameters");
        }

        if (!NamedParameterSpec.X25519
                .getName()
                .equalsIgnoreCase(
                        parameters.getName())) {

            throw new IllegalArgumentException(
                    "Expected X25519 key but found "
                            + parameters.getName());
        }
    }
}