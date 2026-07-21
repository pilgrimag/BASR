package com.basr.entity;

import com.basr.crypto.X25519Codec;

import java.util.Arrays;
import java.util.Objects;

/**
 * KEM 恢复材料 RM_i。
 *
 * 对于 DHKEM-X25519-HKDF-SHA256，RM_i 是发送方生成的
 * 临时 X25519 公钥 enc，采用规范 32 字节编码。
 */
public final class RecoveryMaterial {

    private final byte[] encapsulatedPublicKey;

    public RecoveryMaterial(
            byte[] encapsulatedPublicKey) {

        Objects.requireNonNull(
                encapsulatedPublicKey,
                "encapsulatedPublicKey");

        if (encapsulatedPublicKey.length
                != X25519Codec
                        .ENCODED_PUBLIC_KEY_LENGTH) {

            throw new IllegalArgumentException(
                    "X25519 recovery material must contain 32 bytes");
        }

        this.encapsulatedPublicKey =
                encapsulatedPublicKey.clone();
    }

    public byte[] getEncapsulatedPublicKey() {
        return encapsulatedPublicKey.clone();
    }

    @Override
    public boolean equals(Object object) {

        if (this == object) {
            return true;
        }

        if (!(object
                instanceof RecoveryMaterial other)) {

            return false;
        }

        return Arrays.equals(
                encapsulatedPublicKey,
                other.encapsulatedPublicKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(
                encapsulatedPublicKey);
    }

    @Override
    public String toString() {
        return "RecoveryMaterial{length="
                + encapsulatedPublicKey.length
                + '}';
    }
}