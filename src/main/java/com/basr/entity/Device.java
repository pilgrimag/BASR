package com.basr.entity;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR 本地设备实体。
 *
 * 保存：
 *
 *      ID_i
 *      sk_i
 *      pk_i
 *
 * 其中：
 *
 *      sk_i ∈ Z_p^*
 *      pk_i ∈ G
 *
 * secretKey 只保存在设备本地，不能写入区块链、
 * 注册表、日志或 IPFS。
 */
public final class Device {

    /**
     * 设备身份 ID_i。
     */
    private final String deviceId;

    /**
     * 设备签名私钥 sk_i。
     */
    private final BigInteger secretKey;

    /**
     * 设备签名公钥 pk_i。
     */
    private final ECPoint publicKey;

    public Device(
            String deviceId,
            BigInteger secretKey,
            ECPoint publicKey) {

        Objects.requireNonNull(
                deviceId,
                "deviceId");

        Objects.requireNonNull(
                secretKey,
                "secretKey");

        Objects.requireNonNull(
                publicKey,
                "publicKey");

        if (deviceId.isBlank()) {
            throw new IllegalArgumentException(
                    "deviceId cannot be blank");
        }

        this.deviceId = deviceId;
        this.secretKey = secretKey;
        this.publicKey = publicKey.normalize();
    }

    public String getDeviceId() {
        return deviceId;
    }

    public BigInteger getSecretKey() {
        return secretKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    /**
     * 禁止在 toString() 中输出私钥。
     */
    @Override
    public String toString() {
        return "Device{"
                + "deviceId='" + deviceId + '\''
                + ", publicKeyLength="
                + publicKey.getEncoded(true).length
                + '}';
    }
}