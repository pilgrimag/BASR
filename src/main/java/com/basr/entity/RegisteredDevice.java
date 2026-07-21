package com.basr.entity;

import org.bouncycastle.math.ec.ECPoint;

import java.util.Objects;

/**
 * 公共设备注册记录。
 *
 * 对应注册列表中的：
 *
 *      (ID_i, pk_i)
 *
 * 该对象绝不能包含 sk_i。
 */
public final class RegisteredDevice {

    private final String deviceId;

    private final ECPoint publicKey;

    public RegisteredDevice(
            String deviceId,
            ECPoint publicKey) {

        this.deviceId =
                Objects.requireNonNull(
                        deviceId,
                        "deviceId");

        this.publicKey =
                Objects.requireNonNull(
                        publicKey,
                        "publicKey")
                        .normalize();
    }

    public String getDeviceId() {
        return deviceId;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }
}