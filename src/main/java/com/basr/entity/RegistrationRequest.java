package com.basr.entity;

import org.bouncycastle.math.ec.ECPoint;

import java.util.Objects;

/**
 * 设备注册请求。
 *
 * 对应算法中的：
 *
 *      tau_reg = (ID_i, pk_i, POP_i)
 *
 * 请求中只包含公开信息，不包含设备私钥 sk_i。
 */
public final class RegistrationRequest {

    private final String deviceId;

    private final ECPoint publicKey;

    private final ProofOfPossession proofOfPossession;

    public RegistrationRequest(
            String deviceId,
            ECPoint publicKey,
            ProofOfPossession proofOfPossession) {

        this.deviceId =
                Objects.requireNonNull(
                        deviceId,
                        "deviceId");

        this.publicKey =
                Objects.requireNonNull(
                        publicKey,
                        "publicKey")
                        .normalize();

        this.proofOfPossession =
                Objects.requireNonNull(
                        proofOfPossession,
                        "proofOfPossession");
    }

    public String getDeviceId() {
        return deviceId;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public ProofOfPossession getProofOfPossession() {
        return proofOfPossession;
    }
}