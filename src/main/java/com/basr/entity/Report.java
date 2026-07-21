package com.basr.entity;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR 设备报告描述符：
 *
 * rep_i = (
 *      ID_i,
 *      pk_i,
 *      beta_i,
 *      D_i,
 *      RM_i,
 *      bid,
 *      t,
 *      d_i
 * )
 */
public final class Report {

    private final String deviceId;

    private final ECPoint publicKey;

    private final int beta;

    /**
     * beta=0：原始报告 m_i；
     * beta=1：AEAD 密文 D_i。
     */
    private final byte[] data;

    /**
     * beta=0：null，表示 bottom；
     * beta=1：真实 KEM 恢复材料。
     */
    private final RecoveryMaterial recoveryMaterial;

    private final String batchId;

    private final long timestamp;

    private final BigInteger digest;

    public Report(
            String deviceId,
            ECPoint publicKey,
            int beta,
            byte[] data,
            RecoveryMaterial recoveryMaterial,
            String batchId,
            long timestamp,
            BigInteger digest) {

        this.deviceId =
                Objects.requireNonNull(
                        deviceId,
                        "deviceId");

        this.publicKey =
                Objects.requireNonNull(
                        publicKey,
                        "publicKey")
                        .normalize();

        this.data =
                Objects.requireNonNull(
                        data,
                        "data")
                        .clone();

        this.batchId =
                Objects.requireNonNull(
                        batchId,
                        "batchId");

        this.digest =
                Objects.requireNonNull(
                        digest,
                        "digest");

        if (deviceId.isBlank()) {
            throw new IllegalArgumentException(
                    "deviceId cannot be blank");
        }

        if (batchId.isBlank()) {
            throw new IllegalArgumentException(
                    "batchId cannot be blank");
        }

        if (beta != 0 && beta != 1) {
            throw new IllegalArgumentException(
                    "beta must be 0 or 1");
        }

        if (beta == 0
                && recoveryMaterial != null) {

            throw new IllegalArgumentException(
                    "Non-sensitive report must use RM_i = bottom");
        }

        if (beta == 1
                && recoveryMaterial == null) {

            throw new IllegalArgumentException(
                    "Sensitive report requires recovery material");
        }

        if (digest.signum() < 0) {
            throw new IllegalArgumentException(
                    "digest cannot be negative");
        }

        this.beta = beta;
        this.recoveryMaterial =
                recoveryMaterial;
        this.timestamp = timestamp;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public int getBeta() {
        return beta;
    }

    public byte[] getData() {
        return data.clone();
    }

    public RecoveryMaterial getRecoveryMaterial() {
        return recoveryMaterial;
    }

    public boolean hasRecoveryMaterial() {
        return recoveryMaterial != null;
    }

    public String getBatchId() {
        return batchId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public BigInteger getDigest() {
        return digest;
    }
}