package com.basr.crypto;

import com.basr.entity.RecoveryMaterial;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR 报告、AAD 和签名挑战的统一规范编码。
 *
 * 防止 Sign、SigVerify 和 Recovery 对同一公式采用
 * 不同字段顺序或不同编码。
 */
public final class BasrTranscript {

    private BasrTranscript() {
    }

    /**
     * AAD_i =
     *
     *      ID_i || pk_i || beta_i || bid || t
     */
    public static byte[] buildAad(
            String deviceId,
            ECPoint publicKey,
            int beta,
            String batchId,
            long timestamp) {

        validateCommonFields(
                deviceId,
                publicKey,
                beta,
                batchId);

        return TranscriptEncoder.encode(
                TranscriptEncoder.utf8(deviceId),
                PointCodec.encodeCompressed(publicKey),
                TranscriptEncoder.intValue(beta),
                TranscriptEncoder.utf8(batchId),
                TranscriptEncoder.longValue(timestamp));
    }

    /**
     * d_i = H1(
     *
     *      ID_i || pk_i || beta_i || D_i
     *      || RM_i || bid || t
     *
     * )
     */
    public static BigInteger computeReportDigest(
            PublicParams pp,
            String deviceId,
            ECPoint publicKey,
            int beta,
            byte[] data,
            RecoveryMaterial recoveryMaterial,
            String batchId,
            long timestamp) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(data, "data");

        validateCommonFields(
                deviceId,
                publicKey,
                beta,
                batchId);

        return Hash.H1(
                pp,
                TranscriptEncoder.utf8(deviceId),
                PointCodec.encodeCompressed(publicKey),
                TranscriptEncoder.intValue(beta),
                data,
                encodeRecoveryMaterial(
                        recoveryMaterial),
                TranscriptEncoder.utf8(batchId),
                TranscriptEncoder.longValue(timestamp));
    }

    /**
     * h_i = H2(
     *
     *      bid || t || ID_i || pk_i
     *      || beta_i || d_i || R_i
     *
     * )
     */
    public static BigInteger computeSignatureChallenge(
            PublicParams pp,
            String batchId,
            long timestamp,
            String deviceId,
            ECPoint publicKey,
            int beta,
            BigInteger digest,
            ECPoint commitment) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(digest, "digest");
        Objects.requireNonNull(
                commitment,
                "commitment");

        validateCommonFields(
                deviceId,
                publicKey,
                beta,
                batchId);

        return Hash.H2(
                pp,
                TranscriptEncoder.utf8(batchId),
                TranscriptEncoder.longValue(timestamp),
                TranscriptEncoder.utf8(deviceId),
                PointCodec.encodeCompressed(publicKey),
                TranscriptEncoder.intValue(beta),
                TranscriptEncoder.scalar(
                        digest,
                        pp.getP()),
                PointCodec.encodeCompressed(
                        commitment));
    }

    /**
     * 实例化 RM_i = bottom：
     *
     * - 0x00 表示 bottom；
     * - 0x01 || enc 表示存在恢复材料。
     */
    public static byte[] encodeRecoveryMaterial(
            RecoveryMaterial recoveryMaterial) {

        if (recoveryMaterial == null) {
            return new byte[] {0x00};
        }

        return TranscriptEncoder.concat(
                new byte[] {0x01},
                recoveryMaterial
                        .getEncapsulatedPublicKey());
    }

    private static void validateCommonFields(
            String deviceId,
            ECPoint publicKey,
            int beta,
            String batchId) {

        if (deviceId == null
                || deviceId.isBlank()) {

            throw new IllegalArgumentException(
                    "deviceId cannot be blank");
        }

        Objects.requireNonNull(
                publicKey,
                "publicKey");

        if (beta != 0 && beta != 1) {
            throw new IllegalArgumentException(
                    "beta must be 0 or 1");
        }

        if (batchId == null
                || batchId.isBlank()) {

            throw new IllegalArgumentException(
                    "batchId cannot be blank");
        }
    }
}