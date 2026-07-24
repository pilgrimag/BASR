package com.basr.algorithm;

import com.basr.crypto.Aead;
import com.basr.crypto.BasrTranscript;
import com.basr.crypto.Kem;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.crypto.ScalarSampler;
import com.basr.crypto.Schnorr;
import com.basr.crypto.X25519Codec;
import com.basr.entity.Device;
import com.basr.entity.RecoveryMaterial;
import com.basr.entity.Report;
import com.basr.entity.Signature;
import com.basr.entity.SignedReport;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * BASR Algorithm 3 Sign。
 */
public final class Sign {

    private Sign() {
    }

    /**
     * BASR 签名阶段的细分密码学计时。
     *
     * <p>所有时间均使用 {@link System#nanoTime()} 测量，
     * 单位为纳秒。</p>
     *
     * @param signedReport 生成的完整签名报告
     * @param kemEncapNs KEM 封装时间；公开报告为 0
     * @param aeadEncryptNs AEAD 加密时间；公开报告为 0
     * @param signatureNs 报告摘要与 Schnorr 签名生成时间
     */
    public record SignMeasurement(
            SignedReport signedReport,
            long kemEncapNs,
            long aeadEncryptNs,
            long signatureNs) {

        public SignMeasurement {
            Objects.requireNonNull(
                    signedReport,
                    "signedReport");

            if (kemEncapNs < 0
                    || aeadEncryptNs < 0
                    || signatureNs < 0) {

                throw new IllegalArgumentException(
                        "Measured times cannot be negative");
            }
        }

        /**
         * 敏感数据保护时间：
         * KEM.Encap + AEAD.Enc。
         */
        public long privacyNs() {
            return Math.addExact(
                    kemEncapNs,
                    aeadEncryptNs);
        }

        /**
         * 本方法覆盖的密码学总时间：
         * privacy + digest/Schnorr signature。
         */
        public long cryptoTotalNs() {
            return Math.addExact(
                    privacyNs(),
                    signatureNs);
        }
    }

    /**
     * 执行设备报告签名。
     *
     * @param pp                系统公共参数
     * @param recoveryPublicKey DR 恢复公钥 pk_R
     * @param device            设备及其签名密钥
     * @param rawReport         原始报告 m_i
     * @param beta              敏感标志 beta_i
     * @param batchId           批次标识 bid
     * @param timestamp         时间戳 t
     */
    public static SignedReport sign(
            PublicParams pp,
            XECPublicKey recoveryPublicKey,
            Device device,
            byte[] rawReport,
            int beta,
            String batchId,
            long timestamp) {

        return signMeasured(
                pp,
                recoveryPublicKey,
                device,
                rawReport,
                beta,
                batchId,
                timestamp)
                .signedReport();
    }

    /**
     * 执行设备报告签名，并返回各密码学子阶段的测量结果。
     */
    public static SignMeasurement signMeasured(
            PublicParams pp,
            XECPublicKey recoveryPublicKey,
            Device device,
            byte[] rawReport,
            int beta,
            String batchId,
            long timestamp) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(
                recoveryPublicKey,
                "recoveryPublicKey");
        Objects.requireNonNull(
                device,
                "device");
        Objects.requireNonNull(
                rawReport,
                "rawReport");

        if (beta != 0 && beta != 1) {
            throw new IllegalArgumentException(
                    "beta must be 0 or 1");
        }

        if (batchId == null
                || batchId.isBlank()) {

            throw new IllegalArgumentException(
                    "batchId cannot be blank");
        }

        X25519Codec.requireX25519(
                recoveryPublicKey);

        long kemEncapNs = 0L;
        long aeadEncryptNs = 0L;

        /*
         * 确保设备对象中的 pk_i 确实由 sk_i 导出。
         */
        ECPoint expectedPublicKey =
                Schnorr.derivePublicKey(
                        pp,
                        device.getSecretKey());

        if (!expectedPublicKey.equals(
                device.getPublicKey()
                        .normalize())) {

            throw new IllegalArgumentException(
                    "Device public key does not match secret key");
        }

        if (!PointCodec.isValidGroupElement(
                pp,
                device.getPublicKey())) {

            throw new IllegalArgumentException(
                    "Device public key is not in G");
        }

        byte[] data;
        RecoveryMaterial recoveryMaterial = null;

        if (beta == 1) {

            /*
             * (RM_i, K_i) <-
             *      KEM.Encap(pp_KEM, pk_R)
             */
            long kemStart =
                    System.nanoTime();

            try (Kem.Encapsulation encapsulation =
                         Kem.encap(
                                 pp,
                                 recoveryPublicKey)) {

                kemEncapNs =
                        System.nanoTime() - kemStart;

                recoveryMaterial =
                        encapsulation
                                .getRecoveryMaterial();

                byte[] symmetricKey =
                        encapsulation
                                .copySharedSecret();

                try {
                    /*
                     * AAD_i =
                     *
                     * ID_i || pk_i || beta_i || bid || t
                     */
                    byte[] associatedData =
                            BasrTranscript.buildAad(
                                    device.getDeviceId(),
                                    device.getPublicKey(),
                                    beta,
                                    batchId,
                                    timestamp);

                    /*
                     * D_i <-
                     *
                     * AEAD.Enc(
                     *      pp_AEAD,
                     *      K_i,
                     *      m_i,
                     *      AAD_i
                     * )
                     */
                    long aeadStart =
                            System.nanoTime();

                    data =
                            Aead.encrypt(
                                    pp,
                                    symmetricKey,
                                    rawReport,
                                    associatedData);

                    aeadEncryptNs =
                            System.nanoTime() - aeadStart;

                } finally {
                    Arrays.fill(
                            symmetricKey,
                            (byte) 0);
                }
            }

        } else {

            /*
             * beta_i = 0：
             *
             *      D_i = m_i
             *      RM_i = bottom
             */
            data = rawReport.clone();
        }

        /*
         * d_i = H1(
         *
         *      ID_i || pk_i || beta_i || D_i
         *      || RM_i || bid || t
         *
         * )
         */
        long signatureStart =
                System.nanoTime();

        BigInteger digest =
                BasrTranscript.computeReportDigest(
                        pp,
                        device.getDeviceId(),
                        device.getPublicKey(),
                        beta,
                        data,
                        recoveryMaterial,
                        batchId,
                        timestamp);

        Report report =
                new Report(
                        device.getDeviceId(),
                        device.getPublicKey(),
                        beta,
                        data,
                        recoveryMaterial,
                        batchId,
                        timestamp,
                        digest);

        /*
         * r_i <-$ Z_p^*
         */
        BigInteger nonce =
                ScalarSampler.sampleNonZero(
                        pp.getP());

        /*
         * R_i = [r_i]g
         */
        ECPoint commitment =
                Schnorr.createCommitment(
                        pp,
                        nonce);

        /*
         * h_i = H2(
         *
         *      bid || t || ID_i || pk_i
         *      || beta_i || d_i || R_i
         *
         * )
         */
        BigInteger challenge =
                BasrTranscript
                        .computeSignatureChallenge(
                                pp,
                                batchId,
                                timestamp,
                                device.getDeviceId(),
                                device.getPublicKey(),
                                beta,
                                digest,
                                commitment);

        /*
         * s_i =
         *
         *      r_i + h_i * sk_i mod p
         */
        BigInteger response =
                Schnorr.computeResponse(
                        pp,
                        nonce,
                        challenge,
                        device.getSecretKey());

        Signature signature =
                new Signature(
                        commitment,
                        response);

        SignedReport signedReport =
                new SignedReport(
                        report,
                        signature);

        long signatureNs =
                System.nanoTime() - signatureStart;

        return new SignMeasurement(
                signedReport,
                kemEncapNs,
                aeadEncryptNs,
                signatureNs);
    }
}