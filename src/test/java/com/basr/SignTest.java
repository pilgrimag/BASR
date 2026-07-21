package com.basr;

import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.Aead;
import com.basr.crypto.BasrTranscript;
import com.basr.crypto.Kem;
import com.basr.crypto.PublicParams;
import com.basr.crypto.Schnorr;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.Report;
import com.basr.entity.Signature;
import com.basr.entity.SignedReport;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SignTest {

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private Device device;

    @BeforeEach
    void setUp() {

        pp = Setup.setup(128);

        recoveryKey =
                RecKeyGen.generate(pp);

        device =
                Registration.generateDevice(
                        pp,
                        "device-001");
    }

    @Test
    void nonSensitiveReportShouldBeSigned() {

        byte[] message =
                "temperature=28.5"
                        .getBytes(
                                StandardCharsets.UTF_8);

        SignedReport result =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        device,
                        message,
                        0,
                        "batch-001",
                        1000L);

        Report report = result.getReport();

        assertEquals(0, report.getBeta());

        assertArrayEquals(
                message,
                report.getData());

        assertFalse(
                report.hasRecoveryMaterial());

        assertReportDigestAndSignatureValid(
                result);
    }

    @Test
    void sensitiveReportShouldEncryptAndRecover() {

        byte[] message =
                "device-secret-measurement"
                        .getBytes(
                                StandardCharsets.UTF_8);

        SignedReport result =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        device,
                        message,
                        1,
                        "batch-001",
                        1000L);

        Report report = result.getReport();

        assertEquals(1, report.getBeta());

        assertTrue(
                report.hasRecoveryMaterial());

        assertFalse(
                Arrays.equals(
                        message,
                        report.getData()));

        byte[] symmetricKey =
                Kem.decap(
                        pp,
                        recoveryKey,
                        report.getRecoveryMaterial());

        try {
            byte[] associatedData =
                    BasrTranscript.buildAad(
                            report.getDeviceId(),
                            report.getPublicKey(),
                            report.getBeta(),
                            report.getBatchId(),
                            report.getTimestamp());

            byte[] recovered =
                    Aead.decrypt(
                            pp,
                            symmetricKey,
                            report.getData(),
                            associatedData);

            assertArrayEquals(
                    message,
                    recovered);

        } finally {
            Arrays.fill(
                    symmetricKey,
                    (byte) 0);
        }

        assertReportDigestAndSignatureValid(
                result);
    }

    @Test
    void tamperedAssociatedDataShouldFail() {

        SignedReport result =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        device,
                        "secret".getBytes(
                                StandardCharsets.UTF_8),
                        1,
                        "batch-001",
                        1000L);

        Report report = result.getReport();

        byte[] symmetricKey =
                Kem.decap(
                        pp,
                        recoveryKey,
                        report.getRecoveryMaterial());

        try {
            /*
             * 将 batchId 改为另一个值，
             * AEAD 认证必须失败。
             */
            byte[] tamperedAad =
                    BasrTranscript.buildAad(
                            report.getDeviceId(),
                            report.getPublicKey(),
                            report.getBeta(),
                            "batch-002",
                            report.getTimestamp());

            assertThrows(
                    SecurityException.class,
                    () -> Aead.decrypt(
                            pp,
                            symmetricKey,
                            report.getData(),
                            tamperedAad));

        } finally {
            Arrays.fill(
                    symmetricKey,
                    (byte) 0);
        }
    }

    @Test
    void invalidBetaShouldFail() {

        assertThrows(
                IllegalArgumentException.class,
                () -> Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        device,
                        new byte[] {1, 2, 3},
                        2,
                        "batch-001",
                        1000L));
    }

    @Test
    void repeatedSigningShouldUseFreshNonce() {

        byte[] message =
                "same-report".getBytes(
                        StandardCharsets.UTF_8);

        SignedReport first =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        device,
                        message,
                        0,
                        "batch-001",
                        1000L);

        SignedReport second =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        device,
                        message,
                        0,
                        "batch-001",
                        1000L);

        assertNotEquals(
                first.getSignature().getR(),
                second.getSignature().getR());

        /*
         * beta=0 且所有报告字段相同，因此 d_i 应相同；
         * 但 Schnorr 随机承诺 R_i 应不同。
         */
        assertEquals(
                first.getReport().getDigest(),
                second.getReport().getDigest());
    }

    @Test
    void inconsistentDeviceKeyPairShouldFail() {

        Device other =
                Registration.generateDevice(
                        pp,
                        "device-002");

        Device inconsistent =
                new Device(
                        device.getDeviceId(),
                        device.getSecretKey(),
                        other.getPublicKey());

        assertThrows(
                IllegalArgumentException.class,
                () -> Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        inconsistent,
                        new byte[] {1},
                        0,
                        "batch-001",
                        1000L));
    }

    private void assertReportDigestAndSignatureValid(
            SignedReport signedReport) {

        Report report =
                signedReport.getReport();

        Signature signature =
                signedReport.getSignature();

        BigInteger expectedDigest =
                BasrTranscript.computeReportDigest(
                        pp,
                        report.getDeviceId(),
                        report.getPublicKey(),
                        report.getBeta(),
                        report.getData(),
                        report.getRecoveryMaterial(),
                        report.getBatchId(),
                        report.getTimestamp());

        assertEquals(
                expectedDigest,
                report.getDigest());

        BigInteger challenge =
                BasrTranscript
                        .computeSignatureChallenge(
                                pp,
                                report.getBatchId(),
                                report.getTimestamp(),
                                report.getDeviceId(),
                                report.getPublicKey(),
                                report.getBeta(),
                                report.getDigest(),
                                signature.getR());

        assertTrue(
                Schnorr.verifyResponse(
                        pp,
                        report.getPublicKey(),
                        signature.getR(),
                        challenge,
                        signature.getS()));
    }
}