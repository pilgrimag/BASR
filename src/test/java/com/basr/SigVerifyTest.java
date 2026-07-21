package com.basr;

import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.SigVerify;
import com.basr.algorithm.Sign;
import com.basr.crypto.PublicParams;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.Report;
import com.basr.entity.Signature;
import com.basr.entity.SignedReport;
import com.basr.registry.InMemoryDeviceRegistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BASR SigVerify 测试。
 *
 * 验证目标：
 *
 * 1. 合法非敏感报告验证成功；
 * 2. 合法敏感报告验证成功；
 * 3. 未注册设备验证失败；
 * 4. 报告数据被篡改后验证失败；
 * 5. 报告摘要被篡改后验证失败；
 * 6. Schnorr 响应被篡改后验证失败；
 * 7. 超出 Z_p 范围的响应被拒绝。
 */
class SigVerifyTest {

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private InMemoryDeviceRegistry registry;

    private Device registeredDevice;

    @BeforeEach
    void setUp() {

        /*
         * 初始化系统公共参数。
         */
        pp = Setup.setup(128);

        /*
         * 生成 DR 恢复密钥。
         */
        recoveryKey =
                RecKeyGen.generate(pp);

        /*
         * 创建本地设备注册表。
         */
        registry =
                new InMemoryDeviceRegistry();

        /*
         * 生成并注册一个合法设备。
         */
        registeredDevice =
                Registration.generateDevice(
                        pp,
                        "device-001");

        boolean registered =
                Registration.verifyAndRegister(
                                pp,
                                registry,
                                Registration.createRequest(
                                        pp,
                                        registeredDevice))
                        .isAccepted();

        assertTrue(
                registered,
                "Test device registration must succeed");
    }

    /**
     * 合法非敏感报告应验证成功。
     */
    @Test
    void validNonSensitiveSignatureShouldPass() {

        SignedReport signedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        registeredDevice,
                        "temperature=25.6"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        1000L);

        assertTrue(
                SigVerify.verify(
                        pp,
                        registry,
                        signedReport));
    }

    /**
     * 合法敏感报告应验证成功。
     *
     * SigVerify 不需要解密数据，
     * 只验证密文 D_i、恢复材料 RM_i 和签名之间的绑定关系。
     */
    @Test
    void validSensitiveSignatureShouldPass() {

        SignedReport signedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        registeredDevice,
                        "confidential-measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        1,
                        "batch-001",
                        1000L);

        assertTrue(
                SigVerify.verify(
                        pp,
                        registry,
                        signedReport));
    }

    /**
     * 即使签名数学上有效，如果设备未注册，
     * SigVerify 也必须返回 false。
     */
    @Test
    void unregisteredDeviceShouldFail() {

        Device unregisteredDevice =
                Registration.generateDevice(
                        pp,
                        "device-unregistered");

        SignedReport signedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        unregisteredDevice,
                        "measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        1000L);

        assertFalse(
                SigVerify.verify(
                        pp,
                        registry,
                        signedReport));
    }

    /**
     * 修改 D_i 后，重新计算得到的 d_i' 与原 d_i 不同，
     * 因此验证必须失败。
     */
    @Test
    void tamperedReportDataShouldFail() {

        SignedReport validSignedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        registeredDevice,
                        "original-data"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        1000L);

        Report validReport =
                validSignedReport.getReport();

        Report tamperedReport =
                new Report(
                        validReport.getDeviceId(),
                        validReport.getPublicKey(),
                        validReport.getBeta(),
                        "tampered-data"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        validReport.getRecoveryMaterial(),
                        validReport.getBatchId(),
                        validReport.getTimestamp(),
                        validReport.getDigest());

        assertFalse(
                SigVerify.verify(
                        pp,
                        registry,
                        tamperedReport,
                        validSignedReport.getSignature()));
    }

    /**
     * 直接修改报告摘要 d_i 后，验证必须失败。
     */
    @Test
    void tamperedReportDigestShouldFail() {

        SignedReport validSignedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        registeredDevice,
                        "measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        1000L);

        Report validReport =
                validSignedReport.getReport();

        BigInteger tamperedDigest =
                validReport.getDigest()
                        .add(BigInteger.ONE)
                        .mod(pp.getP());

        Report tamperedReport =
                new Report(
                        validReport.getDeviceId(),
                        validReport.getPublicKey(),
                        validReport.getBeta(),
                        validReport.getData(),
                        validReport.getRecoveryMaterial(),
                        validReport.getBatchId(),
                        validReport.getTimestamp(),
                        tamperedDigest);

        assertFalse(
                SigVerify.verify(
                        pp,
                        registry,
                        tamperedReport,
                        validSignedReport.getSignature()));
    }

    /**
     * 修改 Schnorr 响应 s_i 后，群等式应验证失败。
     */
    @Test
    void tamperedSignatureResponseShouldFail() {

        SignedReport validSignedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        registeredDevice,
                        "measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        1000L);

        Signature validSignature =
                validSignedReport.getSignature();

        BigInteger tamperedResponse =
                validSignature.getS()
                        .add(BigInteger.ONE)
                        .mod(pp.getP());

        Signature tamperedSignature =
                new Signature(
                        validSignature.getR(),
                        tamperedResponse);

        assertFalse(
                SigVerify.verify(
                        pp,
                        registry,
                        validSignedReport.getReport(),
                        tamperedSignature));
    }

    /**
     * s_i 必须属于 Z_p。
     *
     * 当 s_i = p 时已经超出合法范围，
     * 验证应在执行群等式前直接拒绝。
     */
    @Test
    void responseOutsideScalarFieldShouldFail() {

        SignedReport validSignedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        registeredDevice,
                        "measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        1000L);

        Signature invalidSignature =
                new Signature(
                        validSignedReport
                                .getSignature()
                                .getR(),
                        pp.getP());

        assertFalse(
                SigVerify.verify(
                        pp,
                        registry,
                        validSignedReport.getReport(),
                        invalidSignature));
    }
}