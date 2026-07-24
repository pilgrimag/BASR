package com.basr;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Recovery;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.PublicParams;
import com.basr.entity.BatchRecord;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.Report;
import com.basr.entity.SignedReport;
import com.basr.registry.InMemoryDeviceRegistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BASR Data Recovery Protocol 测试。
 *
 * 测试范围：
 *
 * 1. 非敏感报告直接恢复；
 * 2. 敏感报告通过真实 X25519 + AES-GCM 恢复；
 * 3. 目标设备不存在；
 * 4. ID 正确但 R_i 不匹配；
 * 5. 使用错误 DR 恢复密钥；
 * 6. Pkg 被篡改；
 * 7. BRec.mu 被篡改；
 * 8. 敏感报告缺少恢复密钥。
 */
class RecoveryTest {

    private static final String BATCH_ID =
            "batch-001";

    private static final byte[] PUBLIC_MESSAGE =
            "temperature=25"
                    .getBytes(
                            StandardCharsets.UTF_8);

    private static final byte[] SENSITIVE_MESSAGE =
            "confidential-pressure=80"
                    .getBytes(
                            StandardCharsets.UTF_8);

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private InMemoryDeviceRegistry registry;

    private Device publicDevice;

    private Device sensitiveDevice;

    /**
     * 同一测试批次共享的真实 Unix 毫秒时间戳。
     */
    private long batchTimestamp;

    @BeforeEach
    void setUp() {

        pp = Setup.setup(128);

        recoveryKey =
                RecKeyGen.generate(pp);

        registry =
                new InMemoryDeviceRegistry();

        batchTimestamp =
                System.currentTimeMillis();

        publicDevice =
                registerDevice(
                        "device-public");

        sensitiveDevice =
                registerDevice(
                        "device-sensitive");
    }

    /**
     * 非敏感报告应直接返回原始 D_i=m_i。
     *
     * 该分支不需要 DR 恢复私钥，因此传入 null。
     */
    @Test
    void nonSensitiveReportShouldRecoverWithoutRecoveryKey() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry target =
                findEntry(
                        result,
                        publicDevice.getDeviceId());

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        null,
                        result,
                        target.report()
                                .getDeviceId(),
                        target.commitment());

        assertTrue(recovered.isPresent());

        assertArrayEquals(
                PUBLIC_MESSAGE,
                recovered.orElseThrow());
    }

    /**
     * 敏感报告应通过：
     *
     *      X25519 KEM.Decap
     *      +
     *      AES-256-GCM Dec
     *
     * 恢复出原始明文。
     */
    @Test
    void sensitiveReportShouldRecover() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry target =
                findEntry(
                        result,
                        sensitiveDevice.getDeviceId());

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        recoveryKey,
                        result,
                        target.report()
                                .getDeviceId(),
                        target.commitment());

        assertTrue(recovered.isPresent());

        assertArrayEquals(
                SENSITIVE_MESSAGE,
                recovered.orElseThrow());
    }

    /**
     * 已验证敏感报告的测量入口应正确恢复明文，
     * 并分别返回 KEM.Decap 与 AEAD.Dec 时间。
     */
    @Test
    void measuredSensitiveRecoveryShouldSeparateCryptoStages() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry target =
                findEntry(
                        result,
                        sensitiveDevice.getDeviceId());

        Optional<Recovery.RecoveryMeasurement> optionalMeasurement =
                Recovery.recoverSensitivePreverified(
                        pp,
                        recoveryKey,
                        target.report());

        assertTrue(
                optionalMeasurement.isPresent());

        Recovery.RecoveryMeasurement measurement =
                optionalMeasurement.orElseThrow();

        assertArrayEquals(
                SENSITIVE_MESSAGE,
                measurement.plaintext());

        assertTrue(
                measurement.kemDecapNs() > 0L);

        assertTrue(
                measurement.aeadDecryptNs() > 0L);

        assertEquals(
                Math.addExact(
                        measurement.kemDecapNs(),
                        measurement.aeadDecryptNs()),
                measurement.totalNs());
    }

    /**
     * 预验证恢复入口只能处理合法敏感报告，
     * 且使用错误恢复密钥时必须失败。
     */
    @Test
    void measuredRecoveryShouldRejectInvalidInputs() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry publicEntry =
                findEntry(
                        result,
                        publicDevice.getDeviceId());

        assertTrue(
                Recovery.recoverSensitivePreverified(
                                pp,
                                recoveryKey,
                                publicEntry.report())
                        .isEmpty());

        Aggregate.PackageEntry sensitiveEntry =
                findEntry(
                        result,
                        sensitiveDevice.getDeviceId());

        RecoveryKey wrongRecoveryKey =
                RecKeyGen.generate(pp);

        assertTrue(
                Recovery.recoverSensitivePreverified(
                                pp,
                                wrongRecoveryKey,
                                sensitiveEntry.report())
                        .isEmpty());
    }

    /**
     * Pkg 中不存在指定设备身份时应返回 empty。
     */
    @Test
    void unknownTargetDeviceShouldReturnEmpty() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry existing =
                result.packageEntries()
                        .get(0);

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        recoveryKey,
                        result,
                        "device-not-present",
                        existing.commitment());

        assertTrue(recovered.isEmpty());
    }

    /**
     * 即使 ID_i 正确，如果 R_i 不匹配，
     * 也不能恢复该设备的报告。
     */
    @Test
    void correctDeviceWithWrongCommitmentShouldReturnEmpty() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry publicEntry =
                findEntry(
                        result,
                        publicDevice.getDeviceId());

        Aggregate.PackageEntry sensitiveEntry =
                findEntry(
                        result,
                        sensitiveDevice.getDeviceId());

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        recoveryKey,
                        result,
                        publicEntry.report()
                                .getDeviceId(),
                        sensitiveEntry.commitment());

        assertTrue(recovered.isEmpty());
    }

    /**
     * 使用另一组 X25519 恢复密钥时，
     * KEM 解封装得到不同的对称密钥，
     * 最终 AES-GCM 认证必须失败。
     */
    @Test
    void wrongRecoveryKeyShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry target =
                findEntry(
                        result,
                        sensitiveDevice.getDeviceId());

        RecoveryKey wrongRecoveryKey =
                RecKeyGen.generate(pp);

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        wrongRecoveryKey,
                        result,
                        target.report()
                                .getDeviceId(),
                        target.commitment());

        assertTrue(recovered.isEmpty());
    }

    /**
     * Pkg 中的报告数据被篡改时，
     * AggVerify 应首先失败，Recovery 不得继续解密。
     */
    @Test
    void tamperedPackageShouldFailBeforeRecovery() {

        Aggregate.Result result =
                createValidAggregate();

        List<Aggregate.PackageEntry> tamperedPackage =
                new ArrayList<>(
                        result.packageEntries());

        Aggregate.PackageEntry originalEntry =
                tamperedPackage.get(0);

        Report originalReport =
                originalEntry.report();

        /*
         * 修改 D_i，但保留原来的 d_i。
         *
         * AggVerify 重新计算摘要时会发现：
         *
         *      d_i' != d_i
         */
        Report tamperedReport =
                new Report(
                        originalReport.getDeviceId(),
                        originalReport.getPublicKey(),
                        originalReport.getBeta(),
                        "tampered-data"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        originalReport
                                .getRecoveryMaterial(),
                        originalReport.getBatchId(),
                        originalReport.getTimestamp(),
                        originalReport.getDigest());

        tamperedPackage.set(
                0,
                new Aggregate.PackageEntry(
                        tamperedReport,
                        originalEntry.commitment()));

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        recoveryKey,
                        result.batchRecord(),
                        tamperedPackage,
                        originalReport.getDeviceId(),
                        originalEntry.commitment());

        assertTrue(recovered.isEmpty());
    }

    /**
     * BRec 中的 mu 被篡改时，
     * AggVerify 应失败，Recovery 不得继续。
     */
    @Test
    void tamperedMuShouldFailBeforeRecovery() {

        Aggregate.Result result =
                createValidAggregate();

        BatchRecord originalRecord =
                result.batchRecord();

        byte[] tamperedMu =
                originalRecord.getMu();

        tamperedMu[0] ^= 0x01;

        BatchRecord tamperedRecord =
                new BatchRecord(
                        originalRecord.getBatchId(),
                        originalRecord.getTimestamp(),
                        originalRecord
                                .getAggregateSignature(),
                        tamperedMu,
                        originalRecord.getCid());

        Aggregate.PackageEntry target =
                findEntry(
                        result,
                        sensitiveDevice.getDeviceId());

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        recoveryKey,
                        tamperedRecord,
                        result.packageEntries(),
                        target.report()
                                .getDeviceId(),
                        target.commitment());

        assertTrue(recovered.isEmpty());
    }

    /**
     * 敏感报告没有提供 DR 恢复密钥时，
     * 应返回 empty。
     */
    @Test
    void missingRecoveryKeyShouldFailForSensitiveReport() {

        Aggregate.Result result =
                createValidAggregate();

        Aggregate.PackageEntry target =
                findEntry(
                        result,
                        sensitiveDevice.getDeviceId());

        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        null,
                        result,
                        target.report()
                                .getDeviceId(),
                        target.commitment());

        assertTrue(recovered.isEmpty());
    }

    /**
     * 构造包含：
     *
     * 1. 一个非敏感报告；
     * 2. 一个敏感报告。
     */
    private Aggregate.Result createValidAggregate() {

        SignedReport publicReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        publicDevice,
                        PUBLIC_MESSAGE,
                        0,
                        BATCH_ID,
                        batchTimestamp);

        SignedReport sensitiveReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        sensitiveDevice,
                        SENSITIVE_MESSAGE,
                        1,
                        BATCH_ID,
                        batchTimestamp);

        return Aggregate.aggregate(
                        pp,
                        registry,
                        List.of(
                                publicReport,
                                sensitiveReport),
                        BATCH_ID,
                        batchTimestamp)
                .orElseThrow();
    }

    /**
     * 注册一个测试设备。
     */
    private Device registerDevice(
            String deviceId) {

        Device device =
                Registration.generateDevice(
                        pp,
                        deviceId);

        boolean accepted =
                Registration.verifyAndRegister(
                                pp,
                                registry,
                                Registration.createRequest(
                                        pp,
                                        device))
                        .isAccepted();

        assertTrue(
                accepted,
                "Test device registration must succeed");

        return device;
    }

    /**
     * 根据设备 ID 查找测试聚合结果中的条目。
     *
     * 测试构造中，每个设备只有一个报告。
     */
    private static Aggregate.PackageEntry findEntry(
            Aggregate.Result result,
            String deviceId) {

        return result.packageEntries()
                .stream()
                .filter(entry ->
                        deviceId.equals(
                                entry.report()
                                        .getDeviceId()))
                .findFirst()
                .orElseThrow();
    }
}