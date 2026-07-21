package com.basr;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.AggVerify;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Recovery;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.SigVerify;
import com.basr.algorithm.Sign;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.entity.BatchRecord;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.SignedReport;
import com.basr.registry.InMemoryDeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BASR 本地原型端到端测试。
 *
 * 覆盖流程：
 *
 * Setup
 *   -> Register
 *   -> RecKeyGen
 *   -> Sign
 *   -> SigVerify
 *   -> Aggregate
 *   -> AggVerify
 *   -> Recovery
 *
 * 当前测试不调用 Fabric 和 IPFS：
 *
 * 1. InMemoryDeviceRegistry 代替链上设备注册表；
 * 2. Aggregate.Result 直接携带 BRec 和 Pkg；
 * 3. BatchRecord.cid 在本地阶段为 null。
 *
 * 所有密码操作均为真实实现：
 *
 * - secp256k1 Schnorr；
 * - X25519 DHKEM；
 * - HKDF-HMAC-SHA-256；
 * - AES-256-GCM；
 * - SHA-256 域分离哈希。
 */
class BasrEndToEndTest {

    private static final String BATCH_ID =
            "batch-end-to-end";

    private static final byte[] REPORT_ONE =
            "temperature=26.8"
                    .getBytes(StandardCharsets.UTF_8);

    private static final byte[] REPORT_TWO =
            "confidential-pressure=81.6"
                    .getBytes(StandardCharsets.UTF_8);

    private static final byte[] REPORT_THREE =
            "humidity=43"
                    .getBytes(StandardCharsets.UTF_8);

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private InMemoryDeviceRegistry registry;

    private Device deviceOne;

    private Device deviceTwo;

    private Device deviceThree;

    /**
     * 未注册设备，用于验证注册表检查和聚合过滤行为。
     */
    private Device unregisteredDevice;

    /**
     * 同一批次内所有设备共享同一个真实 Unix 毫秒时间戳。
     */
    private long batchTimestamp;

    @BeforeEach
    void setUp() {

        /*
         * Step 1：系统初始化。
         */
        pp = Setup.setup(128);

        /*
         * Step 2：生成 DR 恢复密钥。
         */
        recoveryKey =
                RecKeyGen.generate(pp);

        /*
         * 当前使用内存注册表代替 Fabric 世界状态。
         */
        registry =
                new InMemoryDeviceRegistry();

        /*
         * 批次时间戳只生成一次。
         *
         * 不能让每个设备分别读取当前时间，
         * 否则它们可能因毫秒差异而无法进入同一批次。
         */
        batchTimestamp =
                System.currentTimeMillis();

        /*
         * 生成并注册三台合法设备。
         */
        deviceOne =
                generateAndRegister(
                        "device-001");

        deviceTwo =
                generateAndRegister(
                        "device-002");

        deviceThree =
                generateAndRegister(
                        "device-003");

        /*
         * 生成但不注册第四台设备。
         */
        unregisteredDevice =
                Registration.generateDevice(
                        pp,
                        "device-unregistered");
    }

    /**
     * 完整成功流程，同时检查非法候选过滤和重复报告去重。
     */
    @Test
    void completeBasrWorkflowShouldSucceed() {

        /*
         * Step 3：设备一生成非敏感报告。
         */
        SignedReport signedReportOne =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceOne,
                        REPORT_ONE,
                        0,
                        BATCH_ID,
                        batchTimestamp);

        /*
         * Step 4：设备二生成敏感报告。
         *
         * 内部执行：
         *
         * - X25519 KEM.Encap；
         * - HKDF；
         * - AES-256-GCM；
         * - Schnorr 签名。
         */
        SignedReport signedReportTwo =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceTwo,
                        REPORT_TWO,
                        1,
                        BATCH_ID,
                        batchTimestamp);

        /*
         * Step 5：设备三生成非敏感报告。
         */
        SignedReport signedReportThree =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceThree,
                        REPORT_THREE,
                        0,
                        BATCH_ID,
                        batchTimestamp);

        /*
         * 未注册设备也可以在本地计算数学签名，
         * 但其签名不能通过带注册表检查的 SigVerify。
         */
        SignedReport unregisteredReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        unregisteredDevice,
                        "rogue-report"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        BATCH_ID,
                        batchTimestamp);

        /*
         * Step 6：逐个验证合法设备签名。
         */
        assertTrue(
                SigVerify.verify(
                        pp,
                        registry,
                        signedReportOne));

        assertTrue(
                SigVerify.verify(
                        pp,
                        registry,
                        signedReportTwo));

        assertTrue(
                SigVerify.verify(
                        pp,
                        registry,
                        signedReportThree));

        /*
         * 未注册设备必须验证失败。
         */
        assertFalse(
                SigVerify.verify(
                        pp,
                        registry,
                        unregisteredReport));

        /*
         * Step 7：执行聚合。
         *
         * 候选集合包含：
         *
         * 1. 三个合法报告；
         * 2. signedReportOne 的完全重复项；
         * 3. 未注册设备报告。
         *
         * 预期：
         *
         * - 重复项按 (ID_i,R_i) 去除；
         * - 未注册设备报告被 SigVerify 过滤；
         * - 最终接受三个报告。
         */
        Aggregate.Result aggregateResult =
                Aggregate.aggregate(
                                pp,
                                registry,
                                List.of(
                                        signedReportOne,
                                        signedReportTwo,
                                        signedReportOne,
                                        signedReportThree,
                                        unregisteredReport),
                                BATCH_ID,
                                batchTimestamp)
                        .orElseThrow();

        assertEquals(
                3,
                aggregateResult.acceptedCount());

        BatchRecord batchRecord =
                aggregateResult.batchRecord();

        assertEquals(
                BATCH_ID,
                batchRecord.getBatchId());

        assertEquals(
                batchTimestamp,
                batchRecord.getTimestamp());

        /*
         * 当前尚未执行 IPFS.Put(Pkg)。
         */
        assertFalse(batchRecord.hasCid());
        assertNull(batchRecord.getCid());

        /*
         * Step 8：验证聚合签名和批次包。
         */
        assertTrue(
                AggVerify.verify(
                        pp,
                        registry,
                        aggregateResult));

        /*
         * 找到三个目标报告对应的 Pkg 条目。
         */
        Aggregate.PackageEntry entryOne =
                findEntry(
                        aggregateResult,
                        deviceOne.getDeviceId());

        Aggregate.PackageEntry entryTwo =
                findEntry(
                        aggregateResult,
                        deviceTwo.getDeviceId());

        Aggregate.PackageEntry entryThree =
                findEntry(
                        aggregateResult,
                        deviceThree.getDeviceId());

        /*
         * Step 9：恢复非敏感报告。
         *
         * 非敏感报告不需要 DR 私钥，因此 recoveryKey 可传 null。
         */
        Optional<byte[]> recoveredOne =
                Recovery.recover(
                        pp,
                        registry,
                        null,
                        aggregateResult,
                        entryOne.report()
                                .getDeviceId(),
                        entryOne.commitment());

        assertTrue(recoveredOne.isPresent());

        assertArrayEquals(
                REPORT_ONE,
                recoveredOne.orElseThrow());

        /*
         * Step 10：恢复敏感报告。
         *
         * 内部执行：
         *
         * - AggVerify；
         * - X25519 KEM.Decap；
         * - HKDF；
         * - AES-256-GCM 解密和认证。
         */
        Optional<byte[]> recoveredTwo =
                Recovery.recover(
                        pp,
                        registry,
                        recoveryKey,
                        aggregateResult,
                        entryTwo.report()
                                .getDeviceId(),
                        entryTwo.commitment());

        assertTrue(recoveredTwo.isPresent());

        assertArrayEquals(
                REPORT_TWO,
                recoveredTwo.orElseThrow());

        /*
         * Step 11：恢复第三个非敏感报告。
         */
        Optional<byte[]> recoveredThree =
                Recovery.recover(
                        pp,
                        registry,
                        null,
                        aggregateResult,
                        entryThree.report()
                                .getDeviceId(),
                        entryThree.commitment());

        assertTrue(recoveredThree.isPresent());

        assertArrayEquals(
                REPORT_THREE,
                recoveredThree.orElseThrow());

        /*
         * Step 12：错误 DR 密钥不能恢复敏感报告。
         */
        RecoveryKey wrongRecoveryKey =
                RecKeyGen.generate(pp);

        Optional<byte[]> wrongRecoveryResult =
                Recovery.recover(
                        pp,
                        registry,
                        wrongRecoveryKey,
                        aggregateResult,
                        entryTwo.report()
                                .getDeviceId(),
                        entryTwo.commitment());

        assertTrue(
                wrongRecoveryResult.isEmpty());

        /*
         * 打印完整本地流程结果。
         */
        printWorkflowResult(
                aggregateResult,
                recoveredOne.orElseThrow(),
                recoveredTwo.orElseThrow(),
                recoveredThree.orElseThrow());
    }

    /**
     * 检查 BRec 被篡改后，AggVerify 和 Recovery 均失败。
     */
    @Test
    void tamperedBatchShouldFailVerificationAndRecovery() {

        SignedReport signedReportOne =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceOne,
                        REPORT_ONE,
                        0,
                        BATCH_ID,
                        batchTimestamp);

        SignedReport signedReportTwo =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceTwo,
                        REPORT_TWO,
                        1,
                        BATCH_ID,
                        batchTimestamp);

        Aggregate.Result validResult =
                Aggregate.aggregate(
                                pp,
                                registry,
                                List.of(
                                        signedReportOne,
                                        signedReportTwo),
                                BATCH_ID,
                                batchTimestamp)
                        .orElseThrow();

        assertTrue(
                AggVerify.verify(
                        pp,
                        registry,
                        validResult));

        /*
         * 修改 BRec 中的 mu。
         *
         * getMu() 返回副本，不会修改原始 BatchRecord。
         */
        byte[] tamperedMu =
                validResult
                        .batchRecord()
                        .getMu();

        tamperedMu[0] ^= 0x01;

        BatchRecord originalRecord =
                validResult.batchRecord();

        BatchRecord tamperedRecord =
                new BatchRecord(
                        originalRecord.getBatchId(),
                        originalRecord.getTimestamp(),
                        originalRecord
                                .getAggregateSignature(),
                        tamperedMu,
                        originalRecord.getCid());

        /*
         * Pkg 内容未变，但 mu 已经不匹配。
         */
        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        tamperedRecord,
                        validResult.packageEntries()));

        Aggregate.PackageEntry sensitiveEntry =
                findEntry(
                        validResult,
                        deviceTwo.getDeviceId());

        /*
         * Recovery 必须首先调用 AggVerify，
         * 因而不能在批次验证失败后继续解密。
         */
        Optional<byte[]> recovered =
                Recovery.recover(
                        pp,
                        registry,
                        recoveryKey,
                        tamperedRecord,
                        validResult.packageEntries(),
                        sensitiveEntry.report()
                                .getDeviceId(),
                        sensitiveEntry.commitment());

        assertTrue(recovered.isEmpty());
    }

    /**
     * 生成并注册一个设备。
     */
    private Device generateAndRegister(
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
                "Device registration must succeed: "
                        + deviceId);

        return device;
    }

    /**
     * 在聚合包中查找某设备的唯一报告。
     *
     * 当前端到端测试中每台设备只提交一个有效报告。
     */
    private static Aggregate.PackageEntry findEntry(
            Aggregate.Result result,
            String deviceId) {

        return result
                .packageEntries()
                .stream()
                .filter(entry ->
                        deviceId.equals(
                                entry.report()
                                        .getDeviceId()))
                .findFirst()
                .orElseThrow();
    }

    /**
     * 输出完整流程结果。
     *
     * 不输出任何设备私钥、DR 私钥或对称密钥。
     */
    private static void printWorkflowResult(
            Aggregate.Result result,
            byte[] recoveredOne,
            byte[] recoveredTwo,
            byte[] recoveredThree) {

        HexFormat hex =
                HexFormat.of();

        BatchRecord batchRecord =
                result.batchRecord();

        ECPoint aggregateCommitment =
                batchRecord
                        .getAggregateSignature()
                        .getRagg();

        String encodedAggregateCommitment =
                aggregateCommitment.isInfinity()
                        ? "POINT_AT_INFINITY"
                        : hex.formatHex(
                                PointCodec
                                        .encodeCompressed(
                                                aggregateCommitment));

        System.out.println();
        System.out.println(
                "========== BASR End-to-End Result ==========");

        System.out.println(
                "batchId          = "
                        + batchRecord.getBatchId());

        System.out.println(
                "timestamp        = "
                        + batchRecord.getTimestamp());

        System.out.println(
                "registeredCount  = 3");

        System.out.println(
                "acceptedCount    = "
                        + result.acceptedCount());

        System.out.println(
                "Ragg             = "
                        + encodedAggregateCommitment);

        System.out.println(
                "sagg             = "
                        + batchRecord
                                .getAggregateSignature()
                                .getSagg()
                                .toString(16));

        System.out.println(
                "mu               = "
                        + hex.formatHex(
                                batchRecord.getMu()));

        System.out.println(
                "cid              = "
                        + batchRecord.getCid());

        System.out.println(
                "AggVerify        = PASS");

        System.out.println(
                "recovered[0]     = "
                        + new String(
                                recoveredOne,
                                StandardCharsets.UTF_8));

        System.out.println(
                "recovered[1]     = "
                        + new String(
                                recoveredTwo,
                                StandardCharsets.UTF_8));

        System.out.println(
                "recovered[2]     = "
                        + new String(
                                recoveredThree,
                                StandardCharsets.UTF_8));

        System.out.println(
                "wrong-key test   = PASS");

        System.out.println(
                "============================================");
        System.out.println();
    }
}