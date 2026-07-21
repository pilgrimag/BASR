package com.basr;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.AggVerify;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.PublicParams;
import com.basr.entity.AggregateSignature;
import com.basr.entity.BatchRecord;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.Report;
import com.basr.entity.SignedReport;
import com.basr.registry.InMemoryDeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BASR AggVerify 测试。
 */
class AggVerifyTest {

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private InMemoryDeviceRegistry registry;

    private Device deviceOne;

    private Device deviceTwo;

    private Device deviceThree;

    /**
     * 同一测试批次中的统一真实时间戳。
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

        deviceOne =
                registerDevice("device-001");

        deviceTwo =
                registerDevice("device-002");

        deviceThree =
                registerDevice("device-003");
    }

    /**
     * 合法的 BRec 和 Pkg 应验证成功。
     */
    @Test
    void validAggregateShouldPass() {

        Aggregate.Result result =
                createValidAggregate();

        assertTrue(
                AggVerify.verify(
                        pp,
                        registry,
                        result));
    }

    /**
     * 空 Pkg 对应 q=0，必须验证失败。
     */
    @Test
    void emptyPackageShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        result.batchRecord(),
                        List.of()));
    }

    /**
     * Pkg 中出现相同的 (ID_i,R_i) 时必须失败。
     */
    @Test
    void duplicateDeviceCommitmentShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        List<Aggregate.PackageEntry> duplicated =
                new ArrayList<>(
                        result.packageEntries());

        duplicated.add(
                result.packageEntries().get(0));

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        result.batchRecord(),
                        duplicated));
    }

    /**
     * 篡改报告数据 D_i 后，d_i' != d_i，
     * 因此验证必须失败。
     */
    @Test
    void tamperedReportDataShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        List<Aggregate.PackageEntry> tamperedPackage =
                new ArrayList<>(
                        result.packageEntries());

        Aggregate.PackageEntry originalEntry =
                tamperedPackage.get(0);

        Report originalReport =
                originalEntry.report();

        Report tamperedReport =
                new Report(
                        originalReport.getDeviceId(),
                        originalReport.getPublicKey(),
                        originalReport.getBeta(),
                        "tampered-data"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        originalReport.getRecoveryMaterial(),
                        originalReport.getBatchId(),
                        originalReport.getTimestamp(),
                        originalReport.getDigest());

        tamperedPackage.set(
                0,
                new Aggregate.PackageEntry(
                        tamperedReport,
                        originalEntry.commitment()));

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        result.batchRecord(),
                        tamperedPackage));
    }

    /**
     * 篡改 mu 后，mu' != mu，验证必须失败。
     */
    @Test
    void tamperedMuShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        BatchRecord original =
                result.batchRecord();

        byte[] tamperedMu =
                original.getMu();

        tamperedMu[0] ^= 0x01;

        BatchRecord tamperedRecord =
                new BatchRecord(
                        original.getBatchId(),
                        original.getTimestamp(),
                        original.getAggregateSignature(),
                        tamperedMu,
                        original.getCid());

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        tamperedRecord,
                        result.packageEntries()));
    }

    /**
     * 篡改 R_agg 后，R' != R_agg，
     * 验证必须失败。
     */
    @Test
    void tamperedAggregateCommitmentShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        BatchRecord original =
                result.batchRecord();

        AggregateSignature originalSignature =
                original.getAggregateSignature();

        ECPoint tamperedRagg =
                originalSignature
                        .getRagg()
                        .add(pp.getGenerator())
                        .normalize();

        AggregateSignature tamperedSignature =
                new AggregateSignature(
                        tamperedRagg,
                        originalSignature.getSagg());

        BatchRecord tamperedRecord =
                new BatchRecord(
                        original.getBatchId(),
                        original.getTimestamp(),
                        tamperedSignature,
                        original.getMu(),
                        original.getCid());

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        tamperedRecord,
                        result.packageEntries()));
    }

    /**
     * 篡改 s_agg 后，最终聚合签名等式必须失败。
     */
    @Test
    void tamperedAggregateResponseShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        BatchRecord original =
                result.batchRecord();

        AggregateSignature originalSignature =
                original.getAggregateSignature();

        BigInteger tamperedSagg =
                originalSignature
                        .getSagg()
                        .add(BigInteger.ONE)
                        .mod(pp.getP());

        AggregateSignature tamperedSignature =
                new AggregateSignature(
                        originalSignature.getRagg(),
                        tamperedSagg);

        BatchRecord tamperedRecord =
                new BatchRecord(
                        original.getBatchId(),
                        original.getTimestamp(),
                        tamperedSignature,
                        original.getMu(),
                        original.getCid());

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        tamperedRecord,
                        result.packageEntries()));
    }

    /**
     * Pkg 顺序发生变化时，mu' 会变化，
     * 因而验证必须失败。
     */
    @Test
    void reorderedPackageShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        List<Aggregate.PackageEntry> reordered =
                new ArrayList<>(
                        result.packageEntries());

        Collections.reverse(reordered);

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        result.batchRecord(),
                        reordered));
    }

    /**
     * BRec 中的批次时间戳被修改时，
     * t_i != t，验证必须失败。
     */
    @Test
    void mismatchedBatchTimestampShouldFail() {

        Aggregate.Result result =
                createValidAggregate();

        BatchRecord original =
                result.batchRecord();

        BatchRecord tamperedRecord =
                new BatchRecord(
                        original.getBatchId(),
                        original.getTimestamp() + 1_000L,
                        original.getAggregateSignature(),
                        original.getMu(),
                        original.getCid());

        assertFalse(
                AggVerify.verify(
                        pp,
                        registry,
                        tamperedRecord,
                        result.packageEntries()));
    }

    /**
     * 生成一个包含三个合法报告的聚合结果。
     */
    private Aggregate.Result createValidAggregate() {

        SignedReport first =
                sign(
                        deviceOne,
                        "temperature=25",
                        0);

        SignedReport second =
                sign(
                        deviceTwo,
                        "confidential-pressure=80",
                        1);

        SignedReport third =
                sign(
                        deviceThree,
                        "humidity=40",
                        0);

        return Aggregate.aggregate(
                        pp,
                        registry,
                        List.of(
                                first,
                                second,
                                third),
                        "batch-001",
                        batchTimestamp)
                .orElseThrow();
    }

    /**
     * 注册测试设备。
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
     * 使用当前测试批次的统一时间戳签名。
     */
    private SignedReport sign(
            Device device,
            String message,
            int beta) {

        return Sign.sign(
                pp,
                recoveryKey.getPublicKey(),
                device,
                message.getBytes(
                        StandardCharsets.UTF_8),
                beta,
                "batch-001",
                batchTimestamp);
    }
}