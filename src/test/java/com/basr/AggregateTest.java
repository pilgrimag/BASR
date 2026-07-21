package com.basr;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.BasrTranscript;
import com.basr.crypto.Hash;
import com.basr.crypto.PublicParams;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.Signature;
import com.basr.entity.SignedReport;
import com.basr.registry.InMemoryDeviceRegistry;
import com.basr.crypto.PointCodec;
import com.basr.entity.BatchRecord;
import com.basr.entity.Report;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BASR Aggregate 测试。
 */
class AggregateTest {

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private InMemoryDeviceRegistry registry;

    private Device deviceOne;

    private Device deviceTwo;

    private Device deviceThree;

    /**
     * 当前测试批次的真实 Unix 毫秒时间戳。
     *
     * 该值在每个测试开始时只生成一次，
     * 同一测试中的所有报告和聚合操作共享该值。
     */
    private long batchTimestamp;

    @BeforeEach
    void setUp() {

        pp = Setup.setup(128);

        recoveryKey =
                RecKeyGen.generate(pp);

        registry =
                new InMemoryDeviceRegistry();

        /*
        * 读取当前真实 Unix 毫秒时间戳。
        *
        * 该时间戳作为本测试批次的统一时间戳，
        * 后续所有设备报告和 Aggregate 都使用同一个值。
        */
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
     * 多个合法报告应正确聚合。
     */
    @Test
    void validReportsShouldAggregate() {

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

        Optional<Aggregate.Result> optionalResult =
                Aggregate.aggregate(
                        pp,
                        registry,
                        List.of(
                                first,
                                second,
                                third),
                        "batch-001",
                        batchTimestamp);

        assertTrue(optionalResult.isPresent());

        Aggregate.Result result =
                optionalResult.orElseThrow();

        /*
        * 打印聚合返回结果。
        */
        // printAggregateResult(result);

        assertEquals(
                3,
                result.acceptedCount());

        /*
         * 验证 R_agg = R_1 + R_2 + R_3。
         */
        ECPoint expectedCommitment =
                first.getSignature()
                        .getR()
                        .add(
                                second.getSignature()
                                        .getR())
                        .add(
                                third.getSignature()
                                        .getR())
                        .normalize();

        assertEquals(
                expectedCommitment,
                result.batchRecord()
                        .getAggregateSignature()
                        .getRagg());

        /*
         * 验证 s_agg = s_1 + s_2 + s_3 mod p。
         */
        BigInteger expectedResponse =
                first.getSignature()
                        .getS()
                        .add(
                                second.getSignature()
                                        .getS())
                        .add(
                                third.getSignature()
                                        .getS())
                        .mod(pp.getP());

        assertEquals(
                expectedResponse,
                result.batchRecord()
                        .getAggregateSignature()
                        .getSagg());

        /*
         * 本地阶段没有生成伪造 CID。
         */
        assertFalse(
                result.batchRecord()
                        .hasCid());

        assertNull(
                result.batchRecord()
                        .getCid());

        /*
         * 验证 mu 严格由有序 Pkg 重新计算得到。
         */
        byte[][] entries =
                result.packageEntries()
                        .stream()
                        .map(entry ->
                                BasrTranscript
                                        .encodePackageEntry(
                                                pp,
                                                entry.report(),
                                                entry.commitment()))
                        .toArray(byte[][]::new);

        byte[] expectedMu =
                Hash.H3(pp, entries);

        assertArrayEquals(
                expectedMu,
                result.batchRecord()
                        .getMu());
    }

    /**
     * 完全相同的 (ID_i, R_i) 只能被接受一次。
     */
    @Test
    void exactDeviceCommitmentDuplicateShouldBeRemoved() {

        SignedReport signedReport =
                sign(
                        deviceOne,
                        "measurement",
                        0);

        Aggregate.Result result =
                Aggregate.aggregate(
                                pp,
                                registry,
                                List.of(
                                        signedReport,
                                        signedReport),
                                "batch-001",
                                batchTimestamp)
                        .orElseThrow();

        assertEquals(
                1,
                result.acceptedCount());
    }

    /**
     * 算法按 (ID_i,R_i) 去重。
     *
     * 因此同一设备使用不同随机数产生不同 R_i 时，
     * 两个报告均可被接受。
     */
    @Test
    void sameDeviceWithDifferentCommitmentsShouldRemain() {

        SignedReport first =
                sign(
                        deviceOne,
                        "same-measurement",
                        0);

        SignedReport second =
                sign(
                        deviceOne,
                        "same-measurement",
                        0);

        assertNotEquals(
                first.getSignature().getR(),
                second.getSignature().getR());

        Aggregate.Result result =
                Aggregate.aggregate(
                                pp,
                                registry,
                                List.of(first, second),
                                "batch-001",
                                batchTimestamp)
                        .orElseThrow();

        assertEquals(
                2,
                result.acceptedCount());
    }

    /**
     * 无效条目不会进入 U。
     *
     * 因此如果无效版本在前、合法版本在后，且二者具有
     * 相同的 (ID_i,R_i)，后面的合法版本仍应被接受。
     */
    @Test
    void invalidDuplicateShouldNotBlockLaterValidEntry() {

        SignedReport valid =
                sign(
                        deviceOne,
                        "measurement",
                        0);

        BigInteger invalidResponse =
                valid.getSignature()
                        .getS()
                        .add(BigInteger.ONE)
                        .mod(pp.getP());

        Signature tamperedSignature =
                new Signature(
                        valid.getSignature().getR(),
                        invalidResponse);

        SignedReport invalid =
                new SignedReport(
                        valid.getReport(),
                        tamperedSignature);

        Aggregate.Result result =
                Aggregate.aggregate(
                                pp,
                                registry,
                                List.of(invalid, valid),
                                "batch-001",
                                batchTimestamp)
                        .orElseThrow();

        assertEquals(
                1,
                result.acceptedCount());

        assertEquals(
                valid.getSignature().getR(),
                result.packageEntries()
                        .get(0)
                        .commitment());
    }

    /**
     * 批次或时间戳不匹配的报告必须被忽略。
     */
    @Test
    void mismatchedBatchOrTimestampShouldBeFiltered() {

        SignedReport validForAnotherBatch =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceOne,
                        "measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-002",
                        batchTimestamp);
        
        /*
        * 使用另一个真实含义明确的时间戳，
        * 表示目标批次时间之后 1 秒。
        */
        long differentTimestamp =
                batchTimestamp + 1_000L;

        SignedReport validForAnotherTime =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceTwo,
                        "measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        differentTimestamp);

        Optional<Aggregate.Result> result =
                Aggregate.aggregate(
                        pp,
                        registry,
                        List.of(
                                validForAnotherBatch,
                                validForAnotherTime),
                        "batch-001",
                        batchTimestamp);

        assertTrue(result.isEmpty());
    }

    /**
     * 所有候选报告都无效时应返回 bottom。
     */
    @Test
    void noValidEntryShouldReturnEmpty() {

        Device unregistered =
                Registration.generateDevice(
                        pp,
                        "device-unregistered");

        SignedReport signedReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        unregistered,
                        "measurement"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-001",
                        batchTimestamp);

        Optional<Aggregate.Result> result =
                Aggregate.aggregate(
                        pp,
                        registry,
                        List.of(signedReport),
                        "batch-001",
                        batchTimestamp);

        assertTrue(result.isEmpty());
    }

    /**
     * 注册并返回设备。
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
     * 使用固定目标批次签名报告。
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
                // 1000L);
                batchTimestamp); // 采用真实时间戳
    }

    /**
     * 以可读格式打印 Aggregate 的返回结果。
     *
     * 注意：
     * - 椭圆曲线点使用 SEC1 压缩编码；
     * - 标量使用十六进制；
     * - 不输出任何设备私钥或 DR 私钥。
     */
    private void printAggregateResult(
            Aggregate.Result result) {

        HexFormat hex = HexFormat.of();

        BatchRecord batchRecord =
                result.batchRecord();

        System.out.println();
        System.out.println("========== BASR Aggregate Result ==========");

        System.out.println(
                "acceptedCount = "
                        + result.acceptedCount());

        System.out.println(
                "batchId       = "
                        + batchRecord.getBatchId());

        System.out.println(
                "timestamp     = "
                        + batchRecord.getTimestamp());

        /*
        * Ragg 是 secp256k1 群元素，
        * 使用压缩点编码输出，而不是直接调用 ECPoint.toString()。
        */
        byte[] encodedRagg =
                PointCodec.encodeCompressed(
                        batchRecord
                                .getAggregateSignature()
                                .getRagg());

        System.out.println(
                "Ragg          = "
                        + hex.formatHex(encodedRagg));

        /*
        * sagg 是 Z_p 中的标量。
        */
        System.out.println(
                "sagg          = "
                        + batchRecord
                                .getAggregateSignature()
                                .getSagg()
                                .toString(16));

        /*
        * mu 是 H3 输出的批次承诺摘要。
        */
        System.out.println(
                "mu            = "
                        + hex.formatHex(
                                batchRecord.getMu()));

        /*
        * 当前尚未调用 IPFS.Put，
        * 因而 cid 应为 null。
        */
        System.out.println(
                "cid           = "
                        + batchRecord.getCid());

        System.out.println();
        System.out.println("---------- Package Entries ----------");

        for (int index = 0;
            index < result.packageEntries().size();
            index++) {

            Aggregate.PackageEntry entry =
                    result.packageEntries().get(index);

            Report report =
                    entry.report();

            System.out.println(
                    "Entry[" + index + "]");

            System.out.println(
                    "  deviceId  = "
                            + report.getDeviceId());

            System.out.println(
                    "  beta      = "
                            + report.getBeta());

            System.out.println(
                    "  batchId   = "
                            + report.getBatchId());

            System.out.println(
                    "  timestamp = "
                            + report.getTimestamp());

            System.out.println(
                    "  dataBytes = "
                            + report.getData().length);

            System.out.println(
                    "  hasRM     = "
                            + report.hasRecoveryMaterial());

            System.out.println(
                    "  digest    = "
                            + report
                                    .getDigest()
                                    .toString(16));

            System.out.println(
                    "  R_i       = "
                            + hex.formatHex(
                                    PointCodec
                                            .encodeCompressed(
                                                    entry.commitment())));
        }

        System.out.println(
                "===========================================");
        System.out.println();
    }
}