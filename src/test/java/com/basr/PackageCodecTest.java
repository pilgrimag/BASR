package com.basr;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.AggVerify;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Recovery;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.PublicParams;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.SignedReport;
import com.basr.persistence.PackageCodec;
import com.basr.registry.InMemoryDeviceRegistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BASR Pkg 确定性编解码测试。
 */
class PackageCodecTest {

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private InMemoryDeviceRegistry registry;

    private Device deviceOne;

    private Device deviceTwo;

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
                register("device-001");

        deviceTwo =
                register("device-002");
    }

    /**
     * 同一个 Pkg 重复编码必须得到完全相同的字节。
     */
    @Test
    void encodingShouldBeDeterministic() {

        Aggregate.Result result =
                createAggregate();

        byte[] first =
                PackageCodec.encode(
                        pp,
                        result);

        byte[] second =
                PackageCodec.encode(
                        pp,
                        result);

        assertArrayEquals(first, second);
    }

    /**
     * encode -> decode -> encode 必须保持字节完全一致。
     */
    @Test
    void roundTripShouldPreserveCanonicalBytes() {

        Aggregate.Result result =
                createAggregate();

        byte[] original =
                PackageCodec.encode(
                        pp,
                        result);

        PackageCodec.DecodedPackage decoded =
                PackageCodec.decode(
                        pp,
                        original);

        byte[] reEncoded =
                PackageCodec.encode(
                        pp,
                        decoded.batchId(),
                        decoded.timestamp(),
                        decoded.packageEntries());

        assertArrayEquals(
                original,
                reEncoded);
    }

    /**
     * 解码后的 Pkg 必须继续通过 AggVerify。
     */
    @Test
    void decodedPackageShouldPassAggregateVerification() {

        Aggregate.Result result =
                createAggregate();

        byte[] encoded =
                PackageCodec.encode(
                        pp,
                        result);

        PackageCodec.DecodedPackage decoded =
                PackageCodec.decode(
                        pp,
                        encoded);

        assertTrue(
                AggVerify.verify(
                        pp,
                        registry,
                        result.batchRecord(),
                        decoded.packageEntries()));
    }

    /**
     * 解码后的敏感报告必须能够真实恢复。
     */
    @Test
    void decodedSensitiveReportShouldRecover() {

        Aggregate.Result result =
                createAggregate();

        PackageCodec.DecodedPackage decoded =
                PackageCodec.decode(
                        pp,
                        PackageCodec.encode(
                                pp,
                                result));

        Aggregate.PackageEntry sensitiveEntry =
                decoded.packageEntries()
                        .stream()
                        .filter(entry ->
                                entry.report().getBeta() == 1)
                        .findFirst()
                        .orElseThrow();

        byte[] recovered =
                Recovery.recover(
                                pp,
                                registry,
                                recoveryKey,
                                result.batchRecord(),
                                decoded.packageEntries(),
                                sensitiveEntry
                                        .report()
                                        .getDeviceId(),
                                sensitiveEntry.commitment())
                        .orElseThrow();

        assertArrayEquals(
                "secret-pressure=81.6"
                        .getBytes(
                                StandardCharsets.UTF_8),
                recovered);
    }

    /**
     * 截断包必须被拒绝。
     */
    @Test
    void truncatedPackageShouldBeRejected() {

        byte[] encoded =
                PackageCodec.encode(
                        pp,
                        createAggregate());

        byte[] truncated =
                Arrays.copyOf(
                        encoded,
                        encoded.length - 1);

        assertThrows(
                IllegalArgumentException.class,
                () -> PackageCodec.decode(
                        pp,
                        truncated));
    }

    /**
     * 尾部附加数据必须被拒绝。
     */
    @Test
    void trailingBytesShouldBeRejected() {

        byte[] encoded =
                PackageCodec.encode(
                        pp,
                        createAggregate());

        byte[] modified =
                Arrays.copyOf(
                        encoded,
                        encoded.length + 1);

        modified[modified.length - 1] =
                0x01;

        assertThrows(
                IllegalArgumentException.class,
                () -> PackageCodec.decode(
                        pp,
                        modified));
    }

    private Aggregate.Result createAggregate() {

        SignedReport first =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceOne,
                        "temperature=26.8"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        0,
                        "batch-codec",
                        batchTimestamp);

        SignedReport second =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        deviceTwo,
                        "secret-pressure=81.6"
                                .getBytes(
                                        StandardCharsets.UTF_8),
                        1,
                        "batch-codec",
                        batchTimestamp);

        return Aggregate.aggregate(
                        pp,
                        registry,
                        List.of(first, second),
                        "batch-codec",
                        batchTimestamp)
                .orElseThrow();
    }

    private Device register(
            String deviceId) {

        Device device =
                Registration.generateDevice(
                        pp,
                        deviceId);

        assertTrue(
                Registration.verifyAndRegister(
                                pp,
                                registry,
                                Registration.createRequest(
                                        pp,
                                        device))
                        .isAccepted());

        return device;
    }
}