package com.basr;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.AggVerify;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Recovery;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.PublicParams;
import com.basr.entity.BatchRecord;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.SignedReport;
import com.basr.ipfs.IpfsClient;
import com.basr.ipfs.KuboHttpIpfsClient;
import com.basr.persistence.PackageCodec;
import com.basr.registry.InMemoryDeviceRegistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BASR Pkg 与真实 Kubo IPFS 节点的集成测试。
 *
 * 流程：
 *
 * Aggregate
 *   -> PackageCodec.encode
 *   -> IPFS.put
 *   -> CID
 *   -> IPFS.get
 *   -> PackageCodec.decode
 *   -> AggVerify
 *   -> Recovery
 */
class IpfsPackageIntegrationTest {

    private PublicParams pp;

    private RecoveryKey recoveryKey;

    private InMemoryDeviceRegistry registry;

    private Device publicDevice;

    private Device sensitiveDevice;

    private IpfsClient ipfsClient;

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
                register("device-public");

        sensitiveDevice =
                register("device-sensitive");

        String rpcAddress =
                System.getProperty(
                        "basr.ipfs.rpc",
                        "http://127.0.0.1:5001");

        ipfsClient =
                new KuboHttpIpfsClient(
                        URI.create(rpcAddress));

        /*
         * 普通 mvn test 时若 Kubo 未启动则跳过集成测试，
         * 不影响纯算法单元测试。
         */
        Assumptions.assumeTrue(
                ipfsClient.isAvailable(),
                "Kubo RPC is unavailable. Start: ipfs daemon");
    }

    @Test
    void packageShouldRoundTripThroughRealIpfs() {

        byte[] publicMessage =
                "temperature=27.1"
                        .getBytes(
                                StandardCharsets.UTF_8);

        byte[] sensitiveMessage =
                "confidential-pressure=82.2"
                        .getBytes(
                                StandardCharsets.UTF_8);

        SignedReport publicReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        publicDevice,
                        publicMessage,
                        0,
                        "batch-ipfs",
                        batchTimestamp);

        SignedReport sensitiveReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        sensitiveDevice,
                        sensitiveMessage,
                        1,
                        "batch-ipfs",
                        batchTimestamp);

        Aggregate.Result localResult =
                Aggregate.aggregate(
                                pp,
                                registry,
                                List.of(
                                        publicReport,
                                        sensitiveReport),
                                "batch-ipfs",
                                batchTimestamp)
                        .orElseThrow();

        /*
         * 确定性编码 Pkg。
         */
        byte[] packageBytes =
                PackageCodec.encode(
                        pp,
                        localResult);

        /*
         * 写入真实 IPFS，获得真实 CID。
         */
        String cid =
                ipfsClient.put(packageBytes);

        assertNotNull(cid);
        assertFalse(cid.isBlank());

        /*
         * 补全 BRec 中的 cid。
         */
        BatchRecord completeBatchRecord =
                localResult
                        .batchRecord()
                        .withCid(cid);

        assertTrue(
                completeBatchRecord.hasCid());

        assertEquals(
                cid,
                completeBatchRecord.getCid());

        /*
         * 根据 CID 从 IPFS 读取原始字节。
         */
        byte[] downloadedBytes =
                ipfsClient.get(cid);

        assertArrayEquals(
                packageBytes,
                downloadedBytes);

        /*
         * 解码为运行时 Pkg。
         */
        PackageCodec.DecodedPackage decoded =
                PackageCodec.decode(
                        pp,
                        downloadedBytes);

        assertEquals(
                completeBatchRecord.getBatchId(),
                decoded.batchId());

        assertEquals(
                completeBatchRecord.getTimestamp(),
                decoded.timestamp());

        /*
         * 使用链上 BRec 语义和 IPFS Pkg 执行聚合验证。
         */
        assertTrue(
                AggVerify.verify(
                        pp,
                        registry,
                        completeBatchRecord,
                        decoded.packageEntries()));

        Aggregate.PackageEntry sensitiveEntry =
                decoded.packageEntries()
                        .stream()
                        .filter(entry ->
                                entry.report().getBeta() == 1)
                        .findFirst()
                        .orElseThrow();

        /*
         * 使用真实 IPFS Pkg 恢复敏感报告。
         */
        byte[] recovered =
                Recovery.recover(
                                pp,
                                registry,
                                recoveryKey,
                                completeBatchRecord,
                                decoded.packageEntries(),
                                sensitiveEntry
                                        .report()
                                        .getDeviceId(),
                                sensitiveEntry.commitment())
                        .orElseThrow();

        assertArrayEquals(
                sensitiveMessage,
                recovered);

        System.out.println();
        System.out.println(
                "========== BASR IPFS Integration ==========");

        System.out.println(
                "packageBytes = "
                        + packageBytes.length);

        System.out.println(
                "cid          = "
                        + cid);

        System.out.println(
                "mu           = "
                        + HexFormat.of()
                                .formatHex(
                                        completeBatchRecord
                                                .getMu()));

        System.out.println(
                "AggVerify    = PASS");

        System.out.println(
                "Recovery     = "
                        + new String(
                                recovered,
                                StandardCharsets.UTF_8));

        System.out.println(
                "==========================================");
        System.out.println();
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