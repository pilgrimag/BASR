package com.basr.chaincode;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.crypto.TranscriptEncoder;
import com.basr.entity.BatchRecord;
import com.basr.entity.Device;
import com.basr.entity.ProofOfPossession;
import com.basr.entity.RecoveryKey;
import com.basr.entity.RegistrationRequest;
import com.basr.entity.SignedReport;
import com.basr.ipfs.IpfsClient;
import com.basr.ipfs.KuboHttpIpfsClient;
import com.basr.persistence.PackageCodec;
import com.basr.registry.InMemoryDeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;

import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * BASR Chaincode 单元测试。
 *
 * 真实执行：
 *
 * - secp256k1 设备密钥生成；
 * - Schnorr POP 生成与链码验证；
 * - BASR Sign；
 * - BASR Aggregate；
 * - 确定性 PackageCodec；
 * - 真实 Kubo IPFS add/cat；
 * - 真实 CID；
 * - BRec 链上序列化和读取。
 *
 * 仅模拟 Fabric 运行时提供的：
 *
 * - Context；
 * - ChaincodeStub；
 * - 世界状态键值存储。
 *
 * 不模拟任何密码学或 IPFS 成功输出。
 */
class BasrContractTest {

    private static final String IPFS_RPC_PROPERTY =
            "basr.ipfs.rpc";

    private static final String DEFAULT_IPFS_RPC =
            "http://127.0.0.1:5001";

    private PublicParams pp;

    private BasrContract contract;

    private Context context;

    private ChaincodeStub stub;

    /**
     * 仅用于模拟 Fabric 世界状态。
     *
     * 所有写入值均由真实 Contract 代码生成。
     */
    private Map<String, String> worldState;

    @BeforeEach
    void setUp() {

        pp =
                Setup.setup(128);

        contract =
                new BasrContract();

        worldState =
                new HashMap<>();

        context =
                mock(Context.class);

        stub =
                mock(ChaincodeStub.class);

        when(context.getStub())
                .thenReturn(stub);

        /*
         * Fabric 中不存在的键通常读取为空字符串。
         */
        when(stub.getStringState(anyString()))
                .thenAnswer(invocation -> {

                    String key =
                            invocation.getArgument(
                                    0,
                                    String.class);

                    return worldState.getOrDefault(
                            key,
                            "");
                });

        /*
         * 捕获 Contract 真实产生的世界状态写入。
         */
        doAnswer(invocation -> {

            String key =
                    invocation.getArgument(
                            0,
                            String.class);

            String value =
                    invocation.getArgument(
                            1,
                            String.class);

            worldState.put(
                    key,
                    value);

            return null;

        }).when(stub)
                .putStringState(
                        anyString(),
                        anyString());
    }

    /**
     * 合法设备使用真实密钥和真实 Schnorr POP，
     * 应成功写入链上注册列表。
     */
    @Test
    void validRealPopShouldRegisterAndReadDevice() {

        RegistrationRequest request =
                createRealRegistrationRequest(
                        "device-001");

        assertTrue(
                submitRegistration(request));

        DeviceAsset stored =
                contract.ReadDevice(
                        context,
                        request.getDeviceId());

        assertEquals(
                request.getDeviceId(),
                stored.getDeviceId());

        assertEquals(
                publicKeyHex(request),
                stored.getPublicKeyHex());

        /*
         * 注册写入两个世界状态项：
         *
         * DEVICE:<ID_i>       -> DeviceAsset
         * DEVICE_PK:<pk_i>    -> ID_i
         */
        assertEquals(
                2,
                worldState.size());
    }

    /**
     * 修改真实 POP 的响应 z_i 后，
     * Schnorr POP 验证必须失败。
     */
    @Test
    void forgedPopShouldBeRejected() {

        RegistrationRequest request =
                createRealRegistrationRequest(
                        "device-forged");

        ProofOfPossession proof =
                request.getProofOfPossession();

        BigInteger forgedResponse =
                proof.getResponse()
                        .add(BigInteger.ONE)
                        .mod(pp.getP());

        assertNotEquals(
                proof.getResponse(),
                forgedResponse);

        assertThrows(
                ChaincodeException.class,
                () -> contract.RegisterDevice(
                        context,
                        request.getDeviceId(),
                        publicKeyHex(request),
                        scalarHex(
                                proof.getChallenge()),
                        scalarHex(
                                forgedResponse)));

        /*
         * POP 失败后不得写入任何世界状态。
         */
        assertTrue(
                worldState.isEmpty());
    }

    /**
     * 同一 deviceId 不能重复注册，
     * 即使第二次使用另一组真实密钥和有效 POP。
     */
    @Test
    void duplicateDeviceIdShouldBeRejected() {

        RegistrationRequest first =
                createRealRegistrationRequest(
                        "device-duplicate-id");

        RegistrationRequest second =
                createRealRegistrationRequest(
                        "device-duplicate-id");

        assertNotEquals(
                publicKeyHex(first),
                publicKeyHex(second));

        assertTrue(
                submitRegistration(first));

        assertThrows(
                ChaincodeException.class,
                () -> submitRegistration(second));

        /*
         * 第二次注册失败，状态数量保持不变。
         */
        assertEquals(
                2,
                worldState.size());
    }

    /**
     * 同一个设备公钥不能对应两个不同 ID。
     */
    @Test
    void duplicatePublicKeyShouldBeRejected() {

        RegistrationRequest original =
                createRealRegistrationRequest(
                        "device-original");

        assertTrue(
                submitRegistration(original));

        ProofOfPossession proof =
                original.getProofOfPossession();

        /*
         * 这里使用真实公钥和真实 POP 编码。
         *
         * POP 原本绑定 device-original，但 Contract 在 POP
         * 验证前先执行公钥唯一性检查，因此应直接拒绝重复公钥。
         */
        assertThrows(
                ChaincodeException.class,
                () -> contract.RegisterDevice(
                        context,
                        "device-other",
                        publicKeyHex(original),
                        scalarHex(
                                proof.getChallenge()),
                        scalarHex(
                                proof.getResponse())));

        assertEquals(
                2,
                worldState.size());
    }

    /**
     * IsRegisteredDevice 必须严格检查：
     *
     *      (ID_i,pk_i) in L
     *
     * 而不是只检查 ID 或只检查公钥。
     */
    @Test
    void registeredPairShouldBeRecognizedExactly() {

        RegistrationRequest registered =
                createRealRegistrationRequest(
                        "device-registered");

        RegistrationRequest another =
                createRealRegistrationRequest(
                        "device-another");

        assertTrue(
                submitRegistration(registered));

        assertTrue(
                contract.IsRegisteredDevice(
                        context,
                        registered.getDeviceId(),
                        publicKeyHex(registered)));

        /*
         * ID 正确但公钥不正确。
         */
        assertFalse(
                contract.IsRegisteredDevice(
                        context,
                        registered.getDeviceId(),
                        publicKeyHex(another)));

        /*
         * 公钥正确但 ID 不存在。
         */
        assertFalse(
                contract.IsRegisteredDevice(
                        context,
                        "device-not-registered",
                        publicKeyHex(registered)));
    }

    /**
     * 使用真实 BASR Aggregate、确定性 Pkg 编码和
     * 真实 Kubo CID 创建 BRec，并验证链上读取结果。
     */
    @Test
    void realBatchRecordShouldRoundTrip() {

        RealBatchInput input =
                createRealBatchInput(
                        "batch-chaincode-001");

        assertTrue(
                submitBatchRecord(input));

        BatchRecordAsset stored =
                contract.ReadBatchRecord(
                        context,
                        input.batchRecord()
                                .getBatchId());

        assertEquals(
                input.batchRecord()
                        .getBatchId(),
                stored.getBatchId());

        assertEquals(
                input.batchRecord()
                        .getTimestamp(),
                stored.getTimestamp());

        assertEquals(
                input.aggregateCommitmentHex(),
                stored.getAggregateCommitmentHex());

        assertEquals(
                input.aggregateResponseHex(),
                stored.getAggregateResponseHex());

        assertEquals(
                input.muHex(),
                stored.getMuHex());

        assertEquals(
                input.cid(),
                stored.getCid());

        /*
         * 本测试未注册链上设备，
         * 因此只有一个 BATCH:<bid> 状态项。
         */
        assertEquals(
                1,
                worldState.size());
    }

    /**
     * 同一个 batchId 不能重复写入。
     */
    @Test
    void duplicateBatchIdShouldBeRejected() {

        RealBatchInput input =
                createRealBatchInput(
                        "batch-duplicate");

        assertTrue(
                submitBatchRecord(input));

        assertThrows(
                ChaincodeException.class,
                () -> submitBatchRecord(input));

        assertEquals(
                1,
                worldState.size());
    }

    /**
     * Chaincode 必须拒绝格式错误或越界的 BRec。
     *
     * 除被故意篡改的字段外，其余字段全部来自真实
     * Aggregate 和真实 IPFS 流程。
     */
    @Test
    void malformedBatchFieldsShouldBeRejected() {

        RealBatchInput input =
                createRealBatchInput(
                        "batch-invalid-fields");

        /*
         * 非 CID。
         */
        assertThrows(
                ChaincodeException.class,
                () -> contract.CreateBatchRecord(
                        context,
                        "batch-invalid-cid",
                        input.batchRecord()
                                .getTimestamp(),
                        input.aggregateCommitmentHex(),
                        input.aggregateResponseHex(),
                        input.muHex(),
                        "not-a-valid-cid"));

        /*
         * mu 不是 32 字节。
         */
        assertThrows(
                ChaincodeException.class,
                () -> contract.CreateBatchRecord(
                        context,
                        "batch-invalid-mu",
                        input.batchRecord()
                                .getTimestamp(),
                        input.aggregateCommitmentHex(),
                        input.aggregateResponseHex(),
                        input.muHex()
                                .substring(2),
                        input.cid()));

        /*
         * R_agg 不是 33 字节压缩点，也不是单位元 00。
         */
        assertThrows(
                ChaincodeException.class,
                () -> contract.CreateBatchRecord(
                        context,
                        "batch-invalid-ragg",
                        input.batchRecord()
                                .getTimestamp(),
                        "02",
                        input.aggregateResponseHex(),
                        input.muHex(),
                        input.cid()));

        /*
         * 该值大于 secp256k1 群阶，
         * 因而不是 Z_p 中的合法 s_agg。
         */
        assertThrows(
                ChaincodeException.class,
                () -> contract.CreateBatchRecord(
                        context,
                        "batch-invalid-sagg",
                        input.batchRecord()
                                .getTimestamp(),
                        input.aggregateCommitmentHex(),
                        "ff".repeat(32),
                        input.muHex(),
                        input.cid()));

        /*
         * 所有非法提交都必须在写状态前失败。
         */
        assertTrue(
                worldState.isEmpty());
    }

    /**
     * 使用真实算法创建注册请求。
     */
    private RegistrationRequest
            createRealRegistrationRequest(
                    String deviceId) {

        Device device =
                Registration.generateDevice(
                        pp,
                        deviceId);

        return Registration.createRequest(
                pp,
                device);
    }

    /**
     * 将真实注册请求提交给 Chaincode。
     */
    private boolean submitRegistration(
            RegistrationRequest request) {

        ProofOfPossession proof =
                request.getProofOfPossession();

        return contract.RegisterDevice(
                context,
                request.getDeviceId(),
                publicKeyHex(request),
                scalarHex(
                        proof.getChallenge()),
                scalarHex(
                        proof.getResponse()));
    }

    /**
     * 将 secp256k1 公钥编码为 33 字节压缩点 Hex。
     */
    private static String publicKeyHex(
            RegistrationRequest request) {

        return HexFormat.of()
                .formatHex(
                        PointCodec.encodeCompressed(
                                request.getPublicKey()));
    }

    /**
     * 使用算法模块的统一标量编码：
     *
     *      固定 32 字节、无符号、大端序。
     */
    private String scalarHex(
            BigInteger scalar) {

        return HexFormat.of()
                .formatHex(
                        TranscriptEncoder.scalar(
                                scalar,
                                pp.getP()));
    }

    /**
     * 生成完整且真实的：
     *
     * Aggregate
     *   -> PackageCodec
     *   -> IPFS add
     *   -> CID
     *   -> BRec.withCid
     */
    private RealBatchInput createRealBatchInput(
            String batchId) {

        InMemoryDeviceRegistry localRegistry =
                new InMemoryDeviceRegistry();

        Device publicDevice =
                generateAndRegisterLocally(
                        localRegistry,
                        "device-public-"
                                + batchId);

        Device sensitiveDevice =
                generateAndRegisterLocally(
                        localRegistry,
                        "device-sensitive-"
                                + batchId);

        RecoveryKey recoveryKey =
                RecKeyGen.generate(pp);

        long timestamp =
                System.currentTimeMillis();

        SignedReport publicReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        publicDevice,
                        (
                                "temperature="
                                + batchId
                        ).getBytes(
                                StandardCharsets.UTF_8),
                        0,
                        batchId,
                        timestamp);

        SignedReport sensitiveReport =
                Sign.sign(
                        pp,
                        recoveryKey.getPublicKey(),
                        sensitiveDevice,
                        (
                                "confidential-pressure="
                                + batchId
                        ).getBytes(
                                StandardCharsets.UTF_8),
                        1,
                        batchId,
                        timestamp);

        Aggregate.Result aggregateResult =
                Aggregate.aggregate(
                                pp,
                                localRegistry,
                                List.of(
                                        publicReport,
                                        sensitiveReport),
                                batchId,
                                timestamp)
                        .orElseThrow();

        byte[] packageBytes =
                PackageCodec.encode(
                        pp,
                        aggregateResult);

        IpfsClient ipfsClient =
                realIpfsClient();

        /*
         * 不允许跳过：Kubo 不可用时本测试直接失败。
         */
        assertTrue(
                ipfsClient.isAvailable(),
                "Kubo RPC is unavailable at "
                        + System.getProperty(
                                IPFS_RPC_PROPERTY,
                                DEFAULT_IPFS_RPC)
                        + ". Start the IPFS container.");

        String cid =
                ipfsClient.put(
                        packageBytes);

        assertNotNull(cid);
        assertFalse(cid.isBlank());

        /*
         * 验证 CID 确实能取回完全相同的 Pkg 字节。
         */
        assertArrayEquals(
                packageBytes,
                ipfsClient.get(cid));

        BatchRecord completeRecord =
                aggregateResult
                        .batchRecord()
                        .withCid(cid);

        return new RealBatchInput(
                completeRecord,
                aggregateCommitmentHex(
                        completeRecord),
                scalarHex(
                        completeRecord
                                .getAggregateSignature()
                                .getSagg()),
                HexFormat.of()
                        .formatHex(
                                completeRecord.getMu()),
                cid);
    }

    /**
     * 生成真实设备，并注册到聚合阶段使用的本地 L。
     */
    private Device generateAndRegisterLocally(
            InMemoryDeviceRegistry registry,
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

    /**
     * 将 R_agg 编码为链上格式。
     *
     * 普通群元素为 33 字节压缩点；
     * 群单位元使用 00。
     */
    private static String aggregateCommitmentHex(
            BatchRecord batchRecord) {

        ECPoint point =
                batchRecord
                        .getAggregateSignature()
                        .getRagg()
                        .normalize();

        if (point.isInfinity()) {
            return "00";
        }

        return HexFormat.of()
                .formatHex(
                        PointCodec.encodeCompressed(
                                point));
    }

    /**
     * 将完整真实 BRec 提交给 Chaincode。
     */
    private boolean submitBatchRecord(
            RealBatchInput input) {

        return contract.CreateBatchRecord(
                context,
                input.batchRecord()
                        .getBatchId(),
                input.batchRecord()
                        .getTimestamp(),
                input.aggregateCommitmentHex(),
                input.aggregateResponseHex(),
                input.muHex(),
                input.cid());
    }

    private static IpfsClient realIpfsClient() {

        String rpcAddress =
                System.getProperty(
                        IPFS_RPC_PROPERTY,
                        DEFAULT_IPFS_RPC);

        return new KuboHttpIpfsClient(
                URI.create(rpcAddress));
    }

    /**
     * 测试内部数据载体，不新增独立测试文件。
     */
    private record RealBatchInput(
            BatchRecord batchRecord,
            String aggregateCommitmentHex,
            String aggregateResponseHex,
            String muHex,
            String cid) {
    }
}