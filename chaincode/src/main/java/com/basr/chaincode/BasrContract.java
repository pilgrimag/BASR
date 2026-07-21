package com.basr.chaincode;

import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.entity.ProofOfPossession;
import com.basr.entity.RegistrationRequest;
import com.basr.entity.RegistrationResult;
import com.basr.registry.InMemoryDeviceRegistry;

import com.owlike.genson.Genson;

import org.bouncycastle.math.ec.ECPoint;

import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.License;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * BASR 最小链码。
 *
 * 当前只实现算法严格需要的链上功能：
 *
 * 1. RegisterDevice：
 *    验证真实 Schnorr POP，并将 (ID_i,pk_i) 写入 L；
 *
 * 2. ReadDevice：
 *    根据 ID_i 查询注册项；
 *
 * 3. IsRegisteredDevice：
 *    检查 (ID_i,pk_i) 是否属于 L；
 *
 * 4. CreateBatchRecord：
 *    写入 BRec=(bid,t,sigma_agg,mu,cid)；
 *
 * 5. ReadBatchRecord：
 *    根据 bid 查询 BRec。
 *
 * 不包含初始化模拟数据、更新、删除、撤销和访问策略。
 */
@Contract(
        name = "basr",
        info = @Info(
                title = "BASR Contract",
                description =
                        "BASR device registration "
                        + "and batch-record contract",
                version = "1.0.0",
                license = @License(
                        name = "Apache-2.0",
                        url =
                                "https://www.apache.org/"
                                + "licenses/LICENSE-2.0"
                )
        )
)
@Default
public final class BasrContract
        implements ContractInterface {

    /*
     * 世界状态键命名空间。
     *
     * DEVICE:<ID_i>
     * DEVICE_PK:<pk_i>
     * BATCH:<bid>
     */
    private static final String DEVICE_PREFIX =
            "DEVICE:";

    private static final String DEVICE_PK_PREFIX =
            "DEVICE_PK:";

    private static final String BATCH_PREFIX =
            "BATCH:";

    private static final int MAX_IDENTIFIER_BYTES =
            256;

    private static final int COMPRESSED_POINT_BYTES =
            33;

    private static final int SCALAR_BYTES =
            32;

    private static final int HASH_BYTES =
            32;

    /*
     * 由当前真实 IPFS 客户端产生的 CIDv1
     * 使用小写 base32，例如：
     *
     *     bafkrei...
     */
    private static final Pattern CID_V1_BASE32 =
            Pattern.compile(
                    "b[a-z2-7]{20,199}");

    /*
     * 公共参数由命名曲线和固定算法标识构造，
     * 对所有背书节点是确定的。
     *
     * Chaincode 中不生成任何设备私钥、
     * DR 密钥、签名随机数或时间戳。
     */
    private static final PublicParams PUBLIC_PARAMS =
            Setup.setup(128);

    private final Genson genson =
            new Genson();

    private enum ErrorCode {

        INVALID_ARGUMENT,

        INVALID_PUBLIC_KEY,

        INVALID_POP,

        DEVICE_ALREADY_EXISTS,

        PUBLIC_KEY_ALREADY_EXISTS,

        DEVICE_NOT_FOUND,

        INVALID_BATCH_RECORD,

        BATCH_ALREADY_EXISTS,

        BATCH_NOT_FOUND
    }

    /**
     * 注册设备。
     *
     * 输入：
     *
     *     ID_i
     *     pk_i
     *     c_i
     *     z_i
     *
     * Chaincode 真实执行：
     *
     *     A_i' = [z_i]g - [c_i]pk_i
     *
     *     c_i' = H4(pk_i || ID_i || A_i')
     *
     * 并检查：
     *
     *     c_i' = c_i
     *
     * 验证通过后写入：
     *
     *     L <- L union {(ID_i,pk_i)}
     *
     * @return 成功时返回 true；失败时抛出 ChaincodeException
     */
    @Transaction(
            intent = Transaction.TYPE.SUBMIT)
    public boolean RegisterDevice(
            final Context ctx,
            final String deviceId,
            final String publicKeyHex,
            final String popChallengeHex,
            final String popResponseHex) {

        Objects.requireNonNull(ctx, "ctx");

        String canonicalDeviceId =
                validateIdentifier(
                        deviceId,
                        "deviceId");

        String canonicalPublicKey =
                canonicalDevicePublicKey(
                        publicKeyHex);

        BigInteger challenge =
                parseScalar(
                        popChallengeHex,
                        "popChallengeHex");

        BigInteger response =
                parseScalar(
                        popResponseHex,
                        "popResponseHex");

        ChaincodeStub stub =
                ctx.getStub();

        String deviceKey =
                deviceKey(canonicalDeviceId);

        String publicKeyIndexKey =
                publicKeyIndexKey(
                        canonicalPublicKey);

        if (stateExists(
                stub.getStringState(deviceKey))) {

            throw failure(
                    ErrorCode.DEVICE_ALREADY_EXISTS,
                    "Device already exists: "
                            + canonicalDeviceId);
        }

        if (stateExists(
                stub.getStringState(
                        publicKeyIndexKey))) {

            throw failure(
                    ErrorCode.PUBLIC_KEY_ALREADY_EXISTS,
                    "Public key is already registered");
        }

        ECPoint publicKey;

        try {
            publicKey =
                    PointCodec.decodeCompressed(
                            PUBLIC_PARAMS,
                            HexFormat.of()
                                    .parseHex(
                                            canonicalPublicKey));

        } catch (RuntimeException exception) {

            throw failure(
                    ErrorCode.INVALID_PUBLIC_KEY,
                    "Invalid secp256k1 public key");
        }

        /*
         * 这里不重新实现 H4 或 Schnorr POP。
         *
         * 直接复用 basr-algorithm 中已经经过测试的
         * Registration.verifyAndRegister，从而保证：
         *
         * - H4 域分离一致；
         * - 转录编码一致；
         * - 点编码一致；
         * - 标量处理一致；
         * - POP 方程一致。
         *
         * 临时注册表仅用于执行 POP 验证。
         * 真正的全局唯一性由 Fabric 世界状态检查。
         */
        ProofOfPossession proof =
                new ProofOfPossession(
                        challenge,
                        response);

        RegistrationRequest request =
                new RegistrationRequest(
                        canonicalDeviceId,
                        publicKey,
                        proof);

        RegistrationResult result =
                Registration.verifyAndRegister(
                        PUBLIC_PARAMS,
                        new InMemoryDeviceRegistry(),
                        request);

        if (!result.isAccepted()) {

            throw failure(
                    ErrorCode.INVALID_POP,
                    "Invalid proof of possession");
        }

        DeviceAsset asset =
                new DeviceAsset(
                        canonicalDeviceId,
                        canonicalPublicKey);

        /*
         * 主注册项：
         *
         *     DEVICE:<ID_i> -> DeviceAsset
         */
        stub.putStringState(
                deviceKey,
                genson.serialize(asset));

        /*
         * 公钥唯一性索引：
         *
         *     DEVICE_PK:<pk_i> -> ID_i
         *
         * 这不是额外协议字段，只是为实现：
         *
         *     pk_i not in L
         *
         * 而建立的世界状态索引。
         */
        stub.putStringState(
                publicKeyIndexKey,
                canonicalDeviceId);

        return true;
    }

    /**
     * 根据设备身份读取注册项。
     */
    @Transaction(
            intent = Transaction.TYPE.EVALUATE)
    public DeviceAsset ReadDevice(
            final Context ctx,
            final String deviceId) {

        Objects.requireNonNull(ctx, "ctx");

        String canonicalDeviceId =
                validateIdentifier(
                        deviceId,
                        "deviceId");

        String json =
                ctx.getStub()
                        .getStringState(
                                deviceKey(
                                        canonicalDeviceId));

        if (!stateExists(json)) {

            throw failure(
                    ErrorCode.DEVICE_NOT_FOUND,
                    "Device does not exist: "
                            + canonicalDeviceId);
        }

        return genson.deserialize(
                json,
                DeviceAsset.class);
    }

    /**
     * 检查：
     *
     *     (ID_i,pk_i) in L
     *
     * 该接口后续由 FabricDeviceRegistry 调用，
     * 用于替换 InMemoryDeviceRegistry。
     */
    @Transaction(
            intent = Transaction.TYPE.EVALUATE)
    public boolean IsRegisteredDevice(
            final Context ctx,
            final String deviceId,
            final String publicKeyHex) {

        Objects.requireNonNull(ctx, "ctx");

        String canonicalDeviceId =
                validateIdentifier(
                        deviceId,
                        "deviceId");

        String canonicalPublicKey =
                canonicalDevicePublicKey(
                        publicKeyHex);

        String json =
                ctx.getStub()
                        .getStringState(
                                deviceKey(
                                        canonicalDeviceId));

        if (!stateExists(json)) {
            return false;
        }

        DeviceAsset asset =
                genson.deserialize(
                        json,
                        DeviceAsset.class);

        return canonicalDeviceId.equals(
                asset.getDeviceId())
                && canonicalPublicKey.equals(
                        asset.getPublicKeyHex());
    }

    /**
     * 写入真实批记录：
     *
     *     BRec = (
     *         bid,
     *         t,
     *         R_agg,
     *         s_agg,
     *         mu,
     *         cid
     *     )
     *
     * cid 必须由真实 IPFS.Put(Pkg) 返回。
     *
     * Chaincode 不调用 IPFS，也不生成 cid。
     */
    @Transaction(
            intent = Transaction.TYPE.SUBMIT)
    public boolean CreateBatchRecord(
            final Context ctx,
            final String batchId,
            final long timestamp,
            final String aggregateCommitmentHex,
            final String aggregateResponseHex,
            final String muHex,
            final String cid) {

        Objects.requireNonNull(ctx, "ctx");

        String canonicalBatchId =
                validateIdentifier(
                        batchId,
                        "batchId");

        if (timestamp <= 0L) {

            throw failure(
                    ErrorCode.INVALID_BATCH_RECORD,
                    "timestamp must be positive");
        }

        String canonicalAggregateCommitment =
                canonicalAggregateCommitment(
                        aggregateCommitmentHex);

        String canonicalAggregateResponse =
                canonicalScalarHex(
                        aggregateResponseHex,
                        "aggregateResponseHex");

        String canonicalMu =
                canonicalFixedHex(
                        muHex,
                        HASH_BYTES,
                        "muHex");

        String canonicalCid =
                validateCid(cid);

        ChaincodeStub stub =
                ctx.getStub();

        String key =
                batchKey(
                        canonicalBatchId);

        if (stateExists(
                stub.getStringState(key))) {

            throw failure(
                    ErrorCode.BATCH_ALREADY_EXISTS,
                    "Batch already exists: "
                            + canonicalBatchId);
        }

        BatchRecordAsset record =
                new BatchRecordAsset(
                        canonicalBatchId,
                        timestamp,
                        canonicalAggregateCommitment,
                        canonicalAggregateResponse,
                        canonicalMu,
                        canonicalCid);

        stub.putStringState(
                key,
                genson.serialize(record));

        return true;
    }

    /**
     * 根据 bid 查询真实链上 BRec。
     */
    @Transaction(
            intent = Transaction.TYPE.EVALUATE)
    public BatchRecordAsset ReadBatchRecord(
            final Context ctx,
            final String batchId) {

        Objects.requireNonNull(ctx, "ctx");

        String canonicalBatchId =
                validateIdentifier(
                        batchId,
                        "batchId");

        String json =
                ctx.getStub()
                        .getStringState(
                                batchKey(
                                        canonicalBatchId));

        if (!stateExists(json)) {

            throw failure(
                    ErrorCode.BATCH_NOT_FOUND,
                    "Batch does not exist: "
                            + canonicalBatchId);
        }

        return genson.deserialize(
                json,
                BatchRecordAsset.class);
    }

    /**
     * 设备公钥必须为合法的 secp256k1
     * 33 字节压缩点。
     */
    private static String canonicalDevicePublicKey(
            final String value) {

        String canonical =
                canonicalFixedHex(
                        value,
                        COMPRESSED_POINT_BYTES,
                        "publicKeyHex");

        try {
            ECPoint point =
                    PointCodec.decodeCompressed(
                            PUBLIC_PARAMS,
                            HexFormat.of()
                                    .parseHex(canonical));

            if (point.isInfinity()) {

                throw failure(
                        ErrorCode.INVALID_PUBLIC_KEY,
                        "Device public key "
                                + "cannot be identity");
            }

            return HexFormat.of()
                    .formatHex(
                            PointCodec.encodeCompressed(
                                    point));

        } catch (ChaincodeException exception) {
            throw exception;

        } catch (RuntimeException exception) {

            throw failure(
                    ErrorCode.INVALID_PUBLIC_KEY,
                    "Invalid secp256k1 public key");
        }
    }

    /**
     * R_agg 通常是 33 字节压缩点。
     *
     * 为完整覆盖群运算，允许：
     *
     *     00
     *
     * 表示椭圆曲线群单位元。
     */
    private static String canonicalAggregateCommitment(
            final String value) {

        String normalized =
                requireText(
                        value,
                        "aggregateCommitmentHex")
                        .toLowerCase(Locale.ROOT);

        if ("00".equals(normalized)) {
            return normalized;
        }

        String canonical =
                canonicalFixedHex(
                        normalized,
                        COMPRESSED_POINT_BYTES,
                        "aggregateCommitmentHex");

        try {
            ECPoint point =
                    PointCodec.decodeCompressed(
                            PUBLIC_PARAMS,
                            HexFormat.of()
                                    .parseHex(canonical));

            return HexFormat.of()
                    .formatHex(
                            PointCodec.encodeCompressed(
                                    point));

        } catch (RuntimeException exception) {

            throw failure(
                    ErrorCode.INVALID_BATCH_RECORD,
                    "Invalid aggregate commitment");
        }
    }

    private static BigInteger parseScalar(
            final String value,
            final String fieldName) {

        String canonical =
                canonicalFixedHex(
                        value,
                        SCALAR_BYTES,
                        fieldName);

        BigInteger scalar =
                new BigInteger(
                        1,
                        HexFormat.of()
                                .parseHex(canonical));

        if (scalar.compareTo(
                PUBLIC_PARAMS.getP()) >= 0) {

            throw failure(
                    ErrorCode.INVALID_ARGUMENT,
                    fieldName
                            + " is not in Z_p");
        }

        return scalar;
    }

    private static String canonicalScalarHex(
            final String value,
            final String fieldName) {

        String canonical =
                canonicalFixedHex(
                        value,
                        SCALAR_BYTES,
                        fieldName);

        BigInteger scalar =
                new BigInteger(
                        1,
                        HexFormat.of()
                                .parseHex(canonical));

        if (scalar.compareTo(
                PUBLIC_PARAMS.getP()) >= 0) {

            throw failure(
                    ErrorCode.INVALID_BATCH_RECORD,
                    fieldName
                            + " is not in Z_p");
        }

        return canonical;
    }

    private static String canonicalFixedHex(
            final String value,
            final int expectedBytes,
            final String fieldName) {

        String canonical =
                requireText(
                        value,
                        fieldName)
                        .toLowerCase(Locale.ROOT);

        if (canonical.startsWith("0x")) {

            throw failure(
                    ErrorCode.INVALID_ARGUMENT,
                    fieldName
                            + " must not contain 0x");
        }

        if (canonical.length()
                != expectedBytes * 2) {

            throw failure(
                    ErrorCode.INVALID_ARGUMENT,
                    fieldName
                            + " must contain exactly "
                            + expectedBytes
                            + " bytes");
        }

        for (int index = 0;
             index < canonical.length();
             index++) {

            char character =
                    canonical.charAt(index);

            boolean decimal =
                    character >= '0'
                            && character <= '9';

            boolean hexadecimal =
                    character >= 'a'
                            && character <= 'f';

            if (!decimal && !hexadecimal) {

                throw failure(
                        ErrorCode.INVALID_ARGUMENT,
                        fieldName
                                + " is not valid hex");
            }
        }

        return canonical;
    }

    private static String validateIdentifier(
            final String value,
            final String fieldName) {

        String result =
                requireText(
                        value,
                        fieldName);

        if (!result.equals(result.trim())) {

            throw failure(
                    ErrorCode.INVALID_ARGUMENT,
                    fieldName
                            + " must not contain "
                            + "leading or trailing whitespace");
        }

        byte[] encoded =
                result.getBytes(
                        StandardCharsets.UTF_8);

        if (encoded.length
                > MAX_IDENTIFIER_BYTES) {

            throw failure(
                    ErrorCode.INVALID_ARGUMENT,
                    fieldName
                            + " exceeds maximum length");
        }

        if (result.indexOf('\0') >= 0) {

            throw failure(
                    ErrorCode.INVALID_ARGUMENT,
                    fieldName
                            + " contains NUL");
        }

        return result;
    }

    private static String validateCid(
            final String value) {

        String cid =
                requireText(
                        value,
                        "cid");

        if (!cid.equals(cid.trim())) {

            throw failure(
                    ErrorCode.INVALID_BATCH_RECORD,
                    "cid contains surrounding whitespace");
        }

        if (!CID_V1_BASE32
                .matcher(cid)
                .matches()) {

            throw failure(
                    ErrorCode.INVALID_BATCH_RECORD,
                    "cid must be a lowercase "
                            + "base32 CIDv1");
        }

        return cid;
    }

    private static String requireText(
            final String value,
            final String fieldName) {

        if (value == null
                || value.isBlank()) {

            throw failure(
                    ErrorCode.INVALID_ARGUMENT,
                    fieldName
                            + " cannot be blank");
        }

        return value;
    }

    private static boolean stateExists(
            final String state) {

        return state != null
                && !state.isEmpty();
    }

    private static String deviceKey(
            final String deviceId) {

        return DEVICE_PREFIX
                + deviceId;
    }

    private static String publicKeyIndexKey(
            final String publicKeyHex) {

        return DEVICE_PK_PREFIX
                + publicKeyHex;
    }

    private static String batchKey(
            final String batchId) {

        return BATCH_PREFIX
                + batchId;
    }

    private static ChaincodeException failure(
            final ErrorCode code,
            final String message) {

        return new ChaincodeException(
                message,
                code.name());
    }
}