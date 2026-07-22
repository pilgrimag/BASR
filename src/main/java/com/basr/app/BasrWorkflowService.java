package com.basr.app;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.AggVerify;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Recovery;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Sign;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.entity.AggregateSignature;
import com.basr.entity.BatchRecord;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.RegisteredDevice;
import com.basr.entity.RegistrationRequest;
import com.basr.entity.SignedReport;
import com.basr.fabric.FabricGatewayClient;
import com.basr.ipfs.IpfsClient;
import com.basr.persistence.PackageCodec;
import com.basr.registry.FabricDeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * BASR 应用服务层。
 *
 * 该类将密码算法、Fabric 和 IPFS 组合成可供
 * CLI、REST API 或其他应用入口调用的生产工作流。
 *
 * Fabric 世界状态是设备注册表和批记录的权威来源；
 * IPFS 存储完整批次包；
 * 本类不维护第二份权威账本状态。
 */
public final class BasrWorkflowService {

    private static final HexFormat HEX =
            HexFormat.of();

    private static final int PUBLIC_REPORT =
            0;

    private static final int SENSITIVE_REPORT =
            1;

    private final PublicParams pp;

    private final FabricGatewayClient gateway;

    private final IpfsClient ipfs;

    private final FabricDeviceRegistry registry;

    public BasrWorkflowService(
            final PublicParams pp,
            final FabricGatewayClient gateway,
            final IpfsClient ipfs) {

        this.pp =
                Objects.requireNonNull(
                        pp,
                        "pp");

        this.gateway =
                Objects.requireNonNull(
                        gateway,
                        "gateway");

        this.ipfs =
                Objects.requireNonNull(
                        ipfs,
                        "ipfs");

        this.registry =
                new FabricDeviceRegistry(
                        pp,
                        gateway);
    }

    /**
     * 生成设备密钥、生成真实 Schnorr POP，
     * 并把注册交易提交到 Fabric。
     *
     * 返回的 Device 包含设备私钥，调用者必须安全保存。
     */
    public Device registerDevice(
            final String deviceId) {

        requireText(
                deviceId,
                "deviceId");

        try {
            Device device =
                    Registration.generateDevice(
                            pp,
                            deviceId);

            RegistrationRequest request =
                    Registration.createRequest(
                            pp,
                            device);

            boolean submitted =
                    gateway.registerDevice(
                            pp,
                            request);

            if (!submitted) {
                throw new WorkflowException(
                        "Fabric rejected device "
                                + "registration: "
                                + deviceId);
            }

            RegisteredDevice registered =
                    registry.findByDeviceId(
                                    deviceId)
                            .orElseThrow(
                                    () ->
                                            new WorkflowException(
                                                    "Committed device "
                                                            + "could not "
                                                            + "be read: "
                                                            + deviceId));

            if (!samePoint(
                    device.getPublicKey(),
                    registered.getPublicKey())) {

                throw new WorkflowException(
                        "Committed public key does not "
                                + "match generated device: "
                                + deviceId);
            }

            if (!registry.contains(
                    deviceId,
                    device.getPublicKey())) {

                throw new WorkflowException(
                        "Exact committed registration "
                                + "could not be verified: "
                                + deviceId);
            }

            return device;

        } catch (WorkflowException exception) {
            throw exception;

        } catch (Exception exception) {

            throw new WorkflowException(
                    "Failed to register device: "
                            + deviceId,
                    exception);
        }
    }

    public RecoveryKey generateRecoveryKey() {

        try {
            return RecKeyGen.generate(pp);

        } catch (RuntimeException exception) {

            throw new WorkflowException(
                    "Failed to generate recovery key",
                    exception);
        }
    }

    public SignedReport signPublicReport(
            final Device device,
            final RecoveryKey recoveryKey,
            final byte[] plaintext,
            final String batchId,
            final long timestamp) {

        return signReport(
                device,
                recoveryKey,
                plaintext,
                PUBLIC_REPORT,
                batchId,
                timestamp);
    }

    public SignedReport signSensitiveReport(
            final Device device,
            final RecoveryKey recoveryKey,
            final byte[] plaintext,
            final String batchId,
            final long timestamp) {

        return signReport(
                device,
                recoveryKey,
                plaintext,
                SENSITIVE_REPORT,
                batchId,
                timestamp);
    }

    public SignedReport signReport(
            final Device device,
            final RecoveryKey recoveryKey,
            final byte[] plaintext,
            final int beta,
            final String batchId,
            final long timestamp) {

        Objects.requireNonNull(
                device,
                "device");

        Objects.requireNonNull(
                recoveryKey,
                "recoveryKey");

        Objects.requireNonNull(
                plaintext,
                "plaintext");

        requireText(
                batchId,
                "batchId");

        if (beta != PUBLIC_REPORT
                && beta != SENSITIVE_REPORT) {

            throw new IllegalArgumentException(
                    "beta must be 0 or 1");
        }

        try {
            return Sign.sign(
                    pp,
                    recoveryKey.getPublicKey(),
                    device,
                    plaintext.clone(),
                    beta,
                    batchId,
                    timestamp);

        } catch (RuntimeException exception) {

            throw new WorkflowException(
                    "Failed to sign report for device "
                            + device.getDeviceId(),
                    exception);
        }
    }

    /**
     * 验证并聚合报告，确定性编码 Pkg，上传 IPFS，
     * 然后把 BRec 提交到 Fabric。
     */
    public PublishedBatch aggregateAndPublish(
            final List<SignedReport> reports,
            final String batchId,
            final long timestamp) {

        Objects.requireNonNull(
                reports,
                "reports");

        requireText(
                batchId,
                "batchId");

        if (reports.isEmpty()) {
            throw new IllegalArgumentException(
                    "reports must not be empty");
        }

        try {
            if (!ipfs.isAvailable()) {
                throw new WorkflowException(
                        "IPFS RPC is unavailable");
            }

            Aggregate.Result result =
                    Aggregate.aggregate(
                                    pp,
                                    registry,
                                    List.copyOf(reports),
                                    batchId,
                                    timestamp)
                            .orElseThrow(
                                    () ->
                                            new WorkflowException(
                                                    "No valid reports "
                                                            + "remained "
                                                            + "after "
                                                            + "verification"));

            byte[] packageBytes =
                    PackageCodec.encode(
                            pp,
                            result);

            String cid =
                    ipfs.put(
                            packageBytes);

            requireText(
                    cid,
                    "cid");

            /*
             * 上传后立即执行一次按 CID 下载校验，
             * 防止错误 RPC 响应或内容不一致。
             */
            byte[] downloaded =
                    ipfs.get(cid);

            if (!Arrays.equals(
                    packageBytes,
                    downloaded)) {

                throw new WorkflowException(
                        "IPFS content does not match "
                                + "the uploaded package");
            }

            BatchRecord completeRecord =
                    result.batchRecord()
                            .withCid(cid);

            boolean submitted =
                    gateway.createBatchRecord(
                            pp,
                            completeRecord,
                            cid);

            if (!submitted) {
                throw new WorkflowException(
                        "Fabric rejected batch record: "
                                + batchId);
            }

            BatchRecord committedRecord =
                    readBatchRecord(
                            batchId);

            if (!sameBatchRecord(
                    completeRecord,
                    committedRecord)) {

                throw new WorkflowException(
                        "Committed batch record differs "
                                + "from the submitted record: "
                                + batchId);
            }

            return new PublishedBatch(
                    committedRecord,
                    cid,
                    packageBytes.length);

        } catch (WorkflowException exception) {
            throw exception;

        } catch (Exception exception) {

            throw new WorkflowException(
                    "Failed to aggregate and publish "
                            + "batch "
                            + batchId,
                    exception);
        }
    }

    /**
     * 从 Fabric 读取 BRec，按 CID 下载 Pkg，
     * 然后执行真实聚合验证。
     */
    public VerifiedBatch verifyPublishedBatch(
            final String batchId) {

        requireText(
                batchId,
                "batchId");

        try {
            BatchRecord batchRecord =
                    readBatchRecord(
                            batchId);

            byte[] packageBytes =
                    ipfs.get(
                            batchRecord.getCid());

            PackageCodec.DecodedPackage decoded =
                    PackageCodec.decode(
                            pp,
                            packageBytes);

            if (!batchId.equals(
                    decoded.batchId())) {

                throw new WorkflowException(
                        "Package batch ID does not "
                                + "match Fabric BRec");
            }

            if (batchRecord.getTimestamp()
                    != decoded.timestamp()) {

                throw new WorkflowException(
                        "Package timestamp does not "
                                + "match Fabric BRec");
            }

            boolean valid =
                    AggVerify.verify(
                            pp,
                            registry,
                            batchRecord,
                            decoded.packageEntries());

            if (!valid) {
                throw new WorkflowException(
                        "Aggregate verification failed "
                                + "for batch "
                                + batchId);
            }

            return new VerifiedBatch(
                    batchRecord,
                    decoded.packageEntries(),
                    packageBytes.length);

        } catch (WorkflowException exception) {
            throw exception;

        } catch (Exception exception) {

            throw new WorkflowException(
                    "Failed to verify published batch "
                            + batchId,
                    exception);
        }
    }

    /**
     * 从已经通过 AggVerify 的批次中恢复指定报告。
     */
    public byte[] recoverReport(
            final RecoveryKey recoveryKey,
            final VerifiedBatch verifiedBatch,
            final String deviceId,
            final ECPoint reportCommitment) {

        Objects.requireNonNull(
                recoveryKey,
                "recoveryKey");

        Objects.requireNonNull(
                verifiedBatch,
                "verifiedBatch");

        requireText(
                deviceId,
                "deviceId");

        Objects.requireNonNull(
                reportCommitment,
                "reportCommitment");

        try {
            return Recovery.recover(
                            pp,
                            registry,
                            recoveryKey,
                            verifiedBatch.batchRecord(),
                            verifiedBatch.packageEntries(),
                            deviceId,
                            reportCommitment)
                    .orElseThrow(
                            () ->
                                    new WorkflowException(
                                            "Report recovery "
                                                    + "failed for "
                                                    + deviceId));

        } catch (WorkflowException exception) {
            throw exception;

        } catch (RuntimeException exception) {

            throw new WorkflowException(
                    "Failed to recover report for "
                            + deviceId,
                    exception);
        }
    }

    public FabricDeviceRegistry registry() {
        return registry;
    }

    private BatchRecord readBatchRecord(
            final String batchId)
            throws Exception {

        FabricGatewayClient.BatchRecordView view =
                gateway.readBatchRecord(
                        batchId);

        return toBatchRecord(view);
    }

    private BatchRecord toBatchRecord(
            final FabricGatewayClient.BatchRecordView
                    view) {

        Objects.requireNonNull(
                view,
                "view");

        requireText(
                view.batchId(),
                "ledger batchId");

        requireText(
                view.aggregateCommitmentHex(),
                "aggregateCommitmentHex");

        requireText(
                view.aggregateResponseHex(),
                "aggregateResponseHex");

        requireText(
                view.muHex(),
                "muHex");

        requireText(
                view.cid(),
                "cid");

        if ("00".equals(
                view.aggregateCommitmentHex())) {

            throw new WorkflowException(
                    "Ledger contains an identity "
                            + "aggregate commitment");
        }

        try {
            ECPoint commitment =
                    PointCodec.decodeCompressed(
                                    pp,
                                    HEX.parseHex(
                                            view.aggregateCommitmentHex()))
                            .normalize();

            BigInteger response =
                    new BigInteger(
                            1,
                            HEX.parseHex(
                                    view.aggregateResponseHex()));

            AggregateSignature signature =
                    new AggregateSignature(
                            commitment,
                            response);

            return new BatchRecord(
                    view.batchId(),
                    view.timestamp(),
                    signature,
                    HEX.parseHex(
                            view.muHex()),
                    view.cid());

        } catch (IllegalArgumentException exception) {

            throw new WorkflowException(
                    "Fabric returned malformed "
                            + "batch-record encoding",
                    exception);
        }
    }

    private static boolean sameBatchRecord(
            final BatchRecord left,
            final BatchRecord right) {

        return left.getBatchId()
                .equals(
                        right.getBatchId())
                && left.getTimestamp()
                == right.getTimestamp()
                && left.getCid()
                .equals(
                        right.getCid())
                && Arrays.equals(
                        left.getMu(),
                        right.getMu())
                && samePoint(
                        left.getAggregateSignature()
                                .getAggregateCommitment(),
                        right.getAggregateSignature()
                                .getAggregateCommitment())
                && left.getAggregateSignature()
                .getAggregateResponse()
                .equals(
                        right.getAggregateSignature()
                                .getAggregateResponse());
    }

    private static boolean samePoint(
            final ECPoint left,
            final ECPoint right) {

        if (left == null || right == null) {
            return false;
        }

        return Arrays.equals(
                PointCodec.encodeCompressed(
                        left.normalize()),
                PointCodec.encodeCompressed(
                        right.normalize()));
    }

    private static void requireText(
            final String value,
            final String fieldName) {

        if (value == null
                || value.isBlank()
                || !value.equals(
                        value.trim())) {

            throw new IllegalArgumentException(
                    fieldName
                            + " must be nonblank "
                            + "canonical text");
        }
    }

    public record PublishedBatch(
            BatchRecord batchRecord,
            String cid,
            int packageSize) {

        public PublishedBatch {

            Objects.requireNonNull(
                    batchRecord,
                    "batchRecord");

            requireText(
                    cid,
                    "cid");

            if (packageSize <= 0) {
                throw new IllegalArgumentException(
                        "packageSize must be positive");
            }
        }
    }

    public record VerifiedBatch(
            BatchRecord batchRecord,
            List<Aggregate.PackageEntry>
                    packageEntries,
            int packageSize) {

        public VerifiedBatch {

            Objects.requireNonNull(
                    batchRecord,
                    "batchRecord");

            packageEntries =
                    List.copyOf(
                            Objects.requireNonNull(
                                    packageEntries,
                                    "packageEntries"));

            if (packageEntries.isEmpty()) {
                throw new IllegalArgumentException(
                        "packageEntries must not be empty");
            }

            if (packageSize <= 0) {
                throw new IllegalArgumentException(
                        "packageSize must be positive");
            }
        }
    }

    public static final class WorkflowException
            extends RuntimeException {

        public WorkflowException(
                final String message) {

            super(message);
        }

        public WorkflowException(
                final String message,
                final Throwable cause) {

            super(message, cause);
        }
    }
}