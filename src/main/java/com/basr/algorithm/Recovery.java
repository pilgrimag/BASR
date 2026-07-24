package com.basr.algorithm;

import com.basr.crypto.Aead;
import com.basr.crypto.BasrTranscript;
import com.basr.crypto.Kem;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.entity.BatchRecord;
import com.basr.entity.RecoveryKey;
import com.basr.entity.Report;
import com.basr.registry.DeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * BASR Data Recovery Protocol。
 *
 * 完整算法输入：
 *
 *      pp
 *      L
 *      BRec
 *      Pkg
 *      sk_R
 *      (ID_i, R_i)
 *
 * 本地实现中：
 *
 *      - BRec 直接作为参数传入；
 *      - Pkg 直接作为参数传入；
 *      - 暂不从区块链查询 BRec；
 *      - 暂不根据 CID 从 IPFS 下载 Pkg。
 *
 * 密码学恢复流程保持不变：
 *
 * 1. 调用 AggVerify 验证 BRec 和 Pkg；
 * 2. 按 (ID_i, R_i) 定位目标报告；
 * 3. beta_i = 0 时直接返回 D_i；
 * 4. beta_i = 1 时：
 *
 *      K_i <- KEM.Decap(pp_KEM, sk_R, RM_i)
 *
 *      AAD_i =
 *          ID_i || pk_i || beta_i || bid || t
 *
 *      m_i <- AEAD.Dec(
 *          pp_AEAD,
 *          K_i,
 *          D_i,
 *          AAD_i
 *      )
 *
 * 5. 验证失败、目标不存在或解密失败时返回 Optional.empty()。
 */
public final class Recovery {

    /**
     * 工具类不允许实例化。
     */
    private Recovery() {
    }

    /**
     * 直接恢复 Aggregate 返回结果中的目标报告。
     *
     * @param pp               系统公共参数
     * @param registry         设备注册表 L
     * @param recoveryKey      DR 恢复密钥；恢复非敏感报告时可以为 null
     * @param aggregateResult  Aggregate 输出的 BRec 和 Pkg
     * @param targetDeviceId   目标设备身份 ID_i
     * @param targetCommitment 目标签名承诺 R_i
     * @return 恢复出的原始报告，失败时返回 Optional.empty()
     */
    public static Optional<byte[]> recover(
            PublicParams pp,
            DeviceRegistry registry,
            RecoveryKey recoveryKey,
            Aggregate.Result aggregateResult,
            String targetDeviceId,
            ECPoint targetCommitment) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(registry, "registry");

        if (aggregateResult == null) {
            return Optional.empty();
        }

        return recover(
                pp,
                registry,
                recoveryKey,
                aggregateResult.batchRecord(),
                aggregateResult.packageEntries(),
                targetDeviceId,
                targetCommitment);
    }

    /**
     * 使用独立传入的 BRec 和 Pkg 恢复目标报告。
     *
     * 该接口后续可以直接被 Fabric/IPFS 业务层调用：
     *
     * 1. 从 Fabric 查询 BRec；
     * 2. 根据 cid 从 IPFS 下载并反序列化 Pkg；
     * 3. 调用本方法执行密码学恢复。
     *
     * @param pp               系统公共参数
     * @param registry         设备注册表
     * @param recoveryKey      DR 恢复密钥
     * @param batchRecord      批次记录 BRec
     * @param packageEntries   离线报告包 Pkg
     * @param targetDeviceId   目标 ID_i
     * @param targetCommitment 目标 R_i
     * @return 恢复出的报告字节
     */
    public static Optional<byte[]> recover(
            PublicParams pp,
            DeviceRegistry registry,
            RecoveryKey recoveryKey,
            BatchRecord batchRecord,
            List<Aggregate.PackageEntry> packageEntries,
            String targetDeviceId,
            ECPoint targetCommitment) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(registry, "registry");

        /*
         * 检查恢复输入是否完整。
         */
        if (batchRecord == null
                || packageEntries == null
                || targetDeviceId == null
                || targetDeviceId.isBlank()
                || targetCommitment == null) {

            return Optional.empty();
        }

        /*
         * R_i 必须是签名群 G 中的合法非单位元。
         */
        if (!PointCodec.isValidGroupElement(
                pp,
                targetCommitment)) {

            return Optional.empty();
        }

        /*
         * Recovery 的第一步必须验证整个批次。
         *
         * 不能在未验证 BRec 和 Pkg 的情况下直接解密，
         * 否则攻击者可以替换报告、恢复材料、批次信息或密文。
         */
        if (!AggVerify.verify(
                pp,
                registry,
                batchRecord,
                packageEntries)) {

            return Optional.empty();
        }

        /*
         * 严格按照：
         *
         *      (ID_i, R_i)
         *
         * 定位目标报告。
         *
         * 不能只根据 ID_i 查找，因为同一设备在同一批次中
         * 可能使用不同随机数生成多个不同的 R_i。
         */
        Aggregate.PackageEntry targetEntry = null;

        ECPoint normalizedTargetCommitment =
                targetCommitment.normalize();

        for (Aggregate.PackageEntry entry
                : packageEntries) {

            if (entry == null
                    || entry.report() == null
                    || entry.commitment() == null) {

                /*
                 * AggVerify 理论上已经排除这种情况。
                 * 这里仍保持防御性检查。
                 */
                return Optional.empty();
            }

            boolean sameDevice =
                    targetDeviceId.equals(
                            entry.report().getDeviceId());

            boolean sameCommitment =
                    normalizedTargetCommitment.equals(
                            entry.commitment().normalize());

            if (sameDevice && sameCommitment) {
                targetEntry = entry;
                break;
            }
        }

        /*
         * Pkg 中不存在指定的 (ID_i,R_i)。
         */
        if (targetEntry == null) {
            return Optional.empty();
        }

        Report report =
                targetEntry.report();

        /*
         * beta_i = 0：
         *
         *      D_i = m_i
         *      RM_i = bottom
         *
         * 无需 DR 恢复密钥，直接返回报告正文。
         *
         * Report.getData() 已返回内部数组的副本。
         */
        if (report.getBeta() == 0) {
            return Optional.of(
                    report.getData());
        }

        /*
         * 经过 AggVerify 后，beta_i 理论上只能为 0 或 1。
         */
        if (report.getBeta() != 1) {
            return Optional.empty();
        }

        /*
         * 敏感报告必须提供 DR 恢复密钥。
         */
        if (recoveryKey == null) {
            return Optional.empty();
        }

        /*
         * beta_i = 1 时必须存在恢复材料 RM_i。
         */
        if (!report.hasRecoveryMaterial()) {
            return Optional.empty();
        }

        byte[] symmetricKey = null;

        try {
            /*
             * K_i <- KEM.Decap(
             *          pp_KEM,
             *          sk_R,
             *          RM_i
             *      )
             *
             * 当前具体实现：
             *
             *      DHKEM-X25519-HKDF-SHA256
             */
            symmetricKey =
                    Kem.decap(
                            pp,
                            recoveryKey,
                            report.getRecoveryMaterial());

            /*
             * 重建与 Sign 阶段完全相同的关联数据：
             *
             * AAD_i =
             *      ID_i || pk_i || beta_i || bid || t
             */
            byte[] associatedData =
                    BasrTranscript.buildAad(
                            report.getDeviceId(),
                            report.getPublicKey(),
                            report.getBeta(),
                            report.getBatchId(),
                            report.getTimestamp());

            /*
             * m_i <- AEAD.Dec(
             *          pp_AEAD,
             *          K_i,
             *          D_i,
             *          AAD_i
             *      )
             *
             * 当前具体实现：
             *
             *      AES-256-GCM
             */
            byte[] plaintext =
                    Aead.decrypt(
                            pp,
                            symmetricKey,
                            report.getData(),
                            associatedData);

            return Optional.of(plaintext);

        } catch (SecurityException exception) {
            /*
             * AES-GCM 认证标签验证失败。
             *
             * 常见原因：
             *
             * - 使用了错误的 DR 私钥；
             * - 密文被篡改；
             * - AAD 不一致；
             * - RM_i 与当前密文不匹配。
             */
            return Optional.empty();

        } catch (IllegalArgumentException exception) {
            /*
             * 恢复材料、密钥类型或密文格式非法。
             */
            return Optional.empty();

        } finally {
            /*
             * 临时对称密钥不应长时间保留在内存中。
             */
            if (symmetricKey != null) {
                Arrays.fill(
                        symmetricKey,
                        (byte) 0);
            }
        }
    }
}