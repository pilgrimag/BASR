package com.basr.algorithm;

import com.basr.crypto.BasrTranscript;
import com.basr.crypto.Hash;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.entity.AggregateSignature;
import com.basr.entity.BatchRecord;
import com.basr.entity.Report;
import com.basr.entity.Signature;
import com.basr.entity.SignedReport;
import com.basr.registry.DeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * BASR Algorithm 5: Aggregate。
 *
 * 输入：
 *
 *      pp
 *      L
 *      {(rep_i, sigma_i)}_{i=1}^n
 *      bid
 *      t
 *
 * 输出：
 *
 *      (BRec, Pkg)
 *
 * 或：
 *
 *      bottom
 *
 * 本地实现完整执行：
 *
 * 1. 批次和时间戳筛选；
 * 2. 按 (ID_i, R_i) 去重；
 * 3. 调用 SigVerify；
 * 4. 聚合签名；
 * 5. 构造 Pkg；
 * 6. 计算 mu。
 *
 * 当前暂不执行：
 *
 *      cid <- IPFS.Put(Pkg)
 *      BC[bid] <- BRec
 *
 * 因此本地 BatchRecord 的 cid 为 null。
 */
public final class Aggregate {

    private Aggregate() {
    }

    /**
     * 执行报告聚合。
     *
     * Optional.empty() 对应算法输出 bottom。
     *
     * @param pp         系统公共参数
     * @param registry   设备注册列表 L
     * @param candidates 候选报告和签名
     * @param batchId    目标批次 bid
     * @param timestamp  目标时间戳 t
     * @return 本地聚合结果，或者 Optional.empty()
     */
    public static Optional<Result> aggregate(
            PublicParams pp,
            DeviceRegistry registry,
            List<SignedReport> candidates,
            String batchId,
            long timestamp) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(
                registry,
                "registry");
        Objects.requireNonNull(
                candidates,
                "candidates");

        if (batchId == null
                || batchId.isBlank()) {

            throw new IllegalArgumentException(
                    "batchId cannot be blank");
        }

        /*
         * 对应算法中的集合 I。
         *
         * 使用 List 保留输入索引的递增顺序：
         *
         *      i_1 < ... < i_q
         */
        List<AcceptedEntry> accepted =
                new ArrayList<>();

        /*
         * 对应算法中的集合 U：
         *
         *      U = {(ID_i, R_i)}
         *
         * 只将已经通过 SigVerify 的条目加入 U。
         */
        Set<DuplicateKey> acceptedPairs =
                new HashSet<>();

        for (SignedReport candidate : candidates) {

            /*
             * 外部输入中的空项视为无效项并忽略。
             */
            if (candidate == null) {
                continue;
            }

            Report report =
                    candidate.getReport();

            Signature signature =
                    candidate.getSignature();

            if (report == null
                    || signature == null) {

                continue;
            }

            /*
             * 检查：
             *
             *      bid_i == bid
             *      t_i == t
             */
            if (!batchId.equals(
                    report.getBatchId())
                    || timestamp
                    != report.getTimestamp()) {

                continue;
            }

            final DuplicateKey duplicateKey;

            try {
                /*
                 * 严格按算法使用：
                 *
                 *      (ID_i, R_i)
                 *
                 * 作为去重键。
                 */
                duplicateKey =
                        new DuplicateKey(
                                report.getDeviceId(),
                                Base64.getEncoder()
                                        .encodeToString(
                                                PointCodec
                                                        .encodeCompressed(
                                                                signature
                                                                        .getR())));

            } catch (IllegalArgumentException exception) {
                /*
                 * 非法 R_i 无法形成合法去重键。
                 */
                continue;
            }

            /*
             * 只有此前已经接受过完全相同的
             * (ID_i, R_i) 时才判定为重复。
             */
            if (acceptedPairs.contains(
                    duplicateKey)) {

                continue;
            }

            /*
             * 调用 Algorithm 4 SigVerify。
             */
            if (!SigVerify.verify(
                    pp,
                    registry,
                    report,
                    signature)) {

                continue;
            }

            /*
             * 只有签名验证成功后，才更新 I 和 U。
             */
            accepted.add(
                    new AcceptedEntry(
                            report,
                            signature));

            acceptedPairs.add(
                    duplicateKey);
        }

        /*
         * 如果 I 为空，则返回 bottom。
         */
        if (accepted.isEmpty()) {
            return Optional.empty();
        }

        /*
         * secp256k1 加法群的单位元 O。
         */
        ECPoint aggregateCommitment =
                pp.getGroup()
                        .getCurve()
                        .getInfinity();

        BigInteger aggregateResponse =
                BigInteger.ZERO;

        List<PackageEntry> packageEntries =
                new ArrayList<>(
                        accepted.size());

        for (AcceptedEntry acceptedEntry
                : accepted) {

            Report report =
                    acceptedEntry.report();

            Signature signature =
                    acceptedEntry.signature();

            /*
             * 论文乘法群：
             *
             *      R_agg = product(R_i)
             *
             * secp256k1 加法群：
             *
             *      R_agg = sum(R_i)
             */
            aggregateCommitment =
                    aggregateCommitment
                            .add(signature.getR());

            /*
             * s_agg = sum(s_i) mod p
             */
            aggregateResponse =
                    aggregateResponse
                            .add(signature.getS())
                            .mod(pp.getP());

            /*
             * Pkg 只保存：
             *
             *      (rep_i, R_i)
             *
             * 不保存单签名响应 s_i。
             */
            packageEntries.add(
                    new PackageEntry(
                            report,
                            signature.getR()));
        }

        aggregateCommitment =
                aggregateCommitment.normalize();

        AggregateSignature aggregateSignature =
                new AggregateSignature(
                        aggregateCommitment,
                        aggregateResponse);

        /*
         * 计算：
         *
         * mu = H3(
         *      (rep_1 || R_1)
         *      || ...
         *      || (rep_q || R_q)
         * )
         *
         * packageEntries 顺序与被接受的输入索引顺序一致。
         */
        byte[][] encodedEntries =
                new byte[
                        packageEntries.size()][];

        for (int index = 0;
             index < packageEntries.size();
             index++) {

            PackageEntry entry =
                    packageEntries.get(index);

            encodedEntries[index] =
                    BasrTranscript
                            .encodePackageEntry(
                                    pp,
                                    entry.report(),
                                    entry.commitment());
        }

        byte[] mu =
                Hash.H3(
                        pp,
                        encodedEntries);

        /*
         * 本地版本尚未执行 IPFS.Put(Pkg)，
         * 因而 cid 不存在。
         */
        BatchRecord batchRecord =
                BatchRecord.local(
                        batchId,
                        timestamp,
                        aggregateSignature,
                        mu);

        return Optional.of(
                new Result(
                        batchRecord,
                        packageEntries));
    }

    /**
     * Pkg 中的单个条目：
     *
     *      (rep_i, R_i)
     */
    public record PackageEntry(
            Report report,
            ECPoint commitment) {

        public PackageEntry {

            Objects.requireNonNull(
                    report,
                    "report");

            Objects.requireNonNull(
                    commitment,
                    "commitment");

            commitment =
                    commitment.normalize();

            if (commitment.isInfinity()) {
                throw new IllegalArgumentException(
                        "Individual commitment cannot be infinity");
            }
        }
    }

    /**
     * Aggregate 的本地联合输出。
     *
     * 对应：
     *
     *      (BRec, Pkg)
     */
    public record Result(
            BatchRecord batchRecord,
            List<PackageEntry> packageEntries) {

        public Result {

            Objects.requireNonNull(
                    batchRecord,
                    "batchRecord");

            Objects.requireNonNull(
                    packageEntries,
                    "packageEntries");

            packageEntries =
                    List.copyOf(
                            packageEntries);

            if (packageEntries.isEmpty()) {
                throw new IllegalArgumentException(
                        "Aggregation package cannot be empty");
            }
        }

        public int acceptedCount() {
            return packageEntries.size();
        }
    }

    /**
     * 内部保存通过检查的完整签名，
     * 用于计算 s_agg。
     */
    private record AcceptedEntry(
            Report report,
            Signature signature) {
    }

    /**
     * 严格对应算法中的去重对象：
     *
     *      (ID_i, R_i)
     */
    private record DuplicateKey(
            String deviceId,
            String encodedCommitment) {
    }
}