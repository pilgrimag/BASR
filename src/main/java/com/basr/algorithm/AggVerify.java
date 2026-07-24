package com.basr.algorithm;

import com.basr.crypto.BasrTranscript;
import com.basr.crypto.Hash;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.crypto.Schnorr;
import com.basr.entity.AggregateSignature;
import com.basr.entity.BatchRecord;
import com.basr.entity.Report;
import com.basr.registry.DeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * BASR Algorithm 6: AggVerify。
 *
 * 输入：
 *
 *      pp      ：系统公共参数；
 *      L       ：设备注册列表；
 *      BRec    ：批次记录；
 *      Pkg     ：离线报告包。
 *
 * 输出：
 *
 *      true  ：批次记录和离线包验证成功；
 *      false ：验证失败。
 *
 * 完整验证内容：
 *
 * 1. Pkg 非空；
 * 2. 每个设备身份与公钥已注册；
 * 3. 每个 (ID_i, R_i) 不重复；
 * 4. 每个报告的 bid_i 和 t_i 与 BRec 一致；
 * 5. 每个报告摘要 d_i 正确；
 * 6. 重新计算批次承诺 mu'；
 * 7. 重新计算 R' = sum R_i；
 * 8. 重新计算 T' = sum [h_i]pk_i；
 * 9. 验证 mu' = mu；
 * 10. 验证 R' = R_agg；
 * 11. 验证 [s_agg]g = R' + T'。
 *
 * 当前本地实现直接接收 BRec 和 Pkg，
 * 不查询 Fabric，也不从 IPFS 下载数据。
 */
public final class AggVerify {

    private AggVerify() {
    }

    /**
     * 直接验证 Aggregate 的联合返回结果。
     *
     * @param pp       BASR 系统公共参数
     * @param registry 本地设备注册表
     * @param result   Aggregate 返回的 BRec 和 Pkg
     * @return 是否验证成功
     */
    public static boolean verify(
            PublicParams pp,
            DeviceRegistry registry,
            Aggregate.Result result) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(registry, "registry");

        if (result == null) {
            return false;
        }

        return verify(
                pp,
                registry,
                result.batchRecord(),
                result.packageEntries());
    }

    /**
     * 按照 Algorithm 6 验证 BRec 和 Pkg。
     *
     * @param pp             系统公共参数
     * @param registry       注册设备列表 L
     * @param batchRecord    BRec
     * @param packageEntries Pkg
     * @return 验证结果
     */
    public static boolean verify(
            PublicParams pp,
            DeviceRegistry registry,
            BatchRecord batchRecord,
            List<Aggregate.PackageEntry> packageEntries) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(registry, "registry");

        /*
         * BRec 或 Pkg 缺失时直接拒绝。
         */
        if (batchRecord == null
                || packageEntries == null) {

            return false;
        }

        /*
         * Algorithm 6, Lines 4-6：
         *
         * 如果 q = 0，则返回 0。
         */
        if (packageEntries.isEmpty()) {
            return false;
        }

        AggregateSignature aggregateSignature =
                batchRecord.getAggregateSignature();

        if (aggregateSignature == null) {
            return false;
        }

        /*
         * s_agg 必须属于 Z_p。
         *
         * s_agg 可以为 0，因此使用 isScalar，
         * 而不是 isNonZeroScalar。
         */
        if (!Schnorr.isScalar(
                aggregateSignature.getSagg(),
                pp.getP())) {

            return false;
        }

        /*
         * R_agg 是群 G 中的元素。
         *
         * 聚合承诺在极低概率下可能等于单位元 O，
         * 因此这里允许无穷远点作为合法群单位元。
         */
        if (!isGroupElementAllowIdentity(
                pp,
                aggregateSignature.getRagg())) {

            return false;
        }

        /*
         * Algorithm 6 初始化：
         *
         *      U  <- empty
         *      R' <- 1_G
         *      T' <- 1_G
         *
         * 在椭圆曲线加法群中，1_G 对应无穷远点 O。
         */
        Set<DuplicateKey> acceptedPairs =
                new HashSet<>();

        ECPoint reconstructedCommitment =
                pp.getGroup()
                        .getCurve()
                        .getInfinity();

        ECPoint reconstructedPublicKeyTerm =
                pp.getGroup()
                        .getCurve()
                        .getInfinity();

        /*
         * 保存每个 (rep_i, R_i) 的规范编码，
         * 用于重新计算 mu'。
         */
        byte[][] encodedEntries =
                new byte[packageEntries.size()][];

        for (int index = 0;
             index < packageEntries.size();
             index++) {

            Aggregate.PackageEntry entry =
                    packageEntries.get(index);

            if (entry == null) {
                return false;
            }

            Report report =
                    entry.report();

            ECPoint commitment =
                    entry.commitment();

            if (report == null
                    || commitment == null) {

                return false;
            }

            /*
             * pk_i 必须是 G 中的有效非单位元。
             */
            if (!PointCodec.isValidGroupElement(
                    pp,
                    report.getPublicKey())) {

                return false;
            }

            /*
             * 每个单签名承诺 R_i 必须是 G 中的有效非单位元。
             */
            if (!PointCodec.isValidGroupElement(
                    pp,
                    commitment)) {

                return false;
            }

            /*
             * beta_i 必须属于 {0,1}。
             */
            if (report.getBeta() != 0
                    && report.getBeta() != 1) {

                return false;
            }

            /*
             * 检查 beta_i 与 RM_i 的语义一致性。
             */
            if (report.getBeta() == 0
                    && report.hasRecoveryMaterial()) {

                return false;
            }

            if (report.getBeta() == 1
                    && !report.hasRecoveryMaterial()) {

                return false;
            }

            /*
             * d_i 是 H1 输出，必须属于 Z_p。
             */
            if (!Schnorr.isScalar(
                    report.getDigest(),
                    pp.getP())) {

                return false;
            }

            /*
             * Algorithm 6：
             *
             * 检查：
             *
             *      (ID_i, pk_i) in L
             */
            if (!registry.contains(
                    report.getDeviceId(),
                    report.getPublicKey())) {

                return false;
            }

            /*
             * 检查：
             *
             *      bid_i == bid
             */
            if (!batchRecord
                    .getBatchId()
                    .equals(
                            report.getBatchId())) {

                return false;
            }

            /*
             * 检查：
             *
             *      t_i == t
             */
            if (batchRecord.getTimestamp()
                    != report.getTimestamp()) {

                return false;
            }

            final BigInteger expectedDigest;

            try {
                /*
                 * 重新计算：
                 *
                 * d_i' = H1(
                 *
                 *      ID_i || pk_i || beta_i || D_i
                 *      || RM_i || bid_i || t_i
                 *
                 * )
                 */
                expectedDigest =
                        BasrTranscript
                                .computeReportDigest(
                                        pp,
                                        report.getDeviceId(),
                                        report.getPublicKey(),
                                        report.getBeta(),
                                        report.getData(),
                                        report.getRecoveryMaterial(),
                                        report.getBatchId(),
                                        report.getTimestamp());

            } catch (IllegalArgumentException exception) {
                return false;
            }

            /*
             * 检查：
             *
             *      d_i' == d_i
             */
            if (!expectedDigest.equals(
                    report.getDigest())) {

                return false;
            }

            final String encodedCommitment;

            try {
                encodedCommitment =
                        Base64.getEncoder()
                                .encodeToString(
                                        PointCodec
                                                .encodeCompressed(
                                                        commitment));

            } catch (IllegalArgumentException exception) {
                return false;
            }

            DuplicateKey duplicateKey =
                    new DuplicateKey(
                            report.getDeviceId(),
                            encodedCommitment);

            /*
             * 检查：
             *
             *      (ID_i, R_i) not in U
             */
            if (!acceptedPairs.add(
                    duplicateKey)) {

                return false;
            }

            final BigInteger challenge;

            try {
                /*
                 * 重新计算：
                 *
                 * h_i = H2(
                 *
                 *      bid_i || t_i || ID_i || pk_i
                 *      || beta_i || d_i || R_i
                 *
                 * )
                 */
                challenge =
                        BasrTranscript
                                .computeSignatureChallenge(
                                        pp,
                                        report.getBatchId(),
                                        report.getTimestamp(),
                                        report.getDeviceId(),
                                        report.getPublicKey(),
                                        report.getBeta(),
                                        report.getDigest(),
                                        commitment);

                /*
                 * 对 (rep_i,R_i) 进行规范编码，
                 * 用于计算 mu'。
                 */
                encodedEntries[index] =
                        BasrTranscript
                                .encodePackageEntry(
                                        pp,
                                        report,
                                        commitment);

            } catch (IllegalArgumentException exception) {
                return false;
            }

            /*
             * 论文乘法群：
             *
             *      R' <- R' * R_i
             *
             * secp256k1 加法群：
             *
             *      R' <- R' + R_i
             */
            reconstructedCommitment =
                    reconstructedCommitment
                            .add(commitment);

            /*
             * 论文乘法群：
             *
             *      T' <- T' * pk_i^{h_i}
             *
             * secp256k1 加法群：
             *
             *      T' <- T' + [h_i]pk_i
             */
            reconstructedPublicKeyTerm =
                    reconstructedPublicKeyTerm
                            .add(
                                    report.getPublicKey()
                                            .multiply(
                                                    challenge));
        }

        reconstructedCommitment =
                reconstructedCommitment.normalize();

        reconstructedPublicKeyTerm =
                reconstructedPublicKeyTerm.normalize();

        /*
         * Algorithm 6, Line 7：
         *
         * mu' = H3(
         *
         *      (rep_1 || R_1)
         *      || ...
         *      || (rep_q || R_q)
         *
         * )
         */
        byte[] expectedMu =
                Hash.H3(
                        pp,
                        encodedEntries);

        /*
         * 检查：
         *
         *      mu' == mu
         *
         * 使用 MessageDigest.isEqual 进行字节数组比较。
         */
        if (!MessageDigest.isEqual(
                expectedMu,
                batchRecord.getMu())) {

            return false;
        }

        /*
         * 检查：
         *
         *      R' == R_agg
         */
        if (!reconstructedCommitment.equals(
                aggregateSignature
                        .getRagg()
                        .normalize())) {

            return false;
        }

        /*
         * 计算等式左边：
         *
         *      [s_agg]g
         */
        ECPoint left =
                pp.getGenerator()
                        .multiply(
                                aggregateSignature
                                        .getSagg())
                        .normalize();

        /*
         * 计算等式右边：
         *
         *      R' + T'
         */
        ECPoint right =
                reconstructedCommitment
                        .add(
                                reconstructedPublicKeyTerm)
                        .normalize();

        /*
         * 最终聚合签名验证：
         *
         *      [s_agg]g == R' + T'
         */
        return left.equals(right);
    }

    /**
     * 检查点是否属于群 G，同时允许群单位元 O。
     *
     * PointCodec.isValidGroupElement() 会拒绝 O，
     * 但聚合结果理论上允许等于单位元，因此单独实现。
     */
    private static boolean isGroupElementAllowIdentity(
            PublicParams pp,
            ECPoint point) {

        if (point == null
                || point.getCurve() == null) {

            return false;
        }

        if (!point.getCurve().equals(
                pp.getGroup().getCurve())) {

            return false;
        }

        ECPoint normalized =
                point.normalize();

        if (!normalized.isInfinity()
                && !normalized.isValid()) {

            return false;
        }

        /*
         * 检查：
         *
         *      [p]P = O
         */
        return normalized
                .multiply(pp.getP())
                .isInfinity();
    }

    /**
     * 严格对应算法中的去重键：
     *
     *      (ID_i, R_i)
     */
    private record DuplicateKey(
            String deviceId,
            String encodedCommitment) {
    }
}