package com.basr.algorithm;

import com.basr.crypto.BasrTranscript;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.crypto.Schnorr;
import com.basr.entity.Report;
import com.basr.entity.Signature;
import com.basr.entity.SignedReport;
import com.basr.registry.DeviceRegistry;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR Algorithm 4: SigVerify。
 *
 * 输入：
 *
 *      pp      ：系统公共参数；
 *      L       ：已注册设备公钥列表；
 *      rep_i   ：设备报告；
 *      sigma_i ：设备签名。
 *
 * 输出：
 *
 *      true  ：签名有效；
 *      false ：签名无效。
 *
 * 算法步骤：
 *
 * 1. 检查 (ID_i, pk_i) 是否属于注册列表 L；
 *
 * 2. 重新计算：
 *
 *      d_i' = H1(
 *          ID_i || pk_i || beta_i || D_i
 *          || RM_i || bid || t
 *      )
 *
 * 3. 验证：
 *
 *      d_i' == d_i
 *
 * 4. 重新计算：
 *
 *      h_i = H2(
 *          bid || t || ID_i || pk_i
 *          || beta_i || d_i || R_i
 *      )
 *
 * 5. 验证 Schnorr 等式：
 *
 *      g^{s_i} = R_i * pk_i^{h_i}
 *
 * 在椭圆曲线加法群中的等价形式为：
 *
 *      [s_i]g = R_i + [h_i]pk_i
 *
 * 当前本地版本使用 DeviceRegistry 代替区块链注册列表，
 * 但密码学验证流程与算法描述一致。
 */
public final class SigVerify {

    /**
     * 工具类不允许实例化。
     */
    private SigVerify() {
    }

    /**
     * 验证 Sign 算法产生的联合输出。
     *
     * @param pp           BASR 系统公共参数
     * @param registry     本地设备注册表 L
     * @param signedReport Sign 的联合输出
     * @return 签名是否有效
     */
    public static boolean verify(
            PublicParams pp,
            DeviceRegistry registry,
            SignedReport signedReport) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(registry, "registry");

        /*
         * signedReport 属于外部输入。
         * 缺失时直接判定为无效，而不是继续执行。
         */
        if (signedReport == null) {
            return false;
        }

        return verify(
                pp,
                registry,
                signedReport.getReport(),
                signedReport.getSignature());
    }

    /**
     * 验证独立的报告和签名。
     *
     * 该接口后续会被 Aggregate 直接调用：
     *
     *      SigVerify(pp, L, rep_i, sigma_i)
     *
     * @param pp        BASR 系统公共参数
     * @param registry  本地设备注册表 L
     * @param report    报告 rep_i
     * @param signature 签名 sigma_i
     * @return true 表示验证成功，false 表示验证失败
     */
    public static boolean verify(
            PublicParams pp,
            DeviceRegistry registry,
            Report report,
            Signature signature) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(registry, "registry");

        /*
         * 报告或签名缺失时直接拒绝。
         */
        if (report == null || signature == null) {
            return false;
        }

        /*
         * beta_i 必须属于 {0,1}。
         *
         * 虽然 Report 构造函数已经检查该条件，
         * 但验证算法不能完全依赖对象构造阶段，
         * 因为未来数据可能来自 Fabric、文件或网络反序列化。
         */
        if (report.getBeta() != 0
                && report.getBeta() != 1) {

            return false;
        }

        /*
         * 检查 RM_i 与 beta_i 的语义一致性：
         *
         * beta_i = 0：
         *      RM_i = bottom
         *
         * beta_i = 1：
         *      RM_i 必须存在。
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
         * 检查设备公钥 pk_i 是群 G 中的有效非单位元。
         */
        if (!PointCodec.isValidGroupElement(
                pp,
                report.getPublicKey())) {

            return false;
        }

        /*
         * 检查签名承诺 R_i 是群 G 中的有效非单位元。
         */
        if (!PointCodec.isValidGroupElement(
                pp,
                signature.getR())) {

            return false;
        }

        BigInteger p = pp.getP();

        /*
         * 报告摘要 d_i 是 H1 的输出，因此必须属于 Z_p。
         */
        if (!Schnorr.isScalar(
                report.getDigest(),
                p)) {

            return false;
        }

        /*
         * Schnorr 响应 s_i 必须属于 Z_p。
         */
        if (!Schnorr.isScalar(
                signature.getS(),
                p)) {

            return false;
        }

        /*
         * Algorithm 4, Lines 3-5：
         *
         * 检查：
         *
         *      (ID_i, pk_i) ∈ L
         *
         * 不能只检查 ID_i，也不能只检查 pk_i，
         * 必须检查二者作为同一个注册记录存在。
         */
        if (!registry.contains(
                report.getDeviceId(),
                report.getPublicKey())) {

            return false;
        }

        final BigInteger expectedDigest;

        try {
            /*
             * Algorithm 4, Line 6：
             *
             * d_i' = H1(
             *
             *      ID_i || pk_i || beta_i || D_i
             *      || RM_i || bid || t
             *
             * )
             *
             * BasrTranscript 保证这里的字段顺序和编码方式
             * 与 Sign 完全一致。
             */
            expectedDigest =
                    BasrTranscript.computeReportDigest(
                            pp,
                            report.getDeviceId(),
                            report.getPublicKey(),
                            report.getBeta(),
                            report.getData(),
                            report.getRecoveryMaterial(),
                            report.getBatchId(),
                            report.getTimestamp());

        } catch (IllegalArgumentException exception) {
            /*
             * 报告字段格式非法时直接拒绝。
             */
            return false;
        }

        /*
         * Algorithm 4, Lines 7-9：
         *
         * 验证：
         *
         *      d_i' == d_i
         *
         * 如果报告数据、身份、公钥、敏感标志、恢复材料、
         * 批次 ID 或时间戳中任何一项被修改，该检查都会失败。
         */
        if (!expectedDigest.equals(
                report.getDigest())) {

            return false;
        }

        final BigInteger challenge;

        try {
            /*
             * Algorithm 4, Line 10：
             *
             * h_i = H2(
             *
             *      bid || t || ID_i || pk_i
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
                                    signature.getR());

        } catch (IllegalArgumentException exception) {
            return false;
        }

        /*
         * Algorithm 4, Lines 11-14：
         *
         * 论文乘法群记法：
         *
         *      g^{s_i}
         *          ?=
         *      R_i * pk_i^{h_i}
         *
         * secp256k1 加法群记法：
         *
         *      [s_i]g
         *          ?=
         *      R_i + [h_i]pk_i
         */
        return Schnorr.verifyResponse(
                pp,
                report.getPublicKey(),
                signature.getR(),
                challenge,
                signature.getS());
    }
}