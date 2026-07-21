package com.basr.algorithm;

import com.basr.crypto.PublicParams;
import com.basr.crypto.PublicParams.AeadParameters;
import com.basr.crypto.PublicParams.HashParameters;
import com.basr.crypto.PublicParams.KemParameters;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * BASR Setup 算法。
 *
 * 输入：
 *
 *      安全参数 τ
 *
 * 输出：
 *
 *      pp = (
 *          p,
 *          G,
 *          g,
 *          H1,
 *          H2,
 *          H3,
 *          H4,
 *          pp_KEM,
 *          pp_AEAD
 *      )
 *
 * 当前具体实例化：
 *
 * 1. 设备 Schnorr 签名群：
 *      secp256k1
 *
 * 2. 数据恢复 KEM：
 *      X25519 + HKDF-HMAC-SHA-256
 *
 * 3. 对称认证加密：
 *      AES-256-GCM
 *
 * 4. 哈希函数：
 *      SHA-256，并为 H1-H4 设置独立域分离标签。
 */
public final class Setup {

    /**
     * secp256k1 的通用离散对数安全强度约为 128 位。
     */
    private static final int MAX_SECURITY_PARAMETER = 128;

    private static final String SIGNATURE_CURVE_NAME =
            "secp256k1";

    /**
     * 工具类不需要被实例化。
     */
    private Setup() {
    }

    public static PublicParams setup(
            int securityParameter) {

        /*
         * 当前固定使用 secp256k1。
         *
         * secp256k1 的群阶约为 256 位，
         * 对应约 128 位通用离散对数安全性。
         *
         * 因此这里不允许声称超过 128 位的安全参数。
         */
        if (securityParameter <= 0
                || securityParameter > MAX_SECURITY_PARAMETER) {

            throw new IllegalArgumentException(
                    "secp256k1 supports at most approximately "
                            + MAX_SECURITY_PARAMETER
                            + " bits of generic security");
        }

        /*
         * Algorithm 1, Line 1:
         *
         *      p, G, g <- G(1^τ)
         *
         * 从 Bouncy Castle 加载 secp256k1 标准域参数。
         */
        X9ECParameters curveParameters =
                CustomNamedCurves.getByName(
                        SIGNATURE_CURVE_NAME);

        if (curveParameters == null) {
            throw new IllegalStateException(
                    "Bouncy Castle does not provide curve: "
                            + SIGNATURE_CURVE_NAME);
        }

        /*
         * 论文中的生成元 g。
         *
         * 这是一个真实椭圆曲线群元素。
         */
        ECPoint g =
                curveParameters
                        .getG()
                        .normalize();

        /*
         * 论文中的 p。
         *
         * 注意：
         *
         * 这里必须使用 getN()，即基点生成子群的阶。
         *
         * 不能使用底层有限域特征值作为论文中的 p。
         */
        BigInteger p =
                curveParameters.getN();

        /*
         * 构造论文中的群 G。
         *
         * ECDomainParameters 保存：
         *
         * - 椭圆曲线；
         * - 基点 g；
         * - 群阶 p；
         * - 余因子。
         */
        ECDomainParameters group =
                new ECDomainParameters(
                        curveParameters.getCurve(),
                        g,
                        p,
                        curveParameters.getH());

        /*
         * 对 p 做基本素性检查。
         *
         * 论文要求 G 为素数阶群，因此 p 应为素数。
         */
        if (!p.isProbablePrime(128)) {
            throw new IllegalStateException(
                    "The selected subgroup order p is not prime");
        }

        /*
         * 检查 g 是否属于当前曲线。
         */
        if (!g.isValid()) {
            throw new IllegalStateException(
                    "The generator g is not a valid curve point");
        }

        /*
         * 检查：
         *
         *      [p]g = O
         *
         * 从而确认 g 位于阶为 p 的子群中。
         */
        if (!g.multiply(p).isInfinity()) {
            throw new IllegalStateException(
                    "The generator g does not have order p");
        }

        /*
         * Algorithm 1, Lines 4-7:
         *
         * 定义 H1、H2、H3、H4。
         *
         * 当前四者都使用 SHA-256，
         * 但必须采用不同域分离标签。
         *
         * H1、H2、H4 的具体 hash-to-scalar
         * 将在 Hash.java 中实现。
         *
         * H3 返回字节串，用于批次承诺 μ。
         */
        HashParameters hashParameters =
                new HashParameters(
                        "SHA-256",
                        "BASR-H1-REPORT-DIGEST-v1",
                        "BASR-H2-SIGNATURE-CHALLENGE-v1",
                        "BASR-H3-BATCH-COMMITMENT-v1",
                        "BASR-H4-POP-CHALLENGE-v1",
                        32);

        /*
         * Algorithm 1, Line 2:
         *
         *      pp_KEM <- KEM.Setup(1^τ)
         *
         * 这里选用：
         *
         *      X25519 + HKDF-HMAC-SHA-256
         *
         * KEM 最终导出 32 字节对称密钥，
         * 供 AES-256-GCM 使用。
         *
         * 此处不会生成 DR 密钥。
         * DR 密钥将在 RecKeyGen 中生成。
         */
        KemParameters kemParameters =
                new KemParameters(
                        "DHKEM-X25519-HKDF-SHA256",
                        "X25519",
                        "HKDF-HMAC-SHA-256",
                        32);

        /*
         * Algorithm 1, Line 3:
         *
         *      pp_AEAD <- AEAD.Setup(1^τ)
         *
         * 这里选用：
         *
         *      AES-256-GCM
         *
         * - key：32 字节；
         * - nonce：12 字节；
         * - authentication tag：128 位。
         *
         * 此处不会生成具体密钥或 nonce。
         * 这些值将在每次 Sign 加密时产生。
         */
        AeadParameters aeadParameters =
                new AeadParameters(
                        "AES/GCM/NoPadding",
                        32,
                        12,
                        128);

        /*
         * Algorithm 1, Line 8:
         *
         * pp = (
         *      p,
         *      G,
         *      g,
         *      H1,
         *      H2,
         *      H3,
         *      H4,
         *      pp_KEM,
         *      pp_AEAD
         * )
         */
        return new PublicParams(
                securityParameter,
                SIGNATURE_CURVE_NAME,
                p,
                group,
                g,
                hashParameters,
                kemParameters,
                aeadParameters);
    }
}