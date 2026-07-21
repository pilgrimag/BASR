package com.basr.crypto;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR 系统公共参数。
 *
 * 对应算法中的：
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
 *
 * 其中：
 *
 * p       ：素数阶群 G 的阶；
 * G       ：用于 Schnorr 签名的素数阶椭圆曲线群；
 * g       ：群 G 的生成元；
 * H1-H4   ：带有不同域分离标签的哈希函数；
 * pp_KEM  ：KEM 的公共配置参数；
 * pp_AEAD ：AEAD 的公共配置参数。
 */
public final class PublicParams {

    /**
     * 算法输入的安全参数 τ。
     *
     * 当前使用 secp256k1，因此对应约 128 位通用离散对数安全强度。
     */
    private final int securityParameter;

    /**
     * 签名群采用的命名曲线。
     */
    private final String signatureCurveName;

    /**
     * 论文中的 p。
     *
     * p 是素数阶群 G 的阶，不是椭圆曲线底层有限域的模数。
     *
     * 所有标量都属于 Z_p，例如：
     *
     * sk_i, r_i, c_i, s_i ∈ Z_p。
     */
    private final BigInteger p;

    /**
     * 论文中的素数阶群 G。
     *
     * ECDomainParameters 包含：
     *
     * - 椭圆曲线；
     * - 基点；
     * - 基点阶；
     * - 余因子。
     */
    private final ECDomainParameters group;

    /**
     * 论文中的生成元 g。
     *
     * 在当前实例化中，它是 secp256k1 的标准基点。
     */
    private final ECPoint generator;

    /**
     * H1、H2、H3、H4 的公共配置。
     */
    private final HashParameters hashParameters;

    /**
     * KEM 公共参数 pp_KEM。
     */
    private final KemParameters kemParameters;

    /**
     * AEAD 公共参数 pp_AEAD。
     */
    private final AeadParameters aeadParameters;

    public PublicParams(
            int securityParameter,
            String signatureCurveName,
            BigInteger p,
            ECDomainParameters group,
            ECPoint generator,
            HashParameters hashParameters,
            KemParameters kemParameters,
            AeadParameters aeadParameters) {

        if (securityParameter <= 0) {
            throw new IllegalArgumentException(
                    "securityParameter must be positive");
        }

        this.signatureCurveName =
                Objects.requireNonNull(
                        signatureCurveName,
                        "signatureCurveName");

        this.p = Objects.requireNonNull(p, "p");

        this.group = Objects.requireNonNull(group, "group");

        this.generator =
                Objects.requireNonNull(generator, "generator")
                        .normalize();

        this.hashParameters =
                Objects.requireNonNull(
                        hashParameters,
                        "hashParameters");

        this.kemParameters =
                Objects.requireNonNull(
                        kemParameters,
                        "kemParameters");

        this.aeadParameters =
                Objects.requireNonNull(
                        aeadParameters,
                        "aeadParameters");

        /*
         * 一致性检查1：
         *
         * PublicParams 中单独保存的 p，
         * 必须与椭圆曲线域参数中的基点阶完全相同。
         */
        if (!this.p.equals(this.group.getN())) {
            throw new IllegalArgumentException(
                    "p must equal the order of group G");
        }

        /*
         * 一致性检查2：
         *
         * 单独保存的生成元 g，
         * 必须与群参数 G 中保存的基点一致。
         */
        if (!this.generator.equals(
                this.group.getG().normalize())) {

            throw new IllegalArgumentException(
                    "generator must equal the base point of group G");
        }

        /*
         * 一致性检查3：
         *
         * 生成元不能是无穷远点。
         */
        if (this.generator.isInfinity()) {
            throw new IllegalArgumentException(
                    "generator cannot be the point at infinity");
        }

        /*
         * 一致性检查4：
         *
         * 由于 g 的阶为 p，应满足：
         *
         *      [p]g = O
         *
         * 其中 O 为椭圆曲线无穷远点。
         */
        if (!this.generator.multiply(this.p).isInfinity()) {
            throw new IllegalArgumentException(
                    "generator does not have the expected order p");
        }

        this.securityParameter = securityParameter;
    }

    public int getSecurityParameter() {
        return securityParameter;
    }

    public String getSignatureCurveName() {
        return signatureCurveName;
    }

    public BigInteger getP() {
        return p;
    }

    public ECDomainParameters getGroup() {
        return group;
    }

    public ECPoint getGenerator() {
        return generator;
    }

    public HashParameters getHashParameters() {
        return hashParameters;
    }

    public KemParameters getKemParameters() {
        return kemParameters;
    }

    public AeadParameters getAeadParameters() {
        return aeadParameters;
    }

    /**
     * H1-H4 的配置参数。
     *
     * 四个哈希函数可以使用同一个底层摘要算法，
     * 但必须使用不同域分离标签，防止不同协议用途之间发生混淆。
     *
     * H1、H2、H4 后续需要映射到 Z_p；
     * H3 输出字节串，用于计算批次承诺值 μ。
     */
    public record HashParameters(
            String digestAlgorithm,
            String h1Domain,
            String h2Domain,
            String h3Domain,
            String h4Domain,
            int digestLengthBytes) {

        public HashParameters {
            Objects.requireNonNull(
                    digestAlgorithm,
                    "digestAlgorithm");

            Objects.requireNonNull(h1Domain, "h1Domain");
            Objects.requireNonNull(h2Domain, "h2Domain");
            Objects.requireNonNull(h3Domain, "h3Domain");
            Objects.requireNonNull(h4Domain, "h4Domain");

            if (digestLengthBytes <= 0) {
                throw new IllegalArgumentException(
                        "digestLengthBytes must be positive");
            }
        }
    }

    /**
     * KEM 公共配置参数。
     *
     * 当前采用：
     *
     * - X25519：临时密钥协商；
     * - HKDF-HMAC-SHA-256：从共享秘密导出对称密钥；
     * - 32 字节输出：供 AES-256-GCM 使用。
     *
     * 这里只保存公开的算法配置，不保存 DR 的公私钥。
     */
    public record KemParameters(
            String kemAlgorithm,
            String keyAgreementAlgorithm,
            String kdfAlgorithm,
            int derivedKeyLengthBytes) {

        public KemParameters {
            Objects.requireNonNull(
                    kemAlgorithm,
                    "kemAlgorithm");

            Objects.requireNonNull(
                    keyAgreementAlgorithm,
                    "keyAgreementAlgorithm");

            Objects.requireNonNull(
                    kdfAlgorithm,
                    "kdfAlgorithm");

            if (derivedKeyLengthBytes <= 0) {
                throw new IllegalArgumentException(
                        "derivedKeyLengthBytes must be positive");
            }
        }
    }

    /**
     * AEAD 公共配置参数。
     *
     * 当前采用 AES-256-GCM：
     *
     * - 密钥长度：32 字节；
     * - nonce 长度：12 字节；
     * - authentication tag：128 位。
     *
     * 这里只保存算法配置，不保存单次加密使用的密钥或 nonce。
     */
    public record AeadParameters(
            String transformation,
            int keyLengthBytes,
            int nonceLengthBytes,
            int tagLengthBits) {

        public AeadParameters {
            Objects.requireNonNull(
                    transformation,
                    "transformation");

            if (keyLengthBytes <= 0) {
                throw new IllegalArgumentException(
                        "keyLengthBytes must be positive");
            }

            if (nonceLengthBytes <= 0) {
                throw new IllegalArgumentException(
                        "nonceLengthBytes must be positive");
            }

            if (tagLengthBits <= 0) {
                throw new IllegalArgumentException(
                        "tagLengthBits must be positive");
            }
        }
    }
}