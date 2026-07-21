package com.basr.crypto;

import com.basr.entity.RecoveryKey;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;

/**
 * BASR KEM 底层密码实现。
 *
 * 当前公共参数指定：
 *
 *      DHKEM-X25519-HKDF-SHA256
 *
 * 本阶段只实现：
 *
 *      KEM.KeyGen(pp_KEM)
 *
 * 后续将在本类中继续实现：
 *
 *      KEM.Encap(pp_KEM, pk_R)
 *      KEM.Decap(pp_KEM, sk_R, RM_i)
 *
 * 这里调用 Java 21 JCA 的真实 X25519 实现，
 * 不使用 BigInteger 模拟密钥，也不自行实现 Curve25519 算术。
 */
public final class Kem {

    /**
     * 当前代码支持的 KEM 配置名称。
     *
     * 必须与 Setup 中 pp_KEM 的配置保持一致。
     */
    private static final String SUPPORTED_KEM_ALGORITHM =
            "DHKEM-X25519-HKDF-SHA256";

    /**
     * X25519 标准算法名称。
     */
    private static final String X25519_ALGORITHM =
            "X25519";

    /**
     * 系统安全随机数生成器。
     */
    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    private Kem() {
    }

    /**
     * 使用系统安全随机源生成 DR 恢复密钥对。
     *
     * 对应：
     *
     *      (sk_R, pk_R)
     *          <- KEM.KeyGen(pp_KEM)
     *
     * @param pp BASR 系统公共参数
     * @return 真实 X25519 恢复密钥对
     */
    public static RecoveryKey keyGen(
            PublicParams pp) {

        return keyGen(pp, SECURE_RANDOM);
    }

    /**
     * 使用指定安全随机源生成恢复密钥对。
     *
     * 提供该重载的目的：
     *
     * 1. 允许测试代码注入随机源；
     * 2. 允许未来使用专用 DRBG；
     * 3. 保持密码算法与随机源解耦。
     *
     * 生产环境中不得传入 java.util.Random。
     *
     * @param pp           BASR 公共参数
     * @param secureRandom 密码学安全随机源
     * @return X25519 恢复密钥对
     */
    public static RecoveryKey keyGen(
            PublicParams pp,
            SecureRandom secureRandom) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(
                secureRandom,
                "secureRandom");

        /*
         * 验证 Setup 输出的 pp_KEM 是否与当前实现一致。
         *
         * 不能忽略公共参数并静默使用其他算法，
         * 否则 Setup 和 RecKeyGen 将发生协议不一致。
         */
        validateKemConfiguration(
                pp.getKemParameters());

        try {
            /*
             * 获取 Java 标准 X25519 密钥对生成器。
             *
             * 这是实际的 Curve25519/X25519 密钥生成，
             * 不是普通椭圆曲线 EC 密钥，也不是模拟数据。
             */
            KeyPairGenerator keyPairGenerator =
                    KeyPairGenerator.getInstance(
                            X25519_ALGORITHM);

            /*
             * 显式指定 X25519 参数集。
             *
             * 即便 KeyPairGenerator 已通过 X25519 名称创建，
             * 仍显式初始化参数，避免参数集含义依赖提供者默认值。
             */
            keyPairGenerator.initialize(
                    NamedParameterSpec.X25519,
                    secureRandom);

            /*
             * 生成：
             *
             *      sk_R：X25519 private key
             *      pk_R：X25519 public key
             */
            KeyPair keyPair =
                    keyPairGenerator.generateKeyPair();

            /*
             * 检查提供者返回的私钥类型。
             */
            if (!(keyPair.getPrivate()
                    instanceof XECPrivateKey secretKey)) {

                throw new IllegalStateException(
                        "X25519 provider returned an unsupported "
                                + "private-key implementation: "
                                + keyPair.getPrivate()
                                        .getClass()
                                        .getName());
            }

            /*
             * 检查提供者返回的公钥类型。
             */
            if (!(keyPair.getPublic()
                    instanceof XECPublicKey publicKey)) {

                throw new IllegalStateException(
                        "X25519 provider returned an unsupported "
                                + "public-key implementation: "
                                + keyPair.getPublic()
                                        .getClass()
                                        .getName());
            }

            /*
             * RecoveryKey 构造函数会进一步检查：
             *
             * - 私钥参数确实为 X25519；
             * - 公钥参数确实为 X25519；
             * - 公钥坐标格式有效。
             */
            return new RecoveryKey(
                    secretKey,
                    publicKey);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Unable to generate X25519 recovery key pair",
                    exception);
        }
    }

    /**
     * 验证公共参数中的 KEM 配置。
     *
     * 当前实现只接受：
     *
     *      KEM  = DHKEM-X25519-HKDF-SHA256
     *      DH   = X25519
     *      KDF  = HKDF-HMAC-SHA-256
     *      L    = 32 bytes
     */
    private static void validateKemConfiguration(
            PublicParams.KemParameters parameters) {

        Objects.requireNonNull(
                parameters,
                "kemParameters");

        if (!SUPPORTED_KEM_ALGORITHM.equalsIgnoreCase(
                parameters.kemAlgorithm())) {

            throw new IllegalArgumentException(
                    "Unsupported KEM algorithm: "
                            + parameters.kemAlgorithm());
        }

        if (!X25519_ALGORITHM.equalsIgnoreCase(
                parameters.keyAgreementAlgorithm())) {

            throw new IllegalArgumentException(
                    "Unsupported KEM key-agreement algorithm: "
                            + parameters.keyAgreementAlgorithm());
        }

        if (!"HKDF-HMAC-SHA-256".equalsIgnoreCase(
                parameters.kdfAlgorithm())) {

            throw new IllegalArgumentException(
                    "Unsupported KEM KDF algorithm: "
                            + parameters.kdfAlgorithm());
        }

        if (parameters.derivedKeyLengthBytes() != 32) {
            throw new IllegalArgumentException(
                    "DHKEM-X25519-HKDF-SHA256 must derive "
                            + "a 32-byte AEAD key");
        }
    }
}