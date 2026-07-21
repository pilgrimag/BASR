package com.basr.entity;

import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;

/**
 * BASR 数据恢复实体 DR 的恢复密钥对。
 *
 * 对应算法中的：
 *
 *      (sk_R, pk_R)
 *
 * 当前 KEM 实例化为：
 *
 *      DHKEM-X25519-HKDF-SHA256
 *
 * 因此：
 *
 *      sk_R：X25519 私钥；
 *      pk_R：X25519 公钥。
 *
 * 该密钥对与设备的 secp256k1 签名密钥完全独立：
 *
 * 设备签名密钥：
 *
 *      sk_i ∈ Z_p
 *      pk_i = [sk_i]g
 *
 * DR 恢复密钥：
 *
 *      X25519 private key
 *      X25519 public key
 *
 * 安全注意：
 *
 * 1. sk_R 只能由 DR 本地保存；
 * 2. pk_R 可以公开并分发给设备；
 * 3. sk_R 不应进入注册表、日志、IPFS 或 Fabric；
 * 4. toString() 不得输出任何私钥内容。
 */
public final class RecoveryKey {

    /**
     * DR 恢复私钥 sk_R。
     *
     * XECPrivateKey 是 RFC 7748 曲线私钥的 Java 标准接口。
     */
    private final XECPrivateKey secretKey;

    /**
     * DR 恢复公钥 pk_R。
     *
     * XECPublicKey 使用 X25519 点的 u 坐标表示公钥。
     */
    private final XECPublicKey publicKey;

    /**
     * 创建恢复密钥对象。
     *
     * 构造函数会验证两个密钥都采用 X25519 参数集。
     *
     * @param secretKey DR 的 X25519 私钥
     * @param publicKey DR 的 X25519 公钥
     */
    public RecoveryKey(
            XECPrivateKey secretKey,
            XECPublicKey publicKey) {

        this.secretKey =
                Objects.requireNonNull(
                        secretKey,
                        "secretKey");

        this.publicKey =
                Objects.requireNonNull(
                        publicKey,
                        "publicKey");

        /*
         * 验证私钥采用 X25519 参数集。
         */
        requireX25519Parameters(
                this.secretKey.getParams(),
                "secretKey");

        /*
         * 验证公钥采用 X25519 参数集。
         */
        requireX25519Parameters(
                this.publicKey.getParams(),
                "publicKey");

        /*
         * X25519 公钥通过 u 坐标表示。
         * 合法生成的公钥坐标不应为负数。
         */
        if (this.publicKey.getU().signum() < 0) {
            throw new IllegalArgumentException(
                    "X25519 public-key u-coordinate cannot be negative");
        }
    }

    /**
     * 返回 DR 私钥 sk_R。
     *
     * 该方法仅应在 KEM.Decap 或数据恢复阶段调用。
     */
    public XECPrivateKey getSecretKey() {
        return secretKey;
    }

    /**
     * 返回 DR 公钥 pk_R。
     *
     * 设备在 KEM.Encap 时使用该公钥。
     */
    public XECPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * 返回公钥的标准 X.509 SubjectPublicKeyInfo 编码。
     *
     * 返回副本，避免调用者修改内部数组。
     *
     * 该编码后续可以用于：
     *
     * 1. 本地文件存储；
     * 2. 网络传输；
     * 3. Fabric 状态存储；
     * 4. 从编码恢复 X25519 公钥。
     */
    public byte[] getEncodedPublicKey() {

        byte[] encoded = publicKey.getEncoded();

        if (encoded == null) {
            throw new IllegalStateException(
                    "The provider does not expose public-key encoding");
        }

        return encoded.clone();
    }

    /**
     * 检查密钥参数是否为 X25519。
     */
    private static void requireX25519Parameters(
            AlgorithmParameterSpec parameters,
            String fieldName) {

        if (!(parameters instanceof NamedParameterSpec namedParameters)) {
            throw new IllegalArgumentException(
                    fieldName
                            + " does not use named XEC parameters");
        }

        if (!NamedParameterSpec.X25519
                .getName()
                .equalsIgnoreCase(
                        namedParameters.getName())) {

            throw new IllegalArgumentException(
                    fieldName
                            + " must use X25519 parameters, but uses "
                            + namedParameters.getName());
        }
    }

    /**
     * 禁止输出私钥。
     */
    @Override
    public String toString() {

        return "RecoveryKey{"
                + "algorithm='X25519'"
                + ", publicKeyEncodedLength="
                + getEncodedPublicKey().length
                + '}';
    }
}