package com.basr.crypto;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR 使用的 Schnorr 型基础群运算。
 *
 * 论文采用乘法群记法：
 *
 *      pk = g^sk
 *      A  = g^rho
 *      g^z * pk^(-c)
 *
 * Bouncy Castle 的椭圆曲线使用加法群记法：
 *
 *      PK = [sk]g
 *      A  = [rho]g
 *      A' = [z]g - [c]PK
 */
public final class Schnorr {

    private Schnorr() {
    }

    /**
     * 生成设备签名私钥：
     *
     *      sk <-$ Z_p^*
     */
    public static BigInteger generateSecretKey(
            PublicParams pp) {

        Objects.requireNonNull(pp, "pp");

        return ScalarSampler.sampleNonZero(
                pp.getP());
    }

    /**
     * 根据签名私钥计算设备公钥：
     *
     *      pk = g^sk
     *
     * 椭圆曲线表示：
     *
     *      PK = [sk]g
     */
    public static ECPoint derivePublicKey(
            PublicParams pp,
            BigInteger secretKey) {

        Objects.requireNonNull(pp, "pp");

        requireNonZeroScalar(
                secretKey,
                pp.getP(),
                "secretKey");

        ECPoint publicKey =
                pp.getGenerator()
                        .multiply(secretKey)
                        .normalize();

        if (!PointCodec.isValidGroupElement(
                pp,
                publicKey)) {

            throw new IllegalStateException(
                    "Derived public key is not a valid element of G");
        }

        return publicKey;
    }

    /**
     * 计算 Schnorr 响应：
     *
     *      z = rho + c * sk mod p
     *
     * 注册 POP 和后续签名响应均采用相同代数结构。
     */
    public static BigInteger computeResponse(
            PublicParams pp,
            BigInteger nonce,
            BigInteger challenge,
            BigInteger secretKey) {

        Objects.requireNonNull(pp, "pp");

        BigInteger p = pp.getP();

        requireNonZeroScalar(
                nonce,
                p,
                "nonce");

        requireScalar(
                challenge,
                p,
                "challenge");

        requireNonZeroScalar(
                secretKey,
                p,
                "secretKey");

        return nonce
                .add(challenge.multiply(secretKey))
                .mod(p);
    }

    /**
     * 根据公钥、挑战和响应重构承诺：
     *
     * 乘法群：
     *
     *      A' = g^z * pk^(-c)
     *
     * 椭圆曲线加法群：
     *
     *      A' = [z]g - [c]PK
     */
    public static ECPoint reconstructCommitment(
            PublicParams pp,
            ECPoint publicKey,
            BigInteger challenge,
            BigInteger response) {

        Objects.requireNonNull(pp, "pp");

        if (!PointCodec.isValidGroupElement(
                pp,
                publicKey)) {

            throw new IllegalArgumentException(
                    "publicKey is not a valid element of G");
        }

        requireScalar(
                challenge,
                pp.getP(),
                "challenge");

        requireScalar(
                response,
                pp.getP(),
                "response");

        ECPoint generatorPart =
                pp.getGenerator()
                        .multiply(response);

        ECPoint publicKeyPart =
                publicKey
                        .multiply(challenge);

        return generatorPart
                .subtract(publicKeyPart)
                .normalize();
    }

    /**
     * 判断 value 是否属于 Z_p。
     */
    public static boolean isScalar(
            BigInteger value,
            BigInteger p) {

        return value != null
                && value.signum() >= 0
                && value.compareTo(p) < 0;
    }

    /**
     * 判断 value 是否属于 Z_p^*。
     */
    public static boolean isNonZeroScalar(
            BigInteger value,
            BigInteger p) {

        return value != null
                && value.signum() > 0
                && value.compareTo(p) < 0;
    }

    private static void requireScalar(
            BigInteger value,
            BigInteger p,
            String name) {

        if (!isScalar(value, p)) {
            throw new IllegalArgumentException(
                    name + " must belong to Z_p");
        }
    }

    private static void requireNonZeroScalar(
            BigInteger value,
            BigInteger p,
            String name) {

        if (!isNonZeroScalar(value, p)) {
            throw new IllegalArgumentException(
                    name + " must belong to Z_p^*");
        }
    }

    /**
     * 计算承诺：
     *
     *      R = [r]g
     */
    public static ECPoint createCommitment(
            PublicParams pp,
            BigInteger nonce) {

        Objects.requireNonNull(pp, "pp");

        requireNonZeroScalar(
                nonce,
                pp.getP(),
                "nonce");

        ECPoint commitment =
                pp.getGenerator()
                        .multiply(nonce)
                        .normalize();

        if (!PointCodec.isValidGroupElement(
                pp,
                commitment)) {

            throw new IllegalStateException(
                    "Generated commitment is not in G");
        }

        return commitment;
    }

    /**
     * 验证 Schnorr 等式：
     *
     *      [s]g = R + [h]pk
     */
    public static boolean verifyResponse(
            PublicParams pp,
            ECPoint publicKey,
            ECPoint commitment,
            BigInteger challenge,
            BigInteger response) {

        Objects.requireNonNull(pp, "pp");

        if (!PointCodec.isValidGroupElement(
                pp,
                publicKey)
                || !PointCodec.isValidGroupElement(
                        pp,
                        commitment)) {

            return false;
        }

        if (!isScalar(challenge, pp.getP())
                || !isScalar(response, pp.getP())) {

            return false;
        }

        ECPoint left =
                pp.getGenerator()
                        .multiply(response)
                        .normalize();

        ECPoint right =
                commitment
                        .add(publicKey.multiply(challenge))
                        .normalize();

        return left.equals(right);
    }
}