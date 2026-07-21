package com.basr.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * BASR 哈希函数 H1、H2、H3 和 H4 的具体实例化。
 *
 * Setup 中已经为四个哈希用途配置不同的域分离标签。
 *
 * H1 : {0,1}* -> Z_p
 * H2 : {0,1}* -> Z_p
 * H3 : {0,1}* -> {0,1}^tau
 * H4 : {0,1}* -> Z_p
 *
 * 四个函数可以共享 SHA-256 作为底层摘要算法，
 * 但必须使用不同域分离标签，从而在逻辑上形成独立哈希函数。
 */
public final class Hash {

    private Hash() {
    }

    /**
     * 报告摘要哈希：
     *
     *      H1 : {0,1}* -> Z_p
     */
    public static BigInteger H1(
            PublicParams pp,
            byte[]... fields) {

        return hashToScalar(
                pp,
                pp.getHashParameters().h1Domain(),
                fields);
    }

    /**
     * 签名挑战哈希：
     *
     *      H2 : {0,1}* -> Z_p
     */
    public static BigInteger H2(
            PublicParams pp,
            byte[]... fields) {

        return hashToScalar(
                pp,
                pp.getHashParameters().h2Domain(),
                fields);
    }

    /**
     * 批次承诺哈希：
     *
     *      H3 : {0,1}* -> {0,1}^tau
     */
    public static byte[] H3(
            PublicParams pp,
            byte[]... fields) {

        byte[] result = digest(
                pp,
                pp.getHashParameters().h3Domain(),
                fields);

        int expectedLength =
                pp.getHashParameters()
                        .digestLengthBytes();

        if (result.length != expectedLength) {
            throw new IllegalStateException(
                    "Configured H3 digest length does not match "
                            + "the selected MessageDigest output length");
        }

        return result;
    }

    /**
     * POP 挑战哈希：
     *
     *      H4 : {0,1}* -> Z_p
     */
    public static BigInteger H4(
            PublicParams pp,
            byte[]... fields) {

        return hashToScalar(
                pp,
                pp.getHashParameters().h4Domain(),
                fields);
    }

    /**
     * 将哈希摘要映射到 Z_p。
     *
     * 具体实例化：
     *
     *      x = OS2IP(Hash(domain || transcript))
     *      result = x mod p
     *
     * 对 secp256k1 阶和 SHA-256 而言，这是一个具体可运行的
     * hash-to-scalar 实例化。
     */
    private static BigInteger hashToScalar(
            PublicParams pp,
            String domain,
            byte[]... fields) {

        byte[] digest =
                digest(pp, domain, fields);

        return new BigInteger(1, digest)
                .mod(pp.getP());
    }

    /**
     * 计算带域分离的协议摘要。
     */
    private static byte[] digest(
            PublicParams pp,
            String domain,
            byte[]... fields) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(domain, "domain");
        Objects.requireNonNull(fields, "fields");

        try {
            MessageDigest messageDigest =
                    MessageDigest.getInstance(
                            pp.getHashParameters()
                                    .digestAlgorithm());

            /*
             * 哈希输入：
             *
             *      Encode(domain, field_1, ..., field_n)
             *
             * 每个字段均带长度前缀。
             */
            byte[][] transcriptFields =
                    new byte[fields.length + 1][];

            transcriptFields[0] =
                    TranscriptEncoder.utf8(domain);

            System.arraycopy(
                    fields,
                    0,
                    transcriptFields,
                    1,
                    fields.length);

            byte[] transcript =
                    TranscriptEncoder.encode(
                            transcriptFields);

            return messageDigest.digest(transcript);

        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "Configured digest algorithm is unavailable: "
                            + pp.getHashParameters()
                                    .digestAlgorithm(),
                    exception);
        }
    }
}