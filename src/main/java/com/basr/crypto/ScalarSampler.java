package com.basr.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * 素数阶群标量采样工具。
 *
 * 文档中的：
 *
 *      x <-$ Z_p^*
 *
 * 表示从集合 {1, ..., p-1} 中均匀随机选择非零标量。
 *
 * 本类采用拒绝采样，而不是先生成随机整数后直接对 p 取模。
 * 拒绝采样不会因为模约简而引入额外分布偏差。
 */
public final class ScalarSampler {

    /**
     * 系统安全随机数生成器。
     */
    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    private ScalarSampler() {
    }

    /**
     * 从 Z_p^* 中均匀采样非零标量。
     *
     * @param p 素数阶群 G 的阶
     * @return 满足 1 <= x < p 的随机标量
     */
    public static BigInteger sampleNonZero(
            BigInteger p) {

        return sampleNonZero(p, SECURE_RANDOM);
    }

    /**
     * 使用指定 SecureRandom 从 Z_p^* 中采样。
     *
     * 该重载便于测试或使用专用随机源。
     */
    public static BigInteger sampleNonZero(
            BigInteger p,
            SecureRandom random) {

        Objects.requireNonNull(p, "p");
        Objects.requireNonNull(random, "random");

        if (p.compareTo(BigInteger.TWO) <= 0) {
            throw new IllegalArgumentException(
                    "p must be greater than 2");
        }

        BigInteger value;

        /*
         * new BigInteger(bitLength, random) 产生区间：
         *
         *      [0, 2^bitLength - 1]
         *
         * 拒绝 0 和所有大于等于 p 的值，最终得到
         * Z_p^* 上的均匀分布。
         */
        do {
            value = new BigInteger(p.bitLength(), random);
        } while (value.signum() == 0
                || value.compareTo(p) >= 0);

        return value;
    }
}