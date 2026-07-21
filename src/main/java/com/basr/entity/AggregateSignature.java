package com.basr.entity;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR 聚合签名。
 *
 * 对应算法中的：
 *
 *      sigma_agg = (R_agg, s_agg)
 *
 * 论文采用乘法群记法：
 *
 *      R_agg = product(R_i)
 *      s_agg = sum(s_i) mod p
 *
 * 当前 secp256k1 使用加法群记法，因此：
 *
 *      R_agg = sum(R_i)
 *      s_agg = sum(s_i) mod p
 */
public final class AggregateSignature {

    /**
     * 聚合承诺 R_agg。
     *
     * 这是椭圆曲线群元素。
     */
    private final ECPoint aggregateCommitment;

    /**
     * 聚合响应 s_agg。
     *
     * 这是 Z_p 中的标量。
     */
    private final BigInteger aggregateResponse;

    public AggregateSignature(
            ECPoint aggregateCommitment,
            BigInteger aggregateResponse) {

        this.aggregateCommitment =
                Objects.requireNonNull(
                                aggregateCommitment,
                                "aggregateCommitment")
                        .normalize();

        this.aggregateResponse =
                Objects.requireNonNull(
                        aggregateResponse,
                        "aggregateResponse");

        /*
         * 这里只检查非负性。
         *
         * 是否满足 aggregateResponse < p，
         * 由 Aggregate 和后续 AggVerify 根据 PublicParams 检查。
         */
        if (aggregateResponse.signum() < 0) {
            throw new IllegalArgumentException(
                    "Aggregate response cannot be negative");
        }

        /*
         * 不拒绝无穷远点。
         *
         * 多个合法 R_i 的群和在理论上可能等于单位元 O，
         * 虽然概率极低，但算法描述没有规定应拒绝该情况。
         */
    }

    /**
     * 返回聚合承诺 R_agg。
     */
    public ECPoint getRagg() {
        return aggregateCommitment;
    }

    /**
     * 返回聚合响应 s_agg。
     */
    public BigInteger getSagg() {
        return aggregateResponse;
    }

    /**
     * 与字段语义一致的别名。
     */
    public ECPoint getAggregateCommitment() {
        return aggregateCommitment;
    }

    /**
     * 与字段语义一致的别名。
     */
    public BigInteger getAggregateResponse() {
        return aggregateResponse;
    }

    @Override
    public String toString() {
        return "AggregateSignature{"
                + "aggregateCommitmentIsInfinity="
                + aggregateCommitment.isInfinity()
                + ", aggregateResponseBitLength="
                + aggregateResponse.bitLength()
                + '}';
    }
}