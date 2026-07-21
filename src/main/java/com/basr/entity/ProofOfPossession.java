package com.basr.entity;

import java.math.BigInteger;
import java.util.Objects;

/**
 * 设备公钥持有证明。
 *
 * 对应：
 *
 *      POP_i = (c_i, z_i)
 *
 * 注意：
 *
 * 初始承诺 A_i 不需要包含在 POP 中，
 * 验证方可以通过：
 *
 *      A_i' = [z_i]g - [c_i]pk_i
 *
 * 重构该承诺。
 */
public final class ProofOfPossession {

    /**
     * POP 挑战 c_i。
     */
    private final BigInteger challenge;

    /**
     * POP 响应 z_i。
     */
    private final BigInteger response;

    public ProofOfPossession(
            BigInteger challenge,
            BigInteger response) {

        this.challenge =
                Objects.requireNonNull(
                        challenge,
                        "challenge");

        this.response =
                Objects.requireNonNull(
                        response,
                        "response");
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    public BigInteger getResponse() {
        return response;
    }
}