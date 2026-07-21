package com.basr.entity;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR 单设备签名：
 *
 *      sigma_i = (R_i, s_i)
 */
public final class Signature {

    private final ECPoint r;

    private final BigInteger s;

    public Signature(
            ECPoint r,
            BigInteger s) {

        this.r =
                Objects.requireNonNull(
                        r,
                        "r")
                        .normalize();

        this.s =
                Objects.requireNonNull(
                        s,
                        "s");

        if (r.isInfinity()) {
            throw new IllegalArgumentException(
                    "R_i cannot be the point at infinity");
        }

        if (s.signum() < 0) {
            throw new IllegalArgumentException(
                    "s_i cannot be negative");
        }
    }

    public ECPoint getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }
}