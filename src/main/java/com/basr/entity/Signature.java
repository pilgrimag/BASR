package com.basr.entity;


import java.math.BigInteger;


/**
 * BASR单设备签名
 *
 * 对应：
 *
 * σ_i=(R_i,s_i)
 *
 *
 * Schnorr signature
 *
 */
public class Signature {


    /**
     * 随机承诺
     *
     * R_i=g^{r_i}
     */
    private BigInteger R;



    /**
     * 响应值
     *
     * s_i=r_i+h_i sk_i
     */
    private BigInteger s;



    public Signature(
            BigInteger R,
            BigInteger s){

        this.R=R;

        this.s=s;

    }



    public BigInteger getR(){

        return R;

    }



    public BigInteger getS(){

        return s;

    }


}