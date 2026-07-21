package com.basr.entity;


import java.math.BigInteger;



/**
 * BASR聚合签名
 *
 * 对应：
 *
 * σagg=(Ragg,sagg)
 *
 */
public class AggregateSignature {



    /**
     * 聚合承诺
     *
     *
     * Ragg=ΠRi
     */
    private BigInteger Ragg;




    /**
     * 聚合响应
     *
     *
     * sagg=Σsi
     */
    private BigInteger sagg;




    public AggregateSignature(
            BigInteger Ragg,
            BigInteger sagg){

        this.Ragg=Ragg;

        this.sagg=sagg;

    }



    public BigInteger getRagg(){

        return Ragg;

    }



    public BigInteger getSagg(){

        return sagg;

    }

}