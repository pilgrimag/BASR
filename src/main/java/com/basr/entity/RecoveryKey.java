package com.basr.entity;



import java.math.BigInteger;



/**
 * DR恢复密钥
 *
 * 对应：
 *
 * (sk_R,pk_R)
 *
 *
 * 注意：
 *
 * 该密钥不是设备签名密钥。
 *
 */
public class RecoveryKey {


    /**
     * DR私钥
     *
     * sk_R
     */
    private BigInteger secretKey;



    /**
     * DR公钥
     *
     * pk_R
     */
    private BigInteger publicKey;



    public RecoveryKey(
            BigInteger secretKey,
            BigInteger publicKey){

        this.secretKey=secretKey;

        this.publicKey=publicKey;

    }



    public BigInteger getSecretKey(){

        return secretKey;

    }



    public BigInteger getPublicKey(){

        return publicKey;

    }

}