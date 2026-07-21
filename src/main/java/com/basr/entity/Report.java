package com.basr.entity;


/**
 * BASR报告实体
 *
 * 对应论文：
 *
 * rep_i
 *
 *
 * 一个设备产生一个report，
 * 后续由Aggregator进行聚合。
 *
 */
public class Report {



    /**
     * 设备身份
     *
     * ID_i
     */
    private String deviceId;



    /**
     * 设备公钥
     *
     * pk_i
     */
    private String publicKey;



    /**
     * 数据敏感标识
     *
     *
     * β_i:
     *
     * β_i=1:
     *      敏感数据
     *
     * β_i=0:
     *      普通数据
     *
     */
    private int beta;



    /**
     * 数据密文或者明文
     *
     *
     * β=1:
     *
     *      AEAD ciphertext
     *
     *
     * β=0:
     *
     *      plaintext
     */
    private String data;



    /**
     * KEM恢复材料
     *
     * 对应：
     *
     * RM_i
     *
     *
     * β=1时存在
     */
    private String recoveryMaterial;



    /**
     * 批次ID
     *
     * bid
     */
    private String batchId;



    /**
     * 时间戳
     *
     * t
     */
    private long timestamp;



    /**
     * 报告摘要
     *
     * d_i
     *
     */
    private String digest;




    public Report(){}



    public Report(
            String deviceId,
            String publicKey,
            int beta,
            String data,
            String recoveryMaterial,
            String batchId,
            long timestamp,
            String digest){


        this.deviceId=deviceId;

        this.publicKey=publicKey;

        this.beta=beta;

        this.data=data;

        this.recoveryMaterial=recoveryMaterial;

        this.batchId=batchId;

        this.timestamp=timestamp;

        this.digest=digest;

    }



    public String getDeviceId(){
        return deviceId;
    }


    public int getBeta(){
        return beta;
    }


    public String getData(){
        return data;
    }


    public String getBatchId(){
        return batchId;
    }


    public long getTimestamp(){
        return timestamp;
    }


    public String getDigest(){
        return digest;
    }

}