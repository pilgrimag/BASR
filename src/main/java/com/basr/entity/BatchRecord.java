package com.basr.entity;


/**
 * BASR批记录
 *
 * 对应：
 *
 * BRec
 *
 *
 * 保存聚合结果的链上记录。
 *
 */
public class BatchRecord {


    /**
     * batch identifier
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
     * 聚合签名
     */
    private AggregateSignature signature;



    /**
     * 聚合摘要
     *
     * μ
     *
     */
    private String mu;



    /**
     * IPFS CID
     *
     * cid
     *
     */
    private String cid;




    public BatchRecord(
            String batchId,
            long timestamp,
            AggregateSignature signature,
            String mu,
            String cid){


        this.batchId=batchId;

        this.timestamp=timestamp;

        this.signature=signature;

        this.mu=mu;

        this.cid=cid;

    }



    public String getBatchId(){

        return batchId;

    }


    public AggregateSignature getSignature(){

        return signature;

    }


    public String getCid(){

        return cid;

    }

}