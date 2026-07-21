package com.basr.entity;

import java.util.Arrays;
import java.util.Objects;

/**
 * BASR 批次记录。
 *
 * 完整算法中的链上记录为：
 *
 *      BRec = (bid, t, sigma_agg, mu, cid)
 *
 * 当前本地阶段尚未执行：
 *
 *      cid <- IPFS.Put(Pkg)
 *
 * 因此本地记录允许 cid 为 null。
 *
 * 后续接入 IPFS 后，通过 withCid() 构造包含真实 CID 的记录，
 * 不使用随机字符串或摘要模拟 CID。
 */
public final class BatchRecord {

    /**
     * 批次标识 bid。
     */
    private final String batchId;

    /**
     * 批次时间戳 t。
     */
    private final long timestamp;

    /**
     * 聚合签名 sigma_agg。
     */
    private final AggregateSignature aggregateSignature;

    /**
     * 批次承诺 mu。
     *
     * 当前为 H3 输出的 32 字节摘要。
     */
    private final byte[] mu;

    /**
     * IPFS 内容标识 cid。
     *
     * 本地阶段为 null。
     */
    private final String cid;

    public BatchRecord(
            String batchId,
            long timestamp,
            AggregateSignature aggregateSignature,
            byte[] mu,
            String cid) {

        this.batchId =
                Objects.requireNonNull(
                        batchId,
                        "batchId");

        this.aggregateSignature =
                Objects.requireNonNull(
                        aggregateSignature,
                        "aggregateSignature");

        this.mu =
                Objects.requireNonNull(mu, "mu")
                        .clone();

        if (batchId.isBlank()) {
            throw new IllegalArgumentException(
                    "batchId cannot be blank");
        }

        if (mu.length == 0) {
            throw new IllegalArgumentException(
                    "mu cannot be empty");
        }

        if (cid != null && cid.isBlank()) {
            throw new IllegalArgumentException(
                    "cid cannot be blank when present");
        }

        this.timestamp = timestamp;
        this.cid = cid;
    }

    /**
     * 创建尚未写入 IPFS 的本地批次记录。
     */
    public static BatchRecord local(
            String batchId,
            long timestamp,
            AggregateSignature aggregateSignature,
            byte[] mu) {

        return new BatchRecord(
                batchId,
                timestamp,
                aggregateSignature,
                mu,
                null);
    }

    /**
     * 在获得真实 IPFS CID 后创建完整 BRec。
     *
     * 当前阶段暂不调用。
     */
    public BatchRecord withCid(String realCid) {

        return new BatchRecord(
                batchId,
                timestamp,
                aggregateSignature,
                mu,
                realCid);
    }

    public String getBatchId() {
        return batchId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public AggregateSignature getAggregateSignature() {
        return aggregateSignature;
    }

    /**
     * 保留与之前实体接口相近的 getter。
     */
    public AggregateSignature getSignature() {
        return aggregateSignature;
    }

    public byte[] getMu() {
        return mu.clone();
    }

    /**
     * 本地阶段可能返回 null。
     */
    public String getCid() {
        return cid;
    }

    public boolean hasCid() {
        return cid != null;
    }

    @Override
    public String toString() {
        return "BatchRecord{"
                + "batchId='" + batchId + '\''
                + ", timestamp=" + timestamp
                + ", aggregateSignature="
                + aggregateSignature
                + ", muLength=" + mu.length
                + ", hasCid=" + hasCid()
                + '}';
    }

    @Override
    public boolean equals(Object object) {

        if (this == object) {
            return true;
        }

        if (!(object instanceof BatchRecord other)) {
            return false;
        }

        return timestamp == other.timestamp
                && batchId.equals(other.batchId)
                && aggregateSignature
                        .getRagg()
                        .equals(
                                other.aggregateSignature
                                        .getRagg())
                && aggregateSignature
                        .getSagg()
                        .equals(
                                other.aggregateSignature
                                        .getSagg())
                && Arrays.equals(mu, other.mu)
                && Objects.equals(cid, other.cid);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(
                batchId,
                timestamp,
                aggregateSignature.getRagg(),
                aggregateSignature.getSagg(),
                cid);

        result = 31 * result
                + Arrays.hashCode(mu);

        return result;
    }
}