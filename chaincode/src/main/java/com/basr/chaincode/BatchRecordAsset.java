package com.basr.chaincode;

import com.owlike.genson.annotation.JsonProperty;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

/**
 * BASR 链上批记录。
 *
 * 严格对应：
 *
 *     BRec = (
 *         bid,
 *         t,
 *         sigma_agg,
 *         mu,
 *         cid
 *     )
 *
 * 其中：
 *
 *     sigma_agg = (R_agg, s_agg)
 *
 * 当前实现未加入：
 *
 * - Merkle Root；
 * - AggID；
 * - ctx；
 * - reportCount；
 * - 撤销信息；
 * - 访问策略。
 */
@DataType
public final class BatchRecordAsset {

    @Property
    private final String batchId;

    @Property
    private final long timestamp;

    @Property
    private final String aggregateCommitmentHex;

    @Property
    private final String aggregateResponseHex;

    @Property
    private final String muHex;

    @Property
    private final String cid;

    public BatchRecordAsset(
            @JsonProperty("batchId")
            final String batchId,

            @JsonProperty("timestamp")
            final long timestamp,

            @JsonProperty("aggregateCommitmentHex")
            final String aggregateCommitmentHex,

            @JsonProperty("aggregateResponseHex")
            final String aggregateResponseHex,

            @JsonProperty("muHex")
            final String muHex,

            @JsonProperty("cid")
            final String cid) {

        this.batchId =
                Objects.requireNonNull(
                        batchId,
                        "batchId");

        this.timestamp =
                timestamp;

        this.aggregateCommitmentHex =
                Objects.requireNonNull(
                        aggregateCommitmentHex,
                        "aggregateCommitmentHex");

        this.aggregateResponseHex =
                Objects.requireNonNull(
                        aggregateResponseHex,
                        "aggregateResponseHex");

        this.muHex =
                Objects.requireNonNull(
                        muHex,
                        "muHex");

        this.cid =
                Objects.requireNonNull(
                        cid,
                        "cid");
    }

    public String getBatchId() {
        return batchId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getAggregateCommitmentHex() {
        return aggregateCommitmentHex;
    }

    public String getAggregateResponseHex() {
        return aggregateResponseHex;
    }

    public String getMuHex() {
        return muHex;
    }

    public String getCid() {
        return cid;
    }

    @Override
    public boolean equals(
            final Object object) {

        if (this == object) {
            return true;
        }

        if (!(object
                instanceof BatchRecordAsset other)) {

            return false;
        }

        return timestamp == other.timestamp
                && batchId.equals(other.batchId)
                && aggregateCommitmentHex.equals(
                        other.aggregateCommitmentHex)
                && aggregateResponseHex.equals(
                        other.aggregateResponseHex)
                && muHex.equals(other.muHex)
                && cid.equals(other.cid);
    }

    @Override
    public int hashCode() {

        return Objects.hash(
                batchId,
                timestamp,
                aggregateCommitmentHex,
                aggregateResponseHex,
                muHex,
                cid);
    }

    @Override
    public String toString() {

        return "BatchRecordAsset{"
                + "batchId='"
                + batchId
                + '\''
                + ", timestamp="
                + timestamp
                + ", aggregateCommitmentHex='"
                + aggregateCommitmentHex
                + '\''
                + ", aggregateResponseHex='"
                + aggregateResponseHex
                + '\''
                + ", muHex='"
                + muHex
                + '\''
                + ", cid='"
                + cid
                + '\''
                + '}';
    }
}