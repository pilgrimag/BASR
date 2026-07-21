package com.basr.chaincode;

import com.owlike.genson.annotation.JsonProperty;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

/**
 * BASR 链上设备注册资产。
 *
 * 严格对应算法中的注册列表：
 *
 *     L = {(ID_i, pk_i)}
 *
 * 不在资产中保存：
 *
 * - sk_i；
 * - POP；
 * - 注册时间；
 * - 状态或撤销信息；
 * - 设备报告；
 * - DR 恢复密钥。
 */
@DataType
public final class DeviceAsset {

    @Property
    private final String deviceId;

    @Property
    private final String publicKeyHex;

    public DeviceAsset(
            @JsonProperty("deviceId")
            final String deviceId,

            @JsonProperty("publicKeyHex")
            final String publicKeyHex) {

        this.deviceId =
                Objects.requireNonNull(
                        deviceId,
                        "deviceId");

        this.publicKeyHex =
                Objects.requireNonNull(
                        publicKeyHex,
                        "publicKeyHex");
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getPublicKeyHex() {
        return publicKeyHex;
    }

    @Override
    public boolean equals(
            final Object object) {

        if (this == object) {
            return true;
        }

        if (!(object instanceof DeviceAsset other)) {
            return false;
        }

        return deviceId.equals(other.deviceId)
                && publicKeyHex.equals(
                        other.publicKeyHex);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                deviceId,
                publicKeyHex);
    }

    @Override
    public String toString() {

        return "DeviceAsset{"
                + "deviceId='"
                + deviceId
                + '\''
                + ", publicKeyHex='"
                + publicKeyHex
                + '\''
                + '}';
    }
}