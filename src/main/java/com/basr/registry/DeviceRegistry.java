package com.basr.registry;

import com.basr.entity.RegisteredDevice;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Collection;
import java.util.Optional;

/**
 * BASR 设备公共注册表接口。
 *
 * 当前本地实现对应文档中的：
 *
 *      L = {(ID_i, pk_i)}
 *
 * 后续接入 Fabric 时，可以新增 FabricDeviceRegistry，
 * 而无需修改 POP 密码协议。
 */
public interface DeviceRegistry {

    boolean containsDeviceId(String deviceId);

    boolean containsPublicKey(ECPoint publicKey);

    /**
     * 检查给定 ID 和公钥是否作为同一注册项存在。
     *
     * 后续 SigVerify 使用：
     *
     *      (ID_i, pk_i) ∈ L
     */
    boolean contains(
            String deviceId,
            ECPoint publicKey);

    Optional<RegisteredDevice> findByDeviceId(
            String deviceId);

    /**
     * 原子地注册一条记录。
     *
     * 只有 ID 和公钥均不存在时才插入。
     */
    boolean registerIfAbsent(
            RegisteredDevice device);

    Collection<RegisteredDevice> findAll();

    int size();
}