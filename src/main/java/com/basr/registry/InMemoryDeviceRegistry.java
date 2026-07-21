package com.basr.registry;

import com.basr.crypto.PointCodec;
import com.basr.entity.RegisteredDevice;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * 本地内存设备注册表。
 *
 * 该类只替代区块链的世界状态存储，不替代密码验证。
 *
 * 内部同时维护：
 *
 * 1. deviceId -> RegisteredDevice；
 * 2. compressed public key -> deviceId。
 *
 * 从而能够同时阻止：
 *
 *      (ID_i, *) 已存在
 *
 * 和：
 *
 *      (*, pk_i) 已存在。
 */
public final class InMemoryDeviceRegistry
        implements DeviceRegistry {

    private final Map<String, RegisteredDevice> devicesById =
            new LinkedHashMap<>();

    private final Map<String, String> deviceIdByPublicKey =
            new LinkedHashMap<>();

    @Override
    public synchronized boolean containsDeviceId(
            String deviceId) {

        return deviceId != null
                && devicesById.containsKey(deviceId);
    }

    @Override
    public synchronized boolean containsPublicKey(
            ECPoint publicKey) {

        if (publicKey == null
                || publicKey.isInfinity()) {

            return false;
        }

        return deviceIdByPublicKey.containsKey(
                publicKeyKey(publicKey));
    }

    @Override
    public synchronized boolean contains(
            String deviceId,
            ECPoint publicKey) {

        if (deviceId == null
                || publicKey == null
                || publicKey.isInfinity()) {

            return false;
        }

        RegisteredDevice registered =
                devicesById.get(deviceId);

        if (registered == null) {
            return false;
        }

        return publicKeyKey(
                registered.getPublicKey())
                .equals(publicKeyKey(publicKey));
    }

    @Override
    public synchronized Optional<RegisteredDevice>
    findByDeviceId(
            String deviceId) {

        return Optional.ofNullable(
                devicesById.get(deviceId));
    }

    @Override
    public synchronized boolean registerIfAbsent(
            RegisteredDevice device) {

        Objects.requireNonNull(device, "device");

        String deviceId =
                device.getDeviceId();

        String publicKeyKey =
                publicKeyKey(
                        device.getPublicKey());

        /*
         * 同时检查 ID 唯一性和公钥唯一性。
         */
        if (devicesById.containsKey(deviceId)
                || deviceIdByPublicKey.containsKey(
                        publicKeyKey)) {

            return false;
        }

        devicesById.put(
                deviceId,
                device);

        deviceIdByPublicKey.put(
                publicKeyKey,
                deviceId);

        return true;
    }

    @Override
    public synchronized Collection<RegisteredDevice>
    findAll() {

        return List.copyOf(
                devicesById.values());
    }

    @Override
    public synchronized int size() {
        return devicesById.size();
    }

    /**
     * 使用压缩点编码作为公钥唯一标识。
     */
    private static String publicKeyKey(
            ECPoint publicKey) {

        byte[] encoded =
                PointCodec.encodeCompressed(
                        publicKey);

        return Base64.getEncoder()
                .encodeToString(encoded);
    }
}