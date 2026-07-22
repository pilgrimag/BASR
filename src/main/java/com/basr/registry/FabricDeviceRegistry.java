package com.basr.registry;

import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.entity.RegisteredDevice;
import com.basr.fabric.FabricGatewayClient;

import org.bouncycastle.math.ec.ECPoint;

import org.hyperledger.fabric.client.GatewayException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fabric-backed BASR device registry.
 *
 * Fabric world state is the authoritative source:
 *
 *     L = {(ID_i, pk_i)}
 *
 * This adapter is read-only. Device registration must be
 * performed using:
 *
 *     FabricGatewayClient.registerDevice(pp, request)
 *
 * because secure registration requires the real Schnorr POP:
 *
 *     (ID_i, pk_i, c_i, z_i)
 *
 * registerIfAbsent(RegisteredDevice) cannot securely perform
 * that transaction because RegisteredDevice contains only
 * (ID_i, pk_i).
 */
public final class FabricDeviceRegistry
        implements DeviceRegistry {

    private static final HexFormat HEX =
            HexFormat.of();

    private final PublicParams pp;

    private final FabricGatewayClient gateway;

    /**
     * Positive-only immutable-record cache.
     *
     * Current BASR Chaincode has no device update, delete, or
     * revocation transaction, so a successfully queried positive
     * registration remains valid for this network instance.
     *
     * Negative results are never cached.
     */
    private final Map<String, RegisteredDevice>
            devicesById =
            new ConcurrentHashMap<>();

    private final Map<String, String>
            deviceIdByPublicKey =
            new ConcurrentHashMap<>();

    public FabricDeviceRegistry(
            final PublicParams pp,
            final FabricGatewayClient gateway) {

        this.pp =
                Objects.requireNonNull(
                        pp,
                        "pp");

        this.gateway =
                Objects.requireNonNull(
                        gateway,
                        "gateway");
    }

    /**
     * Checks whether an ID exists in the authoritative Fabric
     * world state.
     */
    // @Override
    // public boolean containsDeviceId(
    //         final String deviceId) {

    //     if (!validDeviceId(deviceId)) {
    //         return false;
    //     }

    //     if (devicesById.containsKey(
    //             deviceId)) {

    //         return true;
    //     }

    //     try {
    //         return gateway.deviceExists(
    //                 deviceId);

    //     } catch (GatewayException exception) {

    //         throw registryFailure(
    //                 "Failed to query device ID: "
    //                         + deviceId,
    //                 exception);
    //     }
    // }

    @Override
    public boolean containsDeviceId(
            final String deviceId) {

        if (!validDeviceId(deviceId)) {
            return false;
        }

        try {
            /*
            * 即使存在正向缓存，也必须进行实时链上查询。
            * Fabric 不可达时必须失败关闭。
            */
            return gateway.deviceExists(deviceId);

        } catch (GatewayException exception) {

            throw registryFailure(
                    "Failed to query device ID: "
                            + deviceId,
                    exception);

        } catch (RuntimeException exception) {

            if (exception
                    instanceof RegistryAccessException
                    registryAccessException) {

                throw registryAccessException;
            }

            throw registryFailure(
                    "Failed to query device ID: "
                            + deviceId,
                    exception);
        }
    }

    /**
     * Checks whether a public key exists using the Chaincode
     * public-key uniqueness index.
     */
    // @Override
    // public boolean containsPublicKey(
    //         final ECPoint publicKey) {

    //     if (!validPublicKey(publicKey)) {
    //         return false;
    //     }

    //     String key =
    //             publicKeyKey(
    //                     publicKey);

    //     if (deviceIdByPublicKey
    //             .containsKey(key)) {

    //         return true;
    //     }

    //     try {
    //         return gateway.publicKeyExists(
    //                 publicKey);

    //     } catch (GatewayException exception) {

    //         throw registryFailure(
    //                 "Failed to query device public key",
    //                 exception);
    //     }
    // }

    @Override
    public boolean containsPublicKey(
            final ECPoint publicKey) {

        if (!validPublicKey(publicKey)) {
            return false;
        }

        try {
            /*
            * 不允许仅依据本地正向缓存接受公钥。
            */
            return gateway.publicKeyExists(publicKey);

        } catch (GatewayException exception) {

            throw registryFailure(
                    "Failed to query device public key",
                    exception);

        } catch (RuntimeException exception) {

            if (exception
                    instanceof RegistryAccessException
                    registryAccessException) {

                throw registryAccessException;
            }

            throw registryFailure(
                    "Failed to query device public key",
                    exception);
        }
    }

    /**
     * Checks exact membership:
     *
     *     (ID_i, pk_i) in L
     */
    // @Override
    // public boolean contains(
    //         final String deviceId,
    //         final ECPoint publicKey) {

    //     if (!validDeviceId(deviceId)
    //             || !validPublicKey(publicKey)) {

    //         return false;
    //     }

    //     RegisteredDevice cached =
    //             devicesById.get(
    //                     deviceId);

    //     if (cached != null) {

    //         return publicKeyKey(
    //                 cached.getPublicKey())
    //                 .equals(
    //                         publicKeyKey(
    //                                 publicKey));
    //     }

    //     try {
    //         boolean exists =
    //                 gateway.isRegisteredDevice(
    //                         deviceId,
    //                         publicKey);

    //         if (exists) {

    //             RegisteredDevice device =
    //                     new RegisteredDevice(
    //                             deviceId,
    //                             publicKey.normalize());

    //             cachePositive(device);
    //         }

    //         return exists;

    //     } catch (GatewayException exception) {

    //         throw registryFailure(
    //                 "Failed to query exact "
    //                         + "device registration: "
    //                         + deviceId,
    //                 exception);
    //     }
    // }

    @Override
    public boolean contains(
            final String deviceId,
            final ECPoint publicKey) {

        if (!validDeviceId(deviceId)
                || !validPublicKey(publicKey)) {

            return false;
        }

        try {
            /*
            * 精确成员关系判断必须以 Fabric 世界状态为准：
            *
            *     (ID_i, pk_i) in L
            */
            boolean exists =
                    gateway.isRegisteredDevice(
                            deviceId,
                            publicKey);

            if (exists) {

                cachePositive(
                        new RegisteredDevice(
                                deviceId,
                                publicKey.normalize()));
            }

            return exists;

        } catch (GatewayException exception) {

            throw registryFailure(
                    "Failed to query exact device "
                            + "registration: "
                            + deviceId,
                    exception);

        } catch (RuntimeException exception) {

            if (exception
                    instanceof RegistryAccessException
                    registryAccessException) {

                throw registryAccessException;
            }

            throw registryFailure(
                    "Failed to query exact device "
                            + "registration: "
                            + deviceId,
                    exception);
        }
    }

    /**
     * Reads and decodes the registered secp256k1 public key.
     */
    // @Override
    // public Optional<RegisteredDevice>
    // findByDeviceId(
    //         final String deviceId) {

    //     if (!validDeviceId(deviceId)) {
    //         return Optional.empty();
    //     }

    //     RegisteredDevice cached =
    //             devicesById.get(
    //                     deviceId);

    //     if (cached != null) {

    //         return Optional.of(
    //                 cached);
    //     }

    //     try {
    //         /*
    //          * Avoid using ReadDevice exceptions as normal
    //          * not-found control flow.
    //          */
    //         if (!gateway.deviceExists(
    //                 deviceId)) {

    //             return Optional.empty();
    //         }

    //         FabricGatewayClient.DeviceAssetView
    //                 view =
    //                 gateway.readDevice(
    //                         deviceId);

    //         RegisteredDevice device =
    //                 decodeDevice(view);

    //         if (!deviceId.equals(
    //                 device.getDeviceId())) {

    //             throw new RegistryAccessException(
    //                     "Ledger returned a different "
    //                             + "device ID: expected "
    //                             + deviceId
    //                             + ", received "
    //                             + device.getDeviceId());
    //         }

    //         cachePositive(device);

    //         return Optional.of(device);

    //     } catch (GatewayException
    //              | IOException exception) {

    //         throw registryFailure(
    //                 "Failed to read registered device: "
    //                         + deviceId,
    //                 exception);

    //     } catch (RegistryAccessException exception) {
    //         throw exception;

    //     } catch (RuntimeException exception) {

    //         throw registryFailure(
    //                 "Invalid device record returned by Fabric: "
    //                         + deviceId,
    //                 exception);
    //     }
    // }

    @Override
    public Optional<RegisteredDevice>
    findByDeviceId(
            final String deviceId) {

        if (!validDeviceId(deviceId)) {
            return Optional.empty();
        }

        try {
            /*
            * 先实时确认链上记录存在。
            * Gateway 不可用时不能返回缓存结果。
            */
            if (!gateway.deviceExists(deviceId)) {
                return Optional.empty();
            }

            RegisteredDevice cached =
                    devicesById.get(deviceId);

            if (cached != null) {
                return Optional.of(cached);
            }

            FabricGatewayClient.DeviceAssetView view =
                    gateway.readDevice(deviceId);

            RegisteredDevice device =
                    decodeDevice(view);

            if (!deviceId.equals(
                    device.getDeviceId())) {

                throw new RegistryAccessException(
                        "Ledger returned a different "
                                + "device ID: expected "
                                + deviceId
                                + ", received "
                                + device.getDeviceId());
            }

            cachePositive(device);

            return Optional.of(device);

        } catch (GatewayException
                | IOException exception) {

            throw registryFailure(
                    "Failed to read registered device: "
                            + deviceId,
                    exception);

        } catch (RegistryAccessException exception) {

            throw exception;

        } catch (RuntimeException exception) {

            throw registryFailure(
                    "Invalid device record returned "
                            + "by Fabric: "
                            + deviceId,
                    exception);
        }
    }

    /**
     * Secure Fabric registration cannot be expressed by this
     * method because RegisteredDevice lacks the POP values
     * (c_i,z_i).
     */
    @Override
    public boolean registerIfAbsent(
            final RegisteredDevice device) {

        Objects.requireNonNull(
                device,
                "device");

        throw new UnsupportedOperationException(
                "FabricDeviceRegistry is read-only. "
                        + "Register devices using "
                        + "FabricGatewayClient.registerDevice"
                        + "(PublicParams, RegistrationRequest).");
    }

    /**
     * Returns the complete authoritative chain registration
     * list.
     */
    @Override
    public Collection<RegisteredDevice>
    findAll() {

        try {
            List<FabricGatewayClient.DeviceAssetView>
                    views =
                    gateway.readAllDevices();

            List<RegisteredDevice> result =
                    new ArrayList<>(
                            views.size());

            for (FabricGatewayClient.DeviceAssetView
                    view : views) {

                RegisteredDevice device =
                        decodeDevice(view);

                cachePositive(device);

                result.add(device);
            }

            result.sort(
                    Comparator.comparing(
                            RegisteredDevice::getDeviceId));

            return List.copyOf(result);

        } catch (GatewayException
                 | IOException exception) {

            throw registryFailure(
                    "Failed to read Fabric device registry",
                    exception);

        } catch (RegistryAccessException exception) {
            throw exception;

        } catch (RuntimeException exception) {

            throw registryFailure(
                    "Fabric returned an invalid "
                            + "device registry",
                    exception);
        }
    }

    /**
     * Returns the current authoritative registration count.
     *
     * This deliberately queries Fabric through findAll()
     * rather than returning the positive-cache size.
     */
    @Override
    public int size() {

        return findAll().size();
    }

    private RegisteredDevice decodeDevice(
            final FabricGatewayClient.DeviceAssetView
                    view) {

        Objects.requireNonNull(
                view,
                "view");

        String deviceId =
                requireDeviceId(
                        view.deviceId());

        String publicKeyHex =
                Objects.requireNonNull(
                                view.publicKeyHex(),
                                "publicKeyHex")
                        .toLowerCase(
                                Locale.ROOT);

        byte[] encoded;

        try {
            encoded =
                    HEX.parseHex(
                            publicKeyHex);

        } catch (IllegalArgumentException exception) {

            throw new RegistryAccessException(
                    "Ledger public key is not valid hex "
                            + "for device "
                            + deviceId,
                    exception);
        }

        ECPoint publicKey;

        try {
            publicKey =
                    PointCodec.decodeCompressed(
                                    pp,
                                    encoded)
                            .normalize();

        } catch (RuntimeException exception) {

            throw new RegistryAccessException(
                    "Ledger public key is not a valid "
                            + "secp256k1 point for device "
                            + deviceId,
                    exception);
        }

        if (publicKey.isInfinity()) {

            throw new RegistryAccessException(
                    "Ledger contains the group identity "
                            + "as a device public key: "
                            + deviceId);
        }

        String canonical =
                publicKeyKey(
                        publicKey);

        if (!canonical.equals(
                publicKeyHex)) {

            throw new RegistryAccessException(
                    "Ledger public key is not in canonical "
                            + "compressed form for device "
                            + deviceId);
        }

        return new RegisteredDevice(
                deviceId,
                publicKey);
    }

    /**
     * Adds only a registration already proven by a successful
     * Fabric query.
     */
    private void cachePositive(
            final RegisteredDevice device) {

        String deviceId =
                device.getDeviceId();

        String key =
                publicKeyKey(
                        device.getPublicKey());

        RegisteredDevice previousById =
                devicesById.putIfAbsent(
                        deviceId,
                        device);

        if (previousById != null
                && !publicKeyKey(
                        previousById.getPublicKey())
                        .equals(key)) {

            throw new RegistryAccessException(
                    "Conflicting public keys returned "
                            + "for device ID "
                            + deviceId);
        }

        String previousId =
                deviceIdByPublicKey.putIfAbsent(
                        key,
                        deviceId);

        if (previousId != null
                && !previousId.equals(
                        deviceId)) {

            /*
             * Roll back a possible first-map insertion made by
             * this invocation.
             */
            if (previousById == null) {

                devicesById.remove(
                        deviceId,
                        device);
            }

            throw new RegistryAccessException(
                    "The same public key was returned "
                            + "for multiple device IDs: "
                            + previousId
                            + " and "
                            + deviceId);
        }
    }

    private static boolean validDeviceId(
            final String deviceId) {

        return deviceId != null
                && !deviceId.isBlank()
                && deviceId.equals(
                        deviceId.trim())
                && deviceId.indexOf('\0') < 0;
    }

    private static String requireDeviceId(
            final String deviceId) {

        if (!validDeviceId(deviceId)) {

            throw new RegistryAccessException(
                    "Ledger returned an invalid device ID");
        }

        return deviceId;
    }

    private static boolean validPublicKey(
            final ECPoint publicKey) {

        return publicKey != null
                && !publicKey.isInfinity();
    }

    private static String publicKeyKey(
            final ECPoint publicKey) {

        return HEX.formatHex(
                PointCodec.encodeCompressed(
                        publicKey.normalize()));
    }

    private static RegistryAccessException
    registryFailure(
            final String message,
            final Throwable cause) {

        return new RegistryAccessException(
                message,
                cause);
    }

    /**
     * Fail-closed exception for unavailable or inconsistent
     * Fabric registry state.
     */
    public static final class RegistryAccessException
            extends RuntimeException {

        public RegistryAccessException(
                final String message) {

            super(message);
        }

        public RegistryAccessException(
                final String message,
                final Throwable cause) {

            super(message, cause);
        }
    }
}