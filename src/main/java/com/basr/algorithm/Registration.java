package com.basr.algorithm;

import com.basr.crypto.Hash;
import com.basr.crypto.PointCodec;
import com.basr.crypto.ScalarSampler;
import com.basr.crypto.Schnorr;
import com.basr.crypto.TranscriptEncoder;
import com.basr.crypto.PublicParams;
import com.basr.entity.Device;
import com.basr.entity.ProofOfPossession;
import com.basr.entity.RegisteredDevice;
import com.basr.entity.RegistrationRequest;
import com.basr.entity.RegistrationResult;
import com.basr.registry.DeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BASR Register Protocol 的本地真实实现。
 *
 * 设备侧：
 *
 * 1. sk_i <-$ Z_p^*
 * 2. pk_i = [sk_i]g
 * 3. rho_i <-$ Z_p^*
 * 4. A_i = [rho_i]g
 * 5. c_i = H4(pk_i || ID_i || A_i)
 * 6. z_i = rho_i + c_i * sk_i mod p
 * 7. POP_i = (c_i, z_i)
 *
 * 注册服务侧：
 *
 * 1. A_i' = [z_i]g - [c_i]pk_i
 * 2. 验证 c_i = H4(pk_i || ID_i || A_i')
 * 3. 检查 ID_i 未注册
 * 4. 检查 pk_i 未注册
 * 5. 保存 (ID_i, pk_i)
 */
public final class Registration {

    private Registration() {
    }

    /**
     * 设备侧：生成设备签名密钥。
     *
     * 对应：
     *
     *      sk_i <-$ Z_p^*
     *      pk_i = [sk_i]g
     */
    public static Device generateDevice(
            PublicParams pp,
            String deviceId) {

        Objects.requireNonNull(pp, "pp");

        if (deviceId == null
                || deviceId.isBlank()) {

            throw new IllegalArgumentException(
                    "deviceId cannot be null or blank");
        }

        BigInteger secretKey =
                Schnorr.generateSecretKey(pp);

        ECPoint publicKey =
                Schnorr.derivePublicKey(
                        pp,
                        secretKey);

        return new Device(
                deviceId,
                secretKey,
                publicKey);
    }

    /**
     * 设备侧：生成注册请求。
     *
     * 输出：
     *
     *      tau_reg = (ID_i, pk_i, POP_i)
     */
    public static RegistrationRequest createRequest(
            PublicParams pp,
            Device device) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(device, "device");

        /*
         * 检查 Device 对象中的公钥确实对应其私钥，
         * 防止调用方传入内部不一致的设备对象。
         */
        ECPoint expectedPublicKey =
                Schnorr.derivePublicKey(
                        pp,
                        device.getSecretKey());

        if (!expectedPublicKey.equals(
                device.getPublicKey().normalize())) {

            throw new IllegalArgumentException(
                    "Device public key does not match its secret key");
        }

        /*
         * rho_i <-$ Z_p^*
         */
        BigInteger rho =
                ScalarSampler.sampleNonZero(
                        pp.getP());

        /*
         * A_i = [rho_i]g
         */
        ECPoint commitment =
                pp.getGenerator()
                        .multiply(rho)
                        .normalize();

        /*
         * c_i = H4(
         *          pk_i
         *          || ID_i
         *          || A_i
         *      )
         *
         * 字段顺序严格遵循算法描述。
         */
        BigInteger challenge =
                Hash.H4(
                        pp,
                        PointCodec.encodeCompressed(
                                device.getPublicKey()),
                        TranscriptEncoder.utf8(
                                device.getDeviceId()),
                        PointCodec.encodeCompressed(
                                commitment));

        /*
         * z_i = rho_i + c_i * sk_i mod p
         */
        BigInteger response =
                Schnorr.computeResponse(
                        pp,
                        rho,
                        challenge,
                        device.getSecretKey());

        ProofOfPossession proof =
                new ProofOfPossession(
                        challenge,
                        response);

        return new RegistrationRequest(
                device.getDeviceId(),
                device.getPublicKey(),
                proof);
    }

    /**
     * 注册服务侧：验证 POP 并写入本地注册表。
     *
     * 当前 DeviceRegistry 是内存注册表；
     * 后续可替换为 Fabric 注册表实现。
     */
    public static RegistrationResult verifyAndRegister(
            PublicParams pp,
            DeviceRegistry registry,
            RegistrationRequest request) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(registry, "registry");

        if (request == null) {
            return RegistrationResult.rejected(
                    "Registration request is null");
        }

        String deviceId =
                request.getDeviceId();

        ECPoint publicKey =
                request.getPublicKey();

        ProofOfPossession proof =
                request.getProofOfPossession();

        if (deviceId == null
                || deviceId.isBlank()) {

            return RegistrationResult.rejected(
                    "Device ID is null or blank");
        }

        /*
         * 验证 pk_i 是群 G 中的合法非单位元。
         */
        if (!PointCodec.isValidGroupElement(
                pp,
                publicKey)) {

            return RegistrationResult.rejected(
                    "Public key is not a valid element of G");
        }

        if (proof == null) {
            return RegistrationResult.rejected(
                    "Proof of possession is missing");
        }

        BigInteger challenge =
                proof.getChallenge();

        BigInteger response =
                proof.getResponse();

        /*
         * c_i, z_i 必须属于 Z_p。
         *
         * challenge 或 response 理论上可以为 0，
         * 因此这里检查 Z_p，而不是 Z_p^*。
         */
        if (!Schnorr.isScalar(
                challenge,
                pp.getP())) {

            return RegistrationResult.rejected(
                    "POP challenge is not in Z_p");
        }

        if (!Schnorr.isScalar(
                response,
                pp.getP())) {

            return RegistrationResult.rejected(
                    "POP response is not in Z_p");
        }

        final ECPoint reconstructedCommitment;

        try {
            /*
             * A_i' = [z_i]g - [c_i]pk_i
             */
            reconstructedCommitment =
                    Schnorr.reconstructCommitment(
                            pp,
                            publicKey,
                            challenge,
                            response);

        } catch (IllegalArgumentException exception) {
            return RegistrationResult.rejected(
                    "Unable to reconstruct POP commitment");
        }

        /*
         * 诚实生成的 rho_i 属于 Z_p^*，
         * 因此 A_i 不应为单位元 O。
         */
        if (reconstructedCommitment.isInfinity()) {
            return RegistrationResult.rejected(
                    "Reconstructed POP commitment is the point at infinity");
        }

        /*
         * c_i' = H4(
         *          pk_i
         *          || ID_i
         *          || A_i'
         *       )
         */
        BigInteger expectedChallenge =
                Hash.H4(
                        pp,
                        PointCodec.encodeCompressed(
                                publicKey),
                        TranscriptEncoder.utf8(
                                deviceId),
                        PointCodec.encodeCompressed(
                                reconstructedCommitment));

        /*
         * 验证：
         *
         *      c_i' == c_i
         */
        if (!expectedChallenge.equals(challenge)) {
            return RegistrationResult.rejected(
                    "Proof of possession verification failed");
        }

        /*
         * 验证注册唯一性：
         *
         *      (ID_i, *) not in L
         */
        if (registry.containsDeviceId(deviceId)) {
            return RegistrationResult.rejected(
                    "Device ID is already registered");
        }

        /*
         * 验证：
         *
         *      (*, pk_i) not in L
         */
        if (registry.containsPublicKey(publicKey)) {
            return RegistrationResult.rejected(
                    "Public key is already registered");
        }

        RegisteredDevice registeredDevice =
                new RegisteredDevice(
                        deviceId,
                        publicKey);

        /*
         * 原子插入，避免两个并发请求在预检查后同时注册。
         */
        boolean inserted =
                registry.registerIfAbsent(
                        registeredDevice);

        if (!inserted) {
            return RegistrationResult.rejected(
                    "Registration conflict occurred");
        }

        return RegistrationResult.accepted();
    }
}