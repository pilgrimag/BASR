package com.basr;

import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.crypto.PublicParams;
import com.basr.entity.Device;
import com.basr.entity.ProofOfPossession;
import com.basr.entity.RegistrationRequest;
import com.basr.entity.RegistrationResult;
import com.basr.registry.InMemoryDeviceRegistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class RegistrationTest {

    private PublicParams pp;

    private InMemoryDeviceRegistry registry;

    @BeforeEach
    void setUp() {
        pp = Setup.setup(128);
        registry = new InMemoryDeviceRegistry();
    }

    /**
     * 正常注册应成功。
     */
    @Test
    void validRegistrationShouldSucceed() {

        Device device =
                Registration.generateDevice(
                        pp,
                        "device-001");

        RegistrationRequest request =
                Registration.createRequest(
                        pp,
                        device);

        RegistrationResult result =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        request);

        assertTrue(
                result.isAccepted(),
                result.getMessage());

        assertEquals(1, registry.size());

        assertTrue(
                registry.contains(
                        device.getDeviceId(),
                        device.getPublicKey()));
    }

    /**
     * 修改 POP 挑战 c_i 后验证必须失败。
     */
    @Test
    void tamperedChallengeShouldFail() {

        Device device =
                Registration.generateDevice(
                        pp,
                        "device-001");

        RegistrationRequest validRequest =
                Registration.createRequest(
                        pp,
                        device);

        ProofOfPossession validProof =
                validRequest.getProofOfPossession();

        BigInteger tamperedChallenge =
                validProof.getChallenge()
                        .add(BigInteger.ONE)
                        .mod(pp.getP());

        ProofOfPossession tamperedProof =
                new ProofOfPossession(
                        tamperedChallenge,
                        validProof.getResponse());

        RegistrationRequest tamperedRequest =
                new RegistrationRequest(
                        validRequest.getDeviceId(),
                        validRequest.getPublicKey(),
                        tamperedProof);

        RegistrationResult result =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        tamperedRequest);

        assertFalse(result.isAccepted());
        assertEquals(0, registry.size());
    }

    /**
     * 修改 POP 响应 z_i 后验证必须失败。
     */
    @Test
    void tamperedResponseShouldFail() {

        Device device =
                Registration.generateDevice(
                        pp,
                        "device-001");

        RegistrationRequest validRequest =
                Registration.createRequest(
                        pp,
                        device);

        ProofOfPossession validProof =
                validRequest.getProofOfPossession();

        BigInteger tamperedResponse =
                validProof.getResponse()
                        .add(BigInteger.ONE)
                        .mod(pp.getP());

        ProofOfPossession tamperedProof =
                new ProofOfPossession(
                        validProof.getChallenge(),
                        tamperedResponse);

        RegistrationRequest tamperedRequest =
                new RegistrationRequest(
                        validRequest.getDeviceId(),
                        validRequest.getPublicKey(),
                        tamperedProof);

        RegistrationResult result =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        tamperedRequest);

        assertFalse(result.isAccepted());
        assertEquals(0, registry.size());
    }

    /**
     * 将注册请求中的公钥替换为其他设备公钥后，
     * 原 POP 不再有效。
     */
    @Test
    void substitutedPublicKeyShouldFail() {

        Device deviceOne =
                Registration.generateDevice(
                        pp,
                        "device-001");

        Device deviceTwo =
                Registration.generateDevice(
                        pp,
                        "device-002");

        RegistrationRequest validRequest =
                Registration.createRequest(
                        pp,
                        deviceOne);

        RegistrationRequest tamperedRequest =
                new RegistrationRequest(
                        validRequest.getDeviceId(),
                        deviceTwo.getPublicKey(),
                        validRequest.getProofOfPossession());

        RegistrationResult result =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        tamperedRequest);

        assertFalse(result.isAccepted());
        assertEquals(0, registry.size());
    }

    /**
     * 相同设备 ID 不能重复注册。
     */
    @Test
    void duplicateDeviceIdShouldFail() {

        Device firstDevice =
                Registration.generateDevice(
                        pp,
                        "device-001");

        Device secondDevice =
                Registration.generateDevice(
                        pp,
                        "device-001");

        RegistrationResult firstResult =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        Registration.createRequest(
                                pp,
                                firstDevice));

        RegistrationResult secondResult =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        Registration.createRequest(
                                pp,
                                secondDevice));

        assertTrue(firstResult.isAccepted());
        assertFalse(secondResult.isAccepted());
        assertEquals(1, registry.size());
    }

    /**
     * 相同公钥不能绑定到另一个设备 ID。
     */
    @Test
    void duplicatePublicKeyShouldFail() {

        Device originalDevice =
                Registration.generateDevice(
                        pp,
                        "device-001");

        RegistrationResult firstResult =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        Registration.createRequest(
                                pp,
                                originalDevice));

        /*
         * 使用同一密钥对构造另一个设备身份。
         * 其 POP 本身是有效的，但注册表应拒绝公钥复用。
         */
        Device aliasDevice =
                new Device(
                        "device-002",
                        originalDevice.getSecretKey(),
                        originalDevice.getPublicKey());

        RegistrationResult secondResult =
                Registration.verifyAndRegister(
                        pp,
                        registry,
                        Registration.createRequest(
                                pp,
                                aliasDevice));

        assertTrue(firstResult.isAccepted());
        assertFalse(secondResult.isAccepted());
        assertEquals(1, registry.size());
    }
}