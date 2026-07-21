package com.basr;

import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Setup;
import com.basr.crypto.PublicParams;
import com.basr.entity.RecoveryKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RecKeyGen 功能测试。
 *
 * 测试目标：
 *
 * 1. 能生成真实 X25519 密钥对；
 * 2. 私钥和公钥使用 X25519 参数；
 * 3. 多次生成的密钥对不同；
 * 4. 生成的密钥能够完成真实 X25519 密钥协商；
 * 5. 空公共参数被拒绝。
 */
class RecKeyGenTest {

    private PublicParams pp;

    @BeforeEach
    void setUp() {

        pp = Setup.setup(128);
    }

    /**
     * 正常执行 RecKeyGen 应生成 X25519 密钥对。
     */
    @Test
    void recoveryKeyGenerationShouldSucceed() {

        RecoveryKey recoveryKey =
                RecKeyGen.generate(pp);

        assertNotNull(
                recoveryKey.getSecretKey());

        assertNotNull(
                recoveryKey.getPublicKey());

        /*
         * 验证私钥使用 X25519 参数集。
         */
        assertTrue(
                recoveryKey.getSecretKey().getParams()
                        instanceof NamedParameterSpec);

        NamedParameterSpec privateParameters =
                (NamedParameterSpec)
                        recoveryKey.getSecretKey()
                                .getParams();

        assertEquals(
                NamedParameterSpec.X25519.getName(),
                privateParameters.getName());

        /*
         * 验证公钥使用 X25519 参数集。
         */
        assertTrue(
                recoveryKey.getPublicKey().getParams()
                        instanceof NamedParameterSpec);

        NamedParameterSpec publicParameters =
                (NamedParameterSpec)
                        recoveryKey.getPublicKey()
                                .getParams();

        assertEquals(
                NamedParameterSpec.X25519.getName(),
                publicParameters.getName());

        /*
         * 验证公钥可以导出标准编码。
         */
        assertNotNull(
                recoveryKey.getEncodedPublicKey());

        assertTrue(
                recoveryKey.getEncodedPublicKey().length > 0);
    }

    /**
     * 两次 RecKeyGen 应以极高概率生成不同的密钥对。
     */
    @Test
    void repeatedGenerationShouldProduceDifferentKeys() {

        RecoveryKey first =
                RecKeyGen.generate(pp);

        RecoveryKey second =
                RecKeyGen.generate(pp);

        /*
         * X25519 公钥由 u 坐标表示。
         */
        assertNotEquals(
                first.getPublicKey().getU(),
                second.getPublicKey().getU());
    }

    /**
     * 验证 RecKeyGen 生成的密钥对能够执行真实 X25519 密钥协商。
     *
     * 测试方法：
     *
     * 1. DR 使用 RecKeyGen 生成 (sk_R, pk_R)；
     * 2. 生成另一方临时 X25519 密钥对；
     * 3. DR 使用 sk_R 和对方公钥计算共享秘密；
     * 4. 对方使用临时私钥和 pk_R 计算共享秘密；
     * 5. 两个共享秘密必须完全相同。
     */
    @Test
    void generatedKeyShouldSupportRealX25519Agreement()
            throws Exception {

        RecoveryKey recoveryKey =
                RecKeyGen.generate(pp);

        /*
         * 创建另一方临时 X25519 密钥对。
         *
         * 后续 KEM.Encap 中的设备将承担类似角色。
         */
        KeyPairGenerator peerGenerator =
                KeyPairGenerator.getInstance(
                        "X25519");

        peerGenerator.initialize(
                NamedParameterSpec.X25519);

        KeyPair peerKeyPair =
                peerGenerator.generateKeyPair();

        /*
         * DR 一侧：
         *
         *      DH(sk_R, ephemeralPublicKey)
         */
        byte[] sharedSecretByRecovery =
                deriveSharedSecret(
                        recoveryKey.getSecretKey(),
                        peerKeyPair.getPublic());

        /*
         * 临时发送方一侧：
         *
         *      DH(ephemeralSecretKey, pk_R)
         */
        byte[] sharedSecretByPeer =
                deriveSharedSecret(
                        peerKeyPair.getPrivate(),
                        recoveryKey.getPublicKey());

        try {
            /*
             * X25519 双方应得到相同的 32 字节共享秘密。
             */
            assertArrayEquals(
                    sharedSecretByRecovery,
                    sharedSecretByPeer);

            assertEquals(
                    32,
                    sharedSecretByRecovery.length);

            /*
             * 正常随机密钥对不应产生全零共享秘密。
             */
            assertFalse(
                    isAllZero(sharedSecretByRecovery));

        } finally {
            /*
             * 测试完成后尽量清除共享秘密数组。
             */
            Arrays.fill(
                    sharedSecretByRecovery,
                    (byte) 0);

            Arrays.fill(
                    sharedSecretByPeer,
                    (byte) 0);
        }
    }

    /**
     * 空公共参数必须被拒绝。
     */
    @Test
    void nullPublicParametersShouldFail() {

        assertThrows(
                NullPointerException.class,
                () -> RecKeyGen.generate(null));
    }

    /**
     * 使用 X25519 执行单次密钥协商。
     */
    private static byte[] deriveSharedSecret(
            PrivateKey privateKey,
            PublicKey publicKey)
            throws Exception {

        KeyAgreement keyAgreement =
                KeyAgreement.getInstance(
                        "X25519");

        keyAgreement.init(privateKey);

        /*
         * X25519 只有一个密钥协商阶段，
         * 因此 lastPhase 参数为 true。
         */
        keyAgreement.doPhase(
                publicKey,
                true);

        return keyAgreement.generateSecret();
    }

    /**
     * 判断字节数组是否全部为零。
     */
    private static boolean isAllZero(
            byte[] bytes) {

        int accumulator = 0;

        for (byte value : bytes) {
            accumulator |= value;
        }

        return accumulator == 0;
    }
}