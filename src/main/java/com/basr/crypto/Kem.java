package com.basr.crypto;

import com.basr.entity.RecoveryKey;
import com.basr.entity.RecoveryMaterial;

import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * BASR KEM 实现。
 *
 * 具体实例：
 *
 *      DHKEM(X25519, HKDF-SHA256)
 *
 * 对应：
 *
 *      KEM.KeyGen
 *      KEM.Encap
 *      KEM.Decap
 */
public final class Kem {

    private static final String SUPPORTED_KEM =
            "DHKEM-X25519-HKDF-SHA256";

    private static final String X25519 =
            "X25519";

    /**
     * RFC 9180 KEM ID：
     *
     *      DHKEM(X25519, HKDF-SHA256) = 0x0020
     */
    private static final byte[] KEM_SUITE_ID =
            TranscriptEncoder.concat(
                    "KEM".getBytes(
                            StandardCharsets.US_ASCII),
                    new byte[] {0x00, 0x20});

    private static final int SHARED_SECRET_LENGTH =
            32;

    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    private Kem() {
    }

    /**
     * KEM.KeyGen。
     */
    public static RecoveryKey keyGen(
            PublicParams pp) {

        Objects.requireNonNull(pp, "pp");

        validateConfiguration(
                pp.getKemParameters());

        try {
            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance(
                            X25519);

            generator.initialize(
                    NamedParameterSpec.X25519,
                    SECURE_RANDOM);

            KeyPair pair =
                    generator.generateKeyPair();

            if (!(pair.getPrivate()
                    instanceof XECPrivateKey privateKey)
                    || !(pair.getPublic()
                    instanceof XECPublicKey publicKey)) {

                throw new IllegalStateException(
                        "Provider returned unsupported X25519 key types");
            }

            return new RecoveryKey(
                    privateKey,
                    publicKey);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Unable to generate X25519 recovery key",
                    exception);
        }
    }

    /**
     * KEM.Encap(pp_KEM, pk_R)。
     *
     * 返回：
     *
     *      RM_i
     *      K_i
     */
    public static Encapsulation encap(
            PublicParams pp,
            XECPublicKey recipientPublicKey) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(
                recipientPublicKey,
                "recipientPublicKey");

        validateConfiguration(
                pp.getKemParameters());

        X25519Codec.requireX25519(
                recipientPublicKey);

        byte[] dhSharedSecret = null;
        byte[] kemContext = null;

        try {
            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance(
                            X25519);

            generator.initialize(
                    NamedParameterSpec.X25519,
                    SECURE_RANDOM);

            KeyPair ephemeralPair =
                    generator.generateKeyPair();

            XECPrivateKey ephemeralPrivateKey =
                    (XECPrivateKey)
                            ephemeralPair.getPrivate();

            XECPublicKey ephemeralPublicKey =
                    (XECPublicKey)
                            ephemeralPair.getPublic();

            /*
             * DH(sk_E, pk_R)
             */
            dhSharedSecret =
                    deriveDhSecret(
                            ephemeralPrivateKey,
                            recipientPublicKey);

            rejectAllZeroSecret(
                    dhSharedSecret);

            /*
             * enc = SerializePublicKey(pk_E)
             */
            byte[] encapsulatedPublicKey =
                    X25519Codec.encodePublicKey(
                            ephemeralPublicKey);

            byte[] recipientEncoding =
                    X25519Codec.encodePublicKey(
                            recipientPublicKey);

            /*
             * kem_context = enc || pkRm
             */
            kemContext =
                    TranscriptEncoder.concat(
                            encapsulatedPublicKey,
                            recipientEncoding);

            byte[] sharedSecret =
                    extractAndExpand(
                            dhSharedSecret,
                            kemContext);

            return new Encapsulation(
                    new RecoveryMaterial(
                            encapsulatedPublicKey),
                    sharedSecret);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "DHKEM encapsulation failed",
                    exception);

        } finally {
            if (dhSharedSecret != null) {
                Arrays.fill(
                        dhSharedSecret,
                        (byte) 0);
            }

            if (kemContext != null) {
                Arrays.fill(
                        kemContext,
                        (byte) 0);
            }
        }
    }

    /**
     * KEM.Decap(pp_KEM, sk_R, RM_i)。
     *
     * RecoveryKey 同时携带 pk_R，以便构造 RFC 9180
     * 要求的 kem_context。
     */
    public static byte[] decap(
            PublicParams pp,
            RecoveryKey recoveryKey,
            RecoveryMaterial recoveryMaterial) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(
                recoveryKey,
                "recoveryKey");
        Objects.requireNonNull(
                recoveryMaterial,
                "recoveryMaterial");

        validateConfiguration(
                pp.getKemParameters());

        X25519Codec.requireX25519(
                recoveryKey.getSecretKey());

        X25519Codec.requireX25519(
                recoveryKey.getPublicKey());

        byte[] dhSharedSecret = null;
        byte[] kemContext = null;

        try {
            byte[] encapsulatedPublicKey =
                    recoveryMaterial
                            .getEncapsulatedPublicKey();

            XECPublicKey ephemeralPublicKey =
                    X25519Codec.decodePublicKey(
                            encapsulatedPublicKey);

            /*
             * DH(sk_R, pk_E)
             */
            dhSharedSecret =
                    deriveDhSecret(
                            recoveryKey.getSecretKey(),
                            ephemeralPublicKey);

            rejectAllZeroSecret(
                    dhSharedSecret);

            byte[] recipientEncoding =
                    X25519Codec.encodePublicKey(
                            recoveryKey.getPublicKey());

            kemContext =
                    TranscriptEncoder.concat(
                            encapsulatedPublicKey,
                            recipientEncoding);

            return extractAndExpand(
                    dhSharedSecret,
                    kemContext);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "DHKEM decapsulation failed",
                    exception);

        } finally {
            if (dhSharedSecret != null) {
                Arrays.fill(
                        dhSharedSecret,
                        (byte) 0);
            }

            if (kemContext != null) {
                Arrays.fill(
                        kemContext,
                        (byte) 0);
            }
        }
    }

    private static byte[] deriveDhSecret(
            XECPrivateKey privateKey,
            XECPublicKey publicKey)
            throws GeneralSecurityException {

        KeyAgreement agreement =
                KeyAgreement.getInstance(
                        X25519);

        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);

        return agreement.generateSecret();
    }

    /**
     * RFC 9180 ExtractAndExpand。
     */
    private static byte[] extractAndExpand(
            byte[] dhSharedSecret,
            byte[] kemContext) {

        byte[] eaePrk =
                Hkdf.labeledExtract(
                        KEM_SUITE_ID,
                        new byte[0],
                        "eae_prk",
                        dhSharedSecret);

        try {
            return Hkdf.labeledExpand(
                    KEM_SUITE_ID,
                    eaePrk,
                    "shared_secret",
                    kemContext,
                    SHARED_SECRET_LENGTH);

        } finally {
            Arrays.fill(eaePrk, (byte) 0);
        }
    }

    private static void rejectAllZeroSecret(
            byte[] secret) {

        int accumulator = 0;

        for (byte value : secret) {
            accumulator |= value;
        }

        if (accumulator == 0) {
            throw new IllegalArgumentException(
                    "X25519 produced an all-zero shared secret");
        }
    }

    private static void validateConfiguration(
            PublicParams.KemParameters parameters) {

        Objects.requireNonNull(
                parameters,
                "kemParameters");

        if (!SUPPORTED_KEM.equalsIgnoreCase(
                parameters.kemAlgorithm())) {

            throw new IllegalArgumentException(
                    "Unsupported KEM: "
                            + parameters.kemAlgorithm());
        }

        if (!X25519.equalsIgnoreCase(
                parameters.keyAgreementAlgorithm())) {

            throw new IllegalArgumentException(
                    "Unsupported key agreement: "
                            + parameters
                                    .keyAgreementAlgorithm());
        }

        if (!"HKDF-HMAC-SHA-256"
                .equalsIgnoreCase(
                        parameters.kdfAlgorithm())) {

            throw new IllegalArgumentException(
                    "Unsupported KDF: "
                            + parameters.kdfAlgorithm());
        }

        if (parameters
                .derivedKeyLengthBytes()
                != SHARED_SECRET_LENGTH) {

            throw new IllegalArgumentException(
                    "KEM shared-secret length must be 32 bytes");
        }
    }

    /**
     * KEM 封装结果。
     *
     * close() 会擦除内部共享秘密。
     */
    public static final class Encapsulation
            implements AutoCloseable {

        private final RecoveryMaterial recoveryMaterial;

        private byte[] sharedSecret;

        private Encapsulation(
                RecoveryMaterial recoveryMaterial,
                byte[] sharedSecret) {

            this.recoveryMaterial =
                    Objects.requireNonNull(
                            recoveryMaterial,
                            "recoveryMaterial");

            this.sharedSecret =
                    Objects.requireNonNull(
                            sharedSecret,
                            "sharedSecret")
                            .clone();
        }

        public RecoveryMaterial getRecoveryMaterial() {
            return recoveryMaterial;
        }

        public byte[] copySharedSecret() {

            if (sharedSecret == null) {
                throw new IllegalStateException(
                        "Encapsulation secret has been destroyed");
            }

            return sharedSecret.clone();
        }

        @Override
        public void close() {

            if (sharedSecret != null) {
                Arrays.fill(
                        sharedSecret,
                        (byte) 0);

                sharedSecret = null;
            }
        }
    }
}