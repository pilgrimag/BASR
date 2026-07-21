package com.basr.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * HKDF-HMAC-SHA-256 实现。
 *
 * 同时实现 RFC 9180 DHKEM 所需的：
 *
 * - LabeledExtract
 * - LabeledExpand
 *
 * 本类不保存长期密钥状态。
 */
public final class Hkdf {

    private static final String HMAC_ALGORITHM =
            "HmacSHA256";

    private static final int HASH_LENGTH = 32;

    private static final byte[] HPKE_VERSION_LABEL =
            "HPKE-v1".getBytes(StandardCharsets.US_ASCII);

    private Hkdf() {
    }

    /**
     * HKDF-Extract。
     */
    public static byte[] extract(
            byte[] salt,
            byte[] inputKeyMaterial) {

        Objects.requireNonNull(
                inputKeyMaterial,
                "inputKeyMaterial");

        byte[] effectiveSalt =
                salt == null || salt.length == 0
                        ? new byte[HASH_LENGTH]
                        : salt.clone();

        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);

            mac.init(new SecretKeySpec(
                    effectiveSalt,
                    HMAC_ALGORITHM));

            return mac.doFinal(inputKeyMaterial);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "Unable to execute HKDF-Extract",
                    exception);

        } finally {
            Arrays.fill(effectiveSalt, (byte) 0);
        }
    }

    /**
     * HKDF-Expand。
     */
    public static byte[] expand(
            byte[] pseudoRandomKey,
            byte[] info,
            int outputLength) {

        Objects.requireNonNull(
                pseudoRandomKey,
                "pseudoRandomKey");

        Objects.requireNonNull(info, "info");

        if (pseudoRandomKey.length < HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "HKDF PRK must contain at least 32 bytes");
        }

        if (outputLength <= 0
                || outputLength > 255 * HASH_LENGTH) {

            throw new IllegalArgumentException(
                    "Invalid HKDF output length");
        }

        int blocks =
                (outputLength + HASH_LENGTH - 1)
                        / HASH_LENGTH;

        byte[] output = new byte[outputLength];
        byte[] previousBlock = new byte[0];

        int outputOffset = 0;

        try {
            for (int counter = 1;
                 counter <= blocks;
                 counter++) {

                Mac mac = Mac.getInstance(
                        HMAC_ALGORITHM);

                mac.init(new SecretKeySpec(
                        pseudoRandomKey,
                        HMAC_ALGORITHM));

                mac.update(previousBlock);
                mac.update(info);
                mac.update((byte) counter);

                byte[] currentBlock =
                        mac.doFinal();

                int copyLength =
                        Math.min(
                                currentBlock.length,
                                outputLength
                                        - outputOffset);

                System.arraycopy(
                        currentBlock,
                        0,
                        output,
                        outputOffset,
                        copyLength);

                outputOffset += copyLength;

                Arrays.fill(
                        previousBlock,
                        (byte) 0);

                previousBlock = currentBlock;
            }

            return output;

        } catch (GeneralSecurityException exception) {
            Arrays.fill(output, (byte) 0);

            throw new IllegalStateException(
                    "Unable to execute HKDF-Expand",
                    exception);

        } finally {
            Arrays.fill(previousBlock, (byte) 0);
        }
    }

    /**
     * RFC 9180 LabeledExtract。
     */
    public static byte[] labeledExtract(
            byte[] suiteId,
            byte[] salt,
            String label,
            byte[] inputKeyMaterial) {

        Objects.requireNonNull(suiteId, "suiteId");
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(
                inputKeyMaterial,
                "inputKeyMaterial");

        byte[] labeledInput =
                TranscriptEncoder.concat(
                        HPKE_VERSION_LABEL,
                        suiteId,
                        label.getBytes(
                                StandardCharsets.US_ASCII),
                        inputKeyMaterial);

        try {
            return extract(salt, labeledInput);
        } finally {
            Arrays.fill(labeledInput, (byte) 0);
        }
    }

    /**
     * RFC 9180 LabeledExpand。
     */
    public static byte[] labeledExpand(
            byte[] suiteId,
            byte[] pseudoRandomKey,
            String label,
            byte[] info,
            int outputLength) {

        Objects.requireNonNull(suiteId, "suiteId");
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(info, "info");

        if (outputLength > 0xffff) {
            throw new IllegalArgumentException(
                    "RFC 9180 length exceeds uint16");
        }

        byte[] length =
                new byte[] {
                        (byte) (outputLength >>> 8),
                        (byte) outputLength
                };

        byte[] labeledInfo =
                TranscriptEncoder.concat(
                        length,
                        HPKE_VERSION_LABEL,
                        suiteId,
                        label.getBytes(
                                StandardCharsets.US_ASCII),
                        info);

        try {
            return expand(
                    pseudoRandomKey,
                    labeledInfo,
                    outputLength);

        } finally {
            Arrays.fill(labeledInfo, (byte) 0);
        }
    }
}