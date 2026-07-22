package com.basr;

import com.basr.algorithm.Aggregate;
import com.basr.algorithm.AggVerify;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Recovery;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.Sign;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.crypto.TranscriptEncoder;
import com.basr.entity.AggregateSignature;
import com.basr.entity.BatchRecord;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.RegistrationRequest;
import com.basr.entity.SignedReport;
import com.basr.fabric.FabricGatewayClient;
import com.basr.ipfs.IpfsClient;
import com.basr.ipfs.KuboHttpIpfsClient;
import com.basr.persistence.PackageCodec;
import com.basr.registry.InMemoryDeviceRegistry;

import org.bouncycastle.math.ec.ECPoint;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BASR Fabric + IPFS + cryptographic algorithm integration test.
 *
 * This test performs real interactions with:
 *
 * - Hyperledger Fabric basrchannel;
 * - deployed BASR chaincode;
 * - Org1 Fabric Gateway;
 * - Kubo IPFS RPC;
 * - BASR secp256k1 signatures;
 * - BASR X25519 + HKDF + AES-GCM recovery;
 * - BASR aggregate verification.
 *
 * No Fabric response, IPFS CID, signature, POP, aggregate
 * signature, or recovery output is simulated.
 */
@EnabledIfSystemProperty(
        named = "basr.fabric.e2e",
        matches = "true"
)
class BasrFabricEndToEndTest {

    private static final HexFormat HEX =
            HexFormat.of();

    private static final int SECURITY_PARAMETER =
            128;

    private static final int PUBLIC_REPORT =
            0;

    private static final int SENSITIVE_REPORT =
            1;

    @Test
    @Timeout(
            value = 2,
            unit = TimeUnit.MINUTES
    )
    void completeRealFabricIpfsWorkflow()
            throws Exception {

        /*
         * -----------------------------------------------------
         * 1. Setup
         * -----------------------------------------------------
         */

        PublicParams pp =
                Setup.setup(
                        SECURITY_PARAMETER);

        IpfsClient ipfsClient =
                new KuboHttpIpfsClient();

        assertTrue(
                ipfsClient.isAvailable(),
                "Kubo RPC is unavailable at "
                        + KuboHttpIpfsClient.DEFAULT_RPC_URI);

        InMemoryDeviceRegistry registry =
                new InMemoryDeviceRegistry();

        String runId =
                uniqueRunId();

        String publicDeviceId =
                "fabric-public-" + runId;

        String sensitiveDeviceId =
                "fabric-sensitive-" + runId;

        String batchId =
                "fabric-batch-" + runId;

        byte[] publicPlaintext =
                (
                        "temperature=23.7;"
                                + "run="
                                + runId
                ).getBytes(
                        StandardCharsets.UTF_8);

        byte[] sensitivePlaintext =
                (
                        "confidential-pressure=82.2;"
                                + "run="
                                + runId
                ).getBytes(
                        StandardCharsets.UTF_8);

        /*
         * -----------------------------------------------------
         * 2. Connect to the real Org1 Fabric Gateway
         * -----------------------------------------------------
         */

        try (FabricGatewayClient gateway =
                     FabricGatewayClient
                             .connectLocalTestNetwork()) {

            assertEquals(
                    "basr",
                    gateway.getChaincodeName());

            assertEquals(
                    "basr",
                    gateway.getContractName());

            /*
             * -------------------------------------------------
             * 3. Generate and register the public device
             * -------------------------------------------------
             */

            Device publicDevice =
                    registerDevice(
                            pp,
                            registry,
                            gateway,
                            publicDeviceId);

            /*
             * -------------------------------------------------
             * 4. Generate and register the sensitive device
             * -------------------------------------------------
             */

            Device sensitiveDevice =
                    registerDevice(
                            pp,
                            registry,
                            gateway,
                            sensitiveDeviceId);

            /*
             * -------------------------------------------------
             * 5. Generate the real DR X25519 recovery key
             * -------------------------------------------------
             */

            RecoveryKey recoveryKey =
                    RecKeyGen.generate(pp);

            assertNotNull(
                    recoveryKey.getSecretKey());

            assertNotNull(
                    recoveryKey.getPublicKey());

            /*
             * The same timestamp is used for all reports in
             * this batch.
             */
            long timestamp =
                    Instant.now()
                            .toEpochMilli();

            /*
             * -------------------------------------------------
             * 6. Sign one public report, beta = 0
             * -------------------------------------------------
             */

            SignedReport publicSignedReport =
                    Sign.sign(
                            pp,
                            recoveryKey.getPublicKey(),
                            publicDevice,
                            publicPlaintext,
                            PUBLIC_REPORT,
                            batchId,
                            timestamp);

            /*
             * -------------------------------------------------
             * 7. Sign one sensitive report, beta = 1
             * -------------------------------------------------
             */

            SignedReport sensitiveSignedReport =
                    Sign.sign(
                            pp,
                            recoveryKey.getPublicKey(),
                            sensitiveDevice,
                            sensitivePlaintext,
                            SENSITIVE_REPORT,
                            batchId,
                            timestamp);

            /*
             * -------------------------------------------------
             * 8. Aggregate real signed reports
             * -------------------------------------------------
             */

            Aggregate.Result aggregateResult =
                    Aggregate.aggregate(
                                    pp,
                                    registry,
                                    List.of(
                                            publicSignedReport,
                                            sensitiveSignedReport),
                                    batchId,
                                    timestamp)
                            .orElseThrow(
                                    () ->
                                            new AssertionError(
                                                    "Aggregate rejected "
                                                            + "valid reports"));

            BatchRecord localBatchRecord =
                    aggregateResult
                            .batchRecord();

            assertFalse(
                    localBatchRecord.hasCid());

            /*
             * -------------------------------------------------
             * 9. Deterministically encode Pkg
             * -------------------------------------------------
             */

            byte[] packageBytes =
                    PackageCodec.encode(
                            pp,
                            aggregateResult);

            assertTrue(
                    packageBytes.length > 0);

            /*
             * -------------------------------------------------
             * 10. Upload the real Pkg to Kubo
             * -------------------------------------------------
             */

            String cid =
                    ipfsClient.put(
                            packageBytes);

            assertNotNull(cid);
            assertFalse(cid.isBlank());

            /*
             * Verify that the returned CID resolves to exactly
             * the uploaded deterministic package bytes.
             */
            byte[] immediateDownload =
                    ipfsClient.get(cid);

            assertArrayEquals(
                    packageBytes,
                    immediateDownload);

            /*
             * -------------------------------------------------
             * 11. Complete BRec with the real CID
             * -------------------------------------------------
             */

            BatchRecord completeBatchRecord =
                    localBatchRecord
                            .withCid(cid);

            assertTrue(
                    completeBatchRecord.hasCid());

            assertEquals(
                    cid,
                    completeBatchRecord.getCid());

            /*
             * -------------------------------------------------
             * 12. Submit BRec to real Fabric
             * -------------------------------------------------
             */

            assertTrue(
                    gateway.createBatchRecord(
                            pp,
                            completeBatchRecord,
                            cid));

            /*
             * -------------------------------------------------
             * 13. Read BRec back from basrchannel
             * -------------------------------------------------
             */

            FabricGatewayClient.BatchRecordView
                    ledgerView =
                    gateway.readBatchRecord(
                            batchId);

            assertEquals(
                    batchId,
                    ledgerView.batchId());

            assertEquals(
                    timestamp,
                    ledgerView.timestamp());

            assertEquals(
                    aggregateCommitmentHex(
                            completeBatchRecord),
                    ledgerView
                            .aggregateCommitmentHex());

            assertEquals(
                    scalarHex(
                            pp,
                            completeBatchRecord
                                    .getAggregateSignature()
                                    .getAggregateResponse()),
                    ledgerView
                            .aggregateResponseHex());

            assertEquals(
                    HEX.formatHex(
                            completeBatchRecord.getMu()),
                    ledgerView.muHex());

            assertEquals(
                    cid,
                    ledgerView.cid());

            /*
             * -------------------------------------------------
             * 14. Reconstruct BRec from real ledger data
             * -------------------------------------------------
             */

            BatchRecord ledgerBatchRecord =
                    toBatchRecord(
                            pp,
                            ledgerView);

            assertEquals(
                    completeBatchRecord,
                    ledgerBatchRecord);

            /*
             * -------------------------------------------------
             * 15. Download Pkg using the CID stored on-chain
             * -------------------------------------------------
             */

            byte[] ledgerReferencedPackage =
                    ipfsClient.get(
                            ledgerBatchRecord.getCid());

            assertArrayEquals(
                    packageBytes,
                    ledgerReferencedPackage);

            /*
             * -------------------------------------------------
             * 16. Decode the downloaded real package
             * -------------------------------------------------
             */

            PackageCodec.DecodedPackage
                    decodedPackage =
                    PackageCodec.decode(
                            pp,
                            ledgerReferencedPackage);

            assertNotNull(
                    decodedPackage.formatVersion());

            assertFalse(
                    decodedPackage
                            .formatVersion()
                            .isBlank());

            assertEquals(
                    batchId,
                    decodedPackage.batchId());

            assertEquals(
                    timestamp,
                    decodedPackage.timestamp());

            assertEquals(
                    2,
                    decodedPackage
                            .packageEntries()
                            .size());

            /*
             * -------------------------------------------------
             * 17. Verify the aggregate signature using:
             *
             *     on-chain BRec
             *     +
             *     IPFS Pkg
             *     +
             *     registered public keys
             * -------------------------------------------------
             */

            assertTrue(
                    AggVerify.verify(
                            pp,
                            registry,
                            ledgerBatchRecord,
                            decodedPackage
                                    .packageEntries()),
                    "AggVerify rejected the ledger/IPFS pair");

            /*
             * -------------------------------------------------
             * 18. Recover the public report
             * -------------------------------------------------
             */

            byte[] recoveredPublic =
                    Recovery.recover(
                                    pp,
                                    registry,
                                    recoveryKey,
                                    ledgerBatchRecord,
                                    decodedPackage
                                            .packageEntries(),
                                    publicDevice.getDeviceId(),
                                    publicSignedReport
                                            .getSignature()
                                            .getR())
                            .orElseThrow(
                                    () ->
                                            new AssertionError(
                                                    "Public report "
                                                            + "recovery failed"));

            assertArrayEquals(
                    publicPlaintext,
                    recoveredPublic);

            /*
             * -------------------------------------------------
             * 19. Recover and decrypt the sensitive report
             * -------------------------------------------------
             */

            byte[] recoveredSensitive =
                    Recovery.recover(
                                    pp,
                                    registry,
                                    recoveryKey,
                                    ledgerBatchRecord,
                                    decodedPackage
                                            .packageEntries(),
                                    sensitiveDevice.getDeviceId(),
                                    sensitiveSignedReport
                                            .getSignature()
                                            .getR())
                            .orElseThrow(
                                    () ->
                                            new AssertionError(
                                                    "Sensitive report "
                                                            + "recovery failed"));

            assertArrayEquals(
                    sensitivePlaintext,
                    recoveredSensitive);

            /*
             * Actual runtime values, not expected placeholders.
             */
            System.out.println();
            System.out.println(
                    "========== BASR Fabric E2E ==========");

            System.out.println(
                    "publicDeviceId    = "
                            + publicDeviceId);

            System.out.println(
                    "sensitiveDeviceId = "
                            + sensitiveDeviceId);

            System.out.println(
                    "batchId           = "
                            + batchId);

            System.out.println(
                    "cid               = "
                            + cid);

            System.out.println(
                    "packageBytes      = "
                            + packageBytes.length);

            System.out.println(
                    "AggVerify         = PASS");

            System.out.println(
                    "publicRecovery    = "
                            + new String(
                                    recoveredPublic,
                                    StandardCharsets.UTF_8));

            System.out.println(
                    "sensitiveRecovery = "
                            + new String(
                                    recoveredSensitive,
                                    StandardCharsets.UTF_8));

            System.out.println(
                    "====================================");

            System.out.println();
        }
    }

    /**
     * Generates a real device and POP, submits the registration
     * to Fabric, reads the asset back, and registers the same
     * verified pair in the local registry used by the current
     * cryptographic algorithm API.
     */
    private static Device registerDevice(
            final PublicParams pp,
            final InMemoryDeviceRegistry registry,
            final FabricGatewayClient gateway,
            final String deviceId)
            throws Exception {

        Device device =
                Registration.generateDevice(
                        pp,
                        deviceId);

        RegistrationRequest request =
                Registration.createRequest(
                        pp,
                        device);

        /*
         * Submit real Schnorr POP to the deployed Chaincode.
         */
        assertTrue(
                gateway.registerDevice(
                        pp,
                        request));

        /*
         * Read the committed registration from Fabric.
         */
        FabricGatewayClient.DeviceAssetView
                ledgerDevice =
                gateway.readDevice(
                        deviceId);

        assertEquals(
                deviceId,
                ledgerDevice.deviceId());

        assertEquals(
                publicKeyHex(
                        device.getPublicKey()),
                ledgerDevice.publicKeyHex());

        /*
         * Check exact on-chain membership:
         *
         *     (ID_i, pk_i) in L
         */
        assertTrue(
                gateway.isRegisteredDevice(
                        deviceId,
                        device.getPublicKey()));

        /*
         * The current Sign/Aggregate/AggVerify APIs consume a
         * DeviceRegistry. Populate it using the same real,
         * verified RegistrationRequest committed to Fabric.
         *
         * This does not replace the Fabric checks above; it
         * supplies the algorithm module's existing registry
         * interface with the exact on-chain registration pair.
         */
        assertTrue(
                Registration.verifyAndRegister(
                                pp,
                                registry,
                                request)
                        .isAccepted());

        return device;
    }

    /**
     * Reconstructs the algorithm-level BatchRecord using only
     * values returned by ReadBatchRecord.
     */
    private static BatchRecord toBatchRecord(
            final PublicParams pp,
            final FabricGatewayClient.BatchRecordView
                    view) {

        ECPoint aggregateCommitment;

        if ("00".equals(
                view.aggregateCommitmentHex())) {

            /*
             * A valid aggregate of the two reports generated by
             * this test should not be the identity.
             */
            throw new IllegalStateException(
                    "Unexpected identity aggregate commitment");
        }

        aggregateCommitment =
                PointCodec.decodeCompressed(
                        pp,
                        HEX.parseHex(
                                view.aggregateCommitmentHex()));

        BigInteger aggregateResponse =
                new BigInteger(
                        1,
                        HEX.parseHex(
                                view.aggregateResponseHex()));

        AggregateSignature aggregateSignature =
                new AggregateSignature(
                        aggregateCommitment,
                        aggregateResponse);

        return new BatchRecord(
                view.batchId(),
                view.timestamp(),
                aggregateSignature,
                HEX.parseHex(
                        view.muHex()),
                view.cid());
    }

    private static String publicKeyHex(
            final ECPoint publicKey) {

        return HEX.formatHex(
                PointCodec.encodeCompressed(
                        publicKey.normalize()));
    }

    private static String aggregateCommitmentHex(
            final BatchRecord batchRecord) {

        ECPoint commitment =
                batchRecord
                        .getAggregateSignature()
                        .getAggregateCommitment()
                        .normalize();

        if (commitment.isInfinity()) {
            return "00";
        }

        return HEX.formatHex(
                PointCodec.encodeCompressed(
                        commitment));
    }

    private static String scalarHex(
            final PublicParams pp,
            final BigInteger scalar) {

        return HEX.formatHex(
                TranscriptEncoder.scalar(
                        scalar,
                        pp.getP()));
    }

    /**
     * Fabric ledger state is persistent, so every integration
     * test invocation must use new identifiers.
     */
    private static String uniqueRunId() {

        String uuid =
                UUID.randomUUID()
                        .toString()
                        .replace(
                                "-",
                                "");

        return Long.toUnsignedString(
                        System.currentTimeMillis(),
                        36)
                + "-"
                + uuid.substring(
                        0,
                        12);
    }
}