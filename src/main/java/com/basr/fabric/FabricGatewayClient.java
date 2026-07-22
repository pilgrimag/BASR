package com.basr.fabric;

import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.crypto.TranscriptEncoder;
import com.basr.entity.BatchRecord;
import com.basr.entity.ProofOfPossession;
import com.basr.entity.RegistrationRequest;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;

import org.bouncycastle.math.ec.ECPoint;

import org.hyperledger.fabric.client.CommitException;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.GatewayException;
import org.hyperledger.fabric.client.Hash;
import org.hyperledger.fabric.client.Network;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;

import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * BASR Fabric Gateway client.
 *
 * This client performs real interactions with the deployed BASR
 * chaincode on Hyperledger Fabric:
 *
 * - RegisterDevice
 * - ReadDevice
 * - IsRegisteredDevice
 * - CreateBatchRecord
 * - ReadBatchRecord
 *
 * No cryptographic value, IPFS CID, transaction result, or ledger
 * response is simulated in this class.
 */
public final class FabricGatewayClient
        implements AutoCloseable {

    private static final String REGISTER_DEVICE =
            "RegisterDevice";

    private static final String READ_DEVICE =
            "ReadDevice";

    private static final String IS_REGISTERED_DEVICE =
            "IsRegisteredDevice";

    private static final String CREATE_BATCH_RECORD =
            "CreateBatchRecord";

    private static final String READ_BATCH_RECORD =
            "ReadBatchRecord";

    private static final HexFormat HEX =
            HexFormat.of();

    private final ManagedChannel grpcChannel;

    private final Gateway gateway;

    private final Contract contract;

    private final ObjectMapper objectMapper;

    private FabricGatewayClient(
            final ManagedChannel grpcChannel,
            final Gateway gateway,
            final Contract contract) {

        this.grpcChannel =
                Objects.requireNonNull(
                        grpcChannel,
                        "grpcChannel");

        this.gateway =
                Objects.requireNonNull(
                        gateway,
                        "gateway");

        this.contract =
                Objects.requireNonNull(
                        contract,
                        "contract");

        this.objectMapper =
                new ObjectMapper();
    }

    /**
     * Connects to the current local Fabric test network using
     * the Org1 administrator identity.
     */
    public static FabricGatewayClient
            connectLocalTestNetwork()
            throws IOException,
                   CertificateException,
                   InvalidKeyException {

        return connect(
                Config.localTestNetwork());
    }

    /**
     * Opens a real TLS gRPC connection to a Fabric Gateway.
     */
    public static FabricGatewayClient connect(
            final Config config)
            throws IOException,
                   CertificateException,
                   InvalidKeyException {

        Objects.requireNonNull(
                config,
                "config");

        validateConfiguration(config);

        Identity identity =
                newIdentity(config);

        Signer signer =
                newSigner(config);

        ChannelCredentials tlsCredentials =
                TlsChannelCredentials
                        .newBuilder()
                        .trustManager(
                                config.tlsCertificatePath()
                                        .toFile())
                        .build();

        ManagedChannel grpcChannel =
                Grpc.newChannelBuilder(
                                config.peerEndpoint(),
                                tlsCredentials)
                        .overrideAuthority(
                                config.tlsAuthorityOverride())
                        .build();

        try {
            Gateway gateway =
                    Gateway.newInstance()
                            .identity(identity)
                            .signer(signer)
                            .hash(Hash.SHA256)
                            .connection(grpcChannel)
                            .connect();

            Network network =
                    gateway.getNetwork(
                            config.channelName());

            /*
             * The Java chaincode declares:
             *
             *     @Contract(name = "basr")
             *
             * Therefore the contract name is selected explicitly
             * instead of relying on default-contract resolution.
             */
            Contract contract =
                    network.getContract(
                            config.chaincodeName(),
                            config.contractName());

            return new FabricGatewayClient(
                    grpcChannel,
                    gateway,
                    contract);

        } catch (RuntimeException | Error exception) {

            grpcChannel.shutdownNow();

            throw exception;
        }
    }

    /**
     * Submits a real device registration request.
     *
     * Chaincode input:
     *
     *     ID_i,
     *     pk_i,
     *     c_i,
     *     z_i
     *
     * The public key and POP are taken directly from the real
     * RegistrationRequest generated by basr-algorithm.
     */
    public boolean registerDevice(
            final PublicParams pp,
            final RegistrationRequest request)
            throws GatewayException,
                   CommitException {

        Objects.requireNonNull(
                pp,
                "pp");

        Objects.requireNonNull(
                request,
                "request");

        ProofOfPossession proof =
                Objects.requireNonNull(
                        request.getProofOfPossession(),
                        "proofOfPossession");

        byte[] response =
                contract.submitTransaction(
                        REGISTER_DEVICE,
                        request.getDeviceId(),
                        publicKeyHex(
                                request.getPublicKey()),
                        scalarHex(
                                pp,
                                proof.getChallenge()),
                        scalarHex(
                                pp,
                                proof.getResponse()));

        return parseBooleanResponse(
                REGISTER_DEVICE,
                response);
    }

    /**
     * Evaluates ReadDevice without creating a ledger transaction.
     */
    public DeviceAssetView readDevice(
            final String deviceId)
            throws GatewayException,
                   IOException {

        requireText(
                deviceId,
                "deviceId");

        byte[] response =
                contract.evaluateTransaction(
                        READ_DEVICE,
                        deviceId);

        return objectMapper.readValue(
                response,
                DeviceAssetView.class);
    }

    /**
     * Checks whether the exact pair (ID_i, pk_i) belongs to
     * the on-chain registration list.
     */
    public boolean isRegisteredDevice(
            final String deviceId,
            final ECPoint publicKey)
            throws GatewayException {

        requireText(
                deviceId,
                "deviceId");

        Objects.requireNonNull(
                publicKey,
                "publicKey");

        byte[] response =
                contract.evaluateTransaction(
                        IS_REGISTERED_DEVICE,
                        deviceId,
                        publicKeyHex(publicKey));

        return parseBooleanResponse(
                IS_REGISTERED_DEVICE,
                response);
    }

    /**
     * Submits:
     *
     *     BRec = (
     *         bid,
     *         t,
     *         R_agg,
     *         s_agg,
     *         mu,
     *         cid
     *     )
     *
     * The CID must already have been returned by the real Kubo
     * IPFS node before this method is called.
     */
    public boolean createBatchRecord(
            final PublicParams pp,
            final BatchRecord batchRecord,
            final String cid)
            throws GatewayException,
                   CommitException {

        Objects.requireNonNull(
                pp,
                "pp");

        Objects.requireNonNull(
                batchRecord,
                "batchRecord");

        requireText(
                cid,
                "cid");

        ECPoint aggregateCommitment =
                batchRecord
                        .getAggregateSignature()
                        .getRagg();

        BigInteger aggregateResponse =
                batchRecord
                        .getAggregateSignature()
                        .getSagg();

        byte[] response =
                contract.submitTransaction(
                        CREATE_BATCH_RECORD,
                        batchRecord.getBatchId(),
                        Long.toString(
                                batchRecord.getTimestamp()),
                        aggregateCommitmentHex(
                                aggregateCommitment),
                        scalarHex(
                                pp,
                                aggregateResponse),
                        HEX.formatHex(
                                batchRecord.getMu()),
                        cid);

        return parseBooleanResponse(
                CREATE_BATCH_RECORD,
                response);
    }

    /**
     * Evaluates ReadBatchRecord without changing ledger state.
     */
    public BatchRecordView readBatchRecord(
            final String batchId)
            throws GatewayException,
                   IOException {

        requireText(
                batchId,
                "batchId");

        byte[] response =
                contract.evaluateTransaction(
                        READ_BATCH_RECORD,
                        batchId);

        return objectMapper.readValue(
                response,
                BatchRecordView.class);
    }

    /**
     * Returns the Fabric chaincode name selected by this client.
     */
    public String getChaincodeName() {
        return contract.getChaincodeName();
    }

    /**
     * Returns the Fabric smart-contract name selected by this
     * client.
     */
    public String getContractName() {
        return contract.getContractName()
                .orElse("");
    }

    /**
     * Closes the Gateway session and its underlying gRPC channel.
     */
    @Override
    public void close() {

        try {
            gateway.close();

        } finally {
            grpcChannel.shutdownNow();

            try {
                grpcChannel.awaitTermination(
                        5,
                        TimeUnit.SECONDS);

            } catch (InterruptedException exception) {
                Thread.currentThread()
                        .interrupt();
            }
        }
    }

    private static Identity newIdentity(
            final Config config)
            throws IOException,
                   CertificateException {

        Path certificatePath =
                singleRegularFile(
                        config.signCertificateDirectory(),
                        "Org1 signing certificate");

        try (Reader certificateReader =
                     Files.newBufferedReader(
                             certificatePath,
                             StandardCharsets.UTF_8)) {

            X509Certificate certificate =
                    Identities.readX509Certificate(
                            certificateReader);

            return new X509Identity(
                    config.mspId(),
                    certificate);
        }
    }

    private static Signer newSigner(
            final Config config)
            throws IOException,
                   InvalidKeyException {

        Path privateKeyPath =
                singleRegularFile(
                        config.privateKeyDirectory(),
                        "Org1 private key");

        try (Reader keyReader =
                     Files.newBufferedReader(
                             privateKeyPath,
                             StandardCharsets.UTF_8)) {

            PrivateKey privateKey =
                    Identities.readPrivateKey(
                            keyReader);

            return Signers.newPrivateKeySigner(
                    privateKey);
        }
    }

    private static Path singleRegularFile(
            final Path directory,
            final String description)
            throws IOException {

        if (!Files.isDirectory(directory)) {

            throw new IOException(
                    description
                            + " directory does not exist: "
                            + directory);
        }

        List<Path> files;

        try (Stream<Path> stream =
                     Files.list(directory)) {

            files =
                    stream.filter(
                                    Files::isRegularFile)
                            .sorted()
                            .toList();
        }

        if (files.size() != 1) {

            throw new IOException(
                    description
                            + " directory must contain exactly "
                            + "one regular file, but found "
                            + files.size()
                            + ": "
                            + directory);
        }

        return files.get(0);
    }

    private static String publicKeyHex(
            final ECPoint publicKey) {

        ECPoint normalized =
                Objects.requireNonNull(
                                publicKey,
                                "publicKey")
                        .normalize();

        if (normalized.isInfinity()) {

            throw new IllegalArgumentException(
                    "Device public key cannot be "
                            + "the group identity");
        }

        return HEX.formatHex(
                PointCodec.encodeCompressed(
                        normalized));
    }

    private static String aggregateCommitmentHex(
            final ECPoint commitment) {

        ECPoint normalized =
                Objects.requireNonNull(
                                commitment,
                                "aggregateCommitment")
                        .normalize();

        /*
         * The Chaincode accepts 00 as the canonical encoding
         * of the elliptic-curve identity element.
         */
        if (normalized.isInfinity()) {
            return "00";
        }

        return HEX.formatHex(
                PointCodec.encodeCompressed(
                        normalized));
    }

    private static String scalarHex(
            final PublicParams pp,
            final BigInteger scalar) {

        Objects.requireNonNull(
                pp,
                "pp");

        Objects.requireNonNull(
                scalar,
                "scalar");

        return HEX.formatHex(
                TranscriptEncoder.scalar(
                        scalar,
                        pp.getP()));
    }

    private static boolean parseBooleanResponse(
            final String transactionName,
            final byte[] response) {

        Objects.requireNonNull(
                response,
                "response");

        String value =
                new String(
                        response,
                        StandardCharsets.UTF_8)
                        .trim();

        return switch (value) {

            case "true" ->
                    true;

            case "false" ->
                    false;

            default ->
                    throw new IllegalStateException(
                            "Unexpected response from "
                                    + transactionName
                                    + ": "
                                    + value);
        };
    }

    private static void validateConfiguration(
            final Config config)
            throws IOException {

        if (!Files.isRegularFile(
                config.tlsCertificatePath())) {

            throw new IOException(
                    "Peer TLS certificate does not exist: "
                            + config.tlsCertificatePath());
        }

        if (!Files.isDirectory(
                config.signCertificateDirectory())) {

            throw new IOException(
                    "Signing certificate directory "
                            + "does not exist: "
                            + config.signCertificateDirectory());
        }

        if (!Files.isDirectory(
                config.privateKeyDirectory())) {

            throw new IOException(
                    "Private-key directory does not exist: "
                            + config.privateKeyDirectory());
        }
    }

    private static String requireText(
            final String value,
            final String fieldName) {

        if (value == null
                || value.isBlank()) {

            throw new IllegalArgumentException(
                    fieldName
                            + " cannot be blank");
        }

        return value;
    }

    /**
     * Fabric connection configuration.
     *
     * All records are nested in this class to avoid creating
     * additional source files.
     */
    public record Config(
            String mspId,
            Path signCertificateDirectory,
            Path privateKeyDirectory,
            Path tlsCertificatePath,
            String peerEndpoint,
            String tlsAuthorityOverride,
            String channelName,
            String chaincodeName,
            String contractName) {

        public Config {

            requireText(
                    mspId,
                    "mspId");

            Objects.requireNonNull(
                    signCertificateDirectory,
                    "signCertificateDirectory");

            Objects.requireNonNull(
                    privateKeyDirectory,
                    "privateKeyDirectory");

            Objects.requireNonNull(
                    tlsCertificatePath,
                    "tlsCertificatePath");

            requireText(
                    peerEndpoint,
                    "peerEndpoint");

            requireText(
                    tlsAuthorityOverride,
                    "tlsAuthorityOverride");

            requireText(
                    channelName,
                    "channelName");

            requireText(
                    chaincodeName,
                    "chaincodeName");

            requireText(
                    contractName,
                    "contractName");

            signCertificateDirectory =
                    signCertificateDirectory
                            .toAbsolutePath()
                            .normalize();

            privateKeyDirectory =
                    privateKeyDirectory
                            .toAbsolutePath()
                            .normalize();

            tlsCertificatePath =
                    tlsCertificatePath
                            .toAbsolutePath()
                            .normalize();
        }

        /**
         * Default configuration for the current BASR Fabric
         * test network.
         *
         * The root path may be overridden using:
         *
         *     -Dbasr.fabric.testNetwork=/path/to/test-network
         */
        public static Config localTestNetwork() {

            Path defaultRoot =
                    Path.of(
                            System.getProperty(
                                    "user.home"),
                            "basr",
                            "blockchain",
                            "fabric-samples",
                            "test-network");

            Path testNetworkRoot =
                    Path.of(
                                    System.getProperty(
                                            "basr.fabric.testNetwork",
                                            defaultRoot.toString()))
                            .toAbsolutePath()
                            .normalize();

            Path org1Root =
                    testNetworkRoot.resolve(
                            Path.of(
                                    "organizations",
                                    "peerOrganizations",
                                    "org1.example.com"));

            Path adminMsp =
                    org1Root.resolve(
                            Path.of(
                                    "users",
                                    "Admin@org1.example.com",
                                    "msp"));

            Path peerRoot =
                    org1Root.resolve(
                            Path.of(
                                    "peers",
                                    "peer0.org1.example.com"));

            return new Config(
                    "Org1MSP",
                    adminMsp.resolve(
                            "signcerts"),
                    adminMsp.resolve(
                            "keystore"),
                    peerRoot.resolve(
                            Path.of(
                                    "tls",
                                    "ca.crt")),
                    "localhost:7051",
                    "peer0.org1.example.com",
                    "basrchannel",
                    "basr",
                    "basr");
        }
    }

    /**
     * JSON view returned by ReadDevice.
     */
    public record DeviceAssetView(
            String deviceId,
            String publicKeyHex) {

        public DeviceAssetView {

            requireText(
                    deviceId,
                    "deviceId");

            requireText(
                    publicKeyHex,
                    "publicKeyHex");
        }
    }

    /**
     * JSON view returned by ReadBatchRecord.
     */
    public record BatchRecordView(
            String batchId,
            long timestamp,
            String aggregateCommitmentHex,
            String aggregateResponseHex,
            String muHex,
            String cid) {

        public BatchRecordView {

            requireText(
                    batchId,
                    "batchId");

            if (timestamp <= 0L) {

                throw new IllegalArgumentException(
                        "timestamp must be positive");
            }

            requireText(
                    aggregateCommitmentHex,
                    "aggregateCommitmentHex");

            requireText(
                    aggregateResponseHex,
                    "aggregateResponseHex");

            requireText(
                    muHex,
                    "muHex");

            requireText(
                    cid,
                    "cid");
        }
    }
}