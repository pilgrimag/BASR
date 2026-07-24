package com.basr.benchmark;

import com.basr.algorithm.AggVerify;
import com.basr.algorithm.Aggregate;
import com.basr.algorithm.RecKeyGen;
import com.basr.algorithm.Recovery;
import com.basr.algorithm.Registration;
import com.basr.algorithm.Setup;
import com.basr.algorithm.SigVerify;
import com.basr.algorithm.Sign;
import com.basr.crypto.PublicParams;
import com.basr.entity.Device;
import com.basr.entity.RecoveryKey;
import com.basr.entity.SignedReport;
import com.basr.registry.InMemoryDeviceRegistry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * BASR pure-cryptography benchmark runner.
 *
 * <p>Fabric, IPFS, Setup, recovery-key generation, device-key generation,
 * and registration are outside all measured intervals.</p>
 */
public final class CryptoBenchmarkMain {

    private static final int SECURITY_PARAMETER = 128;
    private static final int FULL_FIXED_N = 200;
    private static final String BATCH_ID = "benchmark-batch";
    private static final long TIMESTAMP_BASE = 1_800_000_000_000L;

    private static final List<String> CSV_HEADER =
            List.of(
                    "scheme",
                    "experiment",
                    "profile",
                    "run",
                    "n",
                    "ns",
                    "nr",
                    "report_size_bytes",
                    "sign_ns",
                    "kem_encap_ns",
                    "aead_encrypt_ns",
                    "privacy_ns",
                    "sigverify_ns",
                    "aggregate_ns",
                    "aggverify_ns",
                    "total_crypto_ns",
                    "kem_decap_ns",
                    "aead_decrypt_ns",
                    "recovery_ns",
                    "accepted_count",
                    "correctness");

    private CryptoBenchmarkMain() {
    }

    public static void main(
            String[] args) throws Exception {

        Config config = Config.parse(args);

        Files.createDirectories(
                config.outputDirectory());

        Path csvPath =
                config.outputDirectory()
                        .resolve("basr-crypto-raw.csv");

        Path metadataPath =
                config.outputDirectory()
                        .resolve("basr-crypto-metadata.txt");

        writeMetadata(metadataPath, config);

        PublicParams pp =
                Setup.setup(SECURITY_PARAMETER);

        RecoveryKey recoveryKey =
                RecKeyGen.generate(pp);

        System.out.println("BASR crypto benchmark");
        System.out.println(
                "profile      = " + config.profile().name());
        System.out.println(
                "warmups      = " + config.warmupRuns());
        System.out.println(
                "measurements = " + config.measurementRuns());
        System.out.println(
                "report bytes = " + config.reportSizeBytes());
        System.out.println(
                "output       = " + csvPath.toAbsolutePath());

        long sequence = 0L;

        try (BenchmarkCsvWriter csv =
                     new BenchmarkCsvWriter(
                             csvPath,
                             CSV_HEADER)) {

            sequence =
                    runSizeSweep(
                            csv,
                            pp,
                            recoveryKey,
                            config,
                            sequence);

            sequence =
                    runSensitiveSweep(
                            csv,
                            pp,
                            recoveryKey,
                            config,
                            sequence);

            runRecoverySweep(
                    csv,
                    pp,
                    recoveryKey,
                    config,
                    sequence);
        }

        System.out.println();
        System.out.println(
                "Benchmark completed successfully.");
        System.out.println(
                "Raw CSV: " + csvPath.toAbsolutePath());
        System.out.println(
                "Metadata: " + metadataPath.toAbsolutePath());
    }

    private static long runSizeSweep(
            BenchmarkCsvWriter csv,
            PublicParams pp,
            RecoveryKey recoveryKey,
            Config config,
            long sequence) throws IOException {

        for (int n : config.profile().sizeSweep()) {
            System.out.printf(
                    Locale.ROOT,
                    "%n[size sweep] n=%d%n",
                    n);

            Fixture fixture =
                    createFixture(
                            pp,
                            n,
                            config.reportSizeBytes());

            for (int warmup = 0;
                 warmup < config.warmupRuns();
                 warmup++) {

                runCryptoIteration(
                        pp,
                        recoveryKey,
                        fixture,
                        0,
                        TIMESTAMP_BASE + sequence++);
            }

            for (int run = 1;
                 run <= config.measurementRuns();
                 run++) {

                CryptoMeasurement measurement =
                        runCryptoIteration(
                                pp,
                                recoveryKey,
                                fixture,
                                0,
                                TIMESTAMP_BASE + sequence++);

                writeCryptoRow(
                        csv,
                        "size_sweep",
                        config.profile().name(),
                        run,
                        n,
                        0,
                        config.reportSizeBytes(),
                        measurement);
            }
        }

        return sequence;
    }

    private static long runSensitiveSweep(
            BenchmarkCsvWriter csv,
            PublicParams pp,
            RecoveryKey recoveryKey,
            Config config,
            long sequence) throws IOException {

        int n = config.profile().fixedN();

        Fixture fixture =
                createFixture(
                        pp,
                        n,
                        config.reportSizeBytes());

        for (int ns : config.profile().sensitiveSweep()) {
            System.out.printf(
                    Locale.ROOT,
                    "%n[sensitive sweep] n=%d, ns=%d%n",
                    n,
                    ns);

            for (int warmup = 0;
                 warmup < config.warmupRuns();
                 warmup++) {

                runCryptoIteration(
                        pp,
                        recoveryKey,
                        fixture,
                        ns,
                        TIMESTAMP_BASE + sequence++);
            }

            for (int run = 1;
                 run <= config.measurementRuns();
                 run++) {

                CryptoMeasurement measurement =
                        runCryptoIteration(
                                pp,
                                recoveryKey,
                                fixture,
                                ns,
                                TIMESTAMP_BASE + sequence++);

                writeCryptoRow(
                        csv,
                        "sensitive_sweep",
                        config.profile().name(),
                        run,
                        n,
                        ns,
                        config.reportSizeBytes(),
                        measurement);
            }
        }

        return sequence;
    }

    private static void runRecoverySweep(
            BenchmarkCsvWriter csv,
            PublicParams pp,
            RecoveryKey recoveryKey,
            Config config,
            long sequence) throws IOException {

        int n = config.profile().fixedN();

        System.out.printf(
                Locale.ROOT,
                "%n[recovery fixture] n=%d, ns=%d%n",
                n,
                n);

        RecoveryFixture fixture =
                createRecoveryFixture(
                        pp,
                        recoveryKey,
                        n,
                        config.reportSizeBytes(),
                        TIMESTAMP_BASE + sequence);

        for (int nr : config.profile().recoverySweep()) {
            System.out.printf(
                    Locale.ROOT,
                    "%n[recovery sweep] nr=%d%n",
                    nr);

            for (int warmup = 0;
                 warmup < config.warmupRuns();
                 warmup++) {

                runRecoveryIteration(
                        pp,
                        recoveryKey,
                        fixture,
                        nr);
            }

            for (int run = 1;
                 run <= config.measurementRuns();
                 run++) {

                RecoveryMeasurement measurement =
                        runRecoveryIteration(
                                pp,
                                recoveryKey,
                                fixture,
                                nr);

                writeRecoveryRow(
                        csv,
                        config.profile().name(),
                        run,
                        n,
                        nr,
                        config.reportSizeBytes(),
                        fixture.aggregateResult()
                                .acceptedCount(),
                        measurement);
            }
        }
    }

    private static Fixture createFixture(
            PublicParams pp,
            int n,
            int reportSizeBytes) {

        InMemoryDeviceRegistry registry =
                new InMemoryDeviceRegistry();

        List<Device> devices =
                new ArrayList<>(n);

        List<byte[]> messages =
                new ArrayList<>(n);

        for (int index = 0;
             index < n;
             index++) {

            Device device =
                    Registration.generateDevice(
                            pp,
                            String.format(
                                    Locale.ROOT,
                                    "device-%04d",
                                    index));

            boolean accepted =
                    Registration.verifyAndRegister(
                                    pp,
                                    registry,
                                    Registration.createRequest(
                                            pp,
                                            device))
                            .isAccepted();

            if (!accepted) {
                throw new IllegalStateException(
                        "Device registration failed at index "
                                + index);
            }

            devices.add(device);
            messages.add(
                    createReport(
                            reportSizeBytes,
                            index));
        }

        return new Fixture(
                registry,
                List.copyOf(devices),
                immutableMessageCopy(messages));
    }

    private static CryptoMeasurement runCryptoIteration(
            PublicParams pp,
            RecoveryKey recoveryKey,
            Fixture fixture,
            int sensitiveCount,
            long timestamp) {

        if (sensitiveCount < 0
                || sensitiveCount > fixture.devices().size()) {

            throw new IllegalArgumentException(
                    "Invalid sensitiveCount: "
                            + sensitiveCount);
        }

        List<SignedReport> signedReports =
                new ArrayList<>(
                        fixture.devices().size());

        long signNs = 0L;
        long kemEncapNs = 0L;
        long aeadEncryptNs = 0L;

        for (int index = 0;
             index < fixture.devices().size();
             index++) {

            int beta =
                    index < sensitiveCount ? 1 : 0;

            Sign.SignMeasurement measurement =
                    Sign.signMeasured(
                            pp,
                            recoveryKey.getPublicKey(),
                            fixture.devices().get(index),
                            fixture.messages().get(index),
                            beta,
                            BATCH_ID,
                            timestamp);

            signedReports.add(
                    measurement.signedReport());

            signNs =
                    Math.addExact(
                            signNs,
                            measurement.signatureNs());

            kemEncapNs =
                    Math.addExact(
                            kemEncapNs,
                            measurement.kemEncapNs());

            aeadEncryptNs =
                    Math.addExact(
                            aeadEncryptNs,
                            measurement.aeadEncryptNs());
        }

        long sigVerifyStart =
                System.nanoTime();

        for (SignedReport signedReport : signedReports) {
            if (!SigVerify.verify(
                    pp,
                    fixture.registry(),
                    signedReport)) {

                throw new IllegalStateException(
                        "Individual signature verification failed");
            }
        }

        long sigVerifyNs =
                System.nanoTime() - sigVerifyStart;

        long aggregateStart =
                System.nanoTime();

        Aggregate.Result aggregateResult =
                Aggregate.aggregatePreverified(
                                pp,
                                signedReports,
                                BATCH_ID,
                                timestamp)
                        .orElseThrow(
                                () -> new IllegalStateException(
                                        "Aggregation returned empty"));

        long aggregateNs =
                System.nanoTime() - aggregateStart;

        if (aggregateResult.acceptedCount()
                != signedReports.size()) {

            throw new IllegalStateException(
                    "Unexpected accepted count: "
                            + aggregateResult.acceptedCount()
                            + " != "
                            + signedReports.size());
        }

        long aggVerifyStart =
                System.nanoTime();

        boolean aggregateValid =
                AggVerify.verify(
                        pp,
                        fixture.registry(),
                        aggregateResult);

        long aggVerifyNs =
                System.nanoTime() - aggVerifyStart;

        if (!aggregateValid) {
            throw new IllegalStateException(
                    "Aggregate verification failed");
        }

        return new CryptoMeasurement(
                signNs,
                kemEncapNs,
                aeadEncryptNs,
                sigVerifyNs,
                aggregateNs,
                aggVerifyNs,
                aggregateResult.acceptedCount());
    }

    private static RecoveryFixture createRecoveryFixture(
            PublicParams pp,
            RecoveryKey recoveryKey,
            int n,
            int reportSizeBytes,
            long timestamp) {

        Fixture fixture =
                createFixture(
                        pp,
                        n,
                        reportSizeBytes);

        List<SignedReport> signedReports =
                new ArrayList<>(n);

        for (int index = 0;
             index < n;
             index++) {

            SignedReport signedReport =
                    Sign.sign(
                            pp,
                            recoveryKey.getPublicKey(),
                            fixture.devices().get(index),
                            fixture.messages().get(index),
                            1,
                            BATCH_ID,
                            timestamp);

            if (!SigVerify.verify(
                    pp,
                    fixture.registry(),
                    signedReport)) {

                throw new IllegalStateException(
                        "Recovery-fixture signature verification failed");
            }

            signedReports.add(signedReport);
        }

        Aggregate.Result aggregateResult =
                Aggregate.aggregatePreverified(
                                pp,
                                signedReports,
                                BATCH_ID,
                                timestamp)
                        .orElseThrow(
                                () -> new IllegalStateException(
                                        "Recovery-fixture aggregation failed"));

        if (!AggVerify.verify(
                pp,
                fixture.registry(),
                aggregateResult)) {

            throw new IllegalStateException(
                    "Recovery-fixture aggregate verification failed");
        }

        return new RecoveryFixture(
                aggregateResult,
                fixture.messages());
    }

    private static RecoveryMeasurement runRecoveryIteration(
            PublicParams pp,
            RecoveryKey recoveryKey,
            RecoveryFixture fixture,
            int recoveredCount) {

        if (recoveredCount <= 0
                || recoveredCount
                > fixture.aggregateResult()
                        .packageEntries()
                        .size()) {

            throw new IllegalArgumentException(
                    "Invalid recoveredCount: "
                            + recoveredCount);
        }

        long kemDecapNs = 0L;
        long aeadDecryptNs = 0L;

        for (int index = 0;
             index < recoveredCount;
             index++) {

            Aggregate.PackageEntry entry =
                    fixture.aggregateResult()
                            .packageEntries()
                            .get(index);

            var optionalMeasurement =
                    Recovery.recoverSensitivePreverified(
                            pp,
                            recoveryKey,
                            entry.report());

            if (optionalMeasurement.isEmpty()) {
                throw new IllegalStateException(
                        "Preverified recovery failed at index "
                                + index);
            }

            Recovery.RecoveryMeasurement measurement =
                    optionalMeasurement.orElseThrow();

            if (!Arrays.equals(
                    fixture.messages().get(index),
                    measurement.plaintext())) {

                throw new IllegalStateException(
                        "Recovered plaintext mismatch at index "
                                + index);
            }

            kemDecapNs =
                    Math.addExact(
                            kemDecapNs,
                            measurement.kemDecapNs());

            aeadDecryptNs =
                    Math.addExact(
                            aeadDecryptNs,
                            measurement.aeadDecryptNs());
        }

        return new RecoveryMeasurement(
                kemDecapNs,
                aeadDecryptNs);
    }

    private static void writeCryptoRow(
            BenchmarkCsvWriter csv,
            String experiment,
            String profile,
            int run,
            int n,
            int ns,
            int reportSizeBytes,
            CryptoMeasurement measurement)
            throws IOException {

        csv.writeRow(
                "BASR",
                experiment,
                profile,
                run,
                n,
                ns,
                null,
                reportSizeBytes,
                measurement.signNs(),
                measurement.kemEncapNs(),
                measurement.aeadEncryptNs(),
                measurement.privacyNs(),
                measurement.sigVerifyNs(),
                measurement.aggregateNs(),
                measurement.aggVerifyNs(),
                measurement.totalCryptoNs(),
                null,
                null,
                null,
                measurement.acceptedCount(),
                true);
    }

    private static void writeRecoveryRow(
            BenchmarkCsvWriter csv,
            String profile,
            int run,
            int n,
            int nr,
            int reportSizeBytes,
            int acceptedCount,
            RecoveryMeasurement measurement)
            throws IOException {

        csv.writeRow(
                "BASR",
                "recovery_sweep",
                profile,
                run,
                n,
                n,
                nr,
                reportSizeBytes,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                measurement.kemDecapNs(),
                measurement.aeadDecryptNs(),
                measurement.totalNs(),
                acceptedCount,
                true);
    }

    private static byte[] createReport(
            int size,
            int seed) {

        byte[] report = new byte[size];

        for (int index = 0;
             index < size;
             index++) {

            report[index] =
                    (byte) ('A'
                            + Math.floorMod(
                                    seed + index,
                                    26));
        }

        return report;
    }

    private static List<byte[]> immutableMessageCopy(
            List<byte[]> source) {

        List<byte[]> copy =
                new ArrayList<>(source.size());

        for (byte[] message : source) {
            copy.add(message.clone());
        }

        return List.copyOf(copy);
    }

    private static void writeMetadata(
            Path output,
            Config config) throws IOException {

        List<String> lines =
                List.of(
                        "scheme=BASR",
                        "benchmark=pure-cryptography",
                        "created_utc=" + Instant.now(),
                        "profile=" + config.profile().name(),
                        "warmup_runs=" + config.warmupRuns(),
                        "measurement_runs=" + config.measurementRuns(),
                        "report_size_bytes=" + config.reportSizeBytes(),
                        "security_parameter=" + SECURITY_PARAMETER,
                        "signature_curve=secp256k1",
                        "recovery_kem=DHKEM-X25519-HKDF-SHA256",
                        "aead=AES-256-GCM",
                        "hash=SHA-256-domain-separated",
                        "java_version="
                                + System.getProperty("java.version"),
                        "java_vendor="
                                + System.getProperty("java.vendor"),
                        "os_name="
                                + System.getProperty("os.name"),
                        "os_version="
                                + System.getProperty("os.version"),
                        "os_arch="
                                + System.getProperty("os.arch"),
                        "available_processors="
                                + Runtime.getRuntime()
                                        .availableProcessors(),
                        "max_jvm_memory_bytes="
                                + Runtime.getRuntime()
                                        .maxMemory(),
                        "size_sweep="
                                + Arrays.toString(
                                        config.profile()
                                                .sizeSweep()),
                        "fixed_n="
                                + config.profile().fixedN(),
                        "sensitive_sweep="
                                + Arrays.toString(
                                        config.profile()
                                                .sensitiveSweep()),
                        "recovery_sweep="
                                + Arrays.toString(
                                        config.profile()
                                                .recoverySweep()),
                        "timing_clock=System.nanoTime",
                        "fig1_sign=signature_ns_excluding_KEM_and_AEAD",
                        "fig2_sigverify=cumulative_individual_verification_ns",
                        "fig3_aggregate=preverified_aggregation_ns",
                        "fig4_aggverify=aggregate_verification_ns",
                        "fig5_privacy=kem_encap_ns_plus_aead_encrypt_ns",
                        "fig6_processing_and_signing=privacy_ns_plus_sign_ns",
                        "fig7_total_crypto=sign_plus_privacy_plus_sigverify_plus_aggregate_plus_aggverify",
                        "fig8_recovery=kem_decap_ns_plus_aead_decrypt_ns",
                        "fabric_included=false",
                        "ipfs_included=false");

        Files.write(
                output,
                lines,
                StandardCharsets.UTF_8);
    }

    private record Fixture(
            InMemoryDeviceRegistry registry,
            List<Device> devices,
            List<byte[]> messages) {

        private Fixture {
            Objects.requireNonNull(registry, "registry");
            devices = List.copyOf(devices);
            messages = immutableMessageCopy(messages);

            if (devices.isEmpty()
                    || devices.size() != messages.size()) {

                throw new IllegalArgumentException(
                        "Fixture sizes are inconsistent");
            }
        }
    }

    private record RecoveryFixture(
            Aggregate.Result aggregateResult,
            List<byte[]> messages) {

        private RecoveryFixture {
            Objects.requireNonNull(
                    aggregateResult,
                    "aggregateResult");

            messages =
                    immutableMessageCopy(messages);
        }
    }

    private record CryptoMeasurement(
            long signNs,
            long kemEncapNs,
            long aeadEncryptNs,
            long sigVerifyNs,
            long aggregateNs,
            long aggVerifyNs,
            int acceptedCount) {

        private CryptoMeasurement {
            if (signNs < 0
                    || kemEncapNs < 0
                    || aeadEncryptNs < 0
                    || sigVerifyNs < 0
                    || aggregateNs < 0
                    || aggVerifyNs < 0
                    || acceptedCount <= 0) {

                throw new IllegalArgumentException(
                        "Invalid crypto measurement");
            }
        }

        long privacyNs() {
            return Math.addExact(
                    kemEncapNs,
                    aeadEncryptNs);
        }

        long totalCryptoNs() {
            long total =
                    Math.addExact(
                            signNs,
                            privacyNs());

            total =
                    Math.addExact(
                            total,
                            sigVerifyNs);

            total =
                    Math.addExact(
                            total,
                            aggregateNs);

            return Math.addExact(
                    total,
                    aggVerifyNs);
        }
    }

    private record RecoveryMeasurement(
            long kemDecapNs,
            long aeadDecryptNs) {

        private RecoveryMeasurement {
            if (kemDecapNs < 0
                    || aeadDecryptNs < 0) {

                throw new IllegalArgumentException(
                        "Invalid recovery measurement");
            }
        }

        long totalNs() {
            return Math.addExact(
                    kemDecapNs,
                    aeadDecryptNs);
        }
    }

    private record Profile(
            String name,
            int[] sizeSweep,
            int fixedN,
            int[] sensitiveSweep,
            int[] recoverySweep,
            int defaultWarmups,
            int defaultMeasurements) {

        private Profile {
            Objects.requireNonNull(name, "name");
            sizeSweep = sizeSweep.clone();
            sensitiveSweep = sensitiveSweep.clone();
            recoverySweep = recoverySweep.clone();
        }

        @Override
        public int[] sizeSweep() {
            return sizeSweep.clone();
        }

        @Override
        public int[] sensitiveSweep() {
            return sensitiveSweep.clone();
        }

        @Override
        public int[] recoverySweep() {
            return recoverySweep.clone();
        }

        static Profile parse(
                String value) {

            return switch (
                    value.toLowerCase(Locale.ROOT)) {

                case "smoke" ->
                        new Profile(
                                "smoke",
                                new int[] {2, 4},
                                4,
                                new int[] {1, 2},
                                new int[] {1, 2},
                                1,
                                2);

                case "full" ->
                        new Profile(
                                "full",
                                new int[] {
                                        50,
                                        100,
                                        200,
                                        400,
                                        600,
                                        800,
                                        1000
                                },
                                FULL_FIXED_N,
                                new int[] {
                                        10,
                                        30,
                                        70,
                                        120,
                                        170,
                                        190
                                },
                                new int[] {
                                        10,
                                        30,
                                        70,
                                        120,
                                        170,
                                        190
                                },
                                5,
                                30);

                default ->
                        throw new IllegalArgumentException(
                                "Unknown profile: "
                                        + value
                                        + ". Expected smoke or full.");
            };
        }
    }

    private record Config(
            Profile profile,
            Path outputDirectory,
            int warmupRuns,
            int measurementRuns,
            int reportSizeBytes) {

        private Config {
            Objects.requireNonNull(profile, "profile");
            Objects.requireNonNull(
                    outputDirectory,
                    "outputDirectory");

            if (warmupRuns < 0) {
                throw new IllegalArgumentException(
                        "warmupRuns cannot be negative");
            }

            if (measurementRuns <= 0) {
                throw new IllegalArgumentException(
                        "measurementRuns must be positive");
            }

            if (reportSizeBytes <= 0) {
                throw new IllegalArgumentException(
                        "reportSizeBytes must be positive");
            }
        }

        static Config parse(
                String[] args) {

            if (args.length < 2
                    || args.length > 5) {

                throw new IllegalArgumentException(
                        "Usage: CryptoBenchmarkMain "
                                + "<smoke|full> <output-directory> "
                                + "[warmup-runs] [measurement-runs] "
                                + "[report-size-bytes]");
            }

            Profile profile =
                    Profile.parse(args[0]);

            Path outputDirectory =
                    Path.of(args[1]);

            int warmupRuns =
                    args.length >= 3
                            ? parseInteger(
                                    args[2],
                                    "warmup-runs")
                            : profile.defaultWarmups();

            int measurementRuns =
                    args.length >= 4
                            ? parseInteger(
                                    args[3],
                                    "measurement-runs")
                            : profile.defaultMeasurements();

            int reportSizeBytes =
                    args.length >= 5
                            ? parseInteger(
                                    args[4],
                                    "report-size-bytes")
                            : 1024;

            return new Config(
                    profile,
                    outputDirectory,
                    warmupRuns,
                    measurementRuns,
                    reportSizeBytes);
        }

        private static int parseInteger(
                String value,
                String name) {

            try {
                return Integer.parseInt(value);

            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException(
                        name
                                + " must be an integer: "
                                + value,
                        exception);
            }
        }
    }
}
