package com.basr.persistence;

import com.basr.algorithm.Aggregate;
import com.basr.crypto.PointCodec;
import com.basr.crypto.PublicParams;
import com.basr.crypto.TranscriptEncoder;
import com.basr.entity.RecoveryMaterial;
import com.basr.entity.Report;

import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * BASR Pkg 的确定性二进制编解码。
 *
 * 编码格式：
 *
 *  magic                  8 bytes
 *  binaryVersion          int32
 *  formatVersion          length-prefixed UTF-8
 *  packageBatchId         length-prefixed UTF-8
 *  packageTimestamp       int64
 *  entryCount             int32
 *
 *  对每个 entry：
 *
 *      deviceId           length-prefixed UTF-8
 *      publicKey          33 bytes
 *      beta               uint8
 *      data               length-prefixed bytes
 *      hasRM              uint8
 *      RM                 32 bytes，当 hasRM=1
 *      reportBatchId      length-prefixed UTF-8
 *      reportTimestamp    int64
 *      digest             32 bytes
 *      commitment R_i     33 bytes
 *
 * 所有整数使用网络字节序，即大端序。
 *
 * 相同的 Pkg 和相同的条目顺序始终产生相同字节。
 */
public final class PackageCodec {

    private static final byte[] MAGIC =
            new byte[] {
                    'B', 'A', 'S', 'R',
                    'P', 'K', 'G', 0
            };

    private static final int BINARY_VERSION = 1;

    private static final int COMPRESSED_POINT_LENGTH = 33;

    private static final int SCALAR_LENGTH = 32;

    private static final int RECOVERY_MATERIAL_LENGTH = 32;

    /**
     * 防止恶意输入造成过量内存分配。
     */
    private static final int MAX_PACKAGE_BYTES =
            64 * 1024 * 1024;

    private static final int MAX_ENTRIES = 100_000;

    private static final int MAX_IDENTIFIER_BYTES = 1_024;

    private static final int MAX_REPORT_DATA_BYTES =
            16 * 1024 * 1024;

    private PackageCodec() {
    }

    /**
     * 编码 Aggregate 的完整本地返回结果。
     */
    public static byte[] encode(
            PublicParams pp,
            Aggregate.Result result) {

        Objects.requireNonNull(result, "result");

        return encode(
                pp,
                result.batchRecord().getBatchId(),
                result.batchRecord().getTimestamp(),
                result.packageEntries());
    }

    /**
     * 编码指定 Pkg。
     */
    public static byte[] encode(
            PublicParams pp,
            String batchId,
            long timestamp,
            List<Aggregate.PackageEntry> entries) {

        return encodeDto(
                toDto(
                        pp,
                        batchId,
                        timestamp,
                        entries));
    }

    /**
     * 将运行时密码对象转换为持久化 DTO。
     */
    public static BasrPackageDto toDto(
            PublicParams pp,
            String batchId,
            long timestamp,
            List<Aggregate.PackageEntry> entries) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(batchId, "batchId");
        Objects.requireNonNull(entries, "entries");

        if (batchId.isBlank()) {
            throw new IllegalArgumentException(
                    "batchId cannot be blank");
        }

        if (entries.isEmpty()) {
            throw new IllegalArgumentException(
                    "entries cannot be empty");
        }

        if (entries.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException(
                    "Too many package entries");
        }

        List<BasrPackageDto.EntryDto> dtoEntries =
                new ArrayList<>(entries.size());

        for (Aggregate.PackageEntry entry : entries) {

            Objects.requireNonNull(entry, "entry");

            Report report =
                    Objects.requireNonNull(
                            entry.report(),
                            "entry.report");

            ECPoint commitment =
                    Objects.requireNonNull(
                            entry.commitment(),
                            "entry.commitment");

            /*
             * Pkg 的所有报告必须属于同一个批次。
             */
            if (!batchId.equals(report.getBatchId())) {
                throw new IllegalArgumentException(
                        "Report batchId differs from package batchId");
            }

            if (timestamp != report.getTimestamp()) {
                throw new IllegalArgumentException(
                        "Report timestamp differs from package timestamp");
            }

            byte[] recoveryMaterial =
                    report.hasRecoveryMaterial()
                            ? report
                                    .getRecoveryMaterial()
                                    .getEncapsulatedPublicKey()
                            : null;

            dtoEntries.add(
                    new BasrPackageDto.EntryDto(
                            report.getDeviceId(),
                            PointCodec.encodeCompressed(
                                    report.getPublicKey()),
                            report.getBeta(),
                            report.getData(),
                            recoveryMaterial,
                            report.getBatchId(),
                            report.getTimestamp(),
                            TranscriptEncoder.scalar(
                                    report.getDigest(),
                                    pp.getP()),
                            PointCodec.encodeCompressed(
                                    commitment)));
        }

        return new BasrPackageDto(
                BasrPackageDto.CURRENT_FORMAT,
                batchId,
                timestamp,
                dtoEntries);
    }

    /**
     * 将 DTO 确定性编码为二进制。
     */
    public static byte[] encodeDto(
            BasrPackageDto dto) {

        Objects.requireNonNull(dto, "dto");

        try {
            ByteArrayOutputStream byteStream =
                    new ByteArrayOutputStream();

            DataOutputStream output =
                    new DataOutputStream(byteStream);

            output.write(MAGIC);
            output.writeInt(BINARY_VERSION);

            writeString(
                    output,
                    dto.formatVersion());

            writeString(
                    output,
                    dto.batchId());

            output.writeLong(dto.timestamp());

            output.writeInt(dto.entries().size());

            for (BasrPackageDto.EntryDto entry
                    : dto.entries()) {

                writeString(
                        output,
                        entry.deviceId());

                writeFixed(
                        output,
                        entry.publicKeyCompressed(),
                        COMPRESSED_POINT_LENGTH,
                        "publicKey");

                output.writeByte(entry.beta());

                writeByteArray(
                        output,
                        entry.data(),
                        MAX_REPORT_DATA_BYTES,
                        "data");

                byte[] recoveryMaterial =
                        entry.recoveryMaterial();

                if (recoveryMaterial == null) {
                    output.writeByte(0);
                } else {
                    output.writeByte(1);

                    writeFixed(
                            output,
                            recoveryMaterial,
                            RECOVERY_MATERIAL_LENGTH,
                            "recoveryMaterial");
                }

                writeString(
                        output,
                        entry.batchId());

                output.writeLong(entry.timestamp());

                writeFixed(
                        output,
                        entry.digestScalar(),
                        SCALAR_LENGTH,
                        "digest");

                writeFixed(
                        output,
                        entry.commitmentCompressed(),
                        COMPRESSED_POINT_LENGTH,
                        "commitment");
            }

            output.flush();

            byte[] encoded =
                    byteStream.toByteArray();

            if (encoded.length > MAX_PACKAGE_BYTES) {
                throw new IllegalArgumentException(
                        "Encoded package exceeds maximum size");
            }

            return encoded;

        } catch (IOException exception) {
            /*
             * ByteArrayOutputStream 正常情况下不会产生 I/O 错误。
             */
            throw new IllegalStateException(
                    "Unable to encode BASR package",
                    exception);
        }
    }

    /**
     * 解码为运行时 Pkg。
     */
    public static DecodedPackage decode(
            PublicParams pp,
            byte[] encoded) {

        Objects.requireNonNull(pp, "pp");

        BasrPackageDto dto =
                decodeDto(encoded);

        List<Aggregate.PackageEntry> entries =
                new ArrayList<>(dto.entries().size());

        for (BasrPackageDto.EntryDto entry
                : dto.entries()) {

            /*
             * 恢复并验证 secp256k1 公钥。
             */
            ECPoint publicKey =
                    PointCodec.decodeCompressed(
                            pp,
                            entry.publicKeyCompressed());

            /*
             * 恢复报告摘要标量。
             */
            BigInteger digest =
                    new BigInteger(
                            1,
                            entry.digestScalar());

            if (digest.compareTo(pp.getP()) >= 0) {
                throw new IllegalArgumentException(
                        "Decoded digest is not in Z_p");
            }

            RecoveryMaterial recoveryMaterial =
                    entry.recoveryMaterial() == null
                            ? null
                            : new RecoveryMaterial(
                                    entry.recoveryMaterial());

            Report report =
                    new Report(
                            entry.deviceId(),
                            publicKey,
                            entry.beta(),
                            entry.data(),
                            recoveryMaterial,
                            entry.batchId(),
                            entry.timestamp(),
                            digest);

            ECPoint commitment =
                    PointCodec.decodeCompressed(
                            pp,
                            entry.commitmentCompressed());

            entries.add(
                    new Aggregate.PackageEntry(
                            report,
                            commitment));
        }

        return new DecodedPackage(
                dto.formatVersion(),
                dto.batchId(),
                dto.timestamp(),
                entries);
    }

    /**
     * 只解码持久化 DTO，不构造密码对象。
     */
    public static BasrPackageDto decodeDto(
            byte[] encoded) {

        Objects.requireNonNull(encoded, "encoded");

        if (encoded.length == 0
                || encoded.length > MAX_PACKAGE_BYTES) {

            throw new IllegalArgumentException(
                    "Invalid package byte length");
        }

        try {
            ByteArrayInputStream byteStream =
                    new ByteArrayInputStream(encoded);

            DataInputStream input =
                    new DataInputStream(byteStream);

            byte[] magic =
                    input.readNBytes(MAGIC.length);

            if (!Arrays.equals(MAGIC, magic)) {
                throw new IllegalArgumentException(
                        "Invalid BASR package magic");
            }

            int binaryVersion =
                    input.readInt();

            if (binaryVersion != BINARY_VERSION) {
                throw new IllegalArgumentException(
                        "Unsupported binary package version: "
                                + binaryVersion);
            }

            String formatVersion =
                    readString(
                            input,
                            MAX_IDENTIFIER_BYTES,
                            "formatVersion");

            String packageBatchId =
                    readString(
                            input,
                            MAX_IDENTIFIER_BYTES,
                            "packageBatchId");

            long packageTimestamp =
                    input.readLong();

            int entryCount =
                    input.readInt();

            if (entryCount <= 0
                    || entryCount > MAX_ENTRIES) {

                throw new IllegalArgumentException(
                        "Invalid package entry count: "
                                + entryCount);
            }

            List<BasrPackageDto.EntryDto> entries =
                    new ArrayList<>(entryCount);

            for (int index = 0;
                 index < entryCount;
                 index++) {

                String deviceId =
                        readString(
                                input,
                                MAX_IDENTIFIER_BYTES,
                                "deviceId");

                byte[] publicKey =
                        readFixed(
                                input,
                                COMPRESSED_POINT_LENGTH,
                                "publicKey");

                int beta =
                        input.readUnsignedByte();

                if (beta != 0 && beta != 1) {
                    throw new IllegalArgumentException(
                            "Invalid beta value");
                }

                byte[] data =
                        readByteArray(
                                input,
                                MAX_REPORT_DATA_BYTES,
                                "data");

                int hasRecoveryMaterial =
                        input.readUnsignedByte();

                final byte[] recoveryMaterial;

                if (hasRecoveryMaterial == 0) {
                    recoveryMaterial = null;
                } else if (hasRecoveryMaterial == 1) {
                    recoveryMaterial =
                            readFixed(
                                    input,
                                    RECOVERY_MATERIAL_LENGTH,
                                    "recoveryMaterial");
                } else {
                    throw new IllegalArgumentException(
                            "Invalid recovery-material flag");
                }

                String reportBatchId =
                        readString(
                                input,
                                MAX_IDENTIFIER_BYTES,
                                "reportBatchId");

                long reportTimestamp =
                        input.readLong();

                byte[] digest =
                        readFixed(
                                input,
                                SCALAR_LENGTH,
                                "digest");

                byte[] commitment =
                        readFixed(
                                input,
                                COMPRESSED_POINT_LENGTH,
                                "commitment");

                /*
                 * 包级元数据和报告级元数据必须一致。
                 */
                if (!packageBatchId.equals(
                        reportBatchId)) {

                    throw new IllegalArgumentException(
                            "Report batchId differs from package batchId");
                }

                if (packageTimestamp
                        != reportTimestamp) {

                    throw new IllegalArgumentException(
                            "Report timestamp differs from package timestamp");
                }

                entries.add(
                        new BasrPackageDto.EntryDto(
                                deviceId,
                                publicKey,
                                beta,
                                data,
                                recoveryMaterial,
                                reportBatchId,
                                reportTimestamp,
                                digest,
                                commitment));
            }

            /*
             * 不允许尾部附加未解释字节。
             */
            if (input.available() != 0) {
                throw new IllegalArgumentException(
                        "Package contains trailing bytes");
            }

            return new BasrPackageDto(
                    formatVersion,
                    packageBatchId,
                    packageTimestamp,
                    entries);

        } catch (EOFException exception) {
            throw new IllegalArgumentException(
                    "Truncated BASR package",
                    exception);

        } catch (IOException exception) {
            throw new IllegalArgumentException(
                    "Unable to decode BASR package",
                    exception);
        }
    }

    private static void writeString(
            DataOutputStream output,
            String value)
            throws IOException {

        Objects.requireNonNull(value, "value");

        byte[] bytes =
                value.getBytes(StandardCharsets.UTF_8);

        if (bytes.length == 0
                || bytes.length > MAX_IDENTIFIER_BYTES) {

            throw new IllegalArgumentException(
                    "Invalid UTF-8 string length");
        }

        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String readString(
            DataInputStream input,
            int maximumLength,
            String fieldName)
            throws IOException {

        byte[] bytes =
                readByteArray(
                        input,
                        maximumLength,
                        fieldName);

        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(
                            CodingErrorAction.REPORT)
                    .onUnmappableCharacter(
                            CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();

        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException(
                    fieldName
                            + " is not valid UTF-8",
                    exception);
        }
    }

    private static void writeByteArray(
            DataOutputStream output,
            byte[] bytes,
            int maximumLength,
            String fieldName)
            throws IOException {

        Objects.requireNonNull(bytes, fieldName);

        if (bytes.length > maximumLength) {
            throw new IllegalArgumentException(
                    fieldName + " is too large");
        }

        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static byte[] readByteArray(
            DataInputStream input,
            int maximumLength,
            String fieldName)
            throws IOException {

        int length =
                input.readInt();

        if (length < 0 || length > maximumLength) {
            throw new IllegalArgumentException(
                    "Invalid " + fieldName + " length");
        }

        return readFixed(
                input,
                length,
                fieldName);
    }

    private static void writeFixed(
            DataOutputStream output,
            byte[] bytes,
            int expectedLength,
            String fieldName)
            throws IOException {

        Objects.requireNonNull(bytes, fieldName);

        if (bytes.length != expectedLength) {
            throw new IllegalArgumentException(
                    fieldName
                            + " must contain exactly "
                            + expectedLength
                            + " bytes");
        }

        output.write(bytes);
    }

    private static byte[] readFixed(
            DataInputStream input,
            int length,
            String fieldName)
            throws IOException {

        byte[] bytes =
                input.readNBytes(length);

        if (bytes.length != length) {
            throw new EOFException(
                    "Unexpected end while reading "
                            + fieldName);
        }

        return bytes;
    }

    /**
     * 解码后的 Pkg。
     */
    public record DecodedPackage(
            String formatVersion,
            String batchId,
            long timestamp,
            List<Aggregate.PackageEntry> packageEntries) {

        public DecodedPackage {

            Objects.requireNonNull(
                    formatVersion,
                    "formatVersion");

            Objects.requireNonNull(
                    batchId,
                    "batchId");

            Objects.requireNonNull(
                    packageEntries,
                    "packageEntries");

            packageEntries =
                    List.copyOf(packageEntries);
        }
    }
}