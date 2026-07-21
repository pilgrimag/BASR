package com.basr.persistence;

import java.util.List;
import java.util.Objects;

/**
 * BASR 离线报告包的持久化 DTO。
 *
 * 对应算法中的：
 *
 *      Pkg = ((rep_i, R_i))_{i=1}^{q}
 *
 * DTO 不保存 ECPoint、BigInteger 等运行时密码对象，
 * 只保存它们的规范字节编码。
 *
 * 当前格式版本：
 *
 *      BASR-PKG-1
 */
public record BasrPackageDto(
        String formatVersion,
        String batchId,
        long timestamp,
        List<EntryDto> entries) {

    public static final String CURRENT_FORMAT =
            "BASR-PKG-1";

    public BasrPackageDto {

        Objects.requireNonNull(
                formatVersion,
                "formatVersion");

        Objects.requireNonNull(
                batchId,
                "batchId");

        Objects.requireNonNull(
                entries,
                "entries");

        if (!CURRENT_FORMAT.equals(formatVersion)) {
            throw new IllegalArgumentException(
                    "Unsupported package format: "
                            + formatVersion);
        }

        if (batchId.isBlank()) {
            throw new IllegalArgumentException(
                    "batchId cannot be blank");
        }

        if (entries.isEmpty()) {
            throw new IllegalArgumentException(
                    "Package entries cannot be empty");
        }

        /*
         * 生成不可修改的列表副本。
         */
        entries = List.copyOf(entries);
    }

    /**
     * Pkg 中的单个：
     *
     *      (rep_i, R_i)
     *
     * 所有 byte[] 在构造和读取时均复制，
     * 防止外部代码修改 DTO 内部状态。
     */
    public record EntryDto(
            String deviceId,
            byte[] publicKeyCompressed,
            int beta,
            byte[] data,
            byte[] recoveryMaterial,
            String batchId,
            long timestamp,
            byte[] digestScalar,
            byte[] commitmentCompressed) {

        public EntryDto {

            Objects.requireNonNull(
                    deviceId,
                    "deviceId");

            Objects.requireNonNull(
                    publicKeyCompressed,
                    "publicKeyCompressed");

            Objects.requireNonNull(
                    data,
                    "data");

            Objects.requireNonNull(
                    batchId,
                    "batchId");

            Objects.requireNonNull(
                    digestScalar,
                    "digestScalar");

            Objects.requireNonNull(
                    commitmentCompressed,
                    "commitmentCompressed");

            if (deviceId.isBlank()) {
                throw new IllegalArgumentException(
                        "deviceId cannot be blank");
            }

            if (batchId.isBlank()) {
                throw new IllegalArgumentException(
                        "batchId cannot be blank");
            }

            if (beta != 0 && beta != 1) {
                throw new IllegalArgumentException(
                        "beta must be 0 or 1");
            }

            if (beta == 0
                    && recoveryMaterial != null) {

                throw new IllegalArgumentException(
                        "Non-sensitive entry must not "
                                + "contain recovery material");
            }

            if (beta == 1
                    && recoveryMaterial == null) {

                throw new IllegalArgumentException(
                        "Sensitive entry requires "
                                + "recovery material");
            }

            publicKeyCompressed =
                    publicKeyCompressed.clone();

            data = data.clone();

            recoveryMaterial =
                    recoveryMaterial == null
                            ? null
                            : recoveryMaterial.clone();

            digestScalar =
                    digestScalar.clone();

            commitmentCompressed =
                    commitmentCompressed.clone();
        }

        @Override
        public byte[] publicKeyCompressed() {
            return publicKeyCompressed.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }

        @Override
        public byte[] recoveryMaterial() {
            return recoveryMaterial == null
                    ? null
                    : recoveryMaterial.clone();
        }

        @Override
        public byte[] digestScalar() {
            return digestScalar.clone();
        }

        @Override
        public byte[] commitmentCompressed() {
            return commitmentCompressed.clone();
        }
    }
}