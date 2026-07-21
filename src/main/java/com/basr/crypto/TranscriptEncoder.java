package com.basr.crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * BASR 协议字段的规范编码工具。
 *
 * 算法描述使用：
 *
 *      x || y || z
 *
 * 但 Java 实现不能直接使用字符串拼接，因为：
 *
 *      "ab" || "c"
 *
 * 和：
 *
 *      "a" || "bc"
 *
 * 会得到相同字节串，从而产生编码歧义。
 *
 * 本实现对每个字段采用：
 *
 *      4字节长度 || 字段内容
 *
 * 形成无歧义的协议 transcript。
 */
public final class TranscriptEncoder {

    private TranscriptEncoder() {
    }

    /**
     * 对多个协议字段进行长度前缀编码。
     */
    public static byte[] encode(
            byte[]... fields) {

        Objects.requireNonNull(fields, "fields");

        try {
            ByteArrayOutputStream byteStream =
                    new ByteArrayOutputStream();

            DataOutputStream output =
                    new DataOutputStream(byteStream);

            for (byte[] field : fields) {
                Objects.requireNonNull(
                        field,
                        "transcript field");

                /*
                 * 字段格式：
                 *
                 *      length(field) || field
                 */
                output.writeInt(field.length);
                output.write(field);
            }

            output.flush();
            return byteStream.toByteArray();

        } catch (IOException exception) {
            /*
             * ByteArrayOutputStream 正常情况下不会发生 I/O 错误。
             */
            throw new IllegalStateException(
                    "Unable to encode protocol transcript",
                    exception);
        }
    }

    /**
     * 将字符串按 UTF-8 编码。
     */
    public static byte[] utf8(
            String value) {

        Objects.requireNonNull(value, "value");
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 将 long 编码为固定 8 字节大端格式。
     *
     * 后续编码时间戳 t 时使用。
     */
    public static byte[] longValue(
            long value) {

        return new byte[] {
                (byte) (value >>> 56),
                (byte) (value >>> 48),
                (byte) (value >>> 40),
                (byte) (value >>> 32),
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }

    /**
     * 将 int 编码为固定 4 字节大端格式。
     *
     * 后续编码 beta 等整数时使用。
     */
    public static byte[] intValue(
            int value) {

        return new byte[] {
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }

    /**
     * 将非负 BigInteger 编码为无符号大端字节串。
     */
    public static byte[] unsignedInteger(
            BigInteger value) {

        Objects.requireNonNull(value, "value");

        if (value.signum() < 0) {
            throw new IllegalArgumentException(
                    "value must be non-negative");
        }

        byte[] encoded = value.toByteArray();

        /*
         * BigInteger.toByteArray() 使用有符号补码。
         * 当最高位为1时，可能额外添加一个 0x00。
         */
        if (encoded.length > 1 && encoded[0] == 0) {
            byte[] unsigned =
                    new byte[encoded.length - 1];

            System.arraycopy(
                    encoded,
                    1,
                    unsigned,
                    0,
                    unsigned.length);

            return unsigned;
        }

        return encoded;
    }

    /**
     * 将多个字节数组直接连接。
     *
     * 注意：
     * 该方法只用于密码标准明确要求的固定格式连接，
     * 例如 RFC 9180 的 kem_context = enc || pkRm。
     *
     * 普通 BASR 协议字段仍应使用 encode() 的长度前缀编码。
     */
    public static byte[] concat(byte[]... arrays) {

        Objects.requireNonNull(arrays, "arrays");

        int totalLength = 0;

        for (byte[] array : arrays) {
            Objects.requireNonNull(array, "array");
            totalLength = Math.addExact(totalLength, array.length);
        }

        byte[] result = new byte[totalLength];
        int offset = 0;

        for (byte[] array : arrays) {
            System.arraycopy(
                    array,
                    0,
                    result,
                    offset,
                    array.length);

            offset += array.length;
        }

        return result;
    }

    /**
     * 将 Z_p 中的标量编码为固定长度无符号大端字节串。
     *
     * 固定长度为：
     *
     *      ceil(bitLength(p) / 8)
     *
     * 后续编码 d_i、h_i、s_i 等标量时使用。
     */
    public static byte[] scalar(
            BigInteger value,
            BigInteger p) {

        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(p, "p");

        if (value.signum() < 0 || value.compareTo(p) >= 0) {
            throw new IllegalArgumentException(
                    "value must belong to Z_p");
        }

        int length = (p.bitLength() + 7) / 8;

        byte[] raw = unsignedInteger(value);

        if (raw.length > length) {
            throw new IllegalArgumentException(
                    "value does not fit the scalar encoding length");
        }

        byte[] encoded = new byte[length];

        System.arraycopy(
                raw,
                0,
                encoded,
                length - raw.length,
                raw.length);

        return encoded;
    }
}