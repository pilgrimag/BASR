package com.basr.crypto;

import org.bouncycastle.math.ec.ECPoint;

import java.util.Arrays;
import java.util.Objects;

/**
 * 椭圆曲线群元素的编码和验证工具。
 *
 * BASR 中：
 *
 *      g, pk_i, A_i, R_i ∈ G
 *
 * 均为真实椭圆曲线点。
 *
 * 哈希、注册表索引和后续链上传输统一使用压缩点编码。
 */
public final class PointCodec {

    private PointCodec() {
    }

    /**
     * 将曲线点编码为 SEC1 压缩格式。
     *
     * secp256k1 压缩点通常为 33 字节：
     *
     *      02/03 || x-coordinate
     */
    public static byte[] encodeCompressed(
            ECPoint point) {

        Objects.requireNonNull(point, "point");

        if (point.isInfinity()) {
            throw new IllegalArgumentException(
                    "Point at infinity cannot be encoded as a public element");
        }

        return point
                .normalize()
                .getEncoded(true);
    }

    /**
     * 判断给定点是否是公共参数指定群 G 中的有效非单位元。
     */
    public static boolean isValidGroupElement(
            PublicParams pp,
            ECPoint point) {

        Objects.requireNonNull(pp, "pp");

        if (point == null || point.isInfinity()) {
            return false;
        }

        /*
         * 防止传入属于其他椭圆曲线的点。
         */
        if (point.getCurve() == null
                || !point.getCurve().equals(
                        pp.getGroup().getCurve())) {

            return false;
        }

        ECPoint normalized = point.normalize();

        /*
         * 检查点满足当前椭圆曲线方程。
         */
        if (!normalized.isValid()) {
            return false;
        }

        /*
         * 检查点位于阶为 p 的子群中：
         *
         *      [p]P = O
         */
        return normalized
                .multiply(pp.getP())
                .isInfinity();
    }

    /**
     * 从压缩编码恢复曲线点，并验证其属于群 G。
     *
     * 后续从文件、网络、Fabric 或 IPFS 读取点时使用。
     */
    public static ECPoint decodeCompressed(
            PublicParams pp,
            byte[] encoded) {

        Objects.requireNonNull(pp, "pp");
        Objects.requireNonNull(encoded, "encoded");

        ECPoint point;

        try {
            point = pp.getGroup()
                    .getCurve()
                    .decodePoint(encoded)
                    .normalize();

        } catch (RuntimeException exception) {
            throw new IllegalArgumentException(
                    "Invalid elliptic-curve point encoding",
                    exception);
        }

        if (!isValidGroupElement(pp, point)) {
            throw new IllegalArgumentException(
                    "Decoded point is not a valid element of G");
        }

        /*
         * 要求输入本身就是规范压缩编码。
         */
        if (!Arrays.equals(
                encoded,
                point.getEncoded(true))) {

            throw new IllegalArgumentException(
                    "Point encoding is not canonical compressed encoding");
        }

        return point;
    }
}