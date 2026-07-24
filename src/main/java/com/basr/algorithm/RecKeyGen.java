package com.basr.algorithm;

import com.basr.crypto.Kem;
import com.basr.crypto.PublicParams;
import com.basr.entity.RecoveryKey;

import java.util.Objects;

/**
 * BASR 恢复密钥生成算法 RecKeyGen。
 *
 * 算法输入：
 *
 *      pp
 *
 * 其中使用：
 *
 *      pp_KEM
 *
 * 算法输出：
 *
 *      (sk_R, pk_R)
 *
 * 具体执行：
 *
 *      (sk_R, pk_R)
 *          <- KEM.KeyGen(pp_KEM)
 *
 * 当前 KEM 具体实例化为：
 *
 *      DHKEM-X25519-HKDF-SHA256
 *
 * 本算法只生成 DR 的长期恢复密钥对。
 *
 * 它不执行：
 *
 *      - KEM 封装；
 *      - KEM 解封装；
 *      - 数据加密；
 *      - 数据恢复。
 */
public final class RecKeyGen {

    private RecKeyGen() {
    }

    /**
     * 生成 DR 恢复密钥对。
     *
     * @param pp BASR 公共参数
     * @return RecoveryKey，其中包含 sk_R 和 pk_R
     */
    public static RecoveryKey generate(
            PublicParams pp) {

        Objects.requireNonNull(pp, "pp");

        /*
         * 调用真实 KEM.KeyGen。
         *
         * RecKeyGen 只负责算法编排；
         * 具体 X25519 密码操作由 crypto.Kem 实现。
         */
        return Kem.keyGen(pp);
    }
}