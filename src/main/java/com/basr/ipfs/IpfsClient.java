package com.basr.ipfs;

/**
 * BASR 使用的最小 IPFS 接口。
 *
 * IPFS 层只处理字节和 CID：
 *
 *      byte[] -> CID
 *      CID    -> byte[]
 *
 * 它不理解 Report、Pkg、ECPoint 或密码算法。
 */
public interface IpfsClient {

    /**
     * 将内容添加到 IPFS，并返回真实 CID。
     */
    String put(byte[] content);

    /**
     * 根据 CID 读取原始内容。
     */
    byte[] get(String cid);

    /**
     * 检查 Kubo RPC API 是否可访问。
     */
    boolean isAvailable();

    /**
     * IPFS 调用异常。
     */
    final class IpfsException
            extends RuntimeException {

        public IpfsException(String message) {
            super(message);
        }

        public IpfsException(
                String message,
                Throwable cause) {

            super(message, cause);
        }
    }
}