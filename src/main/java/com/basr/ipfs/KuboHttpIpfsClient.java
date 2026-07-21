package com.basr.ipfs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * 基于 Java 21 HttpClient 的 Kubo RPC 客户端。
 *
 * 默认 RPC：
 *
 *      http://127.0.0.1:5001
 *
 * 使用：
 *
 *      POST /api/v0/add
 *      POST /api/v0/cat
 *
 * 安全要求：
 *
 * Kubo RPC 具有节点管理权限，只应绑定本机或受保护网络，
 * 不应直接暴露在公网。
 */
public final class KuboHttpIpfsClient
        implements IpfsClient {

    public static final URI DEFAULT_RPC_URI =
            URI.create("http://127.0.0.1:5001");

    private static final int DEFAULT_MAX_OBJECT_BYTES =
            64 * 1024 * 1024;

    private static final Duration CONNECT_TIMEOUT =
            Duration.ofSeconds(5);

    private static final Duration REQUEST_TIMEOUT =
            Duration.ofSeconds(30);

    private final URI rpcBaseUri;

    private final HttpClient httpClient;

    private final ObjectMapper objectMapper;

    private final int maxObjectBytes;

    public KuboHttpIpfsClient() {
        this(
                DEFAULT_RPC_URI,
                DEFAULT_MAX_OBJECT_BYTES);
    }

    public KuboHttpIpfsClient(
            URI rpcBaseUri) {

        this(
                rpcBaseUri,
                DEFAULT_MAX_OBJECT_BYTES);
    }

    public KuboHttpIpfsClient(
            URI rpcBaseUri,
            int maxObjectBytes) {

        this.rpcBaseUri =
                normalizeBaseUri(
                        Objects.requireNonNull(
                                rpcBaseUri,
                                "rpcBaseUri"));

        if (maxObjectBytes <= 0) {
            throw new IllegalArgumentException(
                    "maxObjectBytes must be positive");
        }

        this.maxObjectBytes = maxObjectBytes;

        this.httpClient =
                HttpClient.newBuilder()
                        .connectTimeout(
                                CONNECT_TIMEOUT)
                        .build();

        this.objectMapper =
                new ObjectMapper();
    }

    /**
     * 调用：
     *
     *      POST /api/v0/add
     *
     * 固定指定：
     *
     * - CIDv1；
     * - SHA-256；
     * - raw leaves；
     * - 本地 pin；
     * - 关闭 progress 输出。
     */
    @Override
    public String put(
            byte[] content) {

        Objects.requireNonNull(content, "content");

        if (content.length == 0) {
            throw new IllegalArgumentException(
                    "IPFS content cannot be empty");
        }

        if (content.length > maxObjectBytes) {
            throw new IllegalArgumentException(
                    "IPFS content exceeds configured maximum");
        }

        String boundary =
                "----BASR-"
                        + UUID.randomUUID();

        byte[] prefix =
                (
                        "--" + boundary + "\r\n"
                        + "Content-Disposition: form-data; "
                        + "name=\"file\"; "
                        + "filename=\"basr-package.bin\"\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "\r\n"
                ).getBytes(StandardCharsets.US_ASCII);

        byte[] suffix =
                (
                        "\r\n--"
                        + boundary
                        + "--\r\n"
                ).getBytes(StandardCharsets.US_ASCII);

        HttpRequest.BodyPublisher body =
                HttpRequest.BodyPublishers.concat(
                        HttpRequest.BodyPublishers
                                .ofByteArray(prefix),
                        HttpRequest.BodyPublishers
                                .ofByteArray(content),
                        HttpRequest.BodyPublishers
                                .ofByteArray(suffix));

        URI uri =
                endpoint(
                        "/api/v0/add"
                        + "?cid-version=1"
                        + "&raw-leaves=true"
                        + "&hash=sha2-256"
                        + "&pin=true"
                        + "&progress=false");

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .timeout(REQUEST_TIMEOUT)
                        .header(
                                "Content-Type",
                                "multipart/form-data; boundary="
                                        + boundary)
                        .header(
                                "Accept",
                                "application/json")
                        .POST(body)
                        .build();

        HttpResponse<String> response =
                send(
                        request,
                        HttpResponse.BodyHandlers
                                .ofString(
                                        StandardCharsets.UTF_8));

        requireSuccess(
                response.statusCode(),
                response.body());

        return parseCid(response.body());
    }

    /**
     * 调用：
     *
     *      POST /api/v0/cat?arg=<cid>
     */
    @Override
    public byte[] get(
            String cid) {

        validateCid(cid);

        String encodedCid =
                URLEncoder.encode(
                        cid,
                        StandardCharsets.UTF_8);

        URI uri =
                endpoint(
                        "/api/v0/cat?arg="
                                + encodedCid);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .timeout(REQUEST_TIMEOUT)
                        .POST(
                                HttpRequest.BodyPublishers
                                        .noBody())
                        .build();

        HttpResponse<InputStream> response =
                send(
                        request,
                        HttpResponse.BodyHandlers
                                .ofInputStream());

        if (response.statusCode() < 200
                || response.statusCode() >= 300) {

            try (InputStream body =
                         response.body()) {

                byte[] error =
                        readBounded(
                                body,
                                64 * 1024);

                throw new IpfsException(
                        "Kubo cat failed with HTTP "
                                + response.statusCode()
                                + ": "
                                + new String(
                                        error,
                                        StandardCharsets.UTF_8));

            } catch (IOException exception) {
                throw new IpfsException(
                        "Unable to read Kubo error response",
                        exception);
            }
        }

        try (InputStream body =
                     response.body()) {

            return readBounded(
                    body,
                    maxObjectBytes);

        } catch (IOException exception) {
            throw new IpfsException(
                    "Unable to read IPFS object",
                    exception);
        }
    }

    /**
     * 调用 version 接口检查节点状态。
     */
    @Override
    public boolean isAvailable() {

        try {
            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(
                                    endpoint(
                                            "/api/v0/version"))
                            .timeout(
                                    Duration.ofSeconds(3))
                            .POST(
                                    HttpRequest.BodyPublishers
                                            .noBody())
                            .build();

            HttpResponse<String> response =
                    send(
                            request,
                            HttpResponse.BodyHandlers
                                    .ofString(
                                            StandardCharsets.UTF_8));

            return response.statusCode() >= 200
                    && response.statusCode() < 300;

        } catch (RuntimeException exception) {
            return false;
        }
    }

    private String parseCid(
            String responseBody) {

        if (responseBody == null
                || responseBody.isBlank()) {

            throw new IpfsException(
                    "Kubo add returned an empty response");
        }

        /*
         * add 端点可能返回逐行 JSON。
         * 单文件场景读取最后一个非空 JSON 对象。
         */
        String[] lines =
                responseBody.split("\\R");

        String cid = null;

        for (String line : lines) {

            if (line.isBlank()) {
                continue;
            }

            try {
                JsonNode root =
                        objectMapper.readTree(line);

                JsonNode hash =
                        root.get("Hash");

                if (hash != null
                        && hash.isTextual()
                        && !hash.asText().isBlank()) {

                    cid = hash.asText();
                }

            } catch (IOException exception) {
                throw new IpfsException(
                        "Unable to parse Kubo add response",
                        exception);
            }
        }

        if (cid == null) {
            throw new IpfsException(
                    "Kubo add response does not contain Hash");
        }

        validateCid(cid);

        return cid;
    }

    private static void validateCid(
            String cid) {

        if (cid == null
                || cid.isBlank()) {

            throw new IllegalArgumentException(
                    "cid cannot be blank");
        }

        if (cid.length() > 512) {
            throw new IllegalArgumentException(
                    "cid is too long");
        }

        for (int index = 0;
             index < cid.length();
             index++) {

            char character =
                    cid.charAt(index);

            if (Character.isWhitespace(character)
                    || Character.isISOControl(character)) {

                throw new IllegalArgumentException(
                        "cid contains invalid characters");
            }
        }
    }

    private static void requireSuccess(
            int statusCode,
            String responseBody) {

        if (statusCode < 200
                || statusCode >= 300) {

            throw new IpfsException(
                    "Kubo RPC failed with HTTP "
                            + statusCode
                            + ": "
                            + responseBody);
        }
    }

    private <T> HttpResponse<T> send(
            HttpRequest request,
            HttpResponse.BodyHandler<T> handler) {

        try {
            return httpClient.send(
                    request,
                    handler);

        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

            throw new IpfsException(
                    "Kubo request was interrupted",
                    exception);

        } catch (IOException exception) {
            throw new IpfsException(
                    "Unable to communicate with Kubo at "
                            + rpcBaseUri,
                    exception);
        }
    }

    private URI endpoint(
            String pathAndQuery) {

        return URI.create(
                rpcBaseUri.toString()
                        + pathAndQuery);
    }

    private static URI normalizeBaseUri(
            URI uri) {

        String scheme =
                uri.getScheme();

        if (!"http".equalsIgnoreCase(scheme)
                && !"https".equalsIgnoreCase(scheme)) {

            throw new IllegalArgumentException(
                    "Kubo RPC URI must use HTTP or HTTPS");
        }

        if (uri.getHost() == null) {
            throw new IllegalArgumentException(
                    "Kubo RPC URI must contain a host");
        }

        String normalized =
                uri.toString();

        while (normalized.endsWith("/")) {
            normalized =
                    normalized.substring(
                            0,
                            normalized.length() - 1);
        }

        return URI.create(normalized);
    }

    private static byte[] readBounded(
            InputStream input,
            int maximumBytes)
            throws IOException {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        byte[] buffer =
                new byte[8_192];

        int total = 0;

        while (true) {

            int count =
                    input.read(buffer);

            if (count < 0) {
                break;
            }

            total =
                    Math.addExact(
                            total,
                            count);

            if (total > maximumBytes) {
                Arrays.fill(buffer, (byte) 0);

                throw new IpfsException(
                        "IPFS object exceeds configured maximum");
            }

            output.write(
                    buffer,
                    0,
                    count);
        }

        Arrays.fill(buffer, (byte) 0);

        return output.toByteArray();
    }
}