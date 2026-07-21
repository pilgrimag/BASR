package com.basr.entity;

import java.util.Objects;

/**
 * 注册结果。
 *
 * 算法中的正式输出是：
 *
 *      b_i ∈ {0,1}
 *
 * 本地原型额外保存 message，仅用于测试和调试。
 */
public final class RegistrationResult {

    /**
     * true 对应 b_i = 1；
     * false 对应 b_i = 0。
     */
    private final boolean accepted;

    private final String message;

    private RegistrationResult(
            boolean accepted,
            String message) {

        this.accepted = accepted;
        this.message =
                Objects.requireNonNull(
                        message,
                        "message");
    }

    public static RegistrationResult accepted() {
        return new RegistrationResult(
                true,
                "Registration accepted");
    }

    public static RegistrationResult rejected(
            String message) {

        return new RegistrationResult(
                false,
                message);
    }

    public boolean isAccepted() {
        return accepted;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "RegistrationResult{"
                + "accepted=" + accepted
                + ", message='" + message + '\''
                + '}';
    }
}