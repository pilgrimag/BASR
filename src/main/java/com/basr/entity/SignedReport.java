package com.basr.entity;

import java.util.Objects;

/**
 * Algorithm 3 Sign 的联合输出：
 *
 *      (rep_i, sigma_i)
 */
public final class SignedReport {

    private final Report report;

    private final Signature signature;

    public SignedReport(
            Report report,
            Signature signature) {

        this.report =
                Objects.requireNonNull(
                        report,
                        "report");

        this.signature =
                Objects.requireNonNull(
                        signature,
                        "signature");
    }

    public Report getReport() {
        return report;
    }

    public Signature getSignature() {
        return signature;
    }
}