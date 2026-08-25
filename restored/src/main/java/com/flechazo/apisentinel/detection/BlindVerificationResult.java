package com.flechazo.apisentinel.detection;

/**
 * Result of a programmatic blind-injection verification (boolean or timing).
 * Carries the decisive request/response so callers can record it as a
 * PayloadResult for the verdict cross-validation chain.
 */
public record BlindVerificationResult(
        boolean confirmed,      // programmatic verdict
        String method,          // "boolean_blind" | "timing_blind"
        String detail,          // human-readable one-liner for LLM/report
        boolean wafBlocked,     // a probe response was a WAF block page
        String dbType,          // confirmed/attempted DB type (may be "auto")
        String sentRequest,     // decisive raw request ("" when nothing sent)
        String receivedResponse,// decisive raw response
        int statusCode,
        long elapsedMs
) {
    public static BlindVerificationResult notConfirmed(String method, String detail) {
        return new BlindVerificationResult(false, method, detail, false, "auto", "", "", 0, 0);
    }

    public static BlindVerificationResult blocked(String method) {
        return new BlindVerificationResult(false, method,
                "探针响应被 WAF 拦截，无法判定（可先尝试绕过）", true, "auto", "", "", 0, 0);
    }
}
