package com.flechazo.apisentinel.auth;

import java.util.List;

/**
 * Final result of the authorization bypass detection (Stage 6).
 */
public record AuthTestResult(
    AuthVerdict verdict,             // VULNERABLE / SUSPICIOUS / SAFE / SKIPPED
    String vulnType,                 // HORIZONTAL_IDOR / VERTICAL_PRIV_ESC / UNAUTH_ACCESS / NONE
    List<String> identifiedAuthParams, // auth cookie keys / headers identified
    String sessionALabel,
    String sessionBLabel,
    double maxSimilarity,            // highest similarity across all rounds
    String evidence,                 // human-readable evidence summary
    List<AuthTestRound> rounds       // detailed per-round records
) {
    public enum AuthVerdict { VULNERABLE, SUSPICIOUS, SAFE, SKIPPED }

    public static AuthTestResult skipped(String reason) {
        return new AuthTestResult(AuthVerdict.SKIPPED, "NONE", List.of(),
                "", "", 0, reason, List.of());
    }

    /** Build a text summary suitable for inclusion in Stage 5 prompt. */
    public String toPromptText() {
        if (verdict == AuthVerdict.SKIPPED) return "越权检测: 已跳过 (" + evidence + ")";
        StringBuilder sb = new StringBuilder();
        sb.append("越权检测结果:\n");
        sb.append("  判定: ").append(verdict).append("\n");
        sb.append("  类型: ").append(vulnType).append("\n");
        sb.append("  鉴权参数: ").append(identifiedAuthParams).append("\n");
        sb.append("  最大响应相似度: ").append(String.format("%.1f%%", maxSimilarity * 100)).append("\n");
        sb.append("  会话A: ").append(sessionALabel).append("\n");
        sb.append("  会话B: ").append(sessionBLabel).append("\n");
        for (AuthTestRound r : rounds) {
            sb.append("  - ").append(r.description()).append(": ")
              .append(r.statusCode()).append(" (相似度 ")
              .append(String.format("%.0f%%", r.similarity() * 100)).append(")\n");
        }
        sb.append("  证据: ").append(evidence).append("\n");
        return sb.toString();
    }
}
