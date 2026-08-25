package com.flechazo.apisentinel.ai.analysis;

import java.util.List;

public record AnalysisResult(
    List<VulnFinding> findings,
    String summary,
    RiskLevel overallRisk,
    int tokensUsed,
    long analysisTimeMs,
    String modelUsed,
    String error
) {
    public enum RiskLevel { HIGH, MEDIUM, LOW, INFO, NONE }

    public boolean isSuccess() {
        return error == null || error.isEmpty();
    }

    public static AnalysisResult failed(String error) {
        return new AnalysisResult(List.of(), "", RiskLevel.NONE, 0, 0, "", error);
    }
}
