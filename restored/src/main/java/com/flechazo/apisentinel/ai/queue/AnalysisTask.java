package com.flechazo.apisentinel.ai.queue;

import com.flechazo.apisentinel.model.ApiEntry;

public record AnalysisTask(
    ApiEntry entry,
    String method,
    String url,
    String host,
    String requestBody,
    int statusCode,
    String responseBody,
    String sourceCode,
    AnalysisScope scope,
    AnalysisMode analysisMode
) {
    public enum AnalysisScope { QUICK, STANDARD, DEEP }

    public enum AnalysisMode {
        TRAFFIC_ONLY("纯流量分析"),
        WITH_CODE("关联代码分析"),
        WITH_HISTORY("关联历史数据分析"),
        COMPREHENSIVE("综合分析");

        private final String displayName;
        AnalysisMode(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }
    }

    /** Backward-compatible constructor without analysisMode (defaults to TRAFFIC_ONLY). */
    public AnalysisTask(ApiEntry entry, String method, String url, String host,
                        String requestBody, int statusCode, String responseBody,
                        String sourceCode, AnalysisScope scope) {
        this(entry, method, url, host, requestBody, statusCode, responseBody,
             sourceCode, scope, AnalysisMode.TRAFFIC_ONLY);
    }
}
