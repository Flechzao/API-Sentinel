package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.auth.AuthTestResult;
import com.flechazo.apisentinel.testgen.model.TestCase;

import java.util.List;
import java.util.Map;

/**
 * Full result of a 6-stage analysis pipeline execution.
 *
 * @param stageDescriptions the exact detailed text shown for each stage (1-6) during
 *                           live execution -- persisted so replaying history later shows
 *                           the SAME information instead of a recomputed, lossy summary.
 * @param trafficStats      aggregated traffic statistics from Burp Proxy History (may be empty).
 * @param authTestResult    result of Stage 6 authorization bypass testing (may be null).
 */
public record PipelineResult(
    AnalysisResult trafficAnalysis,
    String sourceCode,
    List<TestCase> testCases,
    List<PayloadResult> payloadResults,
    FinalVerdict verdict,
    Map<Integer, String> stageDescriptions,
    TrafficStats trafficStats,
    AuthTestResult authTestResult
) {
    /** Backward-compatible constructor (no trafficStats, no authTestResult). */
    public PipelineResult(AnalysisResult trafficAnalysis, String sourceCode,
                          List<TestCase> testCases, List<PayloadResult> payloadResults,
                          FinalVerdict verdict, Map<Integer, String> stageDescriptions) {
        this(trafficAnalysis, sourceCode, testCases, payloadResults, verdict,
             stageDescriptions, TrafficStats.empty(), null);
    }

    /** Backward-compatible constructor (no authTestResult). */
    public PipelineResult(AnalysisResult trafficAnalysis, String sourceCode,
                          List<TestCase> testCases, List<PayloadResult> payloadResults,
                          FinalVerdict verdict, Map<Integer, String> stageDescriptions,
                          TrafficStats trafficStats) {
        this(trafficAnalysis, sourceCode, testCases, payloadResults, verdict,
             stageDescriptions, trafficStats, null);
    }
}
