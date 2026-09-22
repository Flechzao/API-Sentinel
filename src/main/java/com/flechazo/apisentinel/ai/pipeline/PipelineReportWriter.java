package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.Comparator;

/**
 * Writes a self-contained JSON report for each pipeline analysis run.
 * Reports are saved to ~/.api-sentinel/reports/ with timestamped filenames.
 *
 * Each report contains the complete 5-stage analysis data including:
 * - Entry metadata, traffic data, traffic stats
 * - Stage 1: findings, summary, risk
 * - Stage 2: code correlation details
 * - Stage 3: generated test cases
 * - Stage 4: payload execution results (full req/resp)
 * - Stage 5: final verdict with confirmed/suspected vulns
 */
public class PipelineReportWriter {

    private static final DateTimeFormatter FILE_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final Path reportsDir;
    private final LeveledLogger logger;

    public PipelineReportWriter(LeveledLogger logger) {
        this.reportsDir = com.flechazo.apisentinel.config.AppPaths.reportsDir();
        this.logger = logger;
    }

    /**
     * Save a complete pipeline report to disk.
     * @return the path to the saved report, or null if saving failed.
     */
    public Path saveReport(ApiEntry entry, PipelineResult result, TrafficStats trafficStats) {
        return saveReportWithChat(entry, result, trafficStats, List.of());
    }

    /**
     * Save a complete pipeline report to disk, including chat history.
     * @param chatHistory optional conversation history as List of {role, content} Maps
     * @return the path to the saved report, or null if saving failed.
     */
    public Path saveReportWithChat(ApiEntry entry, PipelineResult result, TrafficStats trafficStats,
                           List<Object> chatHistory) {
        try {
            Files.createDirectories(reportsDir);

            String timestamp = FILE_FMT.format(LocalDateTime.now());
            String method = entry.getHttpMethod().replace("/", "-");
            String pathSlug = sanitizeForFilename(entry.getApiPath());
            String filename = String.format("%s_%s_%s.json", timestamp, method, pathSlug);
            Path reportFile = reportsDir.resolve(filename);

            Map<String, Object> report = buildReport(entry, result, trafficStats);

            // Append chat history if available
            if (chatHistory != null && !chatHistory.isEmpty()) {
                report.put("stage6_chatHistory", chatHistory);
            }

            String json = GSON.toJson(report);
            Files.writeString(reportFile, json);

            logger.info("[Report] 已保存分析报告: %s (%d bytes)", reportFile.getFileName(), json.length());

            // Auto-cleanup: keep only the latest MAX_REPORTS files
            cleanupOldReports();

            return reportFile;
        } catch (IOException e) {
            logger.error("[Report] 保存分析报告失败: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Get the reports directory path.
     */
    public Path getReportsDir() {
        return reportsDir;
    }

    private static final int MAX_REPORTS = 200;

    /**
     * Remove oldest reports if the directory exceeds MAX_REPORTS files.
     */
    private void cleanupOldReports() {
        try (var stream = Files.list(reportsDir)) {
            List<Path> files = stream
                    .filter(p -> p.toString().endsWith(".json"))
                    .sorted(Comparator.comparingLong(p -> {
                        try { return Files.getLastModifiedTime(p).toMillis(); }
                        catch (IOException e) { return 0L; }
                    }))
                    .collect(java.util.stream.Collectors.toList());

            if (files.size() > MAX_REPORTS) {
                int toDelete = files.size() - MAX_REPORTS;
                for (int i = 0; i < toDelete; i++) {
                    try {
                        Files.delete(files.get(i));
                        logger.debug("[Report] 自动清理旧报告: %s", files.get(i).getFileName());
                    } catch (IOException ignored) {}
                }
                logger.info("[Report] 自动清理了 %d 个旧报告，保留最新 %d 个", toDelete, MAX_REPORTS);
            }
        } catch (IOException e) {
            logger.warn("[Report] 清理旧报告失败: %s", e.getMessage());
        }
    }

    private Map<String, Object> buildReport(ApiEntry entry, PipelineResult result, TrafficStats trafficStats) {
        Map<String, Object> report = new LinkedHashMap<>();

        // === Header ===
        report.put("reportVersion", "1.0.0");
        report.put("generatedAt", Instant.now().toString());
        report.put("generatedAtLocal", LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));

        // === Entry metadata ===
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("id", entry.getId());
        meta.put("httpMethod", entry.getHttpMethod());
        meta.put("apiPath", entry.getApiPath());
        meta.put("domain", entry.getDomain());
        meta.put("status", entry.getStatus().name());
        meta.put("lastStatusCode", entry.getLastStatusCode());
        meta.put("lastUrl", entry.getLastUrl());
        report.put("target", meta);

        // === Traffic data ===
        Map<String, Object> traffic = new LinkedHashMap<>();
        traffic.put("hasTrafficData", entry.hasTrafficData());
        traffic.put("lastRawRequest", entry.getLastRawRequest());
        traffic.put("lastRawResponse", entry.getLastRawResponse());
        if (trafficStats != null && !trafficStats.isEmpty()) {
            traffic.put("historyStats", trafficStats.toMap());
        }
        report.put("trafficData", traffic);

        // === Stage 1: Traffic Analysis ===
        Map<String, Object> stage1 = new LinkedHashMap<>();
        if (result.trafficAnalysis() != null) {
            var ta = result.trafficAnalysis();
            stage1.put("overallRisk", ta.overallRisk().name());
            stage1.put("summary", ta.summary());
            stage1.put("tokensUsed", ta.tokensUsed());
            stage1.put("analysisTimeMs", ta.analysisTimeMs());
            stage1.put("modelUsed", ta.modelUsed());

            List<Map<String, Object>> findings = new ArrayList<>();
            for (var f : ta.findings()) {
                Map<String, Object> fm = new LinkedHashMap<>();
                fm.put("type", f.type());
                fm.put("risk", f.risk());
                fm.put("confidence", f.confidence());
                fm.put("title", f.title());
                fm.put("description", f.description());
                fm.put("evidence", f.evidence());
                fm.put("location", f.location());
                fm.put("remediation", f.remediation());
                findings.add(fm);
            }
            stage1.put("findings", findings);
        }
        report.put("stage1_trafficAnalysis", stage1);

        // === Stage 2: Code Correlation ===
        Map<String, Object> stage2 = new LinkedHashMap<>();
        stage2.put("sourceCode", result.sourceCode());
        if (result.stageDescriptions().containsKey(2)) {
            stage2.put("description", result.stageDescriptions().get(2));
        }
        report.put("stage2_codeCorrelation", stage2);

        // === Stage 3: Test Cases ===
        Map<String, Object> stage3 = new LinkedHashMap<>();
        List<Map<String, Object>> testCases = new ArrayList<>();
        for (TestCase tc : result.testCases()) {
            Map<String, Object> tcm = new LinkedHashMap<>();
            tcm.put("name", tc.name());
            tcm.put("category", tc.category());
            tcm.put("targetParam", tc.targetParam());
            tcm.put("payload", tc.payload());
            tcm.put("method", tc.method());
            tcm.put("path", tc.path());
            tcm.put("headers", tc.headers());
            tcm.put("body", tc.body());
            tcm.put("description", tc.description());
            tcm.put("expectedIfVulnerable", tc.expectedIfVulnerable());
            tcm.put("riskIfConfirmed", tc.riskIfConfirmed());
            testCases.add(tcm);
        }
        stage3.put("testCaseCount", testCases.size());
        stage3.put("testCases", testCases);
        if (result.stageDescriptions().containsKey(3)) {
            stage3.put("description", result.stageDescriptions().get(3));
        }
        report.put("stage3_payloadGeneration", stage3);

        // === Stage 4: Payload Execution ===
        Map<String, Object> stage4 = new LinkedHashMap<>();
        List<Map<String, Object>> payloadResults = new ArrayList<>();
        for (PayloadResult pr : result.payloadResults()) {
            Map<String, Object> prm = new LinkedHashMap<>();
            prm.put("testCaseName", pr.testCase() != null ? pr.testCase().name() : "(ad-hoc request)");
            prm.put("category", pr.testCase() != null ? pr.testCase().category() : "manual");
            prm.put("sentRequest", pr.sentRequest());
            prm.put("receivedResponse", pr.receivedResponse());
            prm.put("statusCode", pr.statusCode());
            prm.put("responseTimeMs", pr.responseTimeMs());
            prm.put("anomalyDetected", pr.anomalyDetected());
            prm.put("executionIndex", pr.executionIndex());
            prm.put("authSession", pr.authSession());
            prm.put("wafVendor", pr.wafVendor());
            prm.put("wafScore", pr.wafScore());
            prm.put("claimedByVerdict", pr.claimedByVerdict());
            payloadResults.add(prm);
        }
        long anomalyCount = result.payloadResults().stream().filter(PayloadResult::anomalyDetected).count();
        stage4.put("totalExecuted", payloadResults.size());
        stage4.put("anomalyCount", anomalyCount);
        stage4.put("payloadResults", payloadResults);
        if (result.stageDescriptions().containsKey(4)) {
            stage4.put("description", result.stageDescriptions().get(4));
        }
        report.put("stage4_payloadExecution", stage4);

        // === Stage 5: Final Verdict ===
        Map<String, Object> stage5 = new LinkedHashMap<>();
        var verdict = result.verdict();
        stage5.put("overallRisk", verdict.overallRisk());
        stage5.put("summary", verdict.summary());
        stage5.put("recommendations", verdict.recommendations());
        stage5.put("totalTokensUsed", verdict.totalTokensUsed());

        List<Map<String, Object>> confirmed = new ArrayList<>();
        for (ConfirmedVuln cv : verdict.confirmedVulns()) {
            Map<String, Object> cvm = new LinkedHashMap<>();
            cvm.put("type", cv.type());
            cvm.put("title", cv.title());
            cvm.put("evidence", cv.evidence());
            cvm.put("payloadUsed", cv.payloadUsed());
            cvm.put("response", cv.response());
            cvm.put("verifyCommand", cv.verifyCommand());
            if (cv.identityProof() != null && !cv.identityProof().isEmpty()) {
                cvm.put("identityProof", cv.identityProof());
            }
            if (cv.cvss() != null && !cv.cvss().isEmpty()) {
                cvm.put("cvss", cv.cvss());
            }
            confirmed.add(cvm);
        }
        stage5.put("confirmedVulns", confirmed);

        List<Map<String, Object>> suspected = new ArrayList<>();
        for (SuspectedVuln sv : verdict.suspectedVulns()) {
            Map<String, Object> svm = new LinkedHashMap<>();
            svm.put("type", sv.type());
            svm.put("title", sv.title());
            svm.put("reason", sv.reason());
            svm.put("verifyCommand", sv.verifyCommand());
            if (sv.confidence() != null && !sv.confidence().isEmpty()) {
                svm.put("confidence", sv.confidence());
            }
            if (sv.escalationPath() != null && !sv.escalationPath().isEmpty()) {
                svm.put("escalationPath", sv.escalationPath());
            }
            if (sv.payloadUsed() != null && !sv.payloadUsed().isEmpty()) {
                svm.put("payloadUsed", sv.payloadUsed());
            }
            suspected.add(svm);
        }
        stage5.put("suspectedVulns", suspected);

        // P0-2 fix: Write rejection reasons (anti-hallucination audit trail)
        if (verdict.rejectionReasons() != null && !verdict.rejectionReasons().isEmpty()) {
            stage5.put("rejectionReasons", verdict.rejectionReasons());
            stage5.put("rejectionCount", verdict.rejectionReasons().size());
        }

        report.put("stage5_finalVerdict", stage5);

        // === Stage 5 (Auth Test): Authorization bypass test results ===
        if (result.authTestResult() != null) {
            Map<String, Object> authTest = new LinkedHashMap<>();
            var authResult = result.authTestResult();
            authTest.put("verdict", authResult.verdict().name());
            authTest.put("vulnType", authResult.vulnType());
            authTest.put("maxSimilarity", authResult.maxSimilarity());
            authTest.put("sessionA", authResult.sessionALabel());
            authTest.put("sessionB", authResult.sessionBLabel());
            authTest.put("identifiedAuthParams", authResult.identifiedAuthParams());
            authTest.put("evidence", authResult.evidence());
            if (authResult.rounds() != null) {
                List<Map<String, Object>> roundsList = new ArrayList<>();
                for (var round : authResult.rounds()) {
                    Map<String, Object> rm = new LinkedHashMap<>();
                    rm.put("description", round.description());
                    rm.put("statusCode", round.statusCode());
                    rm.put("similarity", round.similarity());
                    roundsList.add(rm);
                }
                authTest.put("rounds", roundsList);
            }
            report.put("stage5_authTest", authTest);
        }

        // === Stage descriptions (raw text) ===
        report.put("stageDescriptions", result.stageDescriptions());

        return report;
    }

    /**
     * Sanitize an API path for use as a filename component.
     * /api/v2/profiles/me → api-v2-profiles-me
     */
    private static String sanitizeForFilename(String path) {
        if (path == null || path.isEmpty()) return "unknown";
        String sanitized = path.replaceAll("[^a-zA-Z0-9._-]", "-")
                               .replaceAll("-+", "-")
                               .replaceAll("^-|-$", "");
        if (sanitized.length() > 80) {
            sanitized = sanitized.substring(0, 80);
        }
        return sanitized.isEmpty() ? "unknown" : sanitized;
    }

    /**
     * Update the chat history section of an existing report file in place.
     *
     * <p>Used by follow-up conversations in the chat panel: when the user
     * asks a follow-up question after an analysis completes, the new Q/A
     * exchanges should be appended to the original report so it reflects the
     * full conversation. The original analysis data (stages 1-5) is preserved.
     *
     * @param reportFile  path to an existing report JSON file
     * @param chatHistory the updated conversation history (full, not incremental)
     * @return true if the file was updated successfully
     */
    public boolean updateChatHistory(Path reportFile, List<Object> chatHistory) {
        if (reportFile == null || !Files.exists(reportFile)) {
            logger.debug("[Report] updateChatHistory: file does not exist: %s", reportFile);
            return false;
        }
        if (chatHistory == null || chatHistory.isEmpty()) {
            return true; // Nothing to write, treat as success.
        }
        try {
            String existing = Files.readString(reportFile);
            com.google.gson.JsonObject root = com.google.gson.JsonParser
                    .parseString(existing).getAsJsonObject();

            // Build the same shape as saveReportWithChat (role/content maps)
            com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
            for (Object item : chatHistory) {
                arr.add(GSON.toJsonTree(item));
            }
            root.add("stage6_chatHistory", arr);

            Files.writeString(reportFile, GSON.toJson(root));
            logger.info("[Report] 追问对话已追加到报告: %s (%d 条消息)",
                    reportFile.getFileName(), chatHistory.size());
            return true;
        } catch (Exception e) {
            logger.error("[Report] 更新追问对话失败: %s — %s", reportFile, e.getMessage());
            return false;
        }
    }
}
