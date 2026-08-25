package com.flechazo.apisentinel.ai.pipeline;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.execution.RequestEngineOptions;
import burp.api.montoya.http.execution.RequestExecution;
import burp.api.montoya.http.execution.RequestExecutionEngine;
import burp.api.montoya.http.execution.RequestExecutionResult;
import burp.api.montoya.http.execution.RequestResult;
import burp.api.montoya.http.execution.RequestStatus;
import burp.api.montoya.http.execution.ResourcePool;
import burp.api.montoya.http.execution.Retention;
import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnerabilityAnalyzer;
import com.flechazo.apisentinel.ai.prompt.FinalVerdictPrompt;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.codeindex.RepoGrepper;
import com.flechazo.apisentinel.codeindex.SinkAnnotator;
import com.flechazo.apisentinel.codeindex.SinkMap;
import com.flechazo.apisentinel.codeindex.parser.RouteEntry;
import com.flechazo.apisentinel.detection.ActiveProbeExecutor;
import com.flechazo.apisentinel.detection.WafDetector;
import com.flechazo.apisentinel.detection.WafEncoder;
import com.flechazo.apisentinel.auth.AuthParamIdentifier;
import com.flechazo.apisentinel.auth.AuthTestExecutor;
import com.flechazo.apisentinel.auth.AuthTestResult;
import com.flechazo.apisentinel.auth.SessionDiscovery;
import com.flechazo.apisentinel.auth.SessionInfo;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.testgen.TestCaseService;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.flechazo.apisentinel.util.JsonExtractor;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Orchestrates the 6-stage analysis pipeline:
 * 1. Traffic analysis (VulnerabilityAnalyzer) — pure HTTP traffic, no source code
 * 2. Code correlation (CodeIndexService) — report matching source files/routes
 * 3. Test payload generation (TestCaseService) — guided by Stage 1 findings + source code
 * 4. Auto-execute payloads (Montoya HTTP) — with original auth context
 * 5. Authorization bypass testing — auto-discover sessions, swap auth params, compare responses
 * 6. Final comprehensive AI verdict (FinalVerdictPrompt) — with baseline + source code + auth test
 */
/**
 * Pipeline 六阶段固定流水线分析引擎。Stage 1-6 按固定顺序执行，每阶段输出喂入下一阶段，
 * 最后经 VerdictValidator 交叉验证产出 FinalVerdict。适合批量系统化分析。
 *
 * @see com.flechazo.apisentinel.ai.pipeline.VerdictValidator
 * @see com.flechazo.apisentinel.ai.pipeline.PipelineResult
 */
public class AnalysisPipeline {

    // Per-stage LLM call timeouts (seconds). Stage 1 analyzes a single
    // request/response and should be quick; Stage 6 synthesizes many payload
    // results and legitimately takes longer. The blanket 200s meant short
    // stages waited too long on failure and long stages could still time out.
    private static final int STAGE1_TIMEOUT_SEC = 60;
    private static final int STAGE3_TIMEOUT_SEC = 90;
    private static final int STAGE6_TIMEOUT_SEC = 180;

    private final LlmProvider provider;
    /** Optional cheaper model for Stage-1 traffic triage (multi-model tiering).
     *  Null/blank = use the main provider model for everything. */
    private volatile String fastModel;
    public void setFastModel(String model) { this.fastModel = model; }

    /** Cross-run reuse window: if the same endpoint was analyzed within this many
     *  minutes, its previous verdict is injected as "known conclusions" context. */
    private volatile int reuseWindowMinutes = 30;
    public void setReuseWindowMinutes(int minutes) { this.reuseWindowMinutes = Math.max(0, minutes); }
    private final MontoyaApi montoyaApi;
    private final CodeIndexService codeIndexService;
    private final LeveledLogger logger;
    private final ExecutorService executor;
    private final PipelineConfig config;
    private final List<com.flechazo.apisentinel.config.CodeRepo> codeRepos;
    private final WafDetector wafDetector;

    /** Result used when WAF detection is switched off. */
    private static final WafDetector.WafDetectionResult WAF_DISABLED =
            new WafDetector.WafDetectionResult(null, 0, "waf detection disabled");

    /**
     * Authentication headers to carry forward from original requests.
     */
    private static final Set<String> AUTH_HEADER_NAMES = Set.of(
            "cookie", "authorization", "x-token", "x-access-token",
            "x-csrf-token", "x-xsrf-token", "x-api-key", "x-auth-token",
            "x-session-id", "x-request-id", "token", "session",
            "x-forwarded-for", "x-real-ip"
    );

    /**
     * Callback interface for pipeline progress updates.
     * All methods are called from the pipeline worker thread.
     */
    public interface PipelineCallback {
        void onStageStart(int stage, String description);
        void onStageComplete(int stage, String summary);
        void onPayloadExecuted(int index, int total, String payload, int statusCode);
        void onPipelineComplete(PipelineResult result);
        void onPipelineError(String error);

        /** Called when Stage 3 generates test cases — allows Repeater to load them immediately. */
        default void onTestCasesGenerated(List<TestCase> testCases) {}

        /** Called after each Stage 4 payload execution — allows Repeater to show responses live. */
        default void onPayloadResult(int index, PayloadResult result) {}

        /** Called when Stage 1 identifies the traffic data being analyzed — for chat context. */
        default void onTrafficDataIdentified(String method, String url, int statusCode,
                                              String requestSnippet, String responseSnippet) {}

        /** Called after each AI call completes — exposes the raw AI response text for "thinking process" visibility. */
        default void onAiThinkingOutput(int stage, String stageName, String rawAiText) {}

        /** Called when authorization bypass test completes with round details. */
        default void onAuthTestComplete(com.flechazo.apisentinel.auth.AuthTestResult result) {}

        /** Called when the USER requested cancellation: remaining stages are
         *  skipped and no result is produced. UIs must treat this as a clean
         *  stop (not an error) and release their run-state/budget slots. */
        default void onPipelineCancelled() {}
    }

    /** Cooperative-cancel flag; cancel() also interrupts the worker thread so
     *  a blocked LLM future.get()/sleep bails out between checkpoints. */
    private volatile boolean cancelled = false;
    private volatile Thread pipelineThread = null;

    /** Thrown by checkCancelled() at stage boundaries; caught once in execute(). */
    private static class AnalysisCancelledException extends RuntimeException {
        AnalysisCancelledException() { super("analysis cancelled by user"); }
    }

    /** Request cancellation. The pipeline stops at the next stage boundary
     *  (or immediately if blocked in an LLM call) and reports via
     *  onPipelineCancelled(). Already-collected per-stage data stays in the
     *  entry's history via earlier callbacks, but no PipelineResult is built. */
    public void cancel() {
        cancelled = true;
        Thread t = pipelineThread;
        if (t != null) t.interrupt();
    }

    private void checkCancelled() {
        if (cancelled) throw new AnalysisCancelledException();
    }

    public AnalysisPipeline(LlmProvider provider,
                            MontoyaApi montoyaApi,
                            CodeIndexService codeIndexService,
                            PipelineConfig config,
                            List<com.flechazo.apisentinel.config.CodeRepo> codeRepos,
                            LeveledLogger logger) {
        this.provider = provider;
        this.montoyaApi = montoyaApi;
        this.codeIndexService = codeIndexService;
        this.config = config;
        this.codeRepos = codeRepos != null ? codeRepos : List.of();
        this.logger = logger;
        this.wafDetector = new WafDetector(logger);
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-pipeline");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Execute the full 5-stage pipeline for the given API entry.
     */
    public CompletableFuture<PipelineResult> execute(ApiEntry entry, PipelineCallback callback) {
        return CompletableFuture.supplyAsync(() -> {
            pipelineThread = Thread.currentThread();
            try {
            Map<Integer, String> stageDescriptions = new java.util.LinkedHashMap<>();
            try {
                // ===== Pre-step A: Code lookup (local, no AI call) =====
                // Code lookup is done early because it's needed by Stage 3 (payload gen) and
                // Stage 6 (final verdict). Stage 1 does NOT use source code — it is pure traffic
                // analysis. Stage 2 reports the code correlation details.
                String sourceCode = "";
                String codeLookupDescription = "";
                if (config.useCodeRepo() && codeIndexService != null) {
                    CodeLookupResult codeLookup = lookupCodeDetailed(entry);
                    sourceCode = codeLookup.sourceCode();
                    codeLookupDescription = codeLookup.description();
                }

                // ===== Pre-step B: Single-pass Proxy History scan =====
                // Scans ALL matching requests in one pass: collects aggregated stats AND
                // optionally backfills traffic data (if entry has none).
                boolean needsBackfill = !entry.hasTrafficData();
                HistoryScanResult historyScan = scanHistoryOnce(entry, needsBackfill);
                TrafficStats trafficStats = historyScan.trafficStats();

                // ===== Stage 1: Traffic Analysis (pure HTTP traffic, NO source code) =====
                checkCancelled();
                callback.onStageStart(1, "分析接口流量数据...");

                String historyNote = "";
                AnalysisResult trafficAnalysis;
                if (needsBackfill) {
                    if (historyScan.backfillFound()) {
                        historyNote = String.format(
                                "（已扫描 Burp History 共 %d 条记录，按路径/方法筛选后匹配到 %d 条，使用最新一条：%s）\n\n",
                                historyScan.totalScanned(), historyScan.matchedCount(), historyScan.chosenSummary());
                        callback.onStageStart(1, "已从 Burp History 检索到匹配流量，开始分析...");
                        // Stage 1 = pure traffic analysis, no source code
                        trafficAnalysis = analyzeTraffic(entry, "", trafficStats, callback);
                    } else {
                        callback.onStageStart(1, "未在 Burp History 中找到匹配流量，跳过流量分析...");
                        trafficAnalysis = new AnalysisResult(List.of(),
                                String.format("该接口没有可用的流量数据：已扫描 Burp Proxy History 共 %d 条记录，"
                                        + "按路径 \"%s\" 筛选后未找到匹配的（非 OPTIONS/HEAD）请求。"
                                        + "因此跳过了本次基于流量的 AI 分析（未消耗 AI 调用）。"
                                        + "建议先通过浏览器/客户端实际触发一次该接口的请求，或在 Burp 中重放该请求后再重新分析。",
                                        historyScan.totalScanned(), entry.getApiPath()),
                                AnalysisResult.RiskLevel.NONE, 0, 0, "", null);
                    }
                } else {
                    // Stage 1 = pure traffic analysis, no source code
                    trafficAnalysis = analyzeTraffic(entry, "", trafficStats, callback);
                }

                // Push traffic data context to chat for "thinking process" visibility
                if (entry.hasTrafficData()) {
                    callback.onTrafficDataIdentified(
                            entry.getHttpMethod(),
                            entry.getLastUrl(),
                            entry.getLastStatusCode(),
                            truncate(entry.getLastRawRequest(), 2000),
                            truncate(entry.getLastRawResponse(), 2000));
                }

                if (!trafficAnalysis.isSuccess()) {
                    callback.onStageComplete(1, "失败: " + trafficAnalysis.error());
                    throw new RuntimeException("AI 服务调用失败: " + trafficAnalysis.error()
                            + "（请检查「设置 → AI 设置」中 Provider 的服务地址/API Key/网络连通性，"
                            + "可点击「测试连接」验证）");
                }
                String stage1Summary = historyNote + buildStage1DetailText(trafficAnalysis);
                if (!trafficStats.isEmpty()) {
                    stage1Summary += "\n\n📊 流量统计: 共匹配 " + trafficStats.totalMatched() + " 条历史请求"
                            + " | 状态码: " + trafficStats.statusCodeDistribution()
                            + " | 响应大小: " + trafficStats.minResponseSize() + "~" + trafficStats.maxResponseSize() + "B";
                }
                stageDescriptions.put(1, stage1Summary);
                callback.onStageComplete(1, stage1Summary);

                // ===== Stage 2: Report Code Correlation =====
                checkCancelled();
                if (config.useCodeRepo() && codeIndexService != null) {
                    callback.onStageStart(2, "关联代码仓库...");
                    stageDescriptions.put(2, codeLookupDescription);
                    callback.onStageComplete(2, codeLookupDescription);
                } else {
                    callback.onStageStart(2, "跳过代码关联（未配置）");
                    stageDescriptions.put(2, "已跳过（未配置代码仓库关联）");
                    callback.onStageComplete(2, "已跳过");
                }

                // ===== Stage 3: Generate Payloads (guided by Stage 1 findings) =====
                checkCancelled();
                callback.onStageStart(3, "生成测试Payload...");
                PayloadGenResult payloadGen = generatePayloadsDetailed(entry, trafficAnalysis, sourceCode);
                List<TestCase> testCases = payloadGen.cases();
                stageDescriptions.put(3, payloadGen.description());
                callback.onStageComplete(3, payloadGen.description());
                // Push test cases immediately so Repeater can show them before Stage 4 starts
                if (!testCases.isEmpty()) {
                    callback.onTestCasesGenerated(testCases);
                }

                // ===== Stage 4: Auto-execute payloads (with auth context) =====
                checkCancelled();
                List<PayloadResult> payloadResults = new ArrayList<>();
                if (config.autoExecute() && !testCases.isEmpty()) {
                    callback.onStageStart(4, "自动发送Payload验证...");
                    payloadResults = executePayloads(entry, testCases, callback);
                    String stage4Summary = buildStage4DetailText(payloadResults);
                    stageDescriptions.put(4, stage4Summary);
                    callback.onStageComplete(4, stage4Summary);
                } else {
                    callback.onStageStart(4, "跳过自动验证");
                    String stage4Summary = config.autoExecute() ? "无Payload可执行" : "自动执行已关闭";
                    stageDescriptions.put(4, stage4Summary);
                    callback.onStageComplete(4, stage4Summary);
                }

                // ===== Stage 5: Authorization Bypass Testing =====
                checkCancelled();
                AuthTestResult authTestResult = null;
                if (config.authTestEnabled()) {
                    callback.onStageStart(5, "鉴权绕过检测...");
                    authTestResult = executeAuthTest(entry, callback);
                    String stage5Summary;
                    if (authTestResult == null || authTestResult.verdict() == AuthTestResult.AuthVerdict.SKIPPED) {
                        stage5Summary = "已跳过: " + (authTestResult != null ? authTestResult.evidence() : "无可用会话");
                    } else {
                        stage5Summary = String.format("鉴权检测完成: %s (相似度 %.1f%%) %s",
                                authTestResult.verdict(), authTestResult.maxSimilarity() * 100,
                                authTestResult.vulnType() != null ? "- " + authTestResult.vulnType() : "");
                    }
                    stageDescriptions.put(5, stage5Summary);
                    callback.onStageComplete(5, stage5Summary);
                    if (authTestResult != null && authTestResult.verdict() != AuthTestResult.AuthVerdict.SKIPPED) {
                        callback.onAuthTestComplete(authTestResult);
                    }
                } else {
                    callback.onStageStart(5, "跳过鉴权检测（未启用）");
                    stageDescriptions.put(5, "已跳过（未启用鉴权检测）");
                    callback.onStageComplete(5, "已跳过");
                }

                // ===== Stage 5.5: Active probes (CORS/JWT/CRLF/NoSQL) =====
                // Programmatic verification of the classes passive detection
                // can only hint at. Results are merged into payloadResults so
                // Stage 6, persistence and the Repeater pick them up for free.
                checkCancelled();
                if (config.activeProbeEnabled()) {
                    callback.onStageStart(5, "主动探针（CORS/JWT伪造/CRLF/NoSQL）...");
                    List<PayloadResult> probeResults = List.of();
                    try {
                        probeResults = new ActiveProbeExecutor(montoyaApi, logger,
                                config.wafDetectionEnabled()).execute(entry);
                    } catch (Exception e) {
                        logger.warn("[Pipeline] 主动探针执行失败: %s", e.getMessage());
                    }
                    if (!probeResults.isEmpty()) {
                        payloadResults.addAll(probeResults);
                    }
                    long probeHits = probeResults.stream().filter(PayloadResult::anomalyDetected).count();
                    String probeSummary = String.format("主动探针: %d 个响应, %d 个程序化确认",
                            probeResults.size(), probeHits);
                    stageDescriptions.put(5, (stageDescriptions.getOrDefault(5, "") + " | " + probeSummary)
                            .replaceFirst("^\\s*\\|\\s*", ""));
                    callback.onStageComplete(5, probeSummary);
                }

                // ===== Stage 5.6: Blind SQLi verification (boolean → timing) =====
                // Auto-runs ONLY when Stage 1 flagged SQLi suspicion; candidate
                // params come from the captured request (query/JSON keys matching
                // typical SQL param names), capped by maxBlindProbeRequests.
                checkCancelled();
                if (config.blindVerificationEnabled() && trafficAnalysis != null
                        && trafficAnalysis.findings() != null
                        && trafficAnalysis.findings().stream().anyMatch(
                                f -> f.type() != null && f.type().toLowerCase().contains("sql"))) {
                    callback.onStageStart(5, "盲注验证（布尔/时序）...");
                    List<PayloadResult> blindResults = new ArrayList<>();
                    try {
                        blindResults = executeBlindVerification(entry);
                    } catch (Exception e) {
                        logger.warn("[Pipeline] 盲注验证失败: %s", e.getMessage());
                    }
                    if (!blindResults.isEmpty()) {
                        payloadResults.addAll(blindResults);
                    }
                    long blindHits = blindResults.stream().filter(PayloadResult::anomalyDetected).count();
                    String blindSummary = String.format("盲注验证: %d 个探针, %d 个程序化确认",
                            blindResults.size(), blindHits);
                    stageDescriptions.put(5, stageDescriptions.getOrDefault(5, "") + " | " + blindSummary);
                    callback.onStageComplete(5, blindSummary);
                }

                // ===== Stage 5.7: Business-logic verification (safe subset, opt-in) =====
                // Real business operations — only runs when explicitly enabled.
                // Auto subset: price tamper / negative value / coupon replay /
                // step skip. Race & enumeration stay Agent-only (more invasive).
                checkCancelled();
                if (config.businessLogicVerificationEnabled()) {
                    callback.onStageStart(5, "业务逻辑验证（篡改/重放/负数/跳步）...");
                    List<PayloadResult> bizResults = new ArrayList<>();
                    try {
                        bizResults = executeBusinessLogicVerification(entry);
                    } catch (Exception e) {
                        logger.warn("[Pipeline] 业务逻辑验证失败: %s", e.getMessage());
                    }
                    if (!bizResults.isEmpty()) {
                        payloadResults.addAll(bizResults);
                    }
                    long bizHits = bizResults.stream().filter(PayloadResult::anomalyDetected).count();
                    String bizSummary = String.format("业务逻辑验证: %d 项, %d 个程序化确认",
                            bizResults.size(), bizHits);
                    stageDescriptions.put(5, stageDescriptions.getOrDefault(5, "") + " | " + bizSummary);
                    callback.onStageComplete(5, bizSummary);
                }

                // ===== Stage 6: Final comprehensive assessment (with baseline) =====
                checkCancelled();
                callback.onStageStart(6, "AI综合研判...");
                FinalVerdict verdict = finalAssessment(entry, trafficAnalysis, sourceCode,
                        testCases, payloadResults, authTestResult, callback);
                String stage6Summary = "研判完成: " + verdict.overallRisk();
                stageDescriptions.put(6, stage6Summary);
                callback.onStageComplete(6, stage6Summary);

                PipelineResult result = new PipelineResult(
                        trafficAnalysis, sourceCode, testCases, payloadResults, verdict,
                        stageDescriptions, trafficStats, authTestResult);
                callback.onPipelineComplete(result);
                return result;

            } catch (AnalysisCancelledException ce) {
                logger.info("Pipeline 用户中断，跳过剩余阶段");
                callback.onPipelineCancelled();
                return null;
            } catch (Throwable e) {
                // Throwable, not Exception: during an extension reload the
                // dying ClassLoader throws NoClassDefFoundError into a run
                // that kept going. The error callback must still settle the
                // panel, or it sits in "running" state forever.
                if (cancelled) {
                    // cancel()'s interrupt blew up a blocking wait before a
                    // checkpoint could fire — same cooperative-stop semantics.
                    callback.onPipelineCancelled();
                    return null;
                }
                String msg = describeException(e);
                logger.error("Pipeline 执行异常: %s", msg);
                callback.onPipelineError(msg);
                throw new RuntimeException(msg, e);
            }
            } finally {
                pipelineThread = null;
                // Clear any pending interrupt so this reused executor thread
                // doesn't poison the next run (see AgentLoop's same finally).
                Thread.interrupted();
            }
        }, executor);
    }

    /**
     * Build a human-readable description for an exception.
     */
    private static String describeException(Throwable e) {
        if (e instanceof java.util.concurrent.TimeoutException
                || e.getCause() instanceof java.util.concurrent.TimeoutException) {
            return "AI 调用超时，可能是网络较慢或 AI 服务响应时间过长，请检查「设置 → AI 设置」的连接状态后重试";
        }
        String msg = e.getMessage();
        if (msg == null || msg.isEmpty()) {
            return e.getClass().getSimpleName() + "（无详细错误信息）";
        }
        return msg;
    }

    // ======================== Stage 1: Traffic Analysis ========================

    /**
     * Combined result of a single-pass Proxy History scan:
     * both backfill data (latest full request) AND aggregated traffic stats.
     */
    private record HistoryScanResult(
        boolean backfillFound,
        int totalScanned,
        int matchedCount,
        String chosenSummary,
        TrafficStats trafficStats
    ) {
        static HistoryScanResult empty(int scanned) {
            return new HistoryScanResult(false, scanned, 0, "", TrafficStats.empty());
        }
    }

    /**
     * Single-pass scan of Burp Proxy History that does BOTH:
     * 1. Backfills the entry's traffic data from the latest matching request (if needed)
     * 2. Collects aggregated TrafficStats across ALL matching requests
     *
     * This replaces the old separate autoBackfillFromHistory() + collectTrafficStats()
     * which redundantly iterated the full history twice.
     *
     * @param needsBackfill if true, also backfill entry traffic from latest match
     */
    private HistoryScanResult scanHistoryOnce(ApiEntry entry, boolean needsBackfill) {
        if (montoyaApi == null) return HistoryScanResult.empty(0);
        try {
            var history = montoyaApi.proxy().history();
            int total = history.size();

            String declared = entry.getHttpMethod();
            java.util.Set<String> declaredMethods = new java.util.HashSet<>();
            if (declared != null && !declared.isEmpty()) {
                for (String m : declared.split("/")) declaredMethods.add(m.toUpperCase());
            }

            // Backfill tracking (latest matching request)
            String bestMethod = null, bestUrl = null, bestHost = null, bestReq = null, bestResp = null;
            int bestStatus = 0;
            int matchedCount = 0;

            // Stats collector
            TrafficStats.Collector statsCollector = new TrafficStats.Collector();

            for (var item : history) {
                try {
                    String url = item.finalRequest().url();
                    String path = com.flechazo.apisentinel.util.UrlUtils.extractPath(url);
                    if (com.flechazo.apisentinel.util.UrlUtils.isStaticResource(path)) continue;
                    if (!com.flechazo.apisentinel.util.UrlUtils.pathsLikelyMatch(entry.getApiPath(), path)) continue;

                    String method = item.finalRequest().method();
                    boolean isNoiseMethod = "OPTIONS".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method);
                    if (isNoiseMethod && !declaredMethods.contains(method.toUpperCase())) {
                        continue;
                    }

                    matchedCount++;

                    int respStatus = 0;
                    int respSize = 0;
                    String contentType = "";

                    // === Collect stats ===
                    if (item.response() != null) {
                        respStatus = item.response().statusCode();
                        respSize = item.response().body() != null ? item.response().body().length() : 0;
                        var ctHeader = item.response().headerValue("Content-Type");
                        contentType = ctHeader != null ? ctHeader : "";
                    }

                    Set<String> paramKeys = new java.util.LinkedHashSet<>();
                    int qIdx = url.indexOf('?');
                    if (qIdx > 0 && qIdx < url.length() - 1) {
                        String queryString = url.substring(qIdx + 1);
                        for (String pair : queryString.split("&")) {
                            int eqIdx = pair.indexOf('=');
                            String key = eqIdx > 0 ? pair.substring(0, eqIdx) : pair;
                            if (!key.isEmpty()) paramKeys.add(key);
                        }
                    }

                    long ts = item.time() != null ? item.time().toInstant().toEpochMilli() : 0;
                    statsCollector.add(method, path, respStatus, respSize, ts, contentType, paramKeys);

                    // === Backfill: keep overwriting to get the LATEST match ===
                    if (needsBackfill) {
                        bestMethod = method;
                        bestUrl = url;
                        bestHost = com.flechazo.apisentinel.util.UrlUtils.stripPort(
                                com.flechazo.apisentinel.util.UrlUtils.extractHost(url));
                        bestReq = com.flechazo.apisentinel.util.HttpMessageUtils.buildRawRequest(item.finalRequest());
                        if (item.response() != null) {
                            bestResp = com.flechazo.apisentinel.util.HttpMessageUtils.buildRawResponse(item.response());
                            bestStatus = item.response().statusCode();
                        } else {
                            bestResp = null;
                            bestStatus = 0;
                        }
                    }
                } catch (Exception ignored) {}
            }

            TrafficStats stats = statsCollector.build();

            if (matchedCount == 0) {
                return new HistoryScanResult(false, total, 0, "", stats);
            }

            // Apply backfill if needed and data was found
            if (needsBackfill && bestReq != null) {
                synchronized (entry) {
                    if (bestMethod != null) entry.appendHttpMethod(bestMethod);
                    if (entry.getDomain().isEmpty() && bestHost != null && !bestHost.isEmpty()) {
                        entry.setDomain(bestHost);
                    }
                    entry.setLastUrl(bestUrl);
                    entry.setLastRawRequest(bestReq);
                    if (bestResp != null) {
                        entry.setLastRawResponse(bestResp);
                        entry.setLastStatusCode(bestStatus);
                    }
                    entry.setLastSeenTimestamp(System.currentTimeMillis());
                }
                String chosenSummary = bestMethod + " " + bestUrl + " -> HTTP " + bestStatus;
                logger.info("[Pipeline] 已从 Burp History 自动回填流量数据: %s (%s)", entry.getApiPath(), chosenSummary);
                return new HistoryScanResult(true, total, matchedCount, chosenSummary, stats);
            }

            if (!stats.isEmpty()) {
                logger.info("[Pipeline] 流量统计: %s 匹配 %d 条历史请求, 状态码分布: %s",
                        entry.getApiPath(), stats.totalMatched(), stats.statusCodeDistribution());
            }
            return new HistoryScanResult(false, total, matchedCount, "", stats);
        } catch (Exception e) {
            logger.debug("[Pipeline] 检索 Proxy History 失败: %s", e.getMessage());
            return HistoryScanResult.empty(0);
        }
    }

    /**
     * Stage 1: Pure traffic analysis — analyzes ONLY the HTTP request/response data.
     * Source code is NOT passed to this stage; code correlation happens in Stage 2,
     * and source code is used by Stage 3 (payload gen) and Stage 6 (final verdict).
     * Receives aggregated TrafficStats from Burp History as additional context.
     * Pushes raw AI response to callback for thinking process visibility.
     */
    private AnalysisResult analyzeTraffic(ApiEntry entry, String sourceCode,
                                           TrafficStats trafficStats, PipelineCallback callback) {
        try {
            VulnerabilityAnalyzer analyzer = new VulnerabilityAnalyzer(provider, logger);
            // Multi-model tiering: route Stage-1 traffic triage to the cheaper
            // model when one is configured; deep stages keep the main model.
            if (fastModel != null && !fastModel.isBlank()) {
                analyzer.setModelOverride(fastModel);
            }

            String method = entry.getHttpMethod();
            String url = entry.getLastUrl().isEmpty() ? entry.getApiPath() : entry.getLastUrl();
            String host = entry.getDomain();
            String requestBody = entry.getLastRawRequest();
            int statusCode = entry.getLastStatusCode();
            String responseBody = entry.getLastRawResponse();
            String params = extractParameters(requestBody, url);

            // Build traffic context from aggregated stats
            StringBuilder trafficContextBuilder = new StringBuilder();
            if (trafficStats != null && !trafficStats.isEmpty()) {
                trafficContextBuilder.append(trafficStats.toPromptSection());
            }
            // User notes (hand-written only since the passive-structuring
            // refactor) + structured passive findings (HttpTrafficHandler's
            // real-time Heuristic/SensitiveInfo/Unauthorized detectors) already
            // scanned this traffic for free before Stage 1 ever ran — fold both
            // in so the AI confirms/refutes them in the final verdict instead
            // of Stage 1 re-deriving them from scratch blind to what was found.
            if (entry.getNote() != null && !entry.getNote().isBlank()) {
                if (trafficContextBuilder.length() > 0) trafficContextBuilder.append("\n\n");
                trafficContextBuilder.append("## 人工备注\n");
                String note = entry.getNote();
                trafficContextBuilder.append(note.length() > 2000 ? note.substring(0, 2000) + "\n[...截断]" : note);
            }
            String passiveFindingsText = entry.buildPassiveFindingsText();
            if (!passiveFindingsText.isEmpty()) {
                if (trafficContextBuilder.length() > 0) trafficContextBuilder.append("\n\n");
                trafficContextBuilder.append("## 被动检测已发现的内容（分析前已存在，请在结论里确认或说明为何是误报）\n");
                trafficContextBuilder.append(passiveFindingsText.length() > 2000
                        ? passiveFindingsText.substring(0, 2000) + "\n[...截断]" : passiveFindingsText);
            }
            // Cross-run reuse: if this endpoint was analyzed recently, fold the
            // previous verdict in as "known conclusions" so the model confirms /
            // refines instead of re-deriving everything from scratch (saves tokens).
            String priorAnalysis = buildPriorAnalysisContext(entry);
            if (!priorAnalysis.isEmpty()) {
                if (trafficContextBuilder.length() > 0) trafficContextBuilder.append("\n\n");
                trafficContextBuilder.append(priorAnalysis);
            }
            String trafficContext = trafficContextBuilder.toString();

            // Stage 1 receives sourceCode="" from caller — pure traffic analysis, no code context
            AnalysisResult result = analyzer.analyze(
                    method, url, host, requestBody, statusCode,
                    responseBody, entry.getApiPath(), params, sourceCode, trafficContext
            ).get(STAGE1_TIMEOUT_SEC, TimeUnit.SECONDS);

            // Push raw AI thinking output: the summary IS the AI's reasoning
            if (callback != null && result.isSuccess()) {
                StringBuilder thinkingText = new StringBuilder();
                thinkingText.append("**AI 分析思路：**\n\n");
                if (result.summary() != null && !result.summary().isEmpty()) {
                    thinkingText.append(result.summary()).append("\n\n");
                }
                if (!result.findings().isEmpty()) {
                    thinkingText.append("**识别到的安全线索（").append(result.findings().size()).append(" 项）：**\n");
                    for (var f : result.findings()) {
                        thinkingText.append("• [").append(f.risk()).append("] ").append(f.title())
                                .append(" — ").append(f.type()).append("\n");
                        if (f.description() != null && !f.description().isEmpty()) {
                            thinkingText.append("  分析: ").append(f.description()).append("\n");
                        }
                        if (f.evidence() != null && !f.evidence().isEmpty()) {
                            thinkingText.append("  证据: ").append(f.evidence()).append("\n");
                        }
                        if (f.location() != null && !f.location().isEmpty()) {
                            thinkingText.append("  位置: ").append(f.location()).append("\n");
                        }
                        if (f.remediation() != null && !f.remediation().isEmpty()) {
                            thinkingText.append("  建议: ").append(f.remediation()).append("\n");
                        }
                        thinkingText.append("\n");
                    }
                } else {
                    thinkingText.append("未发现明显安全问题。\n");
                }
                thinkingText.append("*模型: ").append(result.modelUsed() != null ? result.modelUsed() : "unknown")
                        .append(" | Token 消耗: ").append(result.tokensUsed())
                        .append(" | 耗时: ").append(result.analysisTimeMs()).append("ms*");
                callback.onAiThinkingOutput(1, "流量分析", thinkingText.toString());
            }

            logger.info("[Pipeline] 阶段1完成: %s [%s] %d findings",
                    entry.getApiPath(), result.overallRisk(), result.findings().size());
            return result;

        } catch (Exception e) {
            logger.error("[Pipeline] 阶段1失败: %s", describeException(e));
            return AnalysisResult.failed("流量分析失败: " + describeException(e));
        }
    }

    // ======================== Stage 2: Code Correlation ========================

    private record CodeLookupResult(String sourceCode, String description) {}

    private CodeLookupResult lookupCodeDetailed(ApiEntry entry) {
        try {
            if (codeRepos.isEmpty()) {
                return new CodeLookupResult("", "未配置任何代码仓库（可在「设置 → 代码仓库」中添加并索引）");
            }

            List<com.flechazo.apisentinel.config.CodeRepo> matchingRepos = new ArrayList<>();
            for (var repo : codeRepos) {
                if (repo.matchesDomain(entry.getDomain())) matchingRepos.add(repo);
            }

            StringBuilder desc = new StringBuilder();
            if (matchingRepos.isEmpty()) {
                desc.append("已配置 ").append(codeRepos.size()).append(" 个仓库，但均未关联域名 \"")
                        .append(entry.getDomain().isEmpty() ? "(空)" : entry.getDomain()).append("\":\n");
                for (var repo : codeRepos) {
                    desc.append("  - ").append(repo.getName()).append(" (").append(repo.getPath())
                            .append(") 关联域名: ")
                            .append(repo.getDomains().isEmpty() ? "无" : String.join(", ", repo.getDomains()))
                            .append("\n");
                }
                return new CodeLookupResult("", desc.toString());
            }

            desc.append("已检查 ").append(matchingRepos.size()).append(" 个关联仓库:\n");
            for (var repo : matchingRepos) {
                desc.append("  - ").append(repo.getName()).append(" (").append(repo.getPath()).append(")")
                        .append(repo.isIndexed() ? " [已索引 " + repo.getRouteCount() + " 条路由]" : " [未索引]")
                        .append("\n");
            }

            List<RouteEntry> routes = codeIndexService.findByPathAndDomain(entry.getApiPath(), entry.getDomain(), codeRepos);
            if (routes.isEmpty()) {
                desc.append("未在上述仓库中找到路径 \"").append(entry.getApiPath()).append("\" 的匹配路由");
                return new CodeLookupResult("", desc.toString());
            }

            StringBuilder sourceCode = new StringBuilder();
            desc.append("找到 ").append(routes.size()).append(" 处匹配路由:\n");
            for (RouteEntry route : routes) {
                desc.append("  - ").append(route.sourceFile()).append(":").append(route.startLine())
                        .append(" (").append(route.className()).append(".").append(route.methodName()).append(")\n");
                String snippet = config.maxCodeFollowHops() > 0
                        ? codeIndexService.getFullMethodSource(route)
                        : codeIndexService.getSourceCode(route);
                sourceCode.append("// File: ").append(route.sourceFile())
                        .append(" Line: ").append(route.startLine()).append("\n");
                sourceCode.append("// Class: ").append(route.className())
                        .append(" Method: ").append(route.methodName()).append("\n");
                sourceCode.append(snippet).append("\n\n");

                if (config.maxCodeFollowHops() > 0) {
                    SinkMap sinkMap = codeIndexService.getSinkMap();
                    String hops = followMultiHop(matchingRepos, snippet, config.maxCodeFollowHops(), sinkMap);
                    if (hops != null) {
                        sourceCode.append(hops).append("\n\n");
                        desc.append("    → 多跳追溯(").append(config.maxCodeFollowHops())
                                .append("跳): 已附加调用链代码");
                        if (sinkMap != null && sinkMap.totalSinkCount() > 0) {
                            desc.append("（含 sink 标注）");
                        }
                        desc.append("\n");
                    } else {
                        desc.append("    → 多跳追溯: 未找到明显的下游调用类\n");
                    }
                } else if (config.followOneCodeHop()) {
                    String hop = followOneHop(matchingRepos, snippet);
                    if (hop != null) {
                        sourceCode.append(hop).append("\n\n");
                        desc.append("    → 一跳追溯: 已附加被调用类的代码\n");
                    } else {
                        desc.append("    → 一跳追溯: 未找到明显的下游调用类\n");
                    }
                }
            }
            return new CodeLookupResult(sourceCode.toString(), desc.toString());
        } catch (Exception e) {
            logger.debug("[Pipeline] 查找源码失败: %s", describeException(e));
            return new CodeLookupResult("", "查找源码时出错: " + describeException(e));
        }
    }

    /**
     * Pipeline mode has no tool-calling capability (unlike Agent mode's
     * read_file/grep_repo), so Stage 2 gets one bounded, non-agentic hop:
     * scan the controller snippet for a plausible injected-dependency call
     * (xxxService.method(...) / xxxDao.method(...) / xxxGuard.method(...)),
     * then grep the repo for that class's declaration and pull a window of
     * source around it. Best effort — a regex heuristic, not a real
     * call-graph; returns null when nothing confident is found rather than
     * failing Stage 2.
     */
    private static final Pattern DEPENDENCY_CALL = Pattern.compile(
            "\\b([A-Za-z_][A-Za-z0-9_]*(?:Service|Dao|Repository|Mapper|Manager|Guard))\\s*\\.\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\(");

    private String followOneHop(List<com.flechazo.apisentinel.config.CodeRepo> matchingRepos, String snippet) {
        if (snippet == null || snippet.isBlank()) return null;
        Matcher m = DEPENDENCY_CALL.matcher(snippet);
        Set<String> seen = new LinkedHashSet<>();
        List<String> candidates = new ArrayList<>();
        while (m.find() && candidates.size() < 2) {
            String className = m.group(1);
            if (seen.add(className)) candidates.add(className);
        }
        for (String className : candidates) {
            Pattern classDecl = Pattern.compile("\\b(class|interface)\\s+" + Pattern.quote(className) + "\\b");
            List<RepoGrepper.GrepMatch> matches = RepoGrepper.search(matchingRepos, classDecl, "*.java", 1, 0);
            if (matches.isEmpty()) continue;
            RepoGrepper.GrepMatch match = matches.get(0);
            try {
                List<String> lines = java.nio.file.Files.readAllLines(match.file());
                int start = Math.max(0, match.line() - 3);
                int end = Math.min(lines.size(), match.line() + 40);
                StringBuilder sb = new StringBuilder();
                sb.append("// [一跳追溯] ").append(className).append(" (").append(match.file()).append(")\n");
                for (int i = start; i < end; i++) {
                    sb.append(String.format("%4d | %s%n", i + 1, lines.get(i)));
                }
                return sb.toString();
            } catch (java.io.IOException ignored) {
                // unreadable — try next candidate
            }
        }
        return null;
    }

    private String followMultiHop(List<com.flechazo.apisentinel.config.CodeRepo> matchingRepos,
                                   String snippet, int maxHops, SinkMap sinkMap) {
        if (snippet == null || snippet.isBlank() || maxHops <= 0) return null;

        StringBuilder result = new StringBuilder();
        Set<String> visited = new LinkedHashSet<>();
        List<String> currentSnippets = List.of(snippet);

        for (int hop = 0; hop < maxHops && !currentSnippets.isEmpty(); hop++) {
            List<String> nextSnippets = new ArrayList<>();
            for (String src : currentSnippets) {
                Matcher m = DEPENDENCY_CALL.matcher(src);
                List<String> candidates = new ArrayList<>();
                while (m.find() && candidates.size() < 3) {
                    String className = m.group(1);
                    if (visited.add(className)) candidates.add(className);
                }

                if (sinkMap != null) {
                    candidates.sort((a, b) -> {
                        boolean aHas = sinkMap.hasSinks(a);
                        boolean bHas = sinkMap.hasSinks(b);
                        if (aHas && !bHas) return -1;
                        if (!aHas && bHas) return 1;
                        return 0;
                    });
                }

                for (String className : candidates) {
                    Pattern classDecl = Pattern.compile("\\b(class|interface)\\s+" + Pattern.quote(className) + "\\b");
                    List<RepoGrepper.GrepMatch> matches = RepoGrepper.search(matchingRepos, classDecl, "*.java", 1, 0);
                    if (matches.isEmpty()) continue;
                    RepoGrepper.GrepMatch match = matches.get(0);
                    try {
                        List<String> lines = java.nio.file.Files.readAllLines(match.file());
                        int start = Math.max(0, match.line() - 3);
                        int end = Math.min(lines.size(), match.line() + 80);
                        StringBuilder classCode = new StringBuilder();
                        classCode.append("// [").append(hop + 1).append("跳追溯] ")
                                .append(className).append(" (").append(match.file()).append(")\n");
                        for (int i = start; i < end; i++) {
                            classCode.append(String.format("%4d | %s%n", i + 1, lines.get(i)));
                        }

                        String codeStr = classCode.toString();
                        if (sinkMap != null && sinkMap.hasSinks(className)) {
                            List<SinkMap.SinkEntry> sinks = sinkMap.sinksInClass(className);
                            codeStr = SinkAnnotator.annotateWithSinks(codeStr, sinks);
                        }

                        result.append(codeStr).append("\n");
                        nextSnippets.add(codeStr);
                    } catch (java.io.IOException ignored) {}
                }
            }
            currentSnippets = nextSnippets;
        }

        return result.isEmpty() ? null : result.toString();
    }

    // ======================== Stage 3: Generate Payloads ========================

    private record PayloadGenResult(List<TestCase> cases, String description) {}

    /**
     * so Stage 1 discoveries guide Stage 3 payload generation.
     */
    private PayloadGenResult generatePayloadsDetailed(ApiEntry entry, AnalysisResult trafficAnalysis, String sourceCode) {
        try {
            TestCaseService testCaseService = new TestCaseService(provider, logger);
            String params = extractParameters(entry.getLastRawRequest(), entry.getLastUrl());

            // Truncate source code for Stage 3 to reduce prompt size
            String truncatedSource = sourceCode;
            if (truncatedSource != null && truncatedSource.length() > 6000) {
                truncatedSource = truncatedSource.substring(0, 6000) + "\n[...源码截断以加速生成]";
            }

            var stage1Findings = (trafficAnalysis != null && trafficAnalysis.findings() != null)
                    ? trafficAnalysis.findings()
                    : List.<com.flechazo.apisentinel.ai.analysis.VulnFinding>of();

            var result = testCaseService.generateDetailed(
                    entry.getHttpMethod(), entry.getApiPath(),
                    entry.getDomain(), params, truncatedSource, stage1Findings
            ).get(STAGE3_TIMEOUT_SEC, TimeUnit.SECONDS);

            logger.info("[Pipeline] 阶段3完成: 生成 %d 个测试用例", result.cases().size());

            StringBuilder desc = new StringBuilder();
            if (result.reasoning() != null && !result.reasoning().isEmpty()) {
                desc.append("AI 判断依据: ").append(result.reasoning()).append("\n\n");
            }

            if (!result.isSuccess()) {
                desc.append("⚠ 未生成测试Payload，原因: ").append(result.errorReason());
                if (result.rawResponse() != null && !result.rawResponse().isEmpty()) {
                    desc.append("\nAI 原始响应片段: ").append(truncate(result.rawResponse(), 300));
                }
                return new PayloadGenResult(List.of(), desc.toString());
            }

            if (result.cases().isEmpty()) {
                desc.append("AI 判断该接口暂无需要生成的测试 Payload（详见上方判断依据）");
                return new PayloadGenResult(List.of(), desc.toString());
            }

            desc.append(buildStage3DetailText(result.cases()));
            return new PayloadGenResult(result.cases(), desc.toString());

        } catch (Exception e) {
            logger.error("[Pipeline] 阶段3失败: %s", describeException(e));
            return new PayloadGenResult(List.of(), "生成测试Payload时出错: " + describeException(e));
        }
    }

    // ======================== Stage 4: Execute Payloads ========================

    /**
     * and inject them into every test payload request.
     */
    private Map<String, String> extractAuthHeaders(String rawRequest) {
        Map<String, String> authHeaders = new LinkedHashMap<>();
        if (rawRequest == null || rawRequest.isEmpty()) return authHeaders;

        // Parse headers from raw request (line by line after the request line)
        String[] lines = rawRequest.split("\r?\n");
        boolean pastFirstLine = false;
        for (String line : lines) {
            if (!pastFirstLine) {
                pastFirstLine = true; // skip request line (e.g. "GET /path HTTP/1.1")
                continue;
            }
            if (line.isEmpty()) break; // end of headers

            int colonIdx = line.indexOf(':');
            if (colonIdx <= 0) continue;

            String headerName = line.substring(0, colonIdx).trim();
            String headerValue = line.substring(colonIdx + 1).trim();
            String lowerName = headerName.toLowerCase();

            if (AUTH_HEADER_NAMES.contains(lowerName)
                    || lowerName.startsWith("x-") // carry all custom headers
                    || lowerName.equals("referer")
                    || lowerName.equals("origin")) {
                authHeaders.put(headerName, headerValue);
            }
        }
        return authHeaders;
    }

    private List<PayloadResult> executePayloads(ApiEntry entry, List<TestCase> testCases, PipelineCallback callback) {
        int maxPayloads = Math.min(testCases.size(), config.maxPayloads());

        Map<String, String> originalAuthHeaders = extractAuthHeaders(entry.getLastRawRequest());
        if (!originalAuthHeaders.isEmpty()) {
            logger.info("[Pipeline] 从原始请求中提取到 %d 个认证/上下文头部: %s",
                    originalAuthHeaders.size(), originalAuthHeaders.keySet());
        }

        int baselineStatusCode = entry.getLastStatusCode();
        // Body-only length so header variance (Date, Set-Cookie) doesn't skew
        // the anomaly size comparison.
        int baselineResponseLength = bodyLength(entry.getLastRawResponse());

        // Pre-build all HttpRequest objects with metadata
        List<HttpRequest> httpRequests = new ArrayList<>(maxPayloads);
        List<String> rawRequests = new ArrayList<>(maxPayloads);
        List<TestCase> effectiveCases = new ArrayList<>(maxPayloads);

        for (int i = 0; i < maxPayloads; i++) {
            TestCase tc = testCases.get(i);
            try {
                String rawRequest = buildRawRequest(entry, tc, originalAuthHeaders);
                httpRequests.add(HttpRequest.httpRequest(resolveService(entry), rawRequest));
                rawRequests.add(rawRequest);
                effectiveCases.add(tc);
            } catch (Exception e) {
                logger.warn("[Pipeline] 构建请求失败 #%d: %s", i + 1, e.getMessage());
            }
        }

        // Try RequestExecutionEngine (Montoya 2026.7+), fall back to serial mode
        List<PayloadResult> results;
        try {
            results = executePayloadsWithEngine(effectiveCases, httpRequests, rawRequests,
                    baselineStatusCode, baselineResponseLength, callback);
        } catch (NoSuchMethodError | NoClassDefFoundError | Exception e) {
            logger.info("[Pipeline] RequestExecutionEngine 不可用，使用串行模式: %s", e.getMessage());
            results = executePayloadsSerial(effectiveCases, httpRequests, rawRequests,
                    baselineStatusCode, baselineResponseLength, callback);
        }
        // WAF-blocked payloads get a few encoded-variant retries (appended results).
        return retryWafBlocked(entry, results, baselineStatusCode, baselineResponseLength);
    }

    /**
     * Build the raw HTTP request text for a test case against the given entry.
     * Carries the original request's auth/context headers unless the case is
     * itself an auth-bypass test. Shared by the main execution loop and the
     * WAF-evasion retry loop.
     */
    private String buildRawRequest(ApiEntry entry, TestCase tc, Map<String, String> originalAuthHeaders) {
        String host = entry.getDomain().isEmpty() ? "localhost" : entry.getDomain();
        String method = (tc.method() != null && !tc.method().isEmpty()) ? tc.method() : entry.getHttpMethod();
        String path = (tc.path() != null && !tc.path().isEmpty()) ? tc.path() : entry.getApiPath();

        StringBuilder reqBuilder = new StringBuilder();
        reqBuilder.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        reqBuilder.append("Host: ").append(host).append("\r\n");

        Set<String> addedHeaders = new HashSet<>();
        String category = tc.category() != null ? tc.category() : "";
        boolean isAuthBypassTest = category.contains("认证绕过") || category.equalsIgnoreCase("认证绕过")
                || category.toLowerCase().contains("auth") || category.toLowerCase().contains("bypass")
                || category.toLowerCase().contains("unauth");

        if (!isAuthBypassTest) {
            for (Map.Entry<String, String> ah : originalAuthHeaders.entrySet()) {
                reqBuilder.append(ah.getKey()).append(": ").append(ah.getValue()).append("\r\n");
                addedHeaders.add(ah.getKey().toLowerCase());
            }
        } else {
            logger.info("[Pipeline] 认证绕过测试 \"%s\"，跳过注入认证头", tc.name());
        }

        if (tc.headers() != null) {
            for (Map.Entry<String, String> h : tc.headers().entrySet()) {
                reqBuilder.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
                addedHeaders.add(h.getKey().toLowerCase());
            }
        }

        if (!addedHeaders.contains("user-agent")) {
            reqBuilder.append("User-Agent: API-Sentinel/").append(com.flechazo.apisentinel.ApiSentinelExtension.VERSION).append("-Pipeline\r\n");
        }

        String body = tc.body();
        if (body != null && !body.isEmpty()) {
            if (!addedHeaders.contains("content-type")) {
                if (body.trim().startsWith("{") || body.trim().startsWith("[")) {
                    reqBuilder.append("Content-Type: application/json\r\n");
                } else {
                    reqBuilder.append("Content-Type: application/x-www-form-urlencoded\r\n");
                }
            }
            reqBuilder.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
            reqBuilder.append("\r\n").append(body);
        } else {
            reqBuilder.append("\r\n");
        }
        return reqBuilder.toString();
    }

    /** Resolve scheme/port for the entry based on its last observed URL. */
    private HttpService resolveService(ApiEntry entry) {
        String host = entry.getDomain().isEmpty() ? "localhost" : entry.getDomain();
        String lastUrl = entry.getLastUrl();
        boolean useHttps;
        if (lastUrl != null && lastUrl.toLowerCase().startsWith("http://")) {
            useHttps = false;
        } else {
            useHttps = true;
        }
        String hostName = host.contains(":") ? host.split(":")[0] : host;
        int port;
        if (host.contains(":")) {
            try {
                port = Integer.parseInt(host.split(":")[1]);
            } catch (NumberFormatException nfe) {
                port = useHttps ? 443 : 80;
            }
        } else {
            port = useHttps ? 443 : 80;
        }
        return HttpService.httpService(hostName, port, useHttps);
    }

    /**
     * Retry payloads whose responses look like WAF blocks (score &gt;= 30) using
     * encoded variants from {@link WafEncoder}. Variant results are APPENDED to
     * the result list (the original blocked result stays, preserving the audit
     * fact that the raw payload was blocked). Retries are serial regardless of
     * the main execution path — the volume is tiny (cap below) and reusing the
     * concurrent engine here would complicate its lifecycle.
     *
     * Note: variant results are not pushed through callback.onPayloadResult —
     * they have no backing Repeater table row (executionIndex=-1 marks them).
     * They still flow into the Stage 6 verdict prompt, persistence and
     * VerdictValidator matching.
     */
    private List<PayloadResult> retryWafBlocked(ApiEntry entry, List<PayloadResult> results,
                                                 int baselineStatusCode, int baselineResponseLength) {
        if (!config.wafRetryEnabled() || results == null || results.isEmpty()) return results;
        List<PayloadResult> original = List.copyOf(results);
        List<PayloadResult> all = new ArrayList<>(results);
        Map<String, String> authHeaders = extractAuthHeaders(entry.getLastRawRequest());
        HttpService service = resolveService(entry);
        final int maxVariantRequests = 30; // global cap per analysis run
        int sent = 0;

        for (PayloadResult pr : original) {
            if (pr.wafScore() < PayloadResult.WAF_REVIEW) continue;
            TestCase tc = pr.testCase();
            if (tc == null || tc.payload() == null || tc.payload().isEmpty()) continue;

            List<WafEncoder.Variant> variants = WafEncoder.encodeVariants(tc.category(), tc.payload(), 6);
            for (WafEncoder.Variant v : variants) {
                if (sent >= maxVariantRequests) {
                    logger.info("[Pipeline] WAF 变体重试达到全局上限 %d，停止", maxVariantRequests);
                    return all;
                }
                TestCase variantTc = applyVariant(tc, v.payload());
                if (variantTc == null) break; // payload not embedded in body/path/headers — cannot substitute
                try {
                    String rawRequest = buildRawRequest(entry, variantTc, authHeaders);
                    long start = System.currentTimeMillis();
                    HttpRequestResponse resp = montoyaApi.http().sendRequest(HttpRequest.httpRequest(service, rawRequest));
                    long elapsed = System.currentTimeMillis() - start;
                    int status = resp.response() != null ? resp.response().statusCode() : 0;
                    String respStr = resp.response() != null ? resp.response().toString() : "";

                    boolean anomaly = detectAnomaly(variantTc, baselineStatusCode, baselineResponseLength,
                            status, respStr, elapsed);
                    WafDetector.WafDetectionResult waf = config.wafDetectionEnabled()
                            ? wafDetector.detect(respStr, status, elapsed) : WAF_DISABLED;

                    PayloadResult vpr = new PayloadResult(variantTc, rawRequest, respStr, status, elapsed,
                            anomaly, start, -1, waf.vendor(), waf.score());
                    all.add(vpr);
                    sent++;
                    logger.info("[Pipeline] WAF变体重试 %d/%d: %s [%s] -> %d (waf=%d) %s",
                            sent, maxVariantRequests, tc.name(), v.technique(), status, waf.score(),
                            anomaly ? "[异常]" : "[正常]");

                    // Break-through (no longer blocked) or a real anomaly: stop for this payload.
                    if (anomaly || waf.score() < PayloadResult.WAF_REVIEW) break;
                    Thread.sleep(200);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return all;
                } catch (Exception e) {
                    logger.warn("[Pipeline] WAF变体重试失败: %s", e.getMessage());
                }
            }
        }
        return all;
    }

    /**
     * Build a variant TestCase by substituting the original payload text inside
     * body/path/header-values with the encoded variant. Returns null when the
     * original payload appears nowhere in the constructed request parts — in
     * that case a variant cannot be applied reliably.
     */
    private static TestCase applyVariant(TestCase tc, String variantPayload) {
        String orig = tc.payload();
        if (orig == null || orig.isEmpty()) return null;
        boolean applied = false;

        String body = tc.body();
        if (body != null && body.contains(orig)) {
            body = body.replace(orig, variantPayload);
            applied = true;
        }
        String path = tc.path();
        if (path != null && path.contains(orig)) {
            path = path.replace(orig, variantPayload);
            applied = true;
        }
        Map<String, String> headers = tc.headers();
        if (headers != null) {
            Map<String, String> mutated = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : headers.entrySet()) {
                String val = e.getValue();
                if (val != null && val.contains(orig)) {
                    val = val.replace(orig, variantPayload);
                    applied = true;
                }
                mutated.put(e.getKey(), val);
            }
            headers = mutated;
        }
        if (!applied) return null;

        return new TestCase(tc.name() + " [WAF变体]", tc.category(), tc.targetParam(), variantPayload,
                tc.method(), path, headers, body, tc.description(),
                tc.expectedIfVulnerable(), tc.riskIfConfirmed());
    }

    /**
     * Stage 5.6: programmatic blind SQLi verification for AI-flagged
     * suspicious params. Boolean first (2 requests/param); timing only for
     * params boolean could not confirm. Request budget approximated by
     * config.maxBlindProbeRequests() (boolean=2, timing=up to 6 each).
     */
    private List<PayloadResult> executeBlindVerification(ApiEntry entry) {
        List<PayloadResult> out = new ArrayList<>();
        List<String> candidates = com.flechazo.apisentinel.detection.BlindParamMutator
                .candidateSqlParams(entry, 2);
        if (candidates.isEmpty()) return out;

        var booleanVerifier = new com.flechazo.apisentinel.detection.BooleanBlindVerifier(
                montoyaApi, logger, config.wafDetectionEnabled());
        var timingVerifier = new com.flechazo.apisentinel.detection.TimingBlindVerifier(
                montoyaApi, logger);
        int budget = config.maxBlindProbeRequests();

        for (String param : candidates) {
            if (budget < 2) break;
            String location = com.flechazo.apisentinel.detection.BlindParamMutator
                    .locateParam(entry, param);
            String value = originalParamValue(entry, param, location);
            budget -= 2;
            var b = booleanVerifier.verify(entry, param, location, value);
            out.add(toBlindPayloadResult("布尔盲注-" + param, param, b));
            if (b.confirmed() || b.wafBlocked()) continue;
            if (budget < 6) continue; // timing = 1 baseline + up to 5 DB attempts
            budget -= 6;
            var t = timingVerifier.verify(entry, param, location, value, "auto");
            out.add(toBlindPayloadResult("时序盲注-" + param, param, t));
        }
        return out;
    }

    /** Read the parameter's captured value (query or JSON body; "" elsewhere). */
    private static String originalParamValue(ApiEntry entry, String param, String location) {
        String raw = entry.getLastRawRequest();
        if (raw == null) return "";
        var params = com.flechazo.apisentinel.util.HttpMessageUtils
                .parseQueryParams(com.flechazo.apisentinel.util.HttpMessageUtils.requestTarget(raw));
        if (params.containsKey(param)) return params.get(param);
        var obj = com.flechazo.apisentinel.util.HttpMessageUtils
                .parseJsonObject(com.flechazo.apisentinel.util.HttpMessageUtils.bodyOf(raw));
        if (obj != null && obj.has(param) && obj.get(param).isJsonPrimitive()) {
            return obj.get(param).getAsString();
        }
        return "";
    }

    private static PayloadResult toBlindPayloadResult(String name, String param,
            com.flechazo.apisentinel.detection.BlindVerificationResult r) {
        TestCase tc = new TestCase(name, "盲注验证", param, r.detail(), "", "", null, "",
                "程序化盲注验证（布尔/时序）",
                r.confirmed() ? "程序化确认注入" : "未确认", "HIGH");
        return new PayloadResult(tc, r.sentRequest(), r.receivedResponse(), r.statusCode(),
                r.elapsedMs(), r.confirmed(), System.currentTimeMillis(), -1);
    }

    /**
     * Stage 5.7: safe-subset business-logic verification. Triggers derive from
     * the captured request: business field in JSON body → tamper/negative or
     * coupon replay; step/checkout-style path → step skip.
     */
    private List<PayloadResult> executeBusinessLogicVerification(ApiEntry entry) {
        List<PayloadResult> out = new ArrayList<>();
        var verifier = new com.flechazo.apisentinel.detection.BusinessLogicVerifier(montoyaApi, logger);
        String body = com.flechazo.apisentinel.util.HttpMessageUtils.bodyOf(entry.getLastRawRequest());
        String path = entry.getApiPath() == null ? "" : entry.getApiPath().toLowerCase();

        String bizField = com.flechazo.apisentinel.detection.BusinessLogicVerifier.guessBusinessField(body);
        if (bizField != null) {
            String fl = bizField.toLowerCase();
            boolean couponLike = fl.contains("coupon") || fl.contains("promo")
                    || fl.contains("voucher") || fl.contains("discount");
            var params = new com.flechazo.apisentinel.detection.BusinessLogicVerifier.Params();
            params.targetParam = bizField;
            if (couponLike) {
                out.add(toLogicPayloadResult(verifier.verify(
                        com.flechazo.apisentinel.detection.BusinessLogicVerifier.TestType.REPEAT_COUPON,
                        entry, params)));
            } else {
                var tamper = verifier.verify(
                        com.flechazo.apisentinel.detection.BusinessLogicVerifier.TestType.TAMPER_PRICE,
                        entry, params);
                out.add(toLogicPayloadResult(tamper));
                if (!tamper.confirmed()) {
                    out.add(toLogicPayloadResult(verifier.verify(
                            com.flechazo.apisentinel.detection.BusinessLogicVerifier.TestType.NEGATIVE_VALUE,
                            entry, params)));
                }
            }
        }
        if (path.contains("step") || path.contains("checkout") || path.contains("flow")) {
            var params = new com.flechazo.apisentinel.detection.BusinessLogicVerifier.Params();
            out.add(toLogicPayloadResult(verifier.verify(
                    com.flechazo.apisentinel.detection.BusinessLogicVerifier.TestType.STEP_SKIP,
                    entry, params)));
        }
        return out;
    }

    private static PayloadResult toLogicPayloadResult(
            com.flechazo.apisentinel.detection.BusinessLogicVerifier.LogicFlawResult r) {
        TestCase tc = new TestCase("业务逻辑-" + r.testType().name(), "业务逻辑", "",
                r.detail(), "", "", null, "", "程序化业务逻辑验证",
                r.confirmed() ? "程序化确认" : "未确认", "HIGH");
        return new PayloadResult(tc, r.sentRequest(), r.receivedResponse(), r.statusCode(),
                0, r.confirmed(), System.currentTimeMillis(), -1);
    }

    private List<PayloadResult> executePayloadsWithEngine(
            List<TestCase> cases, List<HttpRequest> requests, List<String> rawRequests,
            int baselineStatusCode, int baselineResponseLength, PipelineCallback callback) {

        int total = cases.size();
        List<PayloadResult> results = Collections.synchronizedList(new ArrayList<>());
        Map<String, Long> sendTimes = new ConcurrentHashMap<>();

        ResourcePool pool = ResourcePool.resourcePool()
                .withConcurrentRequestLimit(5)
                .withThrottle(Duration.ofMillis(200))
                .withMaxRetries(1);

        RequestEngineOptions options = RequestEngineOptions.requestEngineOptions()
                .withName("API-Sentinel Pipeline")
                .withResourcePool(pool);

        RequestExecutionEngine engine = montoyaApi.http().createRequestEngine(options);

        for (int i = 0; i < total; i++) {
            String label = String.valueOf(i);
            sendTimes.put(label, System.currentTimeMillis());
            engine.queue(requests.get(i), label);
        }

        logger.info("[Pipeline] RequestExecutionEngine 已入队 %d 个请求，并发限制=5", total);

        RequestExecution execution = engine.sendAll((result, exec) -> {
            int idx;
            try {
                idx = Integer.parseInt(result.label());
            } catch (NumberFormatException e) {
                return Retention.KEEP;
            }

            long elapsed = System.currentTimeMillis() - sendTimes.getOrDefault(result.label(), System.currentTimeMillis());
            TestCase tc = cases.get(idx);
            String rawReq = rawRequests.get(idx);

            int respStatusCode = 0;
            String responseStr = "";

            if (result.status() == RequestStatus.RESPONDED && result.requestResponse().response() != null) {
                respStatusCode = result.requestResponse().response().statusCode();
                responseStr = result.requestResponse().response().toString();
            }

            boolean anomaly = detectAnomaly(tc, baselineStatusCode, baselineResponseLength,
                    respStatusCode, responseStr, elapsed);
            WafDetector.WafDetectionResult waf = config.wafDetectionEnabled()
                    ? wafDetector.detect(responseStr, respStatusCode, elapsed) : WAF_DISABLED;

            PayloadResult pr = new PayloadResult(tc, rawReq, responseStr, respStatusCode, elapsed, anomaly,
                    sendTimes.getOrDefault(result.label(), System.currentTimeMillis()), idx,
                    waf.vendor(), waf.score());
            results.add(pr);

            callback.onPayloadExecuted(results.size(), total, tc.payload(), respStatusCode);
            callback.onPayloadResult(idx, pr);
            logger.info("[Pipeline] Payload %d/%d: %s -> %d (%dms) %s%s",
                    results.size(), total, tc.name(), respStatusCode, elapsed,
                    anomaly ? "[异常]" : "[正常]",
                    waf.isSuspected() ? "[WAF:" + (waf.vendor() != null ? waf.vendor() : "?") + "]" : "");

            return Retention.KEEP;
        }, Duration.ofSeconds(30));

        execution.lifetime().awaitCompletion();
        logger.info("[Pipeline] RequestExecutionEngine 完成，共 %d 个结果", results.size());
        return new ArrayList<>(results);
    }

    private List<PayloadResult> executePayloadsSerial(
            List<TestCase> cases, List<HttpRequest> requests, List<String> rawRequests,
            int baselineStatusCode, int baselineResponseLength, PipelineCallback callback) {

        List<PayloadResult> results = new ArrayList<>();
        int total = cases.size();

        for (int i = 0; i < total; i++) {
            try {
                long start = System.currentTimeMillis();
                HttpRequestResponse response = montoyaApi.http().sendRequest(requests.get(i));
                long elapsed = System.currentTimeMillis() - start;

                int respStatusCode = response.response() != null ? response.response().statusCode() : 0;
                String responseStr = response.response() != null ? response.response().toString() : "";

                boolean anomaly = detectAnomaly(cases.get(i), baselineStatusCode, baselineResponseLength,
                        respStatusCode, responseStr, elapsed);
                WafDetector.WafDetectionResult waf = config.wafDetectionEnabled()
                        ? wafDetector.detect(responseStr, respStatusCode, elapsed) : WAF_DISABLED;

                PayloadResult pr = new PayloadResult(cases.get(i), rawRequests.get(i), responseStr, respStatusCode, elapsed, anomaly,
                        start, i, waf.vendor(), waf.score());
                results.add(pr);

                callback.onPayloadExecuted(i + 1, total, cases.get(i).payload(), respStatusCode);
                callback.onPayloadResult(i, pr);
                logger.info("[Pipeline] Payload %d/%d: %s -> %d (%dms) %s%s",
                        i + 1, total, cases.get(i).name(), respStatusCode, elapsed,
                        anomaly ? "[异常]" : "[正常]",
                        waf.isSuspected() ? "[WAF:" + (waf.vendor() != null ? waf.vendor() : "?") + "]" : "");

                Thread.sleep(200);
            } catch (Exception e) {
                logger.warn("[Pipeline] Payload执行失败 #%d: %s", i + 1, e.getMessage());
            }
        }
        return results;
    }

    /**
     */
    private boolean detectAnomaly(TestCase tc, int baselineStatus, int baselineRespLen,
                                   int payloadStatus, String payloadResponse, long responseTimeMs) {
        // 1. Status code changes (significant ones)
        if (baselineStatus > 0 && payloadStatus != baselineStatus) {
            // Auth bypass: baseline was 403/401 but payload got 200
            if ((baselineStatus == 403 || baselineStatus == 401) && payloadStatus == 200) return true;
            // NOTE: a bare 5xx is NOT treated as an anomaly. A server error from a
            // payload is often just bad input handling / an internal crash / a
            // timeout — not a confirmed vuln. Flagging it as anomaly inflated the
            // verdict to HIGH/MEDIUM for mere error responses. Real vuln signals
            // (SQL error text, stack traces, reflected payloads, size/time anomalies)
            // are checked below; a 5xx alone is left for the LLM to weigh as at most
            // "suspected".
        }
        // (Removed: standalone `payloadStatus >= 500 -> true`; see note above.)

        String lower = payloadResponse.toLowerCase();

        // 2. SQL error indicators — precise DB-engine signatures to avoid
        // false positives where the response merely mentions "mysql"/"oracle"
        // (e.g. tech-stack descriptions, documentation). Bare substrings like
        // "ora-" also matched English words ("temporary"); ORA-\d{5} does not.
        if (containsSqlError(lower)) {
            return true;
        }

        // 3. Stack trace / debug info leak
        if (lower.contains("stack trace") || lower.contains("exception in thread")
                || lower.contains("traceback (most recent")
                || lower.contains("at com.") || lower.contains("at org.")
                || lower.contains("at java.") || lower.contains("at sun.")) {
            return true;
        }

        // 4. XSS reflection — encoding-aware. Catches payloads reflected
        // verbatim, URL-decoded (%3C → <), HTML-unescaped (&lt; → <), as well
        // as encoded payload variants. Reduces false negatives where the app
        // encodes the reflected payload.
        if (tc.payload() != null && !tc.payload().isEmpty()) {
            String payloadLower = tc.payload().toLowerCase();
            String urlDecoded = safeUrlDecode(lower);
            String htmlUnescaped = htmlUnescape(lower);
            if (lower.contains(payloadLower)
                    || urlDecoded.contains(payloadLower)
                    || htmlUnescaped.contains(payloadLower)) {
                return true;
            }
            // Encoded reflection of the payload itself
            String htmlEncPayload = payloadLower.replace("<", "&lt;").replace(">", "&gt;");
            if (!htmlEncPayload.equals(payloadLower) && lower.contains(htmlEncPayload)) return true;
            String urlEncPayload = payloadLower
                    .replace("<", "%3c").replace(">", "%3e")
                    .replace("\"", "%22").replace("'", "%27");
            if (!urlEncPayload.equals(payloadLower) && lower.contains(urlEncPayload)) return true;
        }
        // Common XSS probe markers (decoded form)
        if (lower.contains("<script>") && lower.contains("alert(")) return true;
        if (lower.contains("<img") && lower.contains("onerror")) return true;
        if (lower.contains("<svg") && lower.contains("onload")) return true;
        if (lower.contains("javascript:") && lower.contains("script")) return true;

        // 5. Response body size anomaly vs baseline — TWO bands:
        //   - large baseline (>500B): original loose band (ratio <0.3 or >2.0);
        //   - small baseline (30–500B, very common for REST endpoints that
        //     return e.g. {"found":true}): the signal is needed TOO — boolean-
        //     blind evidence on small responses (true→62B vs false→15B, ratio
        //     0.24) never registered as an anomaly, so every LLM confirmation
        //     of it got demoted by VerdictValidator. Small bases are noisy,
        //     so the "grew" direction is tightened (must nearly triple).
        int payloadBodyLen = bodyLength(payloadResponse);
        if (payloadBodyLen > 0 && baselineRespLen >= 30) {
            double ratio = (double) payloadBodyLen / baselineRespLen;
            if (baselineRespLen > 500) {
                if (ratio > 2.0 || ratio < 0.3) return true;
            } else {
                if (ratio > 3.0 || ratio < 0.3) return true;
            }
        }

        // 6. Time-based anomaly (potential blind injection — response >5x slower than expected)
        if (responseTimeMs > 10000) return true; // >10s suggests time-based injection

        // 7. Sensitive data patterns in response (SSRF indicators)
        if (lower.contains("root:x:0:") || lower.contains("/etc/passwd")
                || lower.contains("169.254.169.254") || lower.contains("metadata")
                || lower.contains("[boot loader]") || lower.contains("\\windows\\system32")) {
            return true;
        }

        return false;
    }

    /** Precise SQL error signatures per DB engine — avoids matching plain words. */
    private static boolean containsSqlError(String lower) {
        return lower.contains("you have an error in your sql syntax")
                || lower.contains("warning: mysqli")
                || lower.contains("mysqlexception")
                || lower.contains("com.mysql.jdbc")
                || lower.contains("pg::syntaxerror")
                || lower.contains("error: syntax error at")
                || lower.contains("psqlexception")
                || lower.contains("org.postgresql")
                // ORA-\d{5} (Oracle) — the digits avoid matching "oracle"/"temporary"
                || java.util.regex.Pattern.compile("ora-\\d{5}").matcher(lower).find()
                || lower.contains("pls-") && lower.contains("error")
                || lower.contains("sqlserver jdbc driver")
                || lower.contains("com.microsoft.sqlserver")
                || lower.contains("sqlite3::exception")
                || lower.contains("sqlstate[")
                || lower.contains("near \"\": syntax error")
                || lower.contains("sqlexception");
    }

    /** Tolerant URL-decode (%XX → char). Falls back to input on any error. */
    private static String safeUrlDecode(String s) {
        if (s == null || s.indexOf('%') < 0) return s;
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /** Minimal HTML entity unescape for the chars relevant to XSS reflection. */
    private static String htmlUnescape(String s) {
        if (s == null) return s;
        return s.replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", "\"").replace("&#39;", "'")
                .replace("&#x27;", "'").replace("&amp;", "&");
    }

    /** Length of the HTTP message body (after the blank line separating headers). */
    private static int bodyLength(String rawHttp) {
        if (rawHttp == null || rawHttp.isEmpty()) return 0;
        int idx = rawHttp.indexOf("\r\n\r\n");
        if (idx >= 0) return rawHttp.length() - (idx + 4);
        idx = rawHttp.indexOf("\n\n");
        if (idx >= 0) return rawHttp.length() - (idx + 2);
        return rawHttp.length();
    }

    // ======================== Stage 5: Authorization Bypass Testing ========================

    /**
     * Execute authorization bypass testing by discovering sessions from proxy history,
     * identifying auth parameters, and swapping them to detect access control flaws.
     */
    private AuthTestResult executeAuthTest(ApiEntry entry, PipelineCallback callback) {
        try {
            if (montoyaApi == null) {
                return AuthTestResult.skipped("Burp API 不可用");
            }

            // Step 1: Discover sessions from proxy history
            SessionDiscovery discovery = new SessionDiscovery(montoyaApi);
            List<SessionInfo> sessions = discovery.discoverSessions(entry);

            SessionInfo sessionA;
            SessionInfo sessionB;

            if (sessions.size() >= 2) {
                // Auto-discovery succeeded
                sessions.sort((a, b) -> Integer.compare(b.getRequests().size(), a.getRequests().size()));
                sessionA = sessions.get(0);
                sessionB = sessions.get(1);
                logger.info("[Pipeline] 鉴权测试: 自动发现 %d 个会话, 使用 %s 和 %s",
                        sessions.size(), sessionA.shortLabel("A"), sessionB.shortLabel("B"));
            } else if (config.hasManualSessions()) {
                // Fallback to manual session config
                logger.info("[Pipeline] 自动发现不足2个会话，使用手动配置的会话");
                callback.onStageStart(5, "使用手动配置的会话进行越权检测...");

                Map<String, String> cookiesA = SessionDiscovery.parseCookies(config.manualSessionACookie());
                Map<String, String> cookiesB = SessionDiscovery.parseCookies(config.manualSessionBCookie());
                sessionA = new SessionInfo("manual-A", cookiesA, Map.of());
                sessionB = new SessionInfo("manual-B", cookiesB, Map.of());

                // Manual sessions have no requests — need at least one from history for template
                if (!sessions.isEmpty()) {
                    for (var req : sessions.get(0).getRequests()) sessionA.addRequest(req);
                } else if (entry.hasTrafficData()) {
                    // No history sessions at all — can't build a template request
                    return AuthTestResult.skipped("手动配置了会话但未找到可用的请求模板，请先访问目标接口");
                }
            } else {
                return AuthTestResult.skipped(
                        String.format("仅发现 %d 个会话（需要至少2个不同会话才能进行鉴权对比测试）。"
                                + "可在「设置 → 越权配置」手动配置两组会话 Cookie，或使用不同账号访问相同接口后重试。",
                                sessions.size()));
            }

            // Step 2: Identify auth parameters
            List<String> authCookieKeys = AuthParamIdentifier.identifyAuthCookieKeys(sessionA, sessionB);
            List<String> authHeaderKeys = AuthParamIdentifier.identifyAuthHeaders(sessionA, sessionB);

            if (authCookieKeys.isEmpty() && authHeaderKeys.isEmpty()) {
                return AuthTestResult.skipped("两个会话之间未发现差异的鉴权参数（Cookie/Header值相同）");
            }

            logger.info("[Pipeline] 识别到鉴权参数 - Cookie keys: %s, Header keys: %s",
                    authCookieKeys, authHeaderKeys);

            callback.onStageStart(5, String.format("识别到 %d 个鉴权参数，开始交叉测试...",
                    authCookieKeys.size() + authHeaderKeys.size()));

            // Step 3: Execute the auth bypass test (with optional LLM
            // arbitration for gray-zone similarity results)
            AuthTestExecutor executor = new AuthTestExecutor(montoyaApi, provider,
                    config.aiAuthArbitrationEnabled());
            return executor.execute(sessionA, sessionB, authCookieKeys, authHeaderKeys);

        } catch (Exception e) {
            logger.error("[Pipeline] 鉴权测试异常: %s", e.getMessage());
            return AuthTestResult.skipped("执行异常: " + e.getMessage());
        }
    }

    // ======================== Stage 6: Final Assessment ========================

    /**
     * Also pushes raw AI response text for thinking process visibility.
     * Now includes Stage 5 auth test results for comprehensive verdict.
     */
    private FinalVerdict finalAssessment(ApiEntry entry, AnalysisResult trafficAnalysis,
                                          String sourceCode, List<TestCase> testCases,
                                          List<PayloadResult> payloadResults,
                                          AuthTestResult authTestResult,
                                          PipelineCallback callback) {
        try {
            String systemPrompt = FinalVerdictPrompt.getSystemPrompt();
            String baselineResponse = entry.getLastRawResponse();
            String userPrompt = FinalVerdictPrompt.buildUserPrompt(
                    entry.getHttpMethod(), entry.getApiPath(), entry.getDomain(),
                    trafficAnalysis, sourceCode, testCases, payloadResults,
                    baselineResponse, authTestResult);

            LlmRequest request = new LlmRequest(systemPrompt, userPrompt, 4096);
            LlmResponse response = provider.complete(request).get(STAGE6_TIMEOUT_SEC, TimeUnit.SECONDS);

            if (!response.isSuccess()) {
                logger.error("[Pipeline] 阶段6 AI响应失败: %s", response.errorMessage());
                return fallbackVerdict(trafficAnalysis, payloadResults, response.totalTokens());
            }

            // Push raw AI verdict response as thinking output
            if (callback != null) {
                callback.onAiThinkingOutput(6, "AI综合研判",
                        "**AI 研判原始推理：**\n\n```json\n" + response.content() + "\n```\n\n"
                        + "*Token 消耗: " + response.totalTokens() + "*");
            }

            return parseVerdict(response.content(), response.totalTokens(), payloadResults, authTestResult);

        } catch (Exception e) {
            logger.error("[Pipeline] 阶段6失败: %s", describeException(e));
            return fallbackVerdict(trafficAnalysis, payloadResults, 0);
        }
    }

    /**
     * Cross-validates LLM-claimed confirmed vulns against real PayloadResults so
     * hallucinated findings (payload never sent, no anomaly) are downgraded to
     * suspected, and overall_risk=HIGH is only allowed with a surviving confirmed.
     */
    private FinalVerdict parseVerdict(String raw, int totalTokens, List<PayloadResult> payloadResults,
                                      AuthTestResult authTestResult) {
        JsonObject json = JsonExtractor.extract(raw);
        if (json == null) {
            logger.warn("[Pipeline] 阶段6返回非JSON格式，使用原文作为摘要");
            return new FinalVerdict("LOW", List.of(), List.of(), raw, "", totalTokens);
        }

        String overallRisk = JsonExtractor.getStr(json, "overall_risk", "SAFE");

        List<ConfirmedVuln> confirmed = new ArrayList<>();
        if (json.has("confirmed_vulns") && json.get("confirmed_vulns").isJsonArray()) {
            JsonArray arr = json.getAsJsonArray("confirmed_vulns");
            for (var elem : arr) {
                if (!elem.isJsonObject()) continue;
                JsonObject v = elem.getAsJsonObject();
                confirmed.add(new ConfirmedVuln(
                        JsonExtractor.getStr(v, "type", "UNKNOWN"),
                        JsonExtractor.getStr(v, "title", ""),
                        JsonExtractor.getStr(v, "evidence", ""),
                        JsonExtractor.getStr(v, "payload_used", ""),
                        JsonExtractor.getStr(v, "response_snippet", ""),
                        JsonExtractor.getStr(v, "verify_command", ""),
                        JsonExtractor.getStr(v, "identity_proof", ""),
                        JsonExtractor.getStr(v, "cvss", "")
                ));
            }
        }

        List<SuspectedVuln> suspected = new ArrayList<>();
        if (json.has("suspected_vulns") && json.get("suspected_vulns").isJsonArray()) {
            JsonArray arr = json.getAsJsonArray("suspected_vulns");
            for (var elem : arr) {
                if (!elem.isJsonObject()) continue;
                JsonObject v = elem.getAsJsonObject();
                suspected.add(new SuspectedVuln(
                        JsonExtractor.getStr(v, "type", "UNKNOWN"),
                        JsonExtractor.getStr(v, "title", ""),
                        JsonExtractor.getStr(v, "reason", ""),
                        JsonExtractor.getStr(v, "verify_command", ""),
                        "MEDIUM",
                        JsonExtractor.getStr(v, "escalation_path", "")
                ));
            }
        }

        String summary = JsonExtractor.getStr(json, "summary", "");
        String recommendations = JsonExtractor.getStr(json, "recommendations", "");

        return VerdictValidator.validate(overallRisk, confirmed, suspected,
                summary, recommendations, totalTokens, payloadResults, true, authTestResult);
    }

    /**
     * Only upgrades to MEDIUM if there are confirmed anomalies with payload evidence.
     */
    private FinalVerdict fallbackVerdict(AnalysisResult trafficAnalysis, List<PayloadResult> payloadResults, int tokens) {
        // Default to LOW, not MEDIUM
        String risk = "LOW";

        // Only upgrade if traffic analysis found HIGH risk AND payloads confirmed anomalies
        if (trafficAnalysis != null && trafficAnalysis.overallRisk() == AnalysisResult.RiskLevel.HIGH) {
            long anomalyCount = payloadResults.stream().filter(PayloadResult::anomalyDetected).count();
            if (anomalyCount > 0) {
                risk = "MEDIUM"; // only upgrade when BOTH analysis and payload suggest issues
            }
        }

        String summary = trafficAnalysis != null && trafficAnalysis.summary() != null
                ? trafficAnalysis.summary() + " (AI综合研判未完成，仅基于流量分析结果)"
                : "AI综合研判未完成，请检查AI服务配置";

        return new FinalVerdict(risk, List.of(), List.of(), summary, "", tokens);
    }

    // ======================== Utilities ========================

    private String buildStage1DetailText(AnalysisResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("风险等级: ").append(result.overallRisk()).append("\n");
        if (result.summary() != null && !result.summary().isEmpty()) {
            sb.append("分析摘要: ").append(result.summary()).append("\n");
        }
        if (!result.findings().isEmpty()) {
            sb.append("发现 ").append(result.findings().size()).append(" 项:\n");
            int i = 1;
            for (var f : result.findings()) {
                sb.append(i++).append(". [").append(f.risk()).append("] ").append(f.title())
                        .append(" (").append(f.type()).append(")\n");
                if (f.evidence() != null && !f.evidence().isEmpty()) {
                    sb.append("   证据: ").append(truncate(f.evidence(), 200)).append("\n");
                }
            }
        } else {
            sb.append("未发现明显安全问题");
        }
        return sb.toString();
    }

    private String buildStage3DetailText(List<TestCase> testCases) {
        if (testCases.isEmpty()) return "未生成任何测试Payload";
        StringBuilder sb = new StringBuilder();
        sb.append("已生成 ").append(testCases.size()).append(" 个测试Payload:\n");
        int i = 1;
        for (TestCase tc : testCases) {
            sb.append(i++).append(". [").append(tc.category()).append("] ").append(tc.name())
                    .append(" (风险: ").append(tc.riskIfConfirmed()).append(")\n");
            if (tc.description() != null && !tc.description().isEmpty()) {
                sb.append("   思路: ").append(truncate(tc.description(), 150)).append("\n");
            }
        }
        return sb.toString();
    }

    private String buildStage4DetailText(List<PayloadResult> payloadResults) {
        if (payloadResults.isEmpty()) return "未执行任何Payload验证";
        StringBuilder sb = new StringBuilder();
        long anomalyCount = payloadResults.stream().filter(PayloadResult::anomalyDetected).count();
        sb.append("已验证 ").append(payloadResults.size()).append(" 个Payload，检测到 ")
                .append(anomalyCount).append(" 个异常响应:\n");
        int i = 1;
        for (PayloadResult pr : payloadResults) {
            sb.append(i++).append(". ").append(pr.testCase().name())
                    .append(" -> HTTP ").append(pr.statusCode())
                    .append(" (").append(pr.responseTimeMs()).append("ms)")
                    .append(pr.anomalyDetected() ? " ⚠ 异常" : "").append("\n");
        }
        return sb.toString();
    }

    /**
     * Build a compact "previous analysis" context block when this endpoint was
     * analyzed within the reuse window. Injecting the prior verdict lets the
     * model confirm/refine existing conclusions instead of re-deriving everything
     * from scratch, cutting repeated reasoning (and tokens). Returns "" when there
     * is no recent usable analysis (window=0 disables the feature).
     */
    private String buildPriorAnalysisContext(ApiEntry entry) {
        if (reuseWindowMinutes <= 0) return "";
        try {
            com.flechazo.apisentinel.model.AnalysisRecord latest = entry.getLatestAnalysisRecord();
            if (latest == null) return "";
            long ageMs = System.currentTimeMillis() - latest.timestamp();
            if (ageMs < 0 || ageMs > reuseWindowMinutes * 60_000L) return "";
            if (!latest.hasPipelineResult() || latest.pipelineResult().verdict() == null) return "";

            var verdict = latest.pipelineResult().verdict();
            StringBuilder sb = new StringBuilder();
            sb.append("## 上次分析结论（").append(reuseWindowMinutes).append(" 分钟内，作为已知起点，请确认/修正而非重新推导）\n");
            sb.append("总体风险: ").append(verdict.overallRisk()).append("\n");
            if (verdict.confirmedVulns() != null && !verdict.confirmedVulns().isEmpty()) {
                sb.append("已确认漏洞:\n");
                for (var cv : verdict.confirmedVulns()) {
                    sb.append("- [").append(cv.type()).append("] ").append(cv.title()).append("\n");
                }
            }
            if (verdict.suspectedVulns() != null && !verdict.suspectedVulns().isEmpty()) {
                sb.append("疑似漏洞:\n");
                for (var sv : verdict.suspectedVulns()) {
                    sb.append("- [").append(sv.type()).append("] ").append(sv.title()).append("\n");
                }
            }
            if (verdict.summary() != null && !verdict.summary().isBlank()) {
                String s = verdict.summary();
                sb.append("摘要: ").append(s.length() > 800 ? s.substring(0, 800) + "..." : s).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private String extractParameters(String body, String url) {
        StringBuilder params = new StringBuilder();
        if (url != null) {
            int queryIdx = url.indexOf('?');
            if (queryIdx > 0) {
                String queryStr = url.substring(queryIdx + 1);
                String annotated = annotateQueryParams(queryStr);
                params.append(annotated.length() > 400 ? annotated.substring(0, 400) + "..." : annotated);
            }
        }
        if (body != null && !body.isEmpty()) {
            String bodySnippet = body.length() > 500 ? body.substring(0, 500) + "...[截断]" : body;
            if (params.length() > 0) params.append("; ");
            params.append("Body: ").append(bodySnippet);
        }
        return params.toString();
    }

    /** Parse query string into per-param entries with inferred type hints. */
    private String annotateQueryParams(String query) {
        StringBuilder sb = new StringBuilder("Query: ");
        String[] pairs = query.split("&");
        boolean first = true;
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            String k = eq > 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 && eq < pair.length() - 1 ? pair.substring(eq + 1) : "";
            if (k.isEmpty()) continue;
            if (!first) sb.append(", ");
            first = false;
            sb.append(k).append("=").append(truncate(v, 40)).append(" [").append(inferParamType(v)).append("]");
        }
        return sb.toString();
    }

    private static String inferParamType(String v) {
        if (v == null || v.isEmpty()) return "string";
        if (v.matches("-?\\d+(\\.\\d+)?")) return "numeric";
        String low = v.toLowerCase();
        if (low.startsWith("http://") || low.startsWith("https://")) return "url";
        if (low.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}.*")) return "uuid";
        if (low.matches("^[12]\\d{3}-\\d{2}-\\d{2}.*")) return "date";
        if ("true".equals(low) || "false".equals(low)) return "boolean";
        if (low.contains("/") && !low.contains("://")) return "path?";
        if (v.contains("@") && v.contains(".")) return "email?";
        return "string";
    }

    private String truncate(String text, int maxLen) {
        if (text == null) return "";
        if (text.length() <= maxLen) return text;
        return text.substring(0, maxLen) + "...";
    }

    public void shutdown() {
        executor.shutdownNow();
        try {
            executor.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
