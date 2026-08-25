package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.queue.AnalysisTask;
import com.flechazo.apisentinel.ai.queue.AnalysisTask.AnalysisMode;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.event.AiAnalysisCompleteEvent;
import com.flechazo.apisentinel.event.ApiMatchedEvent;
import com.flechazo.apisentinel.event.ClusterHuntTriggerEvent;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.testgen.TestCaseService;
import com.flechazo.apisentinel.testgen.model.TestCase;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Agent auto-pilot controller. When enabled, automatically processes
 * matched APIs through the analysis pipeline: analyze -> generate test cases -> verify.
 * <p>
 * Also drives Controller-level <b>cascade hunting</b> (P2 of the
 * cluster-hunting upgrade, see payloads/chain-hunting.md): when a full
 * Pipeline/Agent analysis ends with VERIFIED confirmed vulns
 * (ClusterHuntTriggerEvent), the source endpoint's sibling routes (same
 * controller / same resource prefix, resolved from the code index) are
 * auto-queued for the same lightweight analysis. Cascades are governed by
 * their own sub-switch ({@code cascadeEnabled}) and are deliberately NOT
 * gated on the auto-mode toggle — a manual Pipeline/Agent run that confirms
 * a vuln cascades too, since spreading is that analysis' own follow-up,
 * while auto mode only governs passive traffic pickup. Cascades stay
 * read-only — the controller never sends requests; sibling requests are only
 * synthesized for analysis input. A {@link GoalState} budget + blocked breaker
 * bounds the storm (consecutive fruitless cascades trip it for the session).
 */
public class AgentController {

    private final AnalysisTaskQueue analysisQueue;
    private final EventBus eventBus;
    private final LlmProviderFactory providerFactory;
    private final LeveledLogger logger;
    /** Code index for sibling-route resolution; null (no repo configured)
     *  silently disables cascade hunting — the correct degradation. */
    private final CodeIndexService codeIndexService;

    // Toggle
    private volatile boolean enabled = false;
    /** Cascade hunting sub-switch — independent of the master auto-pilot
     *  toggle so users can run plain auto-analysis without sibling
     *  spreading. Defaults on (the GoalState breaker already bounds it). */
    private volatile boolean cascadeEnabled = true;
    private java.util.List<com.flechazo.apisentinel.event.EventBus.Subscription> subscriptions;

    // Rate limiting: max 1 auto-analysis per 5 seconds
    private static final long RATE_LIMIT_MS = 5000;
    private volatile long lastAnalysisTime = 0;

    // Configurable limits
    private volatile int maxConcurrentAnalyses = 3;
    private volatile int maxAutoVerifyPerApi = 3;

    // Cascade hunting: per-source cap mirrors the resolver's priority order
    // (same_controller first, write methods first) — the first N siblings are
    // the highest-value ones.
    private static final int MAX_CASCADE_PER_SOURCE = 10;
    private final GoalState goalState = new GoalState();
    /** dedupKey -> source apiPath, for outcomes flowing back into GoalState. */
    private final Map<String, String> cascadeOrigins = new ConcurrentHashMap<>();

    // Track which APIs have been auto-analyzed to avoid re-processing
    private final Set<String> processedApis = ConcurrentHashMap.newKeySet();
    private final AtomicInteger activeAnalyses = new AtomicInteger(0);

    // Stats
    private final AtomicInteger totalAutoAnalyzed = new AtomicInteger(0);
    private final AtomicInteger totalVulnsFound = new AtomicInteger(0);
    private final AtomicInteger totalVerified = new AtomicInteger(0);

    // Pending queue for rate limiting
    private final BlockingQueue<ApiMatchedEvent> pendingQueue = new LinkedBlockingQueue<>(100);
    private final ScheduledExecutorService scheduler;
    private final ExecutorService testGenPool;

    public AgentController(AnalysisTaskQueue analysisQueue,
                           EventBus eventBus,
                           LlmProviderFactory providerFactory,
                           CodeIndexService codeIndexService,
                           LeveledLogger logger) {
        this.analysisQueue = analysisQueue;
        this.eventBus = eventBus;
        this.providerFactory = providerFactory;
        this.codeIndexService = codeIndexService;
        this.logger = logger;

        // Subscribe to API matched events
        java.util.List<com.flechazo.apisentinel.event.EventBus.Subscription> subs = new java.util.ArrayList<>();
        subs.add(eventBus.subscribe(ApiMatchedEvent.class, this::onApiMatched));

        // Subscribe to analysis complete events for auto test-gen
        subs.add(eventBus.subscribe(AiAnalysisCompleteEvent.class, this::onAnalysisComplete));

        // Subscribe to verified-confirmation events for cascade hunting
        subs.add(eventBus.subscribe(ClusterHuntTriggerEvent.class, this::onClusterHuntTrigger));
        this.subscriptions = subs;

        // Scheduler for rate-limited processing
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-agent");
            t.setDaemon(true);
            return t;
        });

        this.testGenPool = Executors.newFixedThreadPool(3, r -> {
            Thread t = new Thread(r, "api-sentinel-agent-testgen");
            t.setDaemon(true);
            return t;
        });

        // Process pending queue every second
        scheduler.scheduleAtFixedRate(this::processPendingQueue, 1, 1, TimeUnit.SECONDS);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isCascadeEnabled() {
        return cascadeEnabled;
    }

    public void setCascadeEnabled(boolean cascadeEnabled) {
        this.cascadeEnabled = cascadeEnabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        if (enabled) {
            logger.info("[Agent] 自动模式已开启");
            eventBus.publish(new AgentStatusEvent(true, "Agent 自动模式已开启"));
        } else {
            logger.info("[Agent] 自动模式已关闭");
            eventBus.publish(new AgentStatusEvent(false, "Agent 自动模式已关闭"));
        }
    }

    public void setMaxConcurrentAnalyses(int max) {
        this.maxConcurrentAnalyses = max;
    }

    public void setMaxAutoVerifyPerApi(int max) {
        this.maxAutoVerifyPerApi = max;
    }

    private void onApiMatched(ApiMatchedEvent event) {
        if (!enabled) return;

        ApiEntry entry = event.entry();

        // (which HttpTrafficHandler populates with all headers via HttpMessageUtils).
        // Only fall back to a basic stub if the event somehow doesn't carry them.
        if (entry.getLastRawRequest() == null || entry.getLastRawRequest().isEmpty()) {
            if (event.rawRequest() != null && !event.rawRequest().isEmpty()) {
                // Best path: use the complete raw request from the event (includes all headers)
                entry.setLastRawRequest(event.rawRequest());
            } else {
                // Fallback: construct a basic request (will lack auth headers)
                StringBuilder rawReq = new StringBuilder();
                rawReq.append(event.method()).append(" ").append(event.url()).append(" HTTP/1.1\r\n");
                rawReq.append("Host: ").append(entry.getDomain()).append("\r\n");
                if (event.requestBody() != null && !event.requestBody().isEmpty()) {
                    rawReq.append("Content-Length: ")
                            .append(event.requestBody().getBytes(java.nio.charset.StandardCharsets.UTF_8).length)
                            .append("\r\n\r\n");
                    rawReq.append(event.requestBody());
                } else {
                    rawReq.append("\r\n");
                }
                entry.setLastRawRequest(rawReq.toString());
            }
        }
        if ((entry.getLastRawResponse() == null || entry.getLastRawResponse().isEmpty())) {
            if (event.rawResponse() != null && !event.rawResponse().isEmpty()) {
                entry.setLastRawResponse(event.rawResponse());
            } else if (event.responseBody() != null) {
                entry.setLastRawResponse(event.responseBody());
            }
        }
        if (entry.getLastUrl() == null || entry.getLastUrl().isEmpty()) {
            entry.setLastUrl(event.url());
        }
        if (entry.getLastStatusCode() == 0) {
            entry.setLastStatusCode(event.statusCode());
        }

        // Skip if already processed (method-scoped: GET /x and POST /x are
        // distinct attack surfaces and must be analyzed separately)
        String key = dedupKey(event.method(), entry.getApiPath());
        if (processedApis.contains(key)) return;

        // Queue for rate-limited processing
        pendingQueue.offer(event);
    }

    private void processPendingQueue() {
        // Cascade siblings are exempt from the auto-mode gate: manual analyses
        // queue them even while auto mode is off. Plain traffic events that
        // were ALREADY queued (auto mode flipped off mid-run) stay untouched —
        // nothing is dropped by the gate. (New traffic never reaches this
        // queue while auto mode is off: onApiMatched drops it at the
        // entrance.)
        //
        // Selection happens WITHOUT removing: the rate-limit / concurrency
        // gates below can still veto this tick, and a vetoed event must keep
        // its queue position. With auto mode off and a stale plain event at
        // the head, scan PAST it to the first cascade sibling — cascades must
        // not starve behind a plain event they cannot displace.
        ApiMatchedEvent candidate = null;
        boolean candidateIsHead = false;
        ApiMatchedEvent head = pendingQueue.peek();
        if (head != null) {
            boolean headIsCascade = cascadeOrigins.containsKey(
                    dedupKey(head.method(), head.entry().getApiPath()));
            if (enabled || headIsCascade) {
                candidate = head;
                candidateIsHead = true;
            } else {
                for (ApiMatchedEvent e : pendingQueue) {
                    if (cascadeOrigins.containsKey(
                            dedupKey(e.method(), e.entry().getApiPath()))) {
                        candidate = e;
                        break;
                    }
                }
            }
        }
        if (candidate == null) return;

        long now = System.currentTimeMillis();
        if (now - lastAnalysisTime < RATE_LIMIT_MS) return;
        if (activeAnalyses.get() >= maxConcurrentAnalyses) return;

        ApiMatchedEvent event;
        if (candidateIsHead) {
            event = pendingQueue.poll();
        } else {
            // Reference equality (ApiEntry has no equals override) removes
            // exactly the candidate found above. Single consumer thread, so
            // nothing else can have removed it between scan and here.
            pendingQueue.remove(candidate);
            event = candidate;
        }
        if (event == null) return;

        String key = dedupKey(event.method(), event.entry().getApiPath());
        if (processedApis.contains(key)) return;

        processedApis.add(key);
        lastAnalysisTime = now;
        activeAnalyses.incrementAndGet();

        logger.info("[Agent] 自动分析: %s %s", event.method(), event.entry().getApiPath());
        eventBus.publish(new AgentProgressEvent(
                "analyzing", event.entry().getApiPath(),
                "正在自动分析 " + event.entry().getApiPath()));

        // Use real traffic data from the entry (stored by onApiMatched or HttpTrafficHandler)
        ApiEntry agentEntry = event.entry();
        String realRequest = agentEntry.getLastRawRequest();
        String realResponse = agentEntry.getLastRawResponse();

        if (realRequest == null) realRequest = "";
        if (realResponse == null) realResponse = "";

        AnalysisTask task = new AnalysisTask(
                agentEntry,
                event.method(),
                event.url(),
                agentEntry.getDomain(),
                realRequest,
                event.statusCode(),
                realResponse,
                "", // source code will be filled if available
                AnalysisTask.AnalysisScope.STANDARD,
                AnalysisMode.COMPREHENSIVE
        );

        boolean submitted = analysisQueue.submit(task);
        if (!submitted) {
            activeAnalyses.decrementAndGet();
            logger.warn("[Agent] 分析队列已满，跳过: %s", key);
        } else {
            totalAutoAnalyzed.incrementAndGet();
        }
    }

    private void onAnalysisComplete(AiAnalysisCompleteEvent event) {
        ApiEntry entry = event.entry();
        AnalysisResult result = event.result();

        // The auto-mode gate applies to plain traffic analyses only. A
        // cascaded sibling's completion must ALWAYS be bookkept (concurrency
        // slot + breaker outcome) even if the user flipped auto mode off
        // mid-flight — otherwise the slot leaks and the breaker goes blind.
        String key = dedupKey(event.method(), entry.getApiPath());
        boolean isCascadeOrigin = cascadeOrigins.containsKey(key);
        if (!enabled && !isCascadeOrigin) return;

        // Only process if this was an agent-initiated analysis (method-scoped)
        if (!processedApis.contains(key)) return;

        // Guard against double-decrement: a MANUAL analysis of a key that was
        // auto-analyzed earlier also lands here (same event type, no source
        // marker) and would drive the counter negative, permanently
        // shrinking the concurrency budget for the rest of the session.
        activeAnalyses.updateAndGet(n -> n > 0 ? n - 1 : 0);

        if (!result.isSuccess() || result.findings().isEmpty()) {
            recordCascadeOutcomeIfAny(event.method(), entry.getApiPath(), false);
            eventBus.publish(new AgentProgressEvent(
                    "done", entry.getApiPath(),
                    "分析完成，未发现漏洞: " + entry.getApiPath()));
            return;
        }

        // Count findings
        int highMedCount = 0;
        for (VulnFinding f : result.findings()) {
            if ("HIGH".equalsIgnoreCase(f.risk()) || "MEDIUM".equalsIgnoreCase(f.risk())) {
                highMedCount++;
            }
        }
        totalVulnsFound.addAndGet(result.findings().size());

        // A cascaded endpoint feeding back into the GoalState breaker
        recordCascadeOutcomeIfAny(event.method(), entry.getApiPath(), highMedCount > 0);

        logger.info("[Agent] 发现 %d 个漏洞 (%d HIGH/MEDIUM): %s",
                result.findings().size(), highMedCount, entry.getApiPath());

        eventBus.publish(new AgentProgressEvent(
                "findings", entry.getApiPath(),
                String.format("发现 %d 个漏洞，正在生成测试用例...", result.findings().size())));

        // Auto-generate test cases if there are HIGH/MEDIUM findings
        if (highMedCount > 0) {
            autoGenerateTestCases(entry);
        }
    }

    /** Feeds a finished analysis back into the cascade breaker when the
     *  endpoint was a cascaded one. Must run BEFORE the cascadeOrigins entry
     *  is removed so exactly one outcome is recorded per cascaded endpoint. */
    private void recordCascadeOutcomeIfAny(String method, String apiPath, boolean foundNewVuln) {
        String key = dedupKey(method, apiPath);
        if (cascadeOrigins.remove(key) == null) return;
        boolean newlyBlocked = goalState.recordCascadeOutcome(foundNewVuln);
        logger.info("[Agent] 级联分析完成: %s -> %s (%s)",
                key, foundNewVuln ? "有新发现" : "无新发现", goalState.describe());
        if (newlyBlocked) {
            eventBus.publish(new AgentProgressEvent("cascade_blocked", apiPath,
                    "级联狩猎已熔断：连续 " + GoalState.BLOCKED_STREAK_THRESHOLD
                            + " 个兄弟端点无新发现，本轮级联不再扩散"));
        }
    }

    /**
     * Cascade hunting trigger: a full Pipeline/Agent analysis ended with
     * VERIFIED confirmed vulns (the trigger is never published for
     * suspected-only results). Queues the source endpoint's sibling routes
     * for the same lightweight auto-analysis — read-only: synthesized
     * sibling requests only feed the analyzer, nothing is ever sent.
     *
     * <p>NOT gated on {@code enabled}: manual runs cascade too (cascade is
     * the analysis' own follow-up, not part of passive traffic pickup).
     */
    private void onClusterHuntTrigger(ClusterHuntTriggerEvent event) {
        if (!cascadeEnabled) return;
        if (codeIndexService == null) {
            // Visible degradation instead of a silent no-op — the user just
            // confirmed a vuln and expects spreading; tell them why not.
            eventBus.publish(new AgentProgressEvent("cascade", event.entry().getApiPath(),
                    "确认漏洞，但未索引代码仓库，级联跳过"));
            return;
        }

        ApiEntry source = event.entry();
        FinalVerdict verdict = event.verdict();
        if (verdict == null || verdict.confirmedVulns() == null || verdict.confirmedVulns().isEmpty()) {
            return; // defensive: suspected-only must never cascade
        }
        if (!goalState.shouldCascade()) {
            logger.info("[Agent] 跳过级联 (%s): %s",
                    goalState.isBlocked() ? "已熔断" : "预算耗尽", source.getApiPath());
            return;
        }

        List<SiblingRouteResolver.CascadeTarget> targets = SiblingRouteResolver.resolveCascadeTargets(
                codeIndexService, event.method(), source.getApiPath(), MAX_CASCADE_PER_SOURCE);
        if (targets.isEmpty()) return;

        int granted = goalState.grantQuota(targets.size());
        if (granted <= 0) return;

        int queued = 0;
        for (int i = 0; i < granted; i++) {
            SiblingRouteResolver.CascadeTarget t = targets.get(i);
            String key = dedupKey(t.httpMethod(), t.concretePath());
            if (processedApis.contains(key)) continue;

            ApiEntry sibling = new ApiEntry(t.httpMethod(), t.concretePath());
            sibling.setDomain(source.getDomain());
            String url = buildSiblingUrl(source.getLastUrl(), t.concretePath());
            sibling.setLastUrl(url);
            // The source's captured request with its request-line rewritten —
            // keeps auth headers/body so the write-method escalation targets
            // get analyzed with real credentials context. Analysis input only.
            String rawReq = rewriteRequestLine(source.getLastRawRequest(), t.httpMethod(),
                    url != null ? url : t.concretePath());
            sibling.setLastRawRequest(rawReq);
            cascadeOrigins.put(key, source.getApiPath());
            pendingQueue.offer(new ApiMatchedEvent(sibling, url, t.httpMethod(),
                    "", "", 0, rawReq, ""));
            queued++;
        }

        if (queued > 0) {
            logger.info("[Agent] 集群级联: %s 确认 %d 个漏洞 -> 入队 %d 个兄弟端点 (%s)",
                    source.getApiPath(), verdict.confirmedVulns().size(), queued, goalState.describe());
            eventBus.publish(new AgentProgressEvent("cascade", source.getApiPath(),
                    String.format("确认漏洞 → 级联狩猎：已入队 %d 个兄弟端点", queued)));
        }
    }

    /** Absolute URL for a cascaded sibling: reuse the source URL's scheme/
     *  host/query, swap in the sibling's concrete path. */
    private static String buildSiblingUrl(String sourceUrl, String concretePath) {
        if (sourceUrl == null || sourceUrl.isEmpty()) return concretePath;
        int schemeEnd = sourceUrl.indexOf("://");
        if (schemeEnd < 0) return concretePath;
        int pathStart = sourceUrl.indexOf('/', schemeEnd + 3);
        String origin = pathStart > 0 ? sourceUrl.substring(0, pathStart) : sourceUrl;
        int queryIdx = sourceUrl.indexOf('?');
        String query = queryIdx >= 0 ? sourceUrl.substring(queryIdx) : "";
        return origin + concretePath + query;
    }

    /** Replaces the request line (method + path) of a captured raw request,
     *  keeping every header and the body — cascade siblings get analyzed
     *  with the source's real auth context. */
    private static String rewriteRequestLine(String rawRequest, String method, String path) {
        if (rawRequest == null || rawRequest.isEmpty()) return "";
        int lineEnd = rawRequest.indexOf('\n');
        String rest = lineEnd >= 0 ? rawRequest.substring(lineEnd + 1) : "";
        return method + " " + path + " HTTP/1.1\n" + rest;
    }

    private void autoGenerateTestCases(ApiEntry entry) {
        testGenPool.submit(() -> {
            try {
                LlmProvider provider = providerFactory.getFirstAvailable();
                if (provider == null) {
                    logger.warn("[Agent] 无可用 LLM Provider，跳过测试用例生成");
                    return;
                }

                String params = "";
                String lastUrl = entry.getLastUrl();
                if (lastUrl != null && lastUrl.contains("?")) {
                    params = "Query: " + lastUrl.substring(lastUrl.indexOf('?') + 1);
                }
                String rawReq = entry.getLastRawRequest();
                if (rawReq != null && !rawReq.isEmpty()) {
                    // Extract body from raw request (after blank line)
                    int bodyStart = rawReq.indexOf("\r\n\r\n");
                    if (bodyStart < 0) bodyStart = rawReq.indexOf("\n\n");
                    if (bodyStart >= 0) {
                        String body = rawReq.substring(bodyStart).trim();
                        if (!body.isEmpty()) {
                            if (!params.isEmpty()) params += "; ";
                            params += "Body: " + (body.length() > 500 ? body.substring(0, 500) : body);
                        }
                    }
                }

                TestCaseService testCaseService = new TestCaseService(provider, logger);
                List<TestCase> cases = testCaseService.generate(
                        entry.getHttpMethod(), entry.getApiPath(),
                        entry.getDomain(), params, "" // source code not available in Agent mode
                ).get(120, TimeUnit.SECONDS);

                if (cases.isEmpty()) {
                    logger.info("[Agent] 未生成测试用例: %s", entry.getApiPath());
                    return;
                }

                logger.info("[Agent] 生成 %d 个测试用例: %s", cases.size(), entry.getApiPath());
                totalVerified.addAndGet(Math.min(cases.size(), maxAutoVerifyPerApi));

                eventBus.publish(new AgentProgressEvent(
                        "testgen_complete", entry.getApiPath(),
                        String.format("已生成 %d 个测试用例", cases.size())));

            } catch (Exception e) {
                logger.debug("[Agent] 测试用例生成失败: %s", e.getMessage());
            }
        });
    }

    // --- Stats accessors ---

    public int getTotalAutoAnalyzed() { return totalAutoAnalyzed.get(); }
    public int getTotalVulnsFound() { return totalVulnsFound.get(); }
    public int getTotalVerified() { return totalVerified.get(); }
    public int getPendingCount() { return pendingQueue.size(); }
    public int getProcessedCount() { return processedApis.size(); }

    /** Cascade-hunting state for UI display. */
    public GoalState getGoalState() { return goalState; }

    /** Method-scoped dedup key: "METHOD path" so GET /x and POST /x are distinct. */
    private static String dedupKey(String method, String apiPath) {
        return (method != null ? method : "") + " " + (apiPath != null ? apiPath : "");
    }

    public void shutdown() {
        enabled = false;
        // Unsubscribe EventBus listeners so a re-load of the extension cannot
        // leave stale listeners producing duplicate processing.
        if (subscriptions != null) {
            subscriptions.forEach(com.flechazo.apisentinel.event.EventBus.Subscription::unsubscribe);
            subscriptions.clear();
        }
        scheduler.shutdownNow();
        testGenPool.shutdownNow();
        try {
            scheduler.awaitTermination(3, TimeUnit.SECONDS);
            testGenPool.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    // --- Agent events ---

    public record AgentStatusEvent(boolean enabled, String message) {}
    public record AgentProgressEvent(String phase, String apiPath, String message) {}
}
