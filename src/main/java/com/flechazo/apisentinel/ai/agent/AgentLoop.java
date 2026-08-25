package com.flechazo.apisentinel.ai.agent;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.agent.tool.*;
import com.flechazo.apisentinel.ai.pipeline.*;
import com.flechazo.apisentinel.ai.provider.*;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.detection.OobService;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.testgen.model.TestCase;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * ReAct 自主工具循环——Agent 模式的核心引擎。LLM 自主选择工具调用，每步推理可见，
 * 终止于 submit_report（通过门禁）或 50 轮安全断路器。支持扩展思考、上下文压缩、
 * 重复批次熔断、并行只读工具、协作式取消。
 *
 * @see AgentController
 * @see com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry
 */
public class AgentLoop {

    /** Safety-net circuit breaker, not a target to run toward. A normal
     *  single-endpoint analysis should finish well before this; hitting it
     *  means the model is stuck (e.g. looping on the same tool) and needs to
     *  be cut off rather than run indefinitely. Public so UI progress code
     *  (AgentFacade, AiAnalysisPanel) can size its progress bar against the
     *  real cap instead of guessing a separate, inevitably-inconsistent number. */
    public static final int MAX_ITERATIONS = 50;
    private static final int MAX_TOKENS_PER_TURN = 16384;
    private static final double TEMPERATURE = 0.3;
    /** Tool results kept fully intact; older ones are compacted. */
    private static final int KEEP_RECENT_TOOL_RESULTS = 15;
    /** Retry attempts on RATE_LIMITED before giving up. */
    private static final int RATE_LIMIT_RETRIES = 2;
    /** Extended-thinking budget requested per turn when the provider supports
     *  it (Claude). Must stay below MAX_TOKENS_PER_TURN with headroom for the
     *  actual tool call/text output — see ClaudeProvider.resolveThinkingBudget. */
    private static final int THINKING_BUDGET_TOKENS = 6000;

    /** Read-only tools with no side effects on each other or on shared session
     *  state — safe to execute concurrently when the model returns several of
     *  them in one response. Anything that sends a request, calls an LLM, or
     *  mutates cross-tool state (generate_payloads, submit_report, etc.) is
     *  deliberately excluded and always runs sequentially. */
    private static final Set<String> PARALLELIZABLE_TOOLS = Set.of(
            "read_file", "grep_repo", "search_source_code", "search_traffic",
            "find_definition", "find_callers", "fingerprint_components",
            "heuristic_scan", "list_sessions", "map_sibling_endpoints");

    private final LlmProvider provider;
    private final MontoyaApi montoyaApi;
    private final CodeIndexService codeIndexService;
    private final PipelineConfig pipelineConfig;
    private final List<CodeRepo> codeRepos;
    private final LeveledLogger logger;
    private final OobService oobService;
    /** Success-pattern memory (P3); null disables injection — each new
     *  analysis then starts from scratch exactly as before. */
    private final com.flechazo.apisentinel.ai.patterns.PatternStore patternStore;
    private final ExecutorService executor;
    private final ExecutorService toolExecutor;
    /** Optional UI bridge for tools that need to ask the operator (sandbox
     *  confirm / ask_user). Null = headless, tools degrade gracefully. */
    private final com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge userInteractionBridge;
    /** Cooperative cancel: set by cancel(), checked between iterations and
     *  tool batches; cancel() also interrupts the loop thread so a blocked
     *  LLM future.get()/sleep bails out promptly. */
    private volatile boolean cancelled = false;
    private volatile Thread loopThread = null;

    public interface AgentCallback {
        void onAgentThinking(String thought);
        void onToolCall(String toolName, String args);
        void onToolResult(String toolName, String result);
        void onAgentComplete(PipelineResult result);
        void onAgentError(String error);
        void onIterationComplete(int iteration, int maxIterations);
        /** Called immediately after generate_payloads produces new test cases. */
        default void onTestCasesGenerated(List<TestCase> allCases) {}
        /** Called immediately after send_request produces a new result. */
        default void onPayloadResultReady(PayloadResult result, int resultIndex) {}
    }

    public AgentLoop(LlmProvider provider, MontoyaApi montoyaApi,
                     CodeIndexService codeIndexService, PipelineConfig pipelineConfig,
                     List<CodeRepo> codeRepos, LeveledLogger logger,
                     OobService oobService) {
        this(provider, montoyaApi, codeIndexService, pipelineConfig, codeRepos,
                logger, oobService, null, null);
    }

    public AgentLoop(LlmProvider provider, MontoyaApi montoyaApi,
                     CodeIndexService codeIndexService, PipelineConfig pipelineConfig,
                     List<CodeRepo> codeRepos, LeveledLogger logger,
                     OobService oobService,
                     com.flechazo.apisentinel.ai.patterns.PatternStore patternStore) {
        this(provider, montoyaApi, codeIndexService, pipelineConfig, codeRepos,
                logger, oobService, patternStore, null);
    }

    public AgentLoop(LlmProvider provider, MontoyaApi montoyaApi,
                     CodeIndexService codeIndexService, PipelineConfig pipelineConfig,
                     List<CodeRepo> codeRepos, LeveledLogger logger,
                     OobService oobService,
                     com.flechazo.apisentinel.ai.patterns.PatternStore patternStore,
                     com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge userInteractionBridge) {
        this.provider = provider;
        this.montoyaApi = montoyaApi;
        this.codeIndexService = codeIndexService;
        this.pipelineConfig = pipelineConfig;
        this.codeRepos = codeRepos;
        this.logger = logger;
        this.oobService = oobService;
        this.patternStore = patternStore;
        this.userInteractionBridge = userInteractionBridge;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-agent-loop");
            t.setDaemon(true);
            return t;
        });
        this.toolExecutor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "api-sentinel-agent-tool-parallel");
            t.setDaemon(true);
            return t;
        });
    }

    public CompletableFuture<PipelineResult> execute(ApiEntry entry, AgentCallback callback) {
        return CompletableFuture.supplyAsync(() -> runLoop(entry, callback), executor);
    }

    /** Request cooperative cancellation. The loop finishes its current atomic
     *  step (or gets interrupted out of a blocking wait), then completes with a
     *  fallback result built from whatever evidence it already collected —
     *  partial data is still persisted and reported, it is not lost. */
    public void cancel() {
        cancelled = true;
        Thread t = loopThread;
        if (t != null) t.interrupt();
    }

    /** True once cancel() has been called — lets UI completion handlers tell
     *  "user stopped it" apart from a natural finish. */
    public boolean isCancelled() { return cancelled; }

    private PipelineResult runLoop(ApiEntry entry, AgentCallback callback) {
        loopThread = Thread.currentThread();
        try {
        ToolContext toolCtx = new ToolContext(entry, provider, montoyaApi,
                codeIndexService, codeRepos, pipelineConfig, logger, oobService);
        if (userInteractionBridge != null) {
            toolCtx.setUserInteractionBridge(userInteractionBridge);
        }

        // Register tools — single shared builder (StandardToolRegistry) so this
        // stays in sync with the two chat-mode tool-calling loops in AiPresenter.
        StandardToolRegistry.Tools tools = StandardToolRegistry.build(toolCtx, true);
        AgentToolRegistry registry = tools.registry();
        AnalyzeTrafficTool analyzeTool = tools.analyzeTool();
        SearchSourceCodeTool codeTool = tools.codeTool();
        GeneratePayloadsTool genTool = tools.genTool();
        SendRequestTool sendTool = tools.sendTool();
        AuthBypassTool authTool = tools.authTool();
        SubmitReportTool reportTool = tools.reportTool();

        // Build initial messages
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(ChatMessage.system(buildSystemPrompt()));
        messages.add(ChatMessage.user(buildInitialUserMessage(entry)));

        List<ToolDefinition> toolDefs = registry.getDefinitions();
        int totalTokensUsed = 0;
        Map<Integer, String> stageDescriptions = new LinkedHashMap<>();

        // Reflection tracking: detect when the Agent is stuck
        int consecutiveNoAnomaly = 0;
        int consecutiveWafBlocks = 0;
        int lastReflectionIteration = -1;
        // Generic stuck-loop guard: fires on ANY repeated identical tool-call
        // batch, unlike the pattern-specific reflection triggers below.
        RepeatCallDetector repeatDetector = new RepeatCallDetector();

        try {
            for (int iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
                if (cancelled) {
                    return completeCancelled(entry, callback, analyzeTool, codeTool, genTool,
                            sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
                }
                logger.info("[Agent] 迭代 %d/%d 开始", iteration + 1, MAX_ITERATIONS);

                // Soft reminder only on the actual last iteration — the loop is
                // otherwise left to pace itself; this is not meant to fire in
                // normal single-endpoint analysis.
                if (iteration == MAX_ITERATIONS - 1) {
                    messages.add(ChatMessage.user(
                            "提示：已进行较多轮分析。如证据已经足够支撑结论，请调用 submit_report 提交；"
                          + "如确实还需要验证，这是最后一轮机会。"));
                }

                // Drop stale extended-thinking blocks BEFORE the budget estimate.
                // Anthropic only requires them echoed back on the turn right
                // after the assistant message that produced them; older turns
                // may drop them. Left alone they ride along forever (compactPass
                // only reclaims tool results) and grow to dominate the context.
                stripStaleThinkingBlocks(messages);

                // Compact oversized old tool results before building the request
                // so the conversation does not silently exceed the model's
                // context window (which would cause truncation or API errors).
                compactIfNeeded(messages);

                LlmRequest request = new LlmRequest(messages, toolDefs, TEMPERATURE, MAX_TOKENS_PER_TURN);
                if (provider.supportsExtendedThinking()) {
                    request = request.withThinking(THINKING_BUDGET_TOKENS);
                }
                LlmResponse response;
                try {
                    response = completeWithRateLimitRetry(provider, request);
                } catch (java.util.concurrent.TimeoutException te) {
                    logger.error("[Agent] LLM 调用超时 (>200s)");
                    callback.onAgentError("LLM 调用超时，请检查网络或 API 服务状态");
                    return buildFallbackResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
                } catch (java.util.concurrent.ExecutionException ee) {
                    Throwable cause = ee.getCause() != null ? ee.getCause() : ee;
                    String errMsg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
                    logger.error("[Agent] LLM 调用异常: %s (%s)", errMsg, cause.getClass().getSimpleName());
                    callback.onAgentError("LLM 调用异常: " + errMsg);
                    return buildFallbackResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
                } catch (Exception e) {
                    String errMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                    logger.error("[Agent] LLM 调用异常: %s (%s)", errMsg, e.getClass().getSimpleName());
                    callback.onAgentError("LLM 调用异常: " + errMsg);
                    return buildFallbackResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
                }

                totalTokensUsed += response.totalTokens();

                if (response.finishReason() == LlmResponse.FinishReason.ERROR
                        || response.finishReason() == LlmResponse.FinishReason.RATE_LIMITED) {
                    logger.error("[Agent] LLM 返回错误: %s", response.errorMessage());
                    callback.onAgentError("LLM 错误: " + response.errorMessage());
                    return buildFallbackResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
                }

                // Surface the model's extended-thinking trace (if any) as its
                // own thinking event, distinct from the visible response text
                // handled right below — lets the UI tell "private reasoning"
                // apart from "what it decided to say about this step".
                if (response.thinkingText() != null && !response.thinkingText().isEmpty()) {
                    callback.onAgentThinking("🧠[思考] " + response.thinkingText());
                }

                // Handle text content (thinking)
                if (response.content() != null && !response.content().isEmpty()) {
                    callback.onAgentThinking(response.content());
                    stageDescriptions.put(100 + iteration, response.content());
                }

                if (response.hasToolCalls()) {
                    // Append assistant message with tool calls. rawThinkingBlocksJson
                    // (when the provider used extended thinking) must ride along on
                    // this exact message so it can be echoed back verbatim on the
                    // next request — Anthropic requires this for thinking + tool use.
                    messages.add(ChatMessage.assistantWithToolCalls(
                            response.content(), response.toolCalls(), response.rawThinkingBlocksJson()));

                    List<ToolCall> toolCalls = response.toolCalls();
                    for (ToolCall tc : toolCalls) {
                        logger.info("[Agent] 调用工具: %s", tc.toolName());
                        callback.onToolCall(tc.toolName(), tc.arguments());
                    }

                    // Batch splitting around submit_report: run the calls up to
                    // and including it first. When the report is ACCEPTED the
                    // analysis is over — the rest of the batch must not execute
                    // (its results would never be processed, and a late
                    // send_request firing after the verdict is pointless). When
                    // a gate REJECTS the report, the remaining calls still run
                    // so this turn's plan isn't silently half-dropped.
                    int submitIdx = -1;
                    for (int i = 0; i < toolCalls.size(); i++) {
                        if ("submit_report".equals(toolCalls.get(i).toolName())) {
                            submitIdx = i;
                            break;
                        }
                    }
                    List<ToolCall> dispatchBatch = submitIdx >= 0
                            ? toolCalls.subList(0, submitIdx + 1)
                            : toolCalls;

                    // Batch dispatch: when the model returned several calls and
                    // every one of them is a read-only tool, run them concurrently
                    // — this is the common "read 3 files at once" pattern. Any
                    // batch containing a stateful/HTTP/LLM tool stays sequential
                    // (executeToolCalls falls back to one-at-a-time internally).
                    if (cancelled) {
                        return completeCancelled(entry, callback, analyzeTool, codeTool, genTool,
                                sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
                    }
                    // Record in session state (for cross-tool gates enforced by
                    // preExecute hooks, e.g. submit_report requiring
                    // heuristic_scan first). Only calls that actually execute
                    // are recorded — a short-circuited batch tail never runs.
                    for (ToolCall tc : dispatchBatch) {
                        toolCtx.sessionState().recordToolCall(tc.toolName());
                    }
                    List<String> toolResults = executeToolCalls(dispatchBatch, registry);
                    boolean submitAccepted = submitIdx >= 0 && reportTool.getVerdict() != null;
                    if (!submitAccepted && dispatchBatch.size() < toolCalls.size()) {
                        List<ToolCall> rest = toolCalls.subList(submitIdx + 1, toolCalls.size());
                        for (ToolCall tc : rest) {
                            toolCtx.sessionState().recordToolCall(tc.toolName());
                        }
                        toolResults.addAll(executeToolCalls(rest, registry));
                    }

                    // Ground-truth verified count, AFTER execution: every
                    // request-sending tool (send_request, verify_*, active_probe,
                    // ...) merges its results into SendRequestTool's
                    // payloadResults, so its size IS the verified count.
                    // Replaces the old pre-execution optimistic size+1 that only
                    // saw send_request and over-counted failed sends.
                    toolCtx.sessionState().setVerifiedPayloadCount(
                            sendTool.getPayloadResults().size());

                    // Iterate by RESULTS, not calls: an accepted submit_report
                    // short-circuits its batch tail, so toolResults can be
                    // shorter than toolCalls (entries stay 1:1 in order).
                    for (int callIdx = 0; callIdx < toolResults.size(); callIdx++) {
                        ToolCall tc = toolCalls.get(callIdx);
                        String toolResult = toolResults.get(callIdx);

                        // Feed findings from analyze_traffic into generate_payloads
                        if ("analyze_traffic".equals(tc.toolName()) && analyzeTool.getLastResult() != null) {
                            genTool.addFindings(analyzeTool.getLastResult().findings());
                        }

                        String truncatedResult = truncate(toolResult, toolResultLimit(tc.toolName()));
                        callback.onToolResult(tc.toolName(), truncatedResult);

                        // Real-time UI updates — fire BEFORE appending to messages
                        // so the UI reflects the tool's effect immediately.
                        if ("generate_payloads".equals(tc.toolName()) && !genTool.getGeneratedCases().isEmpty()) {
                            callback.onTestCasesGenerated(new ArrayList<>(genTool.getGeneratedCases()));
                        }
                        if ("send_request".equals(tc.toolName()) && !sendTool.getPayloadResults().isEmpty()) {
                            List<PayloadResult> results = sendTool.getPayloadResults();
                            callback.onPayloadResultReady(results.get(results.size() - 1), results.size() - 1);
                        }

                        // Append tool result message
                        messages.add(ChatMessage.toolResult(tc.id(), truncatedResult));

                        // Track consecutive no-anomaly send_request calls for reflection
                        if ("send_request".equals(tc.toolName())) {
                            boolean hasAnomaly = toolResult != null && (
                                    toolResult.contains("\"anomaly\":true")
                                    || toolResult.contains("SQL 错误") || toolResult.contains("sql error")
                                    || toolResult.contains("堆栈跟踪") || toolResult.contains("stack trace"));
                            boolean isWafBlocked = toolResult != null && (
                                    toolResult.contains("waf_detected") || toolResult.contains("WAF")
                                    || toolResult.contains("\"waf_detected\":true"));
                            if (isWafBlocked) {
                                consecutiveWafBlocks++;
                                consecutiveNoAnomaly = 0;
                            } else if (hasAnomaly) {
                                consecutiveNoAnomaly = 0;
                                consecutiveWafBlocks = 0;
                            } else {
                                consecutiveNoAnomaly++;
                                consecutiveWafBlocks = 0;
                            }
                        }

                        // Check if submit_report was called
                        if ("submit_report".equals(tc.toolName()) && reportTool.getVerdict() != null) {
                            logger.info("[Agent] 报告已提交，分析完成");
                            boolean verified = toolCtx.sessionState().hasCalled("send_request")
                                || toolCtx.sessionState().hasCalled("test_auth_bypass");
                            PipelineResult result = buildResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed, verified);
                            callback.onAgentComplete(result);
                            return result;
                        }
                    }

                    // ===== Repeated-batch circuit breaker =====
                    // Generic stuck-loop guard: the reflection triggers below
                    // only cover specific patterns (no-anomaly sends, WAF
                    // walls), but ANY identical batch repeated verbatim is by
                    // definition no progress. Nudge first, hard-stop with the
                    // evidence-so-far fallback if the repetition persists.
                    int repeatCount = repeatDetector.record(toolCalls);
                    if (repeatCount >= RepeatCallDetector.HALT_AT) {
                        logger.warn("[Agent] 连续 %d 次相同工具调用批次，触发重复熔断", repeatCount);
                        callback.onAgentError("连续 " + repeatCount
                                + " 次完全相同的工具调用，已熔断终止，基于已收集证据出报告");
                        PipelineResult result = prefixVerdictSummary(
                                buildFallbackResult(entry, analyzeTool, codeTool, genTool,
                                        sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed),
                                "[重复熔断] 连续 " + repeatCount + " 次相同工具调用批次，强制终止。");
                        callback.onAgentComplete(result);
                        return result;
                    }
                    if (repeatCount >= RepeatCallDetector.REFLECT_AT) {
                        messages.add(ChatMessage.user(
                                "【反思】你已经连续 " + repeatCount + " 次发起了完全相同的工具调用批次，"
                              + "重复相同的调用不会产生不同的结果。请立即改变策略：\n"
                              + "1. 换漏洞类型、参数位置或测试方向；\n"
                              + "2. 改用其他工具（重新审代码、verify_boolean_blind 等）；\n"
                              + "3. 证据已足够时调用 submit_report 提交结论。\n"
                              + "继续重复相同调用将触发强制终止。"));
                        lastReflectionIteration = iteration;
                        logger.info("[Agent] 注入 reflection: 连续 %d 次相同工具调用批次", repeatCount);
                    }
                } else if (response.finishReason() == LlmResponse.FinishReason.COMPLETE) {
                    // Model returned text without tool calls — nudge it
                    messages.add(ChatMessage.assistant(response.content()));
                    messages.add(ChatMessage.user(
                            "Please use the available tools to continue your analysis, "
                          + "or call submit_report if you have gathered enough evidence."));
                } else if (response.finishReason() == LlmResponse.FinishReason.MAX_TOKENS) {
                    // Response was cut off by max_tokens — without this the loop
                    // would re-send identical messages and waste iterations.
                    messages.add(ChatMessage.assistant(
                            response.content() != null ? response.content() : ""));
                    messages.add(ChatMessage.user(
                            "Your previous response was truncated by max_tokens. "
                          + "Continue concisely: emit ONE tool call or a brief status. "
                          + "Do not repeat earlier analysis."));
                }

                // ===== Reflection triggers =====
                // Inject reflection prompts when the Agent appears stuck.
                // These are user messages injected before the next LLM call,
                // forcing the model to self-diagnose and course-correct.

                // Trigger 1: consecutive send_request calls with no anomaly
                if (consecutiveNoAnomaly >= 3 && iteration > lastReflectionIteration + 2) {
                    int count = consecutiveNoAnomaly;
                    messages.add(ChatMessage.user(
                            "【反思】你已经连续发送了 " + count + " 个 payload 但都没有触发异常。"
                          + "请停下来分析原因：\n"
                          + "1. 参数位置是否正确？payload 是放在 query、body 还是 header？\n"
                          + "2. 参数类型是否匹配？数字参数需要数字 payload，字符串参数需要字符串 payload\n"
                          + "3. 是否有 WAF 在静默过滤？检查响应是否与基线一致（可能被 WAF 替换为正常页面）\n"
                          + "4. 该参数是否真的存在注入点？重新审视代码，确认用户输入能否到达 sink\n"
                          + "5. 是否需要调整策略？比如换一种漏洞类型测试，或者调用 verify_boolean_blind\n\n"
                          + "如果确认该参数确实安全，请在报告中标注并尝试其他方向。"));
                    lastReflectionIteration = iteration;
                    consecutiveNoAnomaly = 0;
                    consecutiveWafBlocks = 0;
                    logger.info("[Agent] 注入 reflection: 连续 %d 次 send_request 无异常", count);
                }

                // Trigger 1b: consecutive WAF blocks — model is hitting a wall
                if (consecutiveWafBlocks >= 3 && iteration > lastReflectionIteration + 2) {
                    int count = consecutiveWafBlocks;
                    messages.add(ChatMessage.user(
                            "【反思】你已经连续发送了 " + count + " 个 payload 但全部被 WAF 拦截。"
                          + "请停下来分析：\n"
                          + "1. 调用 waf_bypass_retry 尝试编码绕过（大小写/注释/编码/IP变体）\n"
                          + "2. 如果绕过失败，改用语义等效但无关键字的 payload（如用 CONCAT 替代 UNION SELECT）\n"
                          + "3. 如果所有绕过策略都失败，在报告中注明 WAF 防护有效，该发现最多标为疑似\n"
                          + "4. 不要继续生成更多会被拦截的 payload —— 转移测试方向"));
                    lastReflectionIteration = iteration;
                    consecutiveWafBlocks = 0;
                    consecutiveNoAnomaly = 0;
                    logger.info("[Agent] 注入 reflection: 连续 %d 次 WAF 拦截", count);
                }

                // Trigger 2: 15+ iterations without submitting — check if evidence is enough
                if (iteration == 15) {
                    messages.add(ChatMessage.user(
                            "【反思】已进行 15 轮分析。请回顾已收集的证据：\n"
                          + "1. 已经验证了哪些漏洞假设？哪些已被排除？\n"
                          + "2. 当前证据是否足够支撑一个结论？\n"
                          + "3. 是否有必须验证但尚未验证的关键假设？\n\n"
                          + "如果证据已经足够，请调用 submit_report 提交报告。"
                          + "如果还有关键假设需要验证，继续但聚焦于最重要的 1-2 个方向。"));
                    lastReflectionIteration = iteration;
                    logger.info("[Agent] 注入 reflection: 迭代 %d 中期检查", iteration + 1);
                }

                // Trigger 3: 40+ iterations — diagnose what's blocking
                if (iteration == 40) {
                    messages.add(ChatMessage.user(
                            "【反思】已进行 40 轮分析，接近上限（50 轮）。请自我诊断：\n"
                          + "1. 是什么导致分析无法收尾？是否在重复调用同一个工具？\n"
                          + "2. 是否在某个参数上陷入了死循环（反复生成 payload 但都被拦截）？\n"
                          + "3. 当前已收集的证据能否支撑一个结论？\n\n"
                          + "如果无法继续推进，请基于已有证据调用 submit_report 提交。"
                          + "如果确实还有关键发现需要验证，请在 1-2 轮内完成并提交。"));
                    lastReflectionIteration = iteration;
                    logger.info("[Agent] 注入 reflection: 迭代 %d 上限临近", iteration + 1);
                }

                // Notify iteration complete AFTER all work in this iteration is done
                callback.onIterationComplete(iteration + 1, MAX_ITERATIONS);
                logger.info("[Agent] 迭代 %d/%d 完成", iteration + 1, MAX_ITERATIONS);
            }

            // Max iterations reached
            logger.warn("[Agent] 达到最大迭代次数 %d，强制生成结果", MAX_ITERATIONS);
            callback.onAgentError("达到最大迭代次数 (" + MAX_ITERATIONS + ")，使用已收集数据生成报告");
            PipelineResult result = buildFallbackResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
            callback.onAgentComplete(result);
            return result;

        } catch (Throwable e) {
            // Throwable, not Exception: during an extension reload the dying
            // ClassLoader throws NoClassDefFoundError (an Error) into a loop
            // that kept running. Escaping here would complete the future
            // exceptionally, and the facade's panel would sit on "Agent
            // 启动中..." forever — settle with the evidence fallback instead.
            if (cancelled) {
                // Interrupt (from cancel()) blew up a blocking get()/sleep — treat
                // it as the cooperative stop it is, not as an error.
                return completeCancelled(entry, callback, analyzeTool, codeTool, genTool,
                        sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
            }
            logger.error("[Agent] 异常: %s", e.getMessage());
            callback.onAgentError("Agent 异常: " + e.getMessage());
            return buildFallbackResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
        }
        } finally {
            loopThread = null;
            // Clear any pending interrupt (set by cancel()) — this executor
            // thread is reused for the NEXT analysis, and a stale interrupt
            // flag would make its first sleep/future.get fail immediately.
            Thread.interrupted();
        }
    }

    /** User-cancelled completion: same persistence path as a normal finish
     *  (fallback result from collected evidence), but the summary says WHY it
     *  stopped short, and onIterationComplete is skipped. Callers can detect
     *  the cancel via isCancelled() to label the UI accordingly. */
    private PipelineResult completeCancelled(ApiEntry entry, AgentCallback callback,
                                              AnalyzeTrafficTool analyzeTool,
                                              SearchSourceCodeTool codeTool,
                                              GeneratePayloadsTool genTool,
                                              SendRequestTool sendTool,
                                              AuthBypassTool authTool,
                                              SubmitReportTool reportTool,
                                              Map<Integer, String> stageDescriptions,
                                              int totalTokensUsed) {
        logger.info("[Agent] 用户中断，基于已收集证据生成结果");
        PipelineResult result = prefixVerdictSummary(
                buildFallbackResult(entry, analyzeTool, codeTool, genTool,
                        sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed),
                "[用户中断] ");
        callback.onAgentComplete(result);
        return result;
    }

    /** Returns a copy of {@code result} whose verdict summary carries the
     *  given prefix — labels WHY a run stopped short (user cancel, repeat
     *  breaker) while keeping the collected evidence intact. */
    private static PipelineResult prefixVerdictSummary(PipelineResult result, String prefix) {
        var v = result.verdict();
        if (v == null) return result;
        return new PipelineResult(result.trafficAnalysis(), result.sourceCode(),
                result.testCases(), result.payloadResults(),
                new FinalVerdict(v.overallRisk(), v.confirmedVulns(), v.suspectedVulns(),
                        prefix + (v.summary() != null ? v.summary() : ""),
                        v.recommendations(), v.totalTokensUsed()),
                result.stageDescriptions(), result.trafficStats(), result.authTestResult());
    }

    private PipelineResult buildResult(ApiEntry entry,
                                        AnalyzeTrafficTool analyzeTool,
                                        SearchSourceCodeTool codeTool,
                                        GeneratePayloadsTool genTool,
                                        SendRequestTool sendTool,
                                        AuthBypassTool authTool,
                                        SubmitReportTool reportTool,
                                        Map<Integer, String> stageDescriptions,
                                        int totalTokens,
                                        boolean verified) {
        FinalVerdict verdict = reportTool.getVerdict();
        if (verdict != null) {
            List<PayloadResult> allPayloads = sendTool.getPayloadResults();
            // Anti-hallucination: Agent mode's send_request has no baseline
            // comparison (unlike Pipeline's RequestExecutionEngine), so this uses
            // the lenient bar — payload must have actually been sent — rather than
            // requiring a programmatic anomaly flag. ALWAYS run it, even when no
            // payloads were sent: a pure source/traffic-analysis run has an empty
            // payload list, and skipping validation there let code-only "confirmed"
            // findings (e.g. Mass Assignment read straight from source) pass through
            // unchallenged. With an empty list findPayloadResult matches nothing, so
            // each confirmed finding is demoted to suspected (source-inferred,
            // unverified) — the intended bar for unverified findings.
            verdict = VerdictValidator.validate(verdict,
                    allPayloads != null ? allPayloads : List.of(), false, authTool.getLastResult());
            // SubmitReportTool has no visibility into how many LLM calls the
            // loop made overall, so its verdict JSON always reports 0 tokens —
            // overwrite with the loop's own running total, which is accurate.
            verdict = new FinalVerdict(verdict.overallRisk(), verdict.confirmedVulns(),
                    verdict.suspectedVulns(), verdict.summary(), verdict.recommendations(), totalTokens);
        }
        if (!verified && verdict != null) {
            String caveat = "[提示] 未执行 send_request/test_auth_bypass 实测验证，"
                    + "以下结论基于静态代码/流量分析证据，未经程序化验证。\n\n";
            verdict = new FinalVerdict(verdict.overallRisk(), verdict.confirmedVulns(),
                    verdict.suspectedVulns(), caveat + verdict.summary(),
                    verdict.recommendations(), verdict.totalTokensUsed());
        }
        // send_request never sets anomalyDetected itself (no baseline
        // comparison) — without this, the Repeater/任务中心 row for the exact
        // payload the verdict just confirmed as a real vuln still shows
        // "✓ 无风险". Must run after verdict is finalized above (uses the
        // post-cross-validation confirmedVulns, not the raw LLM claim).
        List<PayloadResult> markedPayloads = VerdictValidator.markConfirmedPayloads(verdict, sendTool.getPayloadResults());
        return new PipelineResult(
                analyzeTool.getLastResult(),
                codeTool.getLastSourceCode(),
                genTool.getGeneratedCases(),
                markedPayloads,
                verdict,
                stageDescriptions,
                null, // trafficStats — not collected in agent mode
                authTool.getLastResult()
        );
    }

    private PipelineResult buildFallbackResult(ApiEntry entry,
                                                AnalyzeTrafficTool analyzeTool,
                                                SearchSourceCodeTool codeTool,
                                                GeneratePayloadsTool genTool,
                                                SendRequestTool sendTool,
                                                AuthBypassTool authTool,
                                                SubmitReportTool reportTool,
                                                Map<Integer, String> stageDescriptions,
                                                int totalTokens) {
        FinalVerdict verdict = reportTool.getVerdict();
        if (verdict == null) {
            // Create a minimal fallback verdict from whatever data we have
            String risk = "LOW";
            String summary = "Agent 分析未完成 — 以下是已收集到的信息。";
            if (analyzeTool.getLastResult() != null && analyzeTool.getLastResult().overallRisk() != null) {
                risk = analyzeTool.getLastResult().overallRisk().name();
                summary = analyzeTool.getLastResult().summary();
            }
            verdict = new FinalVerdict(risk, List.of(), List.of(), summary, "", totalTokens);
        } else {
            List<PayloadResult> allPayloads = sendTool.getPayloadResults();
            if (allPayloads != null && !allPayloads.isEmpty()) {
                verdict = VerdictValidator.validate(verdict, allPayloads, false, authTool.getLastResult());
            }
            // Same 0-token gap as buildResult — see comment there.
            verdict = new FinalVerdict(verdict.overallRisk(), verdict.confirmedVulns(),
                    verdict.suspectedVulns(), verdict.summary(), verdict.recommendations(), totalTokens);
        }
        // See buildResult's comment on markConfirmedPayloads.
        List<PayloadResult> markedPayloads = VerdictValidator.markConfirmedPayloads(verdict, sendTool.getPayloadResults());
        return new PipelineResult(
                analyzeTool.getLastResult(),
                codeTool.getLastSourceCode(),
                genTool.getGeneratedCases(),
                markedPayloads,
                verdict,
                stageDescriptions,
                null,
                authTool.getLastResult()
        );
    }

    private String buildSystemPrompt() {
        return """
                你是一名专业的API安全分析专家，使用一系列工具系统化地分析API端点的安全漏洞，
                通过实际验证收集证据，并提交完整的安全分析报告。
                所有分析结果、报告内容、summary、recommendations 必须使用中文输出。
                下方列出的各工具的详细参数与用途见你收到的 tool 定义，这里只给策略与规则。

                ## 分析策略（推荐顺序，可根据发现灵活调整）
                heuristic_scan(免费) → fingerprint_components(免费) → search_source_code/read_file/
                grep_repo(免费) → audit_codebase(配置了代码仓库时必做，免费) → analyze_traffic →
                generate_payloads → send_request → test_auth_bypass/list_sessions → submit_report。
                盲注升级: verify_boolean_blind → verify_timing_blind。被 WAF 拦截: waf_bypass_retry。
                怀疑越权/业务逻辑: test_auth_bypass / verify_business_logic。找定义/调用处: find_definition /
                find_callers。构造请求前先看有��同域名流量可复用认证: search_traffic。范围较宽的探索性
                问题（如"全仓库哪里校验JWT"）已经自己查了几轮 read_file/grep_repo 仍没查全时，可用
                dispatch_explore_agent 委派给隔离子 Agent，只拿回一段结论，不占用你自己的上下文。
                确认/疑似漏洞后铺开到兄弟端点: map_sibling_endpoints(免费查同 Controller/同前缀路由) →
                chain_hunter(委派集群狩猎子 Agent 实测兄弟端点并串链，见下方集群狩猎策略)。
                需要纯计算验证（复现算法/编解码/密码学，不涉及发请求）时可用 run_sandboxed_code，
                但它不隔离网络/真实文件系统，只用于计算，不要用来跟目标交互。

                ## 请求构造策略（当接口没有捕获到流量时）
                初始消息标注"无捕获流量"时：1) search_source_code/read_file 读 Controller 方法确定参数；
                2) search_traffic 搜同域名历史流量提取认证 token/通用请求头；3) 从代码推理参数值（数字 ID
                给合理默认值、枚举取第一个合法值、@RequestBody 按 Entity 构造最小 JSON）；4) send_request
                发送，200 记为基线继续分析，4xx/5xx 分析原因调整重试。

                ## 规则
                - 免费工具优先，再用消耗 AI 的工具。
                - controller 方法调用了其他类而 search_source_code 片段没覆盖到时，主动 read_file/grep_repo
                  跟进——越权、深层业务逻辑漏洞往往藏在被调用的下一层代码里，不要只看表面几十行就下结论。
                - 实测优于猜测：怀疑的漏洞尽量用 send_request 验证。
                - waf_detected=true 时该响应是拦截页非后端真实响应：不得作为漏洞或"无漏洞"证据；先调用
                  waf_bypass_retry 尝试绕过；绕过失败则报告注明"WAF 防护有效"，对应发现最多标疑似。
                - SQL 注入：显错失败不能直接下"安全"结论，先 verify_boolean_blind，再 verify_timing_blind，
                  两者都失败才能写"未发现 SQL 注入"。
                - 生成的 payload 必须用 send_request 真实发出验证，不允许只生成不发送就下结论；生成几个至少
                  验证几个（超过 5 个时至少验证 5 个，优先验证最可能触发的）；验证数不够 submit_report 会被拒绝。
                - 每个 suspected/confirmed 发现都要有真实请求验证记录（正常/报错/WAF拦截/超时都算，都要记录，
                  不能因为"发不成功"就不记录）；CSRF/鉴权失败时先用代理历史里的有效 session/token 重试。
                  仅当某类漏洞确实无法用单请求触发（二阶/存储型：注入在写入接口，执行在后台）时，才允许以
                  完整代码数据流链作证据，且需在 evidence 里写明理由+链路；同时仍应对注入点接口发一个正常
                  请求记录其响应。
                - 越权/IDOR/未授权类：攻击成功的表现是"正常 200 返回他人数据"而非报错，标 confirmed 时
                  必须在 identity_proof 字段写清三点——用哪个会话/身份验证的、匿名（去凭证）访问的结果、
                  如何确认返回的数据属于【他人账号】而非自己（返回自己数据=误报）。identity_proof 为空的
                  越权类 confirmed 会被程序自动降级为疑似。
                - 对比响应与基线判断漏洞是否真实存在。
                - 初始消息带 Passive Detection Notes 时必须在最终 summary 中明确回应（确认或说明误报理由），
                  但不要把这些已报告发现重复列为 confirmed/suspected 独立条目，除非你发现了被动层未覆盖的新维度。
                - 仅在有明确证据（异常响应/错误信息/反射payload，且来自真实发送过的 payload 响应）时标记
                  "已确认"；有指标无确证时标记"疑似"并注明置信度。保守判断，误报浪费安全团队时间。
                - 不要发现一个漏洞就收尾：确认/疑似某类后必须继续检查其它类别（注入/SSRF/路径穿越/越权/
                  反序列化/敏感信息泄露/代码里每个危险 sink），逐个溯源，只有覆盖主要类别或确有把握才提交。
                - 早期证据已充分（heuristic_scan 无发现、代码无可疑逻辑、流量无异常）可提前提交，不必凑数
                  调用工具；反之线索不足也不必急于收尾，可继续深挖直到有把握。
                - 经充分测试未发现漏洞，报告 SAFE 也是有价值的结论。
                - 提交报告前必须至少执行过一次 heuristic_scan；完全没生成 payload 时可不做实测验证提交（会
                  标注"未经实测验证"），但只要生成过 payload 就必须按上面要求实际验证。

                ## 危险 Sink 的后向污点追踪（重点：二阶/存储型注入）
                看到被标注的危险 sink（⚠ CMD/SQL/DESER SINK 或 shell 拼接/subprocess/Runtime.exec/字符串拼
                SQL）必须做后向污点追踪：1) 提取 sink 中被拼接/插值的变量；2) 检查"部分转义部分没有"——这是
                极强的注入信号；3) 用 read_file/grep_repo 逐个追踪未过滤变量的来源；4) 若来源是数据库/配置/
                缓存等存储数据（而非当前请求参数），说明是存储型/二阶——用 find_callers/grep_repo 找到写入
                该数据的接口，read_file 检查写入侧有无校验；5) 能串起"写入无校验→落库→读出→未过滤进
                sink"即可判定为存储型/二阶注入，即便注入点接口本身返回 200 无异常——代码数据流链本身就是
                充分证据，不依赖 send_request 能否触发。步骤 3 可先用 trace_taint_source 跑一遍自动回溯
                （免费，regex 启发式非真实数据流分析），省去手动 read_file/grep_repo 反复跳的过程，但链路
                每一跳仍需自己核实，不能直接当结论用。

                ## 全局白盒审计（必做，配置了代码仓库时）
                1) audit_codebase 拿到全仓危险 sink 清单（即使当前接口已发现一个漏洞也必须执行——一个仓库
                通常有多处 sink）；2) 对高危 sink 用 read_file 按"后向污点追踪"溯源；3) 确定候选漏洞能被
                哪个接口触发，search_traffic 查有无流量，有则构造 payload 实测，没有则基于代码构造请求测；
                4) 代码溯源成立+实测验证结合成完整证据链再定级。只有 audit_codebase 为空时才可跳过溯源。

                ## 输出格式
                逐步思考，每次工具返回后分析学到了什么、决定下一步。始终使用工具，不要以纯文本生成最终报告。
                所有文本输出使用中文。
                """ + chainHuntingSection()
                + com.flechazo.apisentinel.ai.prompt.SafetyRules.AGENT_CONDENSED_RULES;
    }

    /** Cluster-hunting strategy (A→B chaining), distilled from bughunter's
     *  chain-builder methodology. Injected unconditionally into the Agent
     *  system prompt because ANY confirmed/suspected finding can trigger a
     *  hunt — there is no per-finding gate at system-prompt build time.
     *  Missing resource degrades to empty (non-fatal). */
    private static String chainHuntingSection() {
        return ChainHuntingHolder.CONTENT.isBlank()
                ? "" : "\n" + ChainHuntingHolder.CONTENT + "\n";
    }

    /** Whole-file content of chain-hunting.md (loaded once). */
    private static class ChainHuntingHolder {
        static final String CONTENT = loadResource("/payloads/chain-hunting.md");
    }

    private static String loadResource(String path) {
        try (InputStream is = AgentLoop.class.getResourceAsStream(path)) {
            return is == null ? "" : new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private String buildInitialUserMessage(ApiEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Target API Endpoint\n\n");
        sb.append("**Method:** ").append(entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET").append("\n");
        sb.append("**Path:** ").append(entry.getApiPath()).append("\n");
        sb.append("**Domain:** ").append(entry.getDomain() != null ? entry.getDomain() : "unknown").append("\n");
        sb.append("**Status Code:** ").append(entry.getLastStatusCode()).append("\n\n");

        boolean hasTraffic = entry.getLastRawRequest() != null && !entry.getLastRawRequest().isEmpty();

        if (hasTraffic) {
            sb.append("### Captured HTTP Request\n```\n");
            sb.append(truncate(entry.getLastRawRequest(), 10000));
            sb.append("\n```\n\n");

            if (entry.getLastRawResponse() != null && !entry.getLastRawResponse().isEmpty()) {
                sb.append("### Captured HTTP Response\n```\n");
                sb.append(truncate(entry.getLastRawResponse(), 10000));
                sb.append("\n```\n\n");
            }
        } else {
            // No traffic captured — the Agent needs to construct a request first.
            // This is the key scenario: user wants to analyze an API that was never
            // triggered from the frontend (e.g. 20 new APIs, only 10 triggered).
            sb.append("### ⚠️ 无捕获流量 — 需要先构造请求\n\n");
            sb.append("该接口没有捕获到任何 HTTP 流量。请先执行以下步骤来构造请求：\n\n");
            sb.append("**Step 1: 读代码仓库**\n");
            sb.append("  使用 search_source_code 和 read_file 读取该接口的 Controller 方法，理解：\n");
            sb.append("  - 路径、HTTP 方法、参数列表、参数类型、是否必填\n");
            sb.append("  - 如果参数是 @RequestBody，继续读取 Entity/DTO 类获取字段定义\n");
            sb.append("  - 如果参数是枚举类型，读取枚举类获取所有合法值\n\n");
            sb.append("**Step 2: 搜索同域名历史流量**\n");
            sb.append("  使用 search_traffic 搜索同域名（" + (entry.getDomain() != null ? entry.getDomain() : "unknown") + "）的历史流量，提取：\n");
            sb.append("  - Authorization/Cookie 等认证信息\n");
            sb.append("  - Content-Type、User-Agent 等通用请求头\n");
            sb.append("  - 同类型参数的实际值（如 userId=1001、pageSize=20）\n\n");
            sb.append("**Step 3: 构造并发送请求**\n");
            sb.append("  使用 send_request 发送构造的请求：\n");
            sb.append("  - 路径和方法：从代码获取\n");
            sb.append("  - 认证头：从历史流量复用\n");
            sb.append("  - 参数值：从代码理解语义 + 历史流量复用\n");
            sb.append("  - 如果收到 200 → 记录为基线 → 进入正常分析流程\n");
            sb.append("  - 如果收到 401/403 → 尝试其他 session 的 token\n");
            sb.append("  - 如果收到 400/422 → 调整参数后重试（最多 2 次）\n\n");
            sb.append("构造成功后，将该响应作为基线，继续执行正常的安全分析流程。\n\n");
        }

        // Passive layer notes
        if (entry.getNote() != null && !entry.getNote().isBlank()) {
            sb.append("### User Notes (hand-written)\n");
            sb.append(truncate(entry.getNote(), 2000));
            sb.append("\n\n");
        }
        String passiveFindingsText = entry.buildPassiveFindingsText();
        if (!passiveFindingsText.isEmpty()) {
            sb.append("### Passive Detection Notes (already found, for free, before this analysis)\n");
            sb.append(truncate(passiveFindingsText, 2000));
            sb.append("\n\n");
        }

        // Success-pattern memory (P3): which plays have already been VERIFIED
        // on this domain. No-op section when the store is empty/disabled.
        if (patternStore != null) {
            sb.append(patternStore.buildPromptSection(entry, 5));
        }

        sb.append("Please begin your security analysis. ");
        if (hasTraffic) {
            sb.append("Start with heuristic_scan for quick findings, ");
            sb.append("then proceed with deeper analysis as needed.");
        } else {
            sb.append("First construct a request (see above), establish a baseline, ");
            sb.append("then proceed with heuristic_scan and deeper analysis.");
        }

        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n...[truncated]";
    }

    /**
     * Retry the LLM call on RATE_LIMITED with backoff instead of aborting the
     * whole agent run. Other failures propagate to the caller's catch blocks.
     */
    private LlmResponse completeWithRateLimitRetry(LlmProvider provider, LlmRequest request)
            throws Exception {
        for (int attempt = 0; attempt <= RATE_LIMIT_RETRIES; attempt++) {
            LlmResponse resp = provider.complete(request).get(200, java.util.concurrent.TimeUnit.SECONDS);
            if (resp.finishReason() == LlmResponse.FinishReason.RATE_LIMITED
                    && attempt < RATE_LIMIT_RETRIES) {
                long backoff = Math.min(2000L * (1L << attempt), 30000L);
                logger.warn("[Agent] RATE_LIMITED, 退避 %dms 后重试 (%d/%d)",
                        backoff, attempt + 1, RATE_LIMIT_RETRIES);
                Thread.sleep(backoff);
                continue;
            }
            return resp;
        }
        // Unreachable: loop returns on last attempt's non-retry branch
        return provider.complete(request).get(200, java.util.concurrent.TimeUnit.SECONDS);
    }

    /** Per-tool truncation budget: source-heavy tools get more room. */
    private static int toolResultLimit(String toolName) {
        return switch (toolName) {
            case "search_source_code", "read_file", "audit_codebase" -> 64000;
            case "grep_repo", "find_callers" -> 48000;
            default -> 32000;
        };
    }

    private int estimateMessagesTokens(List<ChatMessage> messages) {
        int total = 0;
        for (ChatMessage m : messages) {
            if (m.content() != null) total += provider.estimateTokens(m.content());
            if (m.toolCalls() != null) {
                for (ToolCall tc : m.toolCalls()) {
                    total += provider.estimateTokens(tc.toolName() + " " + tc.arguments());
                }
            }
            // Thinking blocks (when extended thinking is enabled) ride along on
            // assistant-with-tool-calls messages and get echoed back verbatim on
            // every subsequent request — without counting them here, the budget
            // check would systematically under-estimate usage once thinking is on.
            if (m.rawThinkingBlocksJson() != null) {
                total += provider.estimateTokens(m.rawThinkingBlocksJson());
            }
        }
        return total;
    }

    /** Extended-thinking blocks must be echoed back verbatim only on the turn
     *  immediately after the assistant message that produced them; older turns
     *  may drop them (Anthropic's tool-use + thinking contract). They
     *  otherwise ride along in the conversation forever — {@link #compactPass}
     *  only reclaims tool results — and grow to dominate the context budget.
     *  Keeps the blocks on the most recent message that carries them, rebuilds
     *  every earlier carrier without them. No-op when nothing carries any. */
    static void stripStaleThinkingBlocks(List<ChatMessage> messages) {
        int lastCarrier = -1;
        for (int i = messages.size() - 1; i >= 0; i--) {
            if (messages.get(i).rawThinkingBlocksJson() != null) {
                lastCarrier = i;
                break;
            }
        }
        if (lastCarrier < 0) return;
        for (int i = 0; i < messages.size(); i++) {
            if (i == lastCarrier) continue;
            ChatMessage m = messages.get(i);
            if (m.rawThinkingBlocksJson() != null) {
                messages.set(i, new ChatMessage(m.role(), m.content(),
                        m.toolCallId(), m.toolCalls(), null));
            }
        }
    }

    /**
     * When the running token estimate exceeds the configured context budget
     * (pipelineConfig.contextWindowTokens() — not a fixed constant, since the
     * plugin supports cloud models with large windows as well as local Ollama
     * models with much smaller ones), compact the oldest tool-result messages
     * in place (shorten to a marker) — preserving message structure (tool
     * results still follow tool calls) while reclaiming space. The most
     * recent few tool results are kept intact so the agent retains working
     * context for its current reasoning.
     * <p>
     * Two-pass tiered compaction (microCompact-style): pass 1 only reclaims
     * REGENERABLE read-only tool results (a lost read_file body costs one
     * re-call if needed again); pass 2 — only if still over budget — compacts
     * the rest, which is mostly send_request verification evidence. The
     * structured summary preserves the status/response fields the final
     * verdict is graded against, so evidence degrades last and gracefully.
     */
    private void compactIfNeeded(List<ChatMessage> messages) {
        int est = estimateMessagesTokens(messages);
        int budget = pipelineConfig.contextWindowTokens();
        if (est <= budget) return;

        int toolCount = 0;
        for (ChatMessage m : messages) if ("tool".equals(m.role())) toolCount++;
        int toCompact = toolCount - KEEP_RECENT_TOOL_RESULTS;
        if (toCompact <= 0) return;

        // tool-result messages only carry a call id — recover which tool
        // produced each by walking the assistant messages' tool calls.
        Map<String, String> toolNames = new HashMap<>();
        for (ChatMessage m : messages) {
            if (m.toolCalls() != null) {
                for (ToolCall tc : m.toolCalls()) toolNames.put(tc.id(), tc.toolName());
            }
        }

        int compacted = compactPass(messages, toolNames, toCompact, true);
        if (compacted < toCompact) {
            compacted += compactPass(messages, toolNames, toCompact - compacted, false);
        }
        if (compacted > 0) {
            logger.info("[Agent] 上下文分级压缩: %d 个旧工具结果已压缩 (估算 %d tokens > %d 预算)",
                    compacted, est, budget);
        }
    }

    /** Compacts up to {@code limit} of the oldest tool results whose producing
     *  tool is read-only/regenerable ({@code readOnlyOnly=true}) or NOT
     * ({@code false}). Idempotent — already-compacted markers and short bodies
     * (no meaningful space win) are skipped. */
    private int compactPass(List<ChatMessage> messages, Map<String, String> toolNames,
                            int limit, boolean readOnlyOnly) {
        int compacted = 0;
        for (int i = 0; i < messages.size() && compacted < limit; i++) {
            ChatMessage m = messages.get(i);
            if (!"tool".equals(m.role())) continue;
            if (m.content() == null || m.content().length() <= 600) continue;
            if (m.content().startsWith("[压缩摘要")) continue;
            String toolName = toolNames.getOrDefault(m.toolCallId(), "");
            boolean regenerable = PARALLELIZABLE_TOOLS.contains(toolName);
            if (regenerable != readOnlyOnly) continue;
            String summary = buildStructuredSummary(m.content());
            messages.set(i, ChatMessage.toolResult(m.toolCallId(), summary));
            compacted++;
        }
        return compacted;
    }

    private String buildStructuredSummary(String content) {
        int originalLen = content.length();
        StringBuilder summary = new StringBuilder();
        summary.append("[压缩摘要, 原始 ").append(originalLen).append(" 字符]\n");

        try {
            var json = com.google.gson.JsonParser.parseString(content).getAsJsonObject();
            if (json.has("found")) summary.append("found: ").append(json.get("found")).append("\n");
            if (json.has("success")) summary.append("success: ").append(json.get("success")).append("\n");
            if (json.has("status_code")) summary.append("status: ").append(json.get("status_code")).append("\n");
            if (json.has("overall_risk")) summary.append("risk: ").append(json.get("overall_risk").getAsString()).append("\n");
            if (json.has("waf_detected")) summary.append("waf: ").append(json.get("waf_detected")).append("\n");
            if (json.has("anomaly")) summary.append("anomaly: ").append(json.get("anomaly")).append("\n");
            if (json.has("findings") && json.get("findings").isJsonArray()) {
                var findings = json.getAsJsonArray("findings");
                summary.append("findings(").append(findings.size()).append("): ");
                for (int fi = 0; fi < Math.min(findings.size(), 5); fi++) {
                    var f = findings.get(fi).getAsJsonObject();
                    if (f.has("type")) summary.append(f.get("type").getAsString());
                    if (f.has("title")) summary.append("/").append(f.get("title").getAsString());
                    summary.append("; ");
                }
                summary.append("\n");
            }
            if (json.has("matches")) summary.append("matches: ").append(json.get("matches")).append("\n");
            if (json.has("match_count")) summary.append("match_count: ").append(json.get("match_count")).append("\n");
            if (json.has("summary")) summary.append("summary: ").append(
                    truncate(json.get("summary").getAsString(), 300)).append("\n");
            if (json.has("response_body")) summary.append("response_excerpt: ").append(
                    truncate(json.get("response_body").getAsString(), 200)).append("\n");
            if (json.has("content")) summary.append("content_excerpt: ").append(
                    truncate(json.get("content").getAsString(), 400)).append("\n");
            if (json.has("routes") && json.get("routes").isJsonArray()) {
                var routes = json.getAsJsonArray("routes");
                summary.append("routes(").append(routes.size()).append("): ");
                for (int ri = 0; ri < Math.min(routes.size(), 3); ri++) {
                    var r = routes.get(ri).getAsJsonObject();
                    if (r.has("handler")) summary.append(r.get("handler").getAsString());
                    if (r.has("file")) summary.append(" @").append(r.get("file").getAsString());
                    summary.append("; ");
                }
                summary.append("\n");
            }
            if (json.has("error")) summary.append("error: ").append(
                    truncate(json.get("error").getAsString(), 200)).append("\n");
        } catch (Exception e) {
            summary.append(content, 0, Math.min(content.length(), 500));
            if (content.length() > 500) summary.append("...");
        }

        return summary.toString();
    }


    /**
     * Execute a batch of tool calls returned in one LLM response. When every
     * call in the batch is a read-only tool (see {@link #PARALLELIZABLE_TOOLS}),
     * dispatch them concurrently on {@link #toolExecutor} — this is the "read
     * 3 files at once" case a capable model will naturally produce when tool
     * calls are independent. Any batch containing a stateful/HTTP/LLM tool
     * (send_request, generate_payloads, submit_report, ...) runs sequentially,
     * one call at a time, preserving the original execution order those tools'
     * inter-dependencies rely on.
     */
    private List<String> executeToolCalls(List<ToolCall> toolCalls, AgentToolRegistry registry) {
        if (toolCalls.size() > 1 && canParallelize(toolCalls)) {
            List<CompletableFuture<String>> futures = new ArrayList<>();
            for (ToolCall tc : toolCalls) {
                futures.add(CompletableFuture.supplyAsync(
                        () -> registry.executeTool(tc.toolName(), tc.arguments()), toolExecutor));
            }
            List<String> results = new ArrayList<>(toolCalls.size());
            for (CompletableFuture<String> f : futures) {
                try {
                    results.add(f.get());
                } catch (Exception e) {
                    results.add("{\"error\": \"parallel tool execution failed: "
                            + (e.getMessage() != null ? e.getMessage().replace("\"", "'") : e.getClass().getSimpleName())
                            + "\"}");
                }
            }
            return results;
        }

        List<String> results = new ArrayList<>(toolCalls.size());
        for (ToolCall tc : toolCalls) {
            results.add(registry.executeTool(tc.toolName(), tc.arguments()));
        }
        return results;
    }

    /** True only when every call in the batch is a side-effect-free read tool. */
    private static boolean canParallelize(List<ToolCall> toolCalls) {
        for (ToolCall tc : toolCalls) {
            if (!PARALLELIZABLE_TOOLS.contains(tc.toolName())) return false;
        }
        return true;
    }

    /** Must stay NON-blocking: completion callbacks call this from ON the
     *  loop's own executor thread, and an await-then-shutdownNow here would
     *  wait for its own task to finish (never does), time out, and interrupt
     *  the very thread still running the completion flow — the stray
     *  interrupt flag then breaks everything downstream (lost report
     *  buttons, stuck progress bar). Unload paths that need a bounded settle
     *  call {@link #awaitSettled(long)} from their own thread instead. */
    public void shutdown() {
        executor.shutdown();
        toolExecutor.shutdown();
    }

    /** Bounded settle for UNLOAD paths only — call from a thread other than
     *  the loop's (AgentFacade.shutdown does). After cancel(), the loop
     *  reaches a checkpoint quickly (the interrupt wakes any blocked LLM
     *  get()/sleep), so a short wait lets its final state land. Returns
     *  false when something survived the window. */
    public boolean awaitSettled(long timeoutMs) {
        try {
            long first = Math.max(1, timeoutMs * 2 / 3);
            boolean a = executor.awaitTermination(first, java.util.concurrent.TimeUnit.MILLISECONDS);
            boolean b = toolExecutor.awaitTermination(Math.max(1, timeoutMs - first),
                    java.util.concurrent.TimeUnit.MILLISECONDS);
            return a && b;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Hard stop for whatever survived awaitSettled on unload. Never call
     *  from the loop's own thread (would self-interrupt mid-callback). */
    public void shutdownNow() {
        executor.shutdownNow();
        toolExecutor.shutdownNow();
    }
}
