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
    /** P0-7: hard token budget for the preserved-recent-results band.
     *  Even when fewer than {@link #KEEP_RECENT_TOOL_RESULTS} tool results
     *  exist, we compact the oldest of them once their combined size
     *  crosses this budget. Pre-P0-7 the code only counted tool results
     *  (never their size), so a single 40K-token response in each of 15
     *  slots held 600K tokens hostage against the compactor — way past
     *  any sensible context window. 30K is the sweet spot: roughly the
     *  last 2–3 large tool calls or the last 6–8 small ones, which
     *  matches the agent's typical working set. */
    private static final int RECENT_TOOL_RESULTS_TOKEN_BUDGET = 30_000;
    /** Retry attempts on RATE_LIMITED before giving up. */
    private static final int RATE_LIMIT_RETRIES = 2;
    /** Per-turn LLM call timeout in seconds. 200s was too short for models
     *  with extended thinking (DeepSeek reasoner, Claude thinking) which can
     *  take 3-8 minutes per turn. 600s (10 min) gives ample headroom. */
    private static final int LLM_CALL_TIMEOUT_SEC = 600;
    /** Timeout retries — separate from rate limit retries since a timeout
     *  retry costs nothing (no backoff wait) and slow models may just need
     *  more attempts. 5 retries = up to 50 minutes total before giving up. */
    private static final int TIMEOUT_RETRIES = 5;
    /** Extended-thinking budget requested per turn when the provider supports
     *  it (Claude). Must stay below MAX_TOKENS_PER_TURN with headroom for the
     *  actual tool call/text output — see ClaudeProvider.resolveThinkingBudget. */
    /** P1-9: round-shaped thinking budgets. Pre-P1-9, every turn spent
     *  {@code THINKING_BUDGET_TOKENS = 6000} tokens of extended thinking
     *  unconditionally, billed at the output rate (~5× input). Over a
     *  typical 20-iteration run that's 30-60K output tokens worth of
     *  thinking — $0.45–$0.90 per endpoint — on turns where the agent
     *  is just dispatching the next tool call and the previous thinking
     *  already covers the reasoning. Round-shaped:
     *  <ul>
     *    <li><b>First iteration</b>: full budget. The agent is framing
     *        the problem — deep thinking pays off here.</li>
     *    <li><b>Reflection-trigger iteration</b>: full budget. The agent
     *        just got handed a "stop and reconsider" prompt; thinking is
     *        what that prompt is asking for.</li>
     *    <li><b>Routine dispatch turn</b>: reduced budget (1500). The
     *        agent's reasoning is already in the prior thinking block;
     *        the new thinking mostly chooses which tool to call next.
     *        {@code stripStaleThinkingBlocks} already guarantees the old
     *        block isn't echoed back, so a smaller fresh budget doesn't
     *        lose any prior reasoning.</li>
     *  </ul>
     *  Tuned conservatively — routine still gets 1500 tokens rather than
     *  zero — so models that don't degrade cleanly when thinking is off
     *  (older Ollama quantizations, some OpenAI variants) keep working. */
    private static final int THINKING_BUDGET_FULL = 6000;
    private static final int THINKING_BUDGET_ROUTINE = 1500;

    private static int thinkingBudgetForIteration(int iteration,
                                                   int lastReflectionIteration,
                                                   int consecutiveNoAnomaly,
                                                   int consecutiveWafBlocks) {
        if (iteration == 0) return THINKING_BUDGET_FULL;
        // Reflection triggers (mirror the conditions at the injection
        // sites above so the budget matches the work the turn is about
        // to do). The "+2" gap matches the `> lastReflectionIteration+2`
        // guard the injectors themselves use.
        boolean reflectionDue =
                (consecutiveNoAnomaly >= 3 && iteration > lastReflectionIteration + 2)
             || (consecutiveWafBlocks >= 3 && iteration > lastReflectionIteration + 2);
        return reflectionDue ? THINKING_BUDGET_FULL : THINKING_BUDGET_ROUTINE;
    }

    /** Whether {@code toolName} is a side-effect-free read tool — safe to run
     *  concurrently with other read-only tools in the same batch, and its
     *  results are safe to aggressively compact (regenerable, since re-running
     *  the tool reproduces them). Resolved from the tool's own
     *  {@link AgentTool#isReadOnly()} metadata rather than a hardcoded name
     *  list, so a newly registered read-only tool is picked up automatically.
     *  Tools that send a request, call an LLM, or mutate cross-tool state
     *  (generate_payloads, submit_report, chain_hunter, verify_*, …) opt out
     *  by defaulting to {@code false} and always run sequentially in
     *  submission order. */
    private static boolean isReadOnly(AgentToolRegistry registry, String toolName) {
        AgentTool tool = registry.getTool(toolName);
        return tool != null && tool.isReadOnly();
    }

    private final LlmProvider provider;
    private final MontoyaApi montoyaApi;
    private final CodeIndexService codeIndexService;
    private final AnalysisConfig pipelineConfig;
    private final List<CodeRepo> codeRepos;
    private final LeveledLogger logger;
    private final OobService oobService;
    /** Optional fast/cheap model name for lightweight tasks (plan generation,
     *  hypothesis generation, reflection). Same provider, different model. */
    private volatile String fastModel;
    /** Whether cascade hunting (sibling/chain endpoint spreading) is enabled.
     *  When false, the system prompt omits sibling/chain instructions and
     *  the chain tool group is disabled. */
    private volatile boolean cascadeEnabled = true;
    /** ① Context-window rollover: when the conversation approaches the model's
     *  context window, clear history and hand off to a fresh window (durable
     *  state survives in the FindingEvidenceStore). Opt-in for now — clearing
     *  conversation history mid-analysis is a big behavior change, so a first
     *  cut defaults to the old lossy-compaction path until tested in a real
     *  session. Enable with -Dapisentinel.rollover.enabled=true. */
    private volatile boolean rolloverEnabled = Boolean.getBoolean("apisentinel.rollover.enabled");
    /** ① Max context-window rollovers per run before falling back to
     *  compaction (bounds runaway cost from ever-growing windows). */
    private static final int MAX_ROLLOVER_WINDOWS = 3;
    /** ① Fraction of the context window at which rollover triggers (before
     *  the 100% forced compaction in {@link #compactIfNeeded}). */
    private static final double ROLLOVER_TRIGGER_FRACTION = 0.8;
    /** ① Current context-window id (0 in the first window). Incremented on
     *  each rollover; tags progress notes so a new window recovers only what
     *  it's missing via read_analysis_notes(sinceWindow=N). */
    private int currentWindowId = 0;
    /** Reuse-window soft fold: when an endpoint was analyzed within this many
     *  minutes, inject the prior verdict as a "known starting point" into the
     *  initial user message so the model confirms/corrects rather than
     *  re-derives from scratch. Mirrors AnalysisPipeline.buildPriorAnalysisContext
     *  but never short-circuits the loop (hard-skip is deferred — see
     *  docs/plan/reuse-window-agent-migration.md §3.3). {@code <=0} disables. */
    private volatile int reuseWindowMinutes = 30;
    public void setReuseWindowMinutes(int minutes) {
        this.reuseWindowMinutes = Math.max(0, minutes);
    }
    /** Tools disabled by the user (won't be registered). */
    private volatile java.util.Set<String> disabledTools = java.util.Set.of();
    /** Multi-endpoint mode: when non-empty, runLoop sets allEntries on
     *  ToolContext and uses buildMultiEntryUserMessage. */
    private volatile java.util.List<ApiEntry> multiEntries = java.util.List.of();
    /** Success-pattern memory (P3); null disables injection — each new
     *  analysis then starts from scratch exactly as before. */
    private final com.flechazo.apisentinel.ai.patterns.PatternStore patternStore;
    private final ExecutorService executor;
    private final ExecutorService toolExecutor;
    /** Optional UI bridge for tools that need to ask the operator (sandbox
     *  confirm / ask_user). Null = headless, tools degrade gracefully. */
    private final com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge userInteractionBridge;
    /** P2-3: per-run nonce fence for Agent tool results. Minted fresh at the
     *  start of each {@link #runLoop} so every tool result the model sees in a
     *  run carries the same nonce the system prompt's fence instruction told
     *  it to expect. Null before runLoop starts. */
    private com.flechazo.apisentinel.ai.prompt.UntrustedContent untrustedContent;
    /** F-1: Optional browser service for client-side security testing.
     *  Null = browser disabled in settings. */
    private volatile com.flechazo.apisentinel.browser.BrowserService browserService;
    /** P1-6: propagated from AppConfig.includeRawCredentialsInLlm. When
     *  false (default), the Analyzer's RequestRedactor strips credentials
     *  before the LLM sees the traffic. When true, raw credentials pass
     *  through (opt-in via AiSettingsPanel). */
    private volatile boolean includeRawCredentials = false;
    /** F-1: Optional API repository for registering browser-discovered APIs. */
    private volatile com.flechazo.apisentinel.repository.ApiRepository apiRepository;
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
                     CodeIndexService codeIndexService, AnalysisConfig pipelineConfig,
                     List<CodeRepo> codeRepos, LeveledLogger logger,
                     OobService oobService) {
        this(provider, montoyaApi, codeIndexService, pipelineConfig, codeRepos,
                logger, oobService, null, null);
    }

    public AgentLoop(LlmProvider provider, MontoyaApi montoyaApi,
                     CodeIndexService codeIndexService, AnalysisConfig pipelineConfig,
                     List<CodeRepo> codeRepos, LeveledLogger logger,
                     OobService oobService,
                     com.flechazo.apisentinel.ai.patterns.PatternStore patternStore) {
        this(provider, montoyaApi, codeIndexService, pipelineConfig, codeRepos,
                logger, oobService, patternStore, null);
    }

    public AgentLoop(LlmProvider provider, MontoyaApi montoyaApi,
                     CodeIndexService codeIndexService, AnalysisConfig pipelineConfig,
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

    /**
     * Multi-endpoint joint analysis: one Agent loop analyzes all endpoints
     * together. The Agent sees all endpoints in its initial prompt and can
     * cross-reference findings. Results are attributed per-endpoint via
     * {@link SubmitReportTool#getVerdictsByPath()}.
     */
    public CompletableFuture<java.util.Map<String, PipelineResult>> executeMulti(
            java.util.List<ApiEntry> entries, AgentCallback callback) {
        return CompletableFuture.supplyAsync(() -> runLoopMulti(entries, callback), executor);
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

    /** F-1: Set browser service for client-side security testing.
     *  Must be called before execute(). */
    public void setBrowserService(com.flechazo.apisentinel.browser.BrowserService browserService) {
        this.browserService = browserService;
    }

    /** Optional login-profile manager (shared with MCP) — enables browser_login. */
    private volatile com.flechazo.apisentinel.config.LoginProfileManager loginProfileManager;
    public void setLoginProfileManager(com.flechazo.apisentinel.config.LoginProfileManager m) {
        this.loginProfileManager = m;
    }

    /** Optional AppConfig — needed by browser_login (cookie injection). */
    private volatile com.flechazo.apisentinel.config.AppConfig appConfig;
    public void setAppConfig(com.flechazo.apisentinel.config.AppConfig c) {
        this.appConfig = c;
    }

    public void setIncludeRawCredentials(boolean include) {
        this.includeRawCredentials = include;
    }

    /** Set the fast/cheap model name for lightweight LLM tasks. Enables
     *  Plan-then-Execute and AttackHypothesisGenerator. */
    public void setFastModel(String model) {
        this.fastModel = model;
    }

    /** Set whether cascade hunting (sibling/chain endpoint spreading) is enabled. */
    public void setCascadeEnabled(boolean cascadeEnabled) {
        this.cascadeEnabled = cascadeEnabled;
    }

    /** Set disabled tools (won't be registered in StandardToolRegistry). */
    public void setDisabledTools(java.util.Set<String> tools) {
        this.disabledTools = tools != null ? tools : java.util.Set.of();
    }

    /** Set the list of endpoints for multi-endpoint joint analysis.
     *  When non-empty, runLoop uses buildMultiEntryUserMessage and sets
     *  allEntries on ToolContext. */
    public void setMultiEntries(java.util.List<ApiEntry> entries) {
        this.multiEntries = entries != null ? entries : java.util.List.of();
    }

    /** F-1: Set API repository for registering browser-discovered APIs. */
    public void setApiRepository(com.flechazo.apisentinel.repository.ApiRepository apiRepository) {
        this.apiRepository = apiRepository;
    }

    /**
     * Multi-endpoint joint analysis: one Agent loop analyzes all endpoints
     * together. Results attributed per-endpoint via submit_report api_path.
     */
    private java.util.Map<String, PipelineResult> runLoopMulti(
            java.util.List<ApiEntry> entries, AgentCallback callback) {
        if (entries == null || entries.isEmpty()) return java.util.Map.of();
        ApiEntry primary = entries.get(0);
        // Run the standard loop with multi-entry context — the initial
        // message lists all endpoints so the Agent knows about them all.
        // The Agent submits per-endpoint results via submit_report(api_path=...).
        PipelineResult primaryResult = runLoop(primary, callback);
        // Results are collected by SubmitReportTool.verdictsByPath;
        // AgentFacade reads them after the loop completes.
        return java.util.Map.of(primary.getApiPath(), primaryResult);
    }

    private PipelineResult runLoop(ApiEntry entry, AgentCallback callback) {
        loopThread = Thread.currentThread();
        try {
        ToolContext toolCtx = new ToolContext(entry, provider, montoyaApi,
                codeIndexService, codeRepos, pipelineConfig, logger, oobService);
        if (userInteractionBridge != null) {
            toolCtx.setUserInteractionBridge(userInteractionBridge);
        }
        // F-1: Inject browser service if enabled
        if (browserService != null) {
            toolCtx.setBrowserService(browserService);
        }
        if (apiRepository != null) {
            toolCtx.setApiRepository(apiRepository);
        }
        if (appConfig != null) {
            toolCtx.setAppConfig(appConfig);
        }
        if (loginProfileManager != null) {
            toolCtx.setLoginProfileManager(loginProfileManager);
        }
        // Pass disabled tools from config (set by ToolManagementDialog)
        // Also disable chain/sibling tools when cascade hunting is off
        java.util.Set<String> effectiveDisabled = new java.util.HashSet<>(disabledTools != null ? disabledTools : java.util.Set.of());
        if (!cascadeEnabled) {
            effectiveDisabled.add("chain_hunter");
            effectiveDisabled.add("map_sibling_endpoints");
        }
        toolCtx.setDisabledTools(effectiveDisabled);

        // Multi-endpoint mode: set all entries so tools and prompt builder
        // know about all endpoints being analyzed.
        if (!multiEntries.isEmpty()) {
            toolCtx.setAllEntries(multiEntries);
        }

        // Pass fast model for vision decisions in browser tools
        if (fastModel != null && !fastModel.isBlank()) {
            toolCtx.setFastModel(fastModel);
        }

        // Progressive Tool Disclosure + Finding Evidence Store: create these
        // BEFORE building the registry, so StandardToolRegistry.build() can
        // conditionally register request_tools / update_analysis_notes /
        // read_analysis_notes. Pre-fix: they were created AFTER the registry,
        // so the ctx getters returned null during build and the tools were
        // silently dropped — triggering a spurious WARN from the drift guard.
        ProgressiveToolDisclosure toolDisclosure = new ProgressiveToolDisclosure(logger);
        toolCtx.setProgressiveToolDisclosure(toolDisclosure);
        FindingEvidenceStore findingStore = new FindingEvidenceStore(logger);
        toolCtx.setFindingEvidenceStore(findingStore);

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
        // P2-3: mint the per-run nonce fence BEFORE building the system prompt
        // so buildSystemPrompt()'s fence instruction and every tool-result
        // wrapper share one nonce. Pre-P2-3 the Agent's tool results (HTTP
        // responses, grep hits, DOM dumps) entered the conversation as raw
        // text — an attacker response body could carry prompt injection with
        // no fence to demarcate it. (A1 fixed Pipeline's FinalVerdictPrompt
        // but left the Agent loop's tool results unfenced.)
        untrustedContent = com.flechazo.apisentinel.ai.prompt.UntrustedContent.forRun();
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(ChatMessage.system(buildSystemPrompt()));
        // Multi-endpoint mode: if toolCtx has allEntries set, use the
        // multi-entry message that lists all endpoints.
        if (toolCtx.isMultiEndpoint()) {
            messages.add(ChatMessage.user(buildMultiEntryUserMessage(toolCtx.allEntries())));
        } else {
            messages.add(ChatMessage.user(buildInitialUserMessage(entry)));
        }

        // Indices of dynamic system-role messages (reflection / findings /
        // validation) currently sitting in {@code messages}. We track them
        // so the start of each iteration can strip the prior copies before
        // re-injecting a fresh one — otherwise OpenAI/Ollama re-send every
        // stale injection on every turn (linear token waste), and the
        // long-standing comment claiming "remove previous reflection" would
        // keep lying about the behavior.
        List<Integer> dynamicSystemInjectionIndices = new ArrayList<>();

        // Progressive Tool Disclosure was created earlier (before the registry
        // build) so the conditional registrations can see it. The variable is
        // still in scope here for the drift guard and phase pre-activation.

        // Startup drift guard: if a tool name in PHASE_TOOLS doesn't match any
        // registered tool (e.g. a typo like "response_diff" vs "diff_responses"),
        // log a WARN so the silent-unreachable regression can't reoccur.
        String driftReport = ProgressiveToolDisclosure.validateConsistency(registry.getToolNames());
        if (!driftReport.isEmpty()) {
            logger.warn(driftReport);
        }

        // If no traffic AND browser is available, pre-activate BROWSER phase
        // so browser tools are visible from the start (otherwise the agent
        // can't see them and falls back to code analysis, defeating the
        // "browser first" system prompt guidance).
        boolean hasTraffic = entry.getLastRawRequest() != null && !entry.getLastRawRequest().isEmpty();
        if (!hasTraffic && browserService != null) {
            toolDisclosure.requestToolGroup("browser");
            logger.debug("[Agent] 无捕获流量 + 浏览器可用 → 预激活 BROWSER 阶段");
        }

        // Initial tool definitions — will be updated each iteration
        List<ToolDefinition> toolDefs = toolDisclosure.getToolsForPhase(
                ProgressiveToolDisclosure.Phase.RECON, registry);
        int totalTokensUsed = 0;
        Map<Integer, String> stageDescriptions = new LinkedHashMap<>();

        // Reflection tracking: detect when the Agent is stuck
        int consecutiveNoAnomaly = 0;
        int consecutiveWafBlocks = 0;
        // P0-5: buffer of the last N send_request raw result strings so
        // ErrorCompressor.diagnoseBatch can run over REAL tool output
        // instead of a synthetic "normal response × 5" / "waf_blocked × 3"
        // probe. The pre-P0-5 probe made the compressor look at text that
        // wasn't what the model actually saw, producing misleading
        // classifications (the "4 → 290 token inflation" bug). The buffer
        // is bounded to keep the reflection prompt from ballooning.
        java.util.Deque<String> recentSendRequestResults = new java.util.ArrayDeque<>();
        int recentSendRequestResultsCap = 10;
        int lastReflectionIteration = -1;

        // Structured analysis state tracking — survives context compaction
        AnalysisStateTracker stateTracker = new AnalysisStateTracker();
        AnalysisProfile.ProfileResult profile = AnalysisProfile.selectProfile(entry);
        stateTracker.setProfileName(profile.profileName());
        stateTracker.setApplicableCategories(profile.applicableCategories());
        boolean profileInjected = false;

        // Episodic Reflection Memory — verbal reinforcement learning
        // Stores failure reflections in a sliding window, injected before each LLM call
        EpisodicReflectionMemory reflectionMemory = new EpisodicReflectionMemory(logger);
        reflectionMemory.setFastModelName(getFastModelName());

        // Error Compressor — Smart Cascade diagnostic compression
        // Compresses failed batch results from ~5000 to ~200 tokens
        ErrorCompressor errorCompressor = new ErrorCompressor(logger);

        // Finding Evidence Store was created earlier (before the registry
        // build) so the conditional registrations can see it.

        // Plan-then-Execute agent — generates structured analysis plan after recon
        PlanThenExecuteAgent planner = new PlanThenExecuteAgent(logger);
        planner.setFastModelName(getFastModelName());

        // Attack Hypothesis Generator — GoT-style hypothesis tree for guided testing
        AttackHypothesisGenerator hypothesisGen = new AttackHypothesisGenerator(logger);
        hypothesisGen.setFastModelName(getFastModelName());

        // PoC Validator — validates CONFIRMED findings before report submission
        PocValidator pocValidator = new PocValidator(logger);
        // Generic stuck-loop guard: fires on ANY repeated identical tool-call
        // batch, unlike the pattern-specific reflection triggers below.
        RepeatCallDetector repeatDetector = new RepeatCallDetector();

        try {
            for (int iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
                if (cancelled) {
                    return completeCancelled(entry, callback, analyzeTool, codeTool, genTool,
                            sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed);
                }
                logger.debug("[Agent] 迭代 %d/%d 开始", iteration + 1, MAX_ITERATIONS);

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

                // ① Context-window rollover: before forced compaction evicts
                // early reasoning/findings context, hand off to a fresh window.
                // Durable state (structured findings + free-text progress notes)
                // survives in the FindingEvidenceStore; a thread_hint tells the
                // new window to recover it via read_analysis_notes. Falls back
                // to compaction when disabled (default) or the window cap is hit.
                if (!rolloverIfNeeded(messages, findingStore,
                        dynamicSystemInjectionIndices)) {
                    compactIfNeeded(messages, registry);
                }

                // Drop any dynamic system-role injections added in a prior
                // iteration BEFORE we add this turn's fresh copies. Without
                // this, OpenAI/Ollama re-send every stale injection on every
                // turn (linear token waste: ~$1.15/endpoint over a 50-iter
                // run), and the "remove previous reflection" comment below
                // — written years ago but never implemented — would keep
                // lying about the behavior.
                //
                // Claude is unaffected at the wire level (P0-1 merge + P1-7
                // cache marker on the first block keeps the cache hit rate),
                // but the in-memory list still benefits from cleanup — less
                // to compact, less to iterate, less to confuse a future
                // reader of the trace logs.
                removeDynamicSystemInjections(messages, dynamicSystemInjectionIndices);

                // Progressive Tool Disclosure: update phase-aware tool set each iteration.
                // Detect phase from tool call history, then get filtered definitions.
                ProgressiveToolDisclosure.Phase currentPhase =
                        toolDisclosure.detectPhase(toolCtx.sessionState().calledTools(), iteration);
                toolDefs = toolDisclosure.getToolsForPhase(currentPhase, registry);

                // Inject reflection memory before each LLM call
                // (Reflexion pattern: accumulated failure lessons guide next attempt)
                if (!reflectionMemory.isEmpty() && iteration > 0) {
                    // Add a fresh reflection that includes any new lessons; the
                    // prior iteration's copy was removed by the cleanup above.
                    markDynamicSystemInjection(messages, dynamicSystemInjectionIndices);
                    messages.add(ChatMessage.system(reflectionMemory.buildReflectionPrompt()));
                }

                // Inject findings summary if there are persisted findings
                // (FindingEvidenceStore: persistent findings survive context compaction)
                if (findingStore.size() > 0 && iteration % 3 == 0 && iteration > 0) {
                    // Inject every 3 iterations to avoid excessive repetition
                    markDynamicSystemInjection(messages, dynamicSystemInjectionIndices);
                    messages.add(ChatMessage.system(findingStore.buildFindingsSummary()));
                }

                LlmRequest request = new LlmRequest(messages, toolDefs, TEMPERATURE, MAX_TOKENS_PER_TURN);
                if (provider.supportsExtendedThinking()) {
                    request = request.withThinking(thinkingBudgetForIteration(
                            iteration, lastReflectionIteration,
                            consecutiveNoAnomaly, consecutiveWafBlocks));
                }
                LlmResponse response;
                try {
                    response = completeWithRateLimitRetry(provider, request);
                } catch (java.util.concurrent.TimeoutException te) {
                    logger.error("[Agent] LLM 调用超时 (>%.0fs, 已重试 %d 次)",
                            (double) LLM_CALL_TIMEOUT_SEC, TIMEOUT_RETRIES);
                    callback.onAgentError("LLM 调用超时 (>10分钟 × " + TIMEOUT_RETRIES + " 次重试)，请检查网络或 API 服务状态");
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
                        logger.debug("[Agent] 调用工具: %s", tc.toolName());
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

                        // P2-3: append tool result message — fenced with the
                        // per-run nonce so attacker-controlled bytes inside it
                        // (HTTP response bodies, DOM dumps, grep hits, source
                        // comments) can't carry prompt injection past a fence
                        // the model was told to treat as data. The UI callback
                        // above still gets the raw result; only the LLM-bound
                        // message is wrapped.
                        String fencedResult = untrustedContent != null
                                ? untrustedContent.wrap(tc.toolName() + " result", truncatedResult)
                                : truncatedResult;
                        messages.add(ChatMessage.toolResult(tc.id(), fencedResult));

                        // Inject analysis profile after first heuristic_scan
                        if ("heuristic_scan".equals(tc.toolName()) && !profileInjected) {
                            profileInjected = true;
                            String profilePrompt = AnalysisProfile.buildProfilePrompt(profile);
                            messages.add(ChatMessage.user(profilePrompt));
                            logger.debug("[Agent] 注入分析 Profile: %s", profile.profileName());

                            // Plan-then-Execute: generate structured analysis plan
                            // Only when a dedicated fast model is configured (opt-in)
                            if (!planner.hasPlan()) {
                                var fastProvider = getFastProvider(provider);
                                if (fastProvider != null) {
                                    var plan = planner.generatePlan(
                                            entry, toolResult, "", profile, fastProvider);
                                    if (plan != null) {
                                        messages.add(ChatMessage.user(planner.buildPlanPrompt()));
                                    }

                                    // Attack Hypothesis Generator: GoT-style hypothesis tree
                                    // Also requires fast model (opt-in)
                                    if (!hypothesisGen.isGenerated()) {
                                        var hypotheses = hypothesisGen.branch(
                                                entry, toolResult, profile, fastProvider);
                                        if (!hypotheses.isEmpty()) {
                                            messages.add(ChatMessage.user(
                                                    hypothesisGen.buildHypothesisBoard()));
                                        }
                                    }
                                }
                            }
                        }

                        // Record send_request results in state tracker
                        if ("send_request".equals(tc.toolName())) {
                            String paramHint = tc.arguments() != null && tc.arguments().contains("parameter")
                                    ? tc.arguments().substring(0, Math.min(tc.arguments().length(), 100)) : "";
                            stateTracker.recordFromSendRequest(paramHint, toolResult);

                            // P0-5: keep the last N raw results for
                            // ErrorCompressor so the reflection trigger
                            // can diagnose real tool output.
                            recentSendRequestResults.addLast(toolResult);
                            while (recentSendRequestResults.size() > recentSendRequestResultsCap) {
                                recentSendRequestResults.removeFirst();
                            }

                            // Update hypothesis scores based on send_request results
                            if (hypothesisGen.isGenerated()) {
                                var topH = hypothesisGen.getTopHypothesis();
                                if (topH != null) {
                                    hypothesisGen.updateScore(topH.id(), toolResult);
                                }
                            }
                        }

                        // Auto-ingest findings from tool results
                        findingStore.ingestFromToolResult(tc.toolName(), toolResult, iteration);

                        // Track consecutive no-anomaly send_request calls for reflection
                        if ("send_request".equals(tc.toolName())) {
                            boolean hasAnomaly = toolResult != null && (
                                    toolResult.contains("\"anomaly\":true")
                                    || toolResult.contains("SQL 错误") || toolResult.contains("sql error"));
                            boolean isWafBlocked = toolResult != null && (
                                    toolResult.contains("waf_detected") || toolResult.contains("WAF")
                                    || toolResult.contains("\"waf_detected\":true"));
                            // Distinguish real anomalies from generic 500/NPE errors.
                            // A 500 NPE with stack trace is information disclosure,
                            // but it's NOT a successful exploit — the agent is still stuck.
                            // Count it as "no productive anomaly" so the reflection trigger fires.
                            boolean isGenericError = toolResult != null && (
                                    toolResult.contains("NullPointerException")
                                    || toolResult.contains("500")
                                    || toolResult.contains("404")
                                    || toolResult.contains("405")
                                    || toolResult.contains("ClassCastException"));
                            // Real anomaly = anomaly flag or SQL error, but NOT generic 500/NPE
                            boolean isRealAnomaly = hasAnomaly && !isGenericError;

                            if (isWafBlocked) {
                                consecutiveWafBlocks++;
                                consecutiveNoAnomaly = 0;
                            } else if (isRealAnomaly) {
                                consecutiveNoAnomaly = 0;
                                consecutiveWafBlocks = 0;
                            } else {
                                consecutiveNoAnomaly++;
                                consecutiveWafBlocks = 0;
                            }
                        }

                        // Check if submit_report was called
                        if ("submit_report".equals(tc.toolName()) && reportTool.getVerdict() != null) {
                            // PoC Validation: validate CONFIRMED findings before finalizing
                            if (findingStore.hasConfirmed()) {
                                var validationReport = pocValidator.validateAll(findingStore);
                                String validationSummary = pocValidator.buildValidationSummary(validationReport);
                                if (!validationSummary.isEmpty()) {
                                    messages.add(ChatMessage.system(validationSummary));
                                    logger.info("[Agent] PoC 验证: %d 通过, %d 降级",
                                            validationReport.confirmed(), validationReport.downgraded());
                                }
                            }

                            // Multi-endpoint mode: don't terminate until all endpoints
                            // have been reported. Let the Agent decide its own analysis
                            // order — it can interleave testing across endpoints and
                            // submit reports as it finishes each one.
                            if (toolCtx.isMultiEndpoint()) {
                                int reported = reportTool.getVerdictsByPath().size();
                                int total = toolCtx.allEntries().size();
                                if (reported < total) {
                                    var unreported = new java.util.ArrayList<>(
                                            toolCtx.allEntries().stream()
                                                    .map(e -> e.getApiPath())
                                                    .filter(p -> !reportTool.getVerdictsByPath().containsKey(p))
                                                    .toList());
                                    String reminder = String.format(
                                            "已提交 %d/%d 个接口报告。还有 %d 个未提交：%s\n"
                                            + "你可以自由选择分析顺序，也可以交叉对比已分析接口的发现。"
                                            + "完成后调用 submit_report(api_path=接口路径) 提交。",
                                            reported, total, unreported.size(),
                                            String.join("、", unreported));
                                    messages.add(ChatMessage.user(reminder));
                                    logger.info("[Agent] 多端点: 已提交 %d/%d，继续", reported, total);
                                    // Do NOT return — continue the loop
                                } else {
                                    // All endpoints reported — terminate
                                    logger.info("[Agent] 全部 %d 个接口报告已提交，分析完成", total);
                                    boolean verified = toolCtx.sessionState().hasCalled("send_request")
                                        || toolCtx.sessionState().hasCalled("test_auth_bypass");
                                    PipelineResult result = buildResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed, verified);
                                    callback.onAgentComplete(result);
                                    return result;
                                }
                            } else {
                                // Single-endpoint mode: submit_report ends the session
                                logger.info("[Agent] 报告已提交，分析完成");
                                boolean verified = toolCtx.sessionState().hasCalled("send_request")
                                    || toolCtx.sessionState().hasCalled("test_auth_bypass");
                                PipelineResult result = buildResult(entry, analyzeTool, codeTool, genTool, sendTool, authTool, reportTool, stageDescriptions, totalTokensUsed, verified);
                                callback.onAgentComplete(result);
                                return result;
                            }
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
                        logger.debug("[Agent] 注入 reflection: 连续 %d 次相同工具调用批次", repeatCount);
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

                    // Error Compression: generate structured diagnosis
                    // P0-5: feed the compressor the actual recent
                    // send_request results rather than a synthetic
                    // "normal response × N" probe. Falls back to the
                    // legacy synthetic probe only when the buffer is
                    // empty (e.g. on the very first reflection before
                    // any send_request completed), so the reflection
                    // always has something to render.
                    java.util.List<String> realResults = new java.util.ArrayList<>(recentSendRequestResults);
                    if (realResults.isEmpty()) {
                        realResults = java.util.List.of("normal response × " + count);
                    }
                    ErrorCompressor.Diagnosis diagnosis = errorCompressor.diagnoseBatch(
                            realResults, "current parameter", "");

                    // Episodic Reflection: generate verbal lesson for future attempts
                    reflectionMemory.addReflectionDirect(
                            diagnosis.reflectionCategory(),
                            String.format("连续 %d 个 payload 未触发异常", count),
                            diagnosis.suggestedPivot());

                    messages.add(ChatMessage.user(
                            "【反思】你已经连续发送了 " + count + " 个 payload 但都没有触发异常。\n"
                          + diagnosis.compressedText() + "\n"
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
                    logger.debug("[Agent] 注入 reflection: 连续 %d 次 send_request 无异常", count);
                }

                // Trigger 1b: consecutive WAF blocks — model is hitting a wall
                if (consecutiveWafBlocks >= 3 && iteration > lastReflectionIteration + 2) {
                    int count = consecutiveWafBlocks;

                    // Error Compression for WAF blocks
                    // P0-5: same fix as Trigger 1 — real results first,
                    // synthetic probe only as a fallback. The probe
                    // ("waf_blocked × N") was previously misclassified
                    // as ALL_NORMAL because the substring "blocked" was
                    // matched before the synthetic-counting branch ran.
                    java.util.List<String> realWafResults = new java.util.ArrayList<>(recentSendRequestResults);
                    if (realWafResults.isEmpty()) {
                        realWafResults = java.util.List.of("waf_blocked × " + count);
                    }
                    ErrorCompressor.Diagnosis wafDiagnosis = errorCompressor.diagnoseBatch(
                            realWafResults, "current parameter", "");

                    // Episodic Reflection for WAF failures
                    reflectionMemory.addReflectionDirect(
                            "waf_blocked",
                            String.format("连续 %d 个 payload 被 WAF 拦截", count),
                            wafDiagnosis.suggestedPivot());

                    messages.add(ChatMessage.user(
                            "【反思】你已经连续发送了 " + count + " 个 payload 但全部被 WAF 拦截。\n"
                          + wafDiagnosis.compressedText() + "\n"
                          + "请停下来分析：\n"
                          + "1. 调用 waf_bypass_retry 尝试编码绕过（大小写/注释/编码/IP变体）\n"
                          + "2. 如果绕过失败，改用语义等效但无关键字的 payload（如用 CONCAT 替代 UNION SELECT）\n"
                          + "3. 如果所有绕过策略都失败，在报告中注明 WAF 防护有效，该发现最多标为疑似\n"
                          + "4. 不要继续生成更多会被拦截的 payload —— 转移测试方向"));
                    lastReflectionIteration = iteration;
                    consecutiveWafBlocks = 0;
                    consecutiveNoAnomaly = 0;
                    logger.debug("[Agent] 注入 reflection: 连续 %d 次 WAF 拦截", count);
                }

                // Trigger 2: 15+ iterations without submitting — check if evidence is enough
                if (iteration == 15) {
                    String statusSnapshot = stateTracker.buildStatusSnapshot();
                    // Include hypothesis board if GoT is active
                    String hypothesisBoard = hypothesisGen.isGenerated()
                            ? "\n" + hypothesisGen.buildHypothesisBoard() + "\n" : "";
                    messages.add(ChatMessage.user(
                            "【反思】已进行 15 轮分析。\n"
                          + statusSnapshot + hypothesisBoard
                          + "请回顾已收集的证据：\n"
                          + "1. 已经验证了哪些漏洞假设？哪些已被排除？\n"
                          + "2. 当前证据是否足够支撑一个结论？\n"
                          + "3. 是否有必须验证但尚未验证的关键假设？\n\n"
                          + "如果证据已经足够，请调用 submit_report 提交报告。"
                          + "如果还有关键假设需要验证，继续但聚焦于最重要的 1-2 个方向。"));
                    lastReflectionIteration = iteration;
                    logger.debug("[Agent] 注入 reflection: 迭代 %d 中期检查", iteration + 1);
                }

                // Trigger 3: 40+ iterations — diagnose what's blocking
                if (iteration == 40) {
                    String statusSnapshot = stateTracker.buildStatusSnapshot();
                    String coverageCheck = stateTracker.buildCoverageCheck();
                    // Include hypothesis board if GoT is active
                    String hypothesisBoard40 = hypothesisGen.isGenerated()
                            ? "\n" + hypothesisGen.buildHypothesisBoard() + "\n" : "";
                    messages.add(ChatMessage.user(
                            "【反思】已进行 40 轮分析，接近上限（50 轮）。请自我诊断：\n"
                          + statusSnapshot + hypothesisBoard40
                          + (coverageCheck != null ? coverageCheck + "\n\n" : "")
                          + "1. 是什么导致分析无法收尾？是否在重复调用同一个工具？\n"
                          + "2. 是否在某个参数上陷入了死循环（反复生成 payload 但都被拦截）？\n"
                          + "3. 当前已收集的证据能否支撑一个结论？\n\n"
                          + "如果无法继续推进，请基于已有证据调用 submit_report 提交。"
                          + "如果确实还有关键发现需要验证，请在 1-2 轮内完成并提交。"));
                    lastReflectionIteration = iteration;
                    logger.debug("[Agent] 注入 reflection: 迭代 %d 上限临近", iteration + 1);
                }

                // Notify iteration complete AFTER all work in this iteration is done
                callback.onIterationComplete(iteration + 1, MAX_ITERATIONS);
                logger.debug("[Agent] 迭代 %d/%d 完成", iteration + 1, MAX_ITERATIONS);
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
                        v.recommendations(), v.totalTokensUsed(), v.rejectionReasons()),
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
                    verdict.suspectedVulns(), verdict.summary(), verdict.recommendations(),
                    totalTokens, verdict.rejectionReasons());
        }
        if (!verified && verdict != null) {
            String caveat = "[提示] 未执行 send_request/test_auth_bypass 实测验证，"
                    + "以下结论基于静态代码/流量分析证据，未经程序化验证。\n\n";
            verdict = new FinalVerdict(verdict.overallRisk(), verdict.confirmedVulns(),
                    verdict.suspectedVulns(), caveat + verdict.summary(),
                    verdict.recommendations(), verdict.totalTokensUsed(), verdict.rejectionReasons());
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

        // If the agent called submit_report but the VerdictValidator stripped all
        // findings (because SendRequestTool never sets anomaly=true in Agent mode),
        // reconstruct a verdict from the agent's stage descriptions / text findings.
        if (verdict != null && verdict.confirmedVulns().isEmpty()
                && verdict.suspectedVulns().isEmpty()
                && (verdict.summary() == null || verdict.summary().isBlank())) {
            String combinedEvidence = stageDescriptions.values().stream()
                    .reduce("", (a, b) -> a + "\n" + b);
            if (!combinedEvidence.isBlank()) {
                String risk = inferRiskFromEvidence(combinedEvidence);
                List<SuspectedVuln> suspected = createSuspectedFromEvidence(combinedEvidence);
                verdict = new FinalVerdict(risk, List.of(), suspected,
                        combinedEvidence, "Agent 分析完成（verdict 从思考文本重建）", totalTokens);
            }
        }

        if (verdict == null) {
            String risk = "LOW";
            String summary = "Agent 分析未完成 — 以下是已收集到的信息。";
            String combinedEvidence = stageDescriptions.values().stream()
                    .reduce("", (a, b) -> a + "\n" + b);
            List<SuspectedVuln> suspected = List.of();
            if (!combinedEvidence.isBlank()) {
                risk = inferRiskFromEvidence(combinedEvidence);
                summary = combinedEvidence;
                suspected = createSuspectedFromEvidence(combinedEvidence);
            } else if (analyzeTool.getLastResult() != null && analyzeTool.getLastResult().overallRisk() != null) {
                risk = analyzeTool.getLastResult().overallRisk().name();
                summary = analyzeTool.getLastResult().summary();
            }
            // P2-2: surface that this verdict is a best-effort salvage — the
            // agent never called submit_report (budget exhausted / exception /
            // max iterations), so this reconstruction did not pass through the
            // LLM's own final-research step. Prepend the note before validate
            // so it survives into the final summary.
            String salvageNote = "[未完成验证] Agent 未调用 submit_report 即终止（预算耗尽/异常/迭代上限），"
                    + "以下结论从思考文本重建，未经完整 LLM 研判；程序化校验已对其中信息级发现做降级。\n\n";
            verdict = new FinalVerdict(risk, List.of(), suspected,
                    salvageNote + summary, "", totalTokens);
            // P2-2: the reconstructed verdict was built from the agent's
            // thinking text, so it skipped the VerdictValidator cross-check
            // the happy path runs. That let (a) informational-only findings
            // inferred from text survive into suspected_vulns (Phase 2
            // removal never ran) and (b) inferRiskFromEvidence return HIGH
            // from a keyword like "sql注入" while confirmed was empty —
            // violating the "HIGH requires a surviving confirmed" invariant
            // (Phase 5 downgrade never ran). Run it through validate with
            // whatever payloads were collected (possibly empty) so Phase 2
            // informational removal and Phase 5 HIGH-downgrade still apply.
            List<PayloadResult> fallbackPayloads = sendTool.getPayloadResults();
            verdict = VerdictValidator.validate(verdict,
                    fallbackPayloads != null ? fallbackPayloads : List.of(),
                    false, authTool.getLastResult());
        } else {
            List<PayloadResult> allPayloads = sendTool.getPayloadResults();
            if (allPayloads != null && !allPayloads.isEmpty()) {
                verdict = VerdictValidator.validate(verdict, allPayloads, false, authTool.getLastResult());
            }
            if (verdict.confirmedVulns().isEmpty() && verdict.suspectedVulns().isEmpty()
                    && (verdict.summary() == null || verdict.summary().isBlank())) {
                String combinedEvidence = stageDescriptions.values().stream()
                        .reduce("", (a, b) -> a + "\n" + b);
                if (!combinedEvidence.isBlank()) {
                    List<SuspectedVuln> suspected = createSuspectedFromEvidence(combinedEvidence);
                    verdict = new FinalVerdict(
                            inferRiskFromEvidence(combinedEvidence),
                            List.of(), suspected, combinedEvidence,
                            "Agent 分析完成（verdict 从思考文本重建）", totalTokens);
                }
            }
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

    /**
     * Infer risk level from the agent's text evidence.
     * Scans for vulnerability keywords to determine HIGH/MEDIUM/LOW.
     */
    private static String inferRiskFromEvidence(String evidence) {
        if (evidence == null || evidence.isBlank()) return "LOW";
        String lower = evidence.toLowerCase();
        if (lower.contains("rce") || lower.contains("远程代码执行")
                || lower.contains("命令注入") || lower.contains("command injection")
                || lower.contains("sql注入") || lower.contains("sql injection")
                || lower.contains("反序列化") || lower.contains("deserialization")) {
            return "HIGH";
        }
        if (lower.contains("idor") || lower.contains("越权") || lower.contains("未授权")
                || lower.contains("unauthorized") || lower.contains("ssrf")
                || lower.contains("xss") || lower.contains("跨站")
                || lower.contains("路径穿越") || lower.contains("path traversal")
                || lower.contains("xxe") || lower.contains("ssti")
                || lower.contains("认证绕过") || lower.contains("auth bypass")) {
            return "MEDIUM";
        }
        return "LOW";
    }

    /**
     * Create a SuspectedVuln from the agent's text evidence.
     * Scans for vulnerability type keywords and creates a structured finding.
     */
    private static java.util.List<com.flechazo.apisentinel.ai.pipeline.SuspectedVuln> createSuspectedFromEvidence(String evidence) {
        if (evidence == null || evidence.isBlank()) return java.util.List.of();
        String lower = evidence.toLowerCase();
        java.util.List<com.flechazo.apisentinel.ai.pipeline.SuspectedVuln> results = new java.util.ArrayList<>();

        // Detect vulnerability types from keywords
        if (lower.contains("idor") || lower.contains("越权") || lower.contains("未授权") || lower.contains("unauthorized")) {
            results.add(new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                    "越权/IDOR", "未授权访问/越权修改",
                    truncate(evidence, 2000), "", "HIGH"));
        }
        if (lower.contains("sql注入") || lower.contains("sql injection")) {
            results.add(new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                    "SQL注入", "SQL注入漏洞",
                    truncate(evidence, 2000), "", "HIGH"));
        }
        if (lower.contains("xss") || lower.contains("跨站")) {
            results.add(new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                    "XSS", "跨站脚本漏洞",
                    truncate(evidence, 2000), "", "HIGH"));
        }
        if (lower.contains("ssrf")) {
            results.add(new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                    "SSRF", "服务端请求伪造",
                    truncate(evidence, 2000), "", "HIGH"));
        }
        if (lower.contains("信息泄露") || lower.contains("information disclosure") || lower.contains("堆栈") || lower.contains("stack trace")) {
            results.add(new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                    "信息泄露", "敏感信息泄露",
                    truncate(evidence, 2000), "", "MEDIUM"));
        }

        // If no specific type matched, create a generic suspected finding
        if (results.isEmpty() && evidence.length() > 20) {
            results.add(new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                    "其他", "Agent 发现潜在安全问题",
                    truncate(evidence, 2000), "", "MEDIUM"));
        }

        return results;
    }

    /** Built once per Agent run and reused across iterations. Package-private
     *  (P2-2) so tests can assert cross-layer rule alignment — e.g. that the
     *  Agent prompt carries the full conditionally-valid upgrade table whose
     *  vocabulary aligns with {@link SafetyRules#hasChainEvidence}. */
    String buildSystemPrompt() {
        return """
                你是一名专业的API安全分析专家，使用一系列工具系统化地分析API端点的安全漏洞，
                通过实际验证收集证据，并提交完整的安全分析报告。
                所有分析结果、报告内容、summary、recommendations 必须使用中文输出。
                下方列出的各工具的详细参数与用途见你收到的 tool 定义，这里只给策略与规则。

                ## 分析策略（推荐顺序，可根据发现灵活调整）
                先用流量找实证，再用代码补判断：
                1) heuristic_scan(免费) → fingerprint_components(免费)：被动检测 + 组件识别。
                2) 流量先行：search_traffic / analyze_traffic 挖掘已捕获流量——响应是硬证据，比代码推测强，
                   优先从历史流量里找线索与结论。若该端点本身无流量，用 search_traffic 查同域名其他流量，
                   复用 auth_headers 构造请求。若已用 Burp 原生扫描器扫过目标，可调用 get_burp_scan_issues
                   拉取其已报告的 issue 作为假设线索（Burp 擅长传统漏洞，能补你盲区），但每条都须用
                   send_request / verify_* 实测验证后才可定级，不得直接采信扫描器判定。
                3) 代码增强（配置了代码仓库时更好）：audit_codebase / search_source_code / read_file /
                   grep_repo 定位 sink 与校验逻辑，精准判断哪里可能出问题、该怎么测——增强判断，不替代流量实证。
                4) 验证：generate_payloads → send_request 实测；越权/IDOR 优先 mine_history_idor（确定性
                   挖代理历史、不 replay、对 ctoken/签名类认证端点也能从历史实证，只报疑似需复核），
                   可 replay 的认证用 test_auth_bypass；业务逻辑 verify_business_logic；盲注升级
                   verify_boolean_blind → verify_timing_blind；被 WAF 拦截 waf_bypass_retry；
                   找定义/调用处 find_definition / find_callers。
                5) submit_report。
                范围较宽的探索性问题（如"全仓库哪里校验JWT"）已经自己查了几轮 read_file/grep_repo 仍没查全时，
                可用 dispatch_explore_agent 委派给隔离子 Agent，只拿回一段结论，不占用你自己的上下文。
                需要纯计算验证（复现算法/编解码/密码学，不涉及发请求）时可用 run_sandboxed_code，
                但它不隔离网络/真实文件系统，只用于计算，不要用来跟目标交互。

                ## 浏览器工具（前端/客户端安全测试，启用时可用）
                以下工具仅在设置中启用"浏览器能力"后可用，通过 Playwright 控制 Chromium 浏览器:
                - browser_discover(url, depth): 打开前端页面，自动捕获 XHR/Fetch 请求、分析 JS Bundle、
                  提取路由。用于 SPA 应用发现隐藏 API、从前端代码找到硬编码密钥/API Key。depth 1-3。
                  发现的 API 可通过 register_discovered_apis 注册到目标清单。
                - browser_render(url): 渲染页面提取完整 DOM、console 日志、CSP 违规、前端路由。用于
                  检查前端错误信息泄露、CSP 配置、动态生成的内容。
                - browser_dom_xss(url): 检测 DOM XSS 漏洞——检查 innerHTML/document.write/eval 等
                  sink，并尝试用 hash payload 触发执行。
                - register_discovered_apis(apis): 将 browser_discover 发现的 API 注册到仓库，后续可
                  用常规工具链(send_request/auth_bypass 等)测试。
                - browser_find_page(api_method, api_path): 反向定位调用指定 API 的前端页面。三级策略:
                  JS Bundle 搜索(高置信度) → 爬取映射(中) → RESTful 路径推断(低,始终可用)。
                  用于找到触发某接口的前端页面，以便通过 browser_interact 操作 UI 获取真实请求。
                - browser_interact(url, actions): 在页面上执行 UI 操作序列并捕获触发的网络请求。
                  支持: wait_for/click/fill/select/check/type/wait_for_request。
                  返回包含 Authorization、CSRF token、Cookie 等真实 headers 的捕获请求，可直接
                  作为 send_request 的模板。先用 browser_render 确定 selector，再调用此工具。
                  注意: browser_interact 会弹窗要求用户确认（首次），因为它会真实操作页面
                  （点击/填写表单）。browser_find_page/browser_render/browser_discover 只读取
                  页面信息，不需要确认。
                使用策略: 对 SPA 应用或前端入口页面优先使用 browser_discover 发现隐藏 API；对怀疑有
                DOM XSS 的页面使用 browser_dom_xss；browser_render 用于检查前端渲染后的实际 DOM 结构。

                ## 无捕获流量时的首选策略（浏览器优先）
                初始消息标注"无捕获流量"且浏览器工具可用（前端 Base URL 已配置）时，**优先使用浏览器工具**：
                1) browser_find_page(api_method, api_path) → 定位调用该 API 的前端页面
                2) browser_render(候选 URL) → 查看 DOM/表单结构，确定 selector
                3) browser_interact(url, actions) → UI 交互触发 API，捕获含真实认证的请求
                4) 用捕获的请求作为 send_request 模板做安全测试
                浏览器路径能获取真实 auth token/CSRF token/正确参数格式，比从代码推断更准确。

                ## 请求构造策略（浏览器不可用时的回退方案）
                当浏览器工具不可用（未启用或无前端 URL）时，改用代码分析构造请求：
                1) search_source_code/read_file 读 Controller 方法确定参数；
                2) search_traffic 搜同域名历史流量提取认证 token/通用请求头；
                3) 从代码推理参数值（数字 ID 给合理默认值、枚举取第一个合法值、@RequestBody 按 Entity
                构造最小 JSON）；
                4) send_request 发送，200 记为基线继续分析，4xx/5xx 分析原因调整重试。
                **ID 枚举策略**: 当 GET /api/resource/{id} 返回 500/NPE（资源不存在）时，
                不要只试 id=1。批量试常见种子 ID: 1, 2, 100, 1001, 1002, 1003, 2001, 9999。
                如果 1~5 都 NPE，试 1000-1010 范围；如果仍 NPE，试 POST 创建资源再读。
                不要在一个 ID 上反复重试——切换到不同 ID 范围。

                ## 鉴权失败的处理（401/403/登录重定向）
                当 send_request / verify_* / test_auth_bypass 返回 401/403，或响应是登录页 HTML（特征：
                含 <input type="password">、<form action=".../login">、302 跳转到 /sso、/signin、/auth），
                且当前 AppConfig 中无有效 auth cookie 时，**先用 ask_user 询问测试账号密码**再继续：

                1) 调用 ask_user：
                   - question: "检测到 &lt;接口方法 路径&gt; 需要登录态（返回 401/403 或登录页重定向）。
                     是否提供测试账号以便继续测试？"
                   - context: 简述你已排除了哪些可能（如"已确认非 WAF 拦截、非参数错误，纯粹是缺鉴权"）
                   - options: ["提供账号自动登录", "跳过鉴权类测试", "我手动粘贴 cookie"]
                   如果选项为"跳过鉴权类测试"，在最终报告中注明"该接口因缺登录态未做鉴权类测试"，
                   不要硬猜或强行测试。如果选"我手动粘贴 cookie"，让用户在回复里贴 cookie 字符串，
                   你把它作为 Authorization/Cookie header 注入后续 send_request。
                2) 用户给账号密码后，调用 browser_login(
                      login_url=&lt;登录页 URL&gt;,
                      username=&lt;用户名&gt;,
                      password=&lt;密码&gt;,
                      strategy="auto",
                      remember=true
                   )。登录页 URL 从 302 Location 头或前端页面推断；实在找不到就从同域名
                   历史流量或 browser_find_page 里查。remember=true 会把该账号持久化到
                   ~/.api-sentinel/login-profiles.json，下次同域名登录自动复用（用户可手动删除文件）。
                3) 登录成功后 cookie 自动注入 AppConfig，后续 send_request 会带上。继续原分析。
                4) 如果登录失败（表单检测失败、验证码、MFA），工具会返回 troubleshooting 字段，
                   按指引调整 strategy 或提示用户手动登录。**不要在循环里反复重试错误的账号密码。**

                **不要**：在没问过用户的情况下，把代码里看到的硬编码账号/默认密码直接拿去测试
                （即使代码有 admin/admin123 这种占位符，也可能是过期或仅开发环境有效的，要确认）。
                **不要**：用同一个错误账号连续尝试超过 3 次——容易触发账号锁定。
                **不要**：把密码写进最终报告的任何字段（identity_proof 写"用户提供的测试账号"即可，
                不要写用户名和密码原文）。

                ## 工具加载机制（渐进式工具暴露）
                为减少上下文开销，工具按分析阶段分组加载。你初始只会看到当前阶段的工具。
                如果需要其他阶段的工具（如已进入 payload 测试但还没加载 verify_* 工具），
                调用 request_tools(group) 按需加载。可用组:
                - recon: heuristic_scan, audit_codebase, 代码搜索工具
                - payload_testing: generate_payloads, verify_* 系列验证工具
                - browser: browser_discover, browser_render, browser_interact 等
                - advanced: active_probe, generate_oob_probe, run_sandboxed_code
                - chain: chain_hunter, map_sibling_endpoints, dispatch_explore_agent
                大多数情况下系统会自动加载你需要的工具组，request_tools 仅在你发现缺少工具时使用。

                ## 并行工具调用（省时省 token）
                当你需要执行多个**相互独立**的只读操作（如读多个文件、搜索多个关键词、
                同时查代码和搜流量），请在**同一轮**一次性发出所有 tool_call，而不是逐轮
                一个个发。系统会并行执行只读工具，省掉每轮的固定前缀开销（4-8K token/轮）。
                注意：有依赖关系的操作（如先读文件再根据内容搜索）不能并行。

                ## 分析笔记（update_analysis_notes）
                使用 update_analysis_notes 工具主动记录重要发现，防止上下文压缩后丢失：
                - action="add": 记录新发现（category + parameter + evidence + level）
                - action="update": 更新已有发现的置信度（finding_id + level）
                - action="note": 记录一般观察
                类别: SQL_INJECTION, XSS, SSRF, IDOR, PATH_TRAVERSAL, COMMAND_INJECTION, AUTH_BYPASS 等
                级别: CONFIRMED（已确认）、SUSPECTED（疑似）、NEGATIVE（排除）、NOTE（备注）
                建议时机: send_request 确认异常后、audit_codebase 发现高危 sink 后、排除某类漏洞后。

                ## 攻击假设看板（GoT 模式，启用时可见）
                如果收到"攻击假设看板"，这是系统基于侦察结果自动生成的攻击假设树：
                - 每个假设有评分(0-1)，按可能性排序。优先测试高分假设。
                - 状态图标: ✅已确认 ❓疑似 🔄测试中 ⏳待测 ✗已剪枝 🔗已合并
                - 测试某假设后，系统自动更新评分（异常+0.2，正常-0.15，WAF-0.05）
                - 评分低于 0.15 自动剪枝。连续 3 次失败的假设应跳过。
                - 如果两个假设共享根因（同参数或同漏洞类型），可考虑串成攻击链。

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
                  "已确认"；有指标无确证时标记"疑似"并注明置信�����。保守判断，误报浪费安全团队时间。
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
                该数据的接口，read_file 检查写入侧有无校验；5) 能串起"写��无校验→落库→读出→未过滤进
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
                """ + cascadeInstruction() + chainHuntingSection()
                + com.flechazo.apisentinel.ai.prompt.SafetyRules.AGENT_CONDENSED_RULES
                + com.flechazo.apisentinel.ai.prompt.SafetyRules.CONDITIONALLY_VALID_PROMPT_TEXT
                + (untrustedContent != null
                        ? "\n\n" + untrustedContent.fenceInstruction()
                        : "");
    }

    /** Cascade/sibling endpoint spreading instruction — only when cascade is enabled. */
    private String cascadeInstruction() {
        if (!cascadeEnabled) return "";
        return """
                确认/疑似漏洞后铺开到兄弟端点: map_sibling_endpoints(免费查同 Controller/同前缀路由) →
                chain_hunter(委派集群狩猎子 Agent 实测兄弟端点并串链，见下方集群狩猎策略)。
                """;
    }

    /** Cluster-hunting strategy (A→B chaining), distilled from bughunter's
     *  chain-builder methodology. Injected unconditionally into the Agent
     *  system prompt because ANY confirmed/suspected finding can trigger a
     *  hunt — there is no per-finding gate at system-prompt build time.
     *  Missing resource degrades to empty (non-fatal). */
    private String chainHuntingSection() {
        if (!cascadeEnabled) return "";
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
            sb.append("该接口没有捕获到任何 HTTP 流量。\n\n");
            sb.append("**首选: 浏览器驱动（如果 browser_find_page 等工具可用）**\n");
            sb.append("  如果你有 browser_find_page/browser_render/browser_interact 工具，优先走浏览器路径：\n");
            sb.append("  1. browser_find_page 定位调用此 API 的前端页面\n");
            sb.append("  2. browser_render 查看页面 DOM/表单结构\n");
            sb.append("  3. browser_interact 操作 UI 触发此 API，捕获含真实认证的请求\n");
            sb.append("  4. 用捕获的请求作为 send_request 的模板\n\n");
            sb.append("**回退: 代码分析（浏览器不可用时）**\n");
            sb.append("  1. search_source_code/read_file 读 Controller 方法，理解参数/认证方式\n");
            sb.append("  2. search_traffic 搜同域名历史流量提取认证 token\n");
            sb.append("  3. 从代码推理参数值，send_request 发送\n");
            sb.append("  4. 200 → 基线；4xx/5xx → 调整重试\n\n");
            sb.append("构造成功后，将响应作为基线，继续执行正常安全分析流程。\n\n");
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

        // Reuse-window soft fold: inject the prior verdict (if within the
        // configured time window) as a "known starting point" so the model
        // confirms/corrects rather than re-derives from scratch. Mirrors
        // AnalysisPipeline.buildPriorAnalysisContext — see
        // docs/plan/reuse-window-agent-migration.md.
        String priorCtx = buildPriorAnalysisContext(entry);
        if (!priorCtx.isEmpty()) {
            sb.append("\n").append(priorCtx).append("\n");
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

    /**
     * Get the fast/cheap LLM provider for lightweight tasks (plan generation,
     * reflection, hypothesis generation, etc.). Returns null if no fast model
     * is configured — this keeps Plan-then-Execute and GoT as opt-in.
     *
     * <p>When fastModel is configured (e.g., "deepseek-chat" or "claude-haiku"),
     * returns the main provider. The caller uses {@code withModelOverride(fastModel)}
     * to route the call to the fast model on the same provider/endpoint.
     */
    private LlmProvider getFastProvider(LlmProvider mainProvider) {
        if (fastModel != null && !fastModel.isBlank()) {
            return mainProvider;
        }
        return null;
    }

    /** Get the fast model name (null if not configured). */
    private String getFastModelName() {
        return (fastModel != null && !fastModel.isBlank()) ? fastModel : null;
    }

    /**
     * Build the initial user message for multi-endpoint joint analysis.
     * Lists all endpoints with their traffic data, then instructs the Agent
     * to analyze each one and submit per-endpoint reports via
     * {@code submit_report(api_path=...)}.
     */
    private String buildMultiEntryUserMessage(java.util.List<ApiEntry> entries) {
        StringBuilder sb = new StringBuilder();
        sb.append("## 多端点联合安全分析\n\n");
        sb.append("你将分析以下 ").append(entries.size()).append(" 个 API 端点。\n\n");
        sb.append("**分析策略：**\n");
        sb.append("- 你可以自由选择分析顺序，无需按列表顺序逐个分析\n");
        sb.append("- 建议交叉测试：先对所有端点做 heuristic_scan 建立基线，");
        sb.append("再对最可疑的深入检测\n");
        sb.append("- 发现一个端点的漏洞模式后，主动检查其他端点是否存在同样问题\n");
        sb.append("- audit_codebase / search_source_code 的结果对所有端点都有效，无需重复调用\n\n");
        sb.append("**⚠️ 请求构造要求：**\n");
        sb.append("- 使用上方「Captured HTTP Request」作为 send_request 的模板\n");
        sb.append("- 必须保留完整的 URL 路径（含所有前缀和 query 参数）\n");
        sb.append("- 必须保留所有 Cookie 和认证头（Authorization、X-Token 等）\n");
        sb.append("- 只修改你要测试的参数，不要自行拼接 URL\n");
        sb.append("- 如果所有请求都返回 4xx，检查是否遗漏了认证信息或 URL 路径不完整\n\n");
        sb.append("**提交要求：**\n");
        sb.append("- 每个端点分析完毕后调用 submit_report(api_path=接口路径) 提交报告\n");
        sb.append("- 所有 ").append(entries.size()).append(" 个端点都必须提交报告，循环在全部提交后结束\n\n");

        for (int i = 0; i < entries.size(); i++) {
            ApiEntry entry = entries.get(i);
            sb.append("---\n\n");
            sb.append("### 端点 ").append(i + 1).append(": ").append(entry.getApiPath()).append("\n\n");
            sb.append("**Method:** ").append(entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET").append("\n");
            sb.append("**Path:** ").append(entry.getApiPath()).append("\n");
            sb.append("**Domain:** ").append(entry.getDomain() != null ? entry.getDomain() : "unknown").append("\n");
            sb.append("**Status Code:** ").append(entry.getLastStatusCode()).append("\n\n");

            boolean hasTraffic = entry.getLastRawRequest() != null && !entry.getLastRawRequest().isEmpty();
            if (hasTraffic) {
                sb.append("**Captured HTTP Request:**\n```\n");
                sb.append(truncate(entry.getLastRawRequest(), 5000));
                sb.append("\n```\n\n");
                if (entry.getLastRawResponse() != null && !entry.getLastRawResponse().isEmpty()) {
                    sb.append("**Captured HTTP Response:**\n```\n");
                    sb.append(truncate(entry.getLastRawResponse(), 5000));
                    sb.append("\n```\n\n");
                }
            } else {
                sb.append("⚠️ 无捕获流量 — 需要先构造请求\n\n");
            }

            if (entry.getNote() != null && !entry.getNote().isBlank()) {
                sb.append("**User Notes:** ").append(truncate(entry.getNote(), 1000)).append("\n\n");
            }
            String passiveFindingsText = entry.buildPassiveFindingsText();
            if (!passiveFindingsText.isEmpty()) {
                sb.append("**Passive Detection Notes:**\n");
                sb.append(truncate(passiveFindingsText, 1000)).append("\n\n");
            }
        }

        // Reuse-window + pattern store apply to the first entry's domain
        if (!entries.isEmpty()) {
            String priorCtx = buildPriorAnalysisContext(entries.get(0));
            if (!priorCtx.isEmpty()) {
                sb.append("\n").append(priorCtx).append("\n");
            }
            if (patternStore != null) {
                sb.append(patternStore.buildPromptSection(entries.get(0), 5));
            }
        }

        sb.append("\n请开始分析。建议先对每个端点执行 heuristic_scan，");
        sb.append("然后针对最可疑的端点深入检测。每完成一个端点的分析就调用 ");
        sb.append("submit_report(api_path=该端点路径) 提交报告。\n");
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n...[truncated]";
    }

    /**
     * Reuse-window soft fold: if this endpoint was analyzed within
     * {@link #reuseWindowMinutes}, build a summary of the prior verdict for
     * injection into the initial user message. Delegates to the shared
     * {@link PriorAnalysisContextBuilder} (same logic as AnalysisPipeline).
     */
    String buildPriorAnalysisContext(ApiEntry entry) {
        return PriorAnalysisContextBuilder.build(entry, reuseWindowMinutes);
    }

    /**
     * Retry the LLM call on RATE_LIMITED with backoff instead of aborting the
     * whole agent run. Other failures propagate to the caller's catch blocks.
     */
    private LlmResponse completeWithRateLimitRetry(LlmProvider provider, LlmRequest request)
            throws Exception {
        int timeoutAttempts = 0;
        for (int attempt = 0; attempt <= RATE_LIMIT_RETRIES; attempt++) {
            try {
                LlmResponse resp = provider.complete(request)
                        .get(LLM_CALL_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS);
                if (resp.finishReason() == LlmResponse.FinishReason.RATE_LIMITED
                        && attempt < RATE_LIMIT_RETRIES) {
                    long backoff = Math.min(2000L * (1L << attempt), 30000L);
                    logger.warn("[Agent] RATE_LIMITED, 退避 %dms 后重试 (%d/%d)",
                            backoff, attempt + 1, RATE_LIMIT_RETRIES);
                    Thread.sleep(backoff);
                    continue;
                }
                return resp;
            } catch (java.util.concurrent.TimeoutException te) {
                timeoutAttempts++;
                if (timeoutAttempts <= TIMEOUT_RETRIES) {
                    logger.warn("[Agent] LLM 调用超时 (>%.0fs), 重试 (%d/%d)",
                            (double) LLM_CALL_TIMEOUT_SEC, timeoutAttempts, TIMEOUT_RETRIES);
                    attempt--; // don't count timeout against rate-limit attempts
                    continue;
                }
                throw te; // exhausted timeout retries — propagate to caller
            }
        }
        return provider.complete(request)
                .get(LLM_CALL_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS);
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

    /** Marks {@code messages.size()} (i.e. the slot that is about to receive
     *  the next dynamic system injection) so {@link #removeDynamicSystemInjections}
     *  can strip it on the next iteration. Must be called <b>before</b>
     *  {@code messages.add(ChatMessage.system(...))}.
     *
     *  <p>Pairs with {@link #removeDynamicSystemInjections}; together they
     *  implement the "remove previous reflection" cleanup that the inline
     *  comment in {@code runLoop} described for years but was never wired. */
    private void markDynamicSystemInjection(List<ChatMessage> messages, List<Integer> tracker) {
        tracker.add(messages.size());
    }

    /** Removes every system-role message whose position was recorded by
     *  {@link #markDynamicSystemInjection} in a prior iteration. Iterates
     *  in reverse index order so {@code List.remove(int)} stays valid as
     *  earlier entries shift positions; clears the tracker afterwards so
     *  the next iteration starts with a clean slate.
     *
     *  <p>Intentionally skips removals whose recorded index is out of range
     *  or whose slot no longer holds a system message (defensive against
     *  {@code compactIfNeeded} or other passes having shifted the list)
     *  rather than throwing — the cleanup is a best-effort cost control,
     *  not a correctness requirement for Claude (which merges system
     *  messages in the provider anyway, see P0-1). */
    private void removeDynamicSystemInjections(List<ChatMessage> messages, List<Integer> tracker) {
        if (tracker.isEmpty()) return;
        // Reverse order: removing index 5 then 2 is safe; removing 2 then 5
        // would shift the element that was at 5 down to 4 and skip it.
        for (int i = tracker.size() - 1; i >= 0; i--) {
            int idx = tracker.get(i);
            if (idx >= 0 && idx < messages.size()
                    && "system".equals(messages.get(idx).role())) {
                messages.remove(idx);
            }
        }
        tracker.clear();
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
    /** ① Context-window rollover. When the conversation approaches the model's
     *  context window, hand off to a fresh window instead of lossily compacting
     *  old tool results — {@link FindingEvidenceStore} exists precisely because
     *  compaction evicts early findings/reasoning, and rollover avoids that loss
     *  by carrying durable state forward via the store.
     *
     *  <p>The handoff needs no extra LLM round-trip: the thread_hint is built
     *  from the store's durable state (findings + progress notes), and the model
     *  recovers full detail itself via {@code read_analysis_notes} in the new
     *  window (cheap, controllable tool calls). This is the doc's R1 fallback
     *  ("model didn't write progress → auto-summarize") promoted to the main path.
     *
     *  <p>Returns true if a rollover happened (caller skips compaction this
     *  iteration — history is now small); false to fall through to
     *  {@link #compactIfNeeded}. Package-private for direct unit testing. */
    boolean rolloverIfNeeded(List<ChatMessage> messages,
                             FindingEvidenceStore findingStore,
                             List<Integer> dynamicInjectionTracker) {
        if (!rolloverEnabled) return false;
        int budget = pipelineConfig.contextWindowTokens();
        if (budget <= 0) return false;
        int est = estimateMessagesTokens(messages);
        if (est < (int) (budget * ROLLOVER_TRIGGER_FRACTION)) return false;
        if (currentWindowId >= MAX_ROLLOVER_WINDOWS) {
            logger.debug("[Agent] rollover 上限已达 (maxWindows=%d)，回退压缩", MAX_ROLLOVER_WINDOWS);
            return false;
        }

        int priorWindow = currentWindowId;
        String threadHint = buildThreadHint(findingStore, priorWindow);

        // Keep the static system prompt (index 0) and the initial task user
        // message (index 1) — the task definition must survive a rollover.
        // Everything else (grown conversation + tool results) is the overflow
        // we're shedding; its durable payload already lives in the store.
        ChatMessage systemPrompt = messages.isEmpty() ? null : messages.get(0);
        ChatMessage initialTask = messages.size() > 1 ? messages.get(1) : null;
        messages.clear();
        if (systemPrompt != null) messages.add(systemPrompt);
        if (initialTask != null) messages.add(initialTask);
        messages.add(ChatMessage.system(threadHint));

        // The dynamic-injection tracker referenced slots that no longer exist.
        dynamicInjectionTracker.clear();

        currentWindowId++;
        findingStore.setCurrentWindowId(currentWindowId);
        logger.debug("[Agent] 上下文翻转: window %d → %d (est %d ≥ %d%% of %d)；"
                + "历史已清空，thread_hint 注入，模型应 read_analysis_notes 恢复",
                priorWindow, currentWindowId, est,
                (int) (ROLLOVER_TRIGGER_FRACTION * 100), budget);
        return true;
    }

    /** Build the ≤4KB thread_hint injected into a fresh window, summarising the
     *  durable state the prior windows left in the store and pointing the model
     *  at {@code read_analysis_notes} to recover it. Inlines the most recent
     *  progress note so the model has an immediate sense of where it stopped. */
    private String buildThreadHint(FindingEvidenceStore findingStore, int priorWindow) {
        StringBuilder sb = new StringBuilder();
        sb.append("<thread_hint>\n");
        sb.append("上下文已翻转至新窗口 (window ").append(priorWindow + 1)
                .append(")，为避免上下文溢出，对话历史已清空。")
                .append("以下持久状态保留在 store 中，请先恢复再继续：\n");

        int confirmed = findingStore
                .getFindingsByLevel(FindingEvidenceStore.ConfidenceLevel.CONFIRMED).size();
        int suspected = findingStore
                .getFindingsByLevel(FindingEvidenceStore.ConfidenceLevel.SUSPECTED).size();
        sb.append("1. 已记录发现: 已确认 ").append(confirmed).append(" / 疑似 ")
                .append(suspected).append(" 个 — 调用 read_analysis_notes 恢复全部 finding。\n");

        var allProgress = findingStore.allProgress();
        if (!allProgress.isEmpty()) {
            sb.append("2. 进度笔记: 共 ").append(allProgress.size())
                    .append(" 条 — 调用 read_analysis_notes(action=progress) 恢复。\n");
            var last = allProgress.get(allProgress.size() - 1);
            String lastText = last.text().length() > 200
                    ? last.text().substring(0, 200) + "..." : last.text();
            sb.append("   最近一条 (window ").append(last.windowId()).append("): ")
                    .append(lastText).append("\n");
        } else {
            sb.append("2. 进度笔记: 无。如果你在翻转前用 update_analysis_notes(action=progress) "
                    + "记了 hypothesis/卡点/已测端点，这里会保留。\n");
        }
        sb.append("3. 请勿重复已测端点；先用 read_analysis_notes 恢复上下文，再继续未完成的测试。\n");
        sb.append("</thread_hint>");

        String result = sb.toString();
        if (result.length() > 4096) {
            result = result.substring(0, 4093) + "...";
        }
        return result;
    }

    private void compactIfNeeded(List<ChatMessage> messages, AgentToolRegistry registry) {
        int est = estimateMessagesTokens(messages);
        int budget = pipelineConfig.contextWindowTokens();
        if (est <= budget) return;

        int toolCount = 0;
        for (ChatMessage m : messages) if ("tool".equals(m.role())) toolCount++;
        int toCompact = toolCount - KEEP_RECENT_TOOL_RESULTS;

        // P0-7: even when the "keep last N" count is satisfied, compact
        // further if the preserved band itself is bigger than the token
        // budget. The pre-P0-7 code held N tool results hostage no
        // matter how large each one was — a string of 40K send_request
        // responses would keep 600K of tokens permanently live and
        // push the agent into a 400-over-window failure the moment it
        // tried to call the model again. Walk the tool results in
        // reverse order, summing their token size, and mark the oldest
        // ones past the budget as additional compaction targets.
        if (toCompact <= 0) {
            int recentTokens = 0;
            int extraNeeded = 0;
            for (int i = messages.size() - 1; i >= 0; i--) {
                ChatMessage m = messages.get(i);
                if (!"tool".equals(m.role())) continue;
                int size = m.content() != null ? provider.estimateTokens(m.content()) : 0;
                recentTokens += size;
                if (recentTokens > RECENT_TOOL_RESULTS_TOKEN_BUDGET) {
                    extraNeeded++;
                }
            }
            toCompact = extraNeeded;
        }
        if (toCompact <= 0) return;

        // tool-result messages only carry a call id — recover which tool
        // produced each by walking the assistant messages' tool calls.
        Map<String, String> toolNames = new HashMap<>();
        for (ChatMessage m : messages) {
            if (m.toolCalls() != null) {
                for (ToolCall tc : m.toolCalls()) toolNames.put(tc.id(), tc.toolName());
            }
        }

        int compacted = compactPass(messages, toolNames, toCompact, true, registry);
        if (compacted < toCompact) {
            compacted += compactPass(messages, toolNames, toCompact - compacted, false, registry);
        }
        if (compacted > 0) {
            logger.debug("[Agent] 上下文分级压缩: %d 个旧工具结果已压缩 (估算 %d tokens > %d 预算)",
                    compacted, est, budget);
        }
    }

    /** Compacts up to {@code limit} of the oldest tool results whose producing
     *  tool is read-only/regenerable ({@code readOnlyOnly=true}) or NOT
     * ({@code false}). Idempotent — already-compacted markers and short bodies
     * (no meaningful space win) are skipped. */
    private int compactPass(List<ChatMessage> messages, Map<String, String> toolNames,
                            int limit, boolean readOnlyOnly, AgentToolRegistry registry) {
        int compacted = 0;
        for (int i = 0; i < messages.size() && compacted < limit; i++) {
            ChatMessage m = messages.get(i);
            if (!"tool".equals(m.role())) continue;
            if (m.content() == null || m.content().length() <= 600) continue;
            if (m.content().startsWith("[压缩摘要")) continue;
            String toolName = toolNames.getOrDefault(m.toolCallId(), "");
            boolean regenerable = isReadOnly(registry, toolName);
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
        if (toolCalls.size() > 1 && canParallelize(toolCalls, registry)) {
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

    /** True only when every call in the batch is a side-effect-free read tool.
     *  Package-private (P2-2) so tests can pin the concurrency-safety
     *  invariant: stateful/HTTP/LLM tools (send_request, chain_hunter,
     *  submit_report, verify_*, …) must never parallelise, or the shared
     *  SendRequestTool.payloadResults pool + citedExecutionIndex lookups
     *  would race. */
    static boolean canParallelize(List<ToolCall> toolCalls, AgentToolRegistry registry) {
        for (ToolCall tc : toolCalls) {
            if (!isReadOnly(registry, tc.toolName())) return false;
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
