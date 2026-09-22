package com.flechazo.apisentinel.ai.agent.tool;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.pipeline.AnalysisConfig;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.detection.OobService;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.repository.ApiRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared context passed to every tool. Now a regular class (not a record)
 * so it can carry a mutable {@link ToolSessionState} that tools can read
 * and update — used by preExecute hooks to enforce cross-tool gates
 * (e.g. submit_report requiring heuristic_scan first).
 */
public class ToolContext {

    private final ApiEntry entry;
    /** Multi-endpoint mode: when non-empty, the Agent is analyzing multiple
     *  endpoints in one loop. {@link #entry} is still set (first entry) for
     *  backward-compat with tools that use {@link #entry()}. */
    private List<ApiEntry> allEntries = List.of();
    private final LlmProvider provider;
    private final MontoyaApi montoyaApi;
    private final CodeIndexService codeIndexService;
    private final List<CodeRepo> codeRepos;
    private final AnalysisConfig pipelineConfig;
    private final LeveledLogger logger;
    private final OobService oobService;
    private final ToolSessionState sessionState;
    /** Optional UI bridge letting tools ask the operator questions (sandbox
     *  confirm, ask_user). Null = no UI attached (tests, headless) — tools
     *  must degrade gracefully (fallback dialog / autonomous decision). */
    private volatile UserInteractionBridge userInteractionBridge;
    /** F-1: Optional browser service for client-side security testing.
     *  Null = browser disabled in settings — browser tools degrade gracefully. */
    private volatile BrowserService browserService;
    /** Fast/cheap model for vision decisions in browser tools (e.g. ExplorationEngine). */
    private volatile String fastModel;
    /** Finding updater for chat follow-up conversations (promote suspected→confirmed). */
    private volatile FindingUpdater findingUpdater;
    /** P1-6: propagated from AppConfig.includeRawCredentialsInLlm. When
     *  false (default), AnalyzeTrafficTool and every tool that hands raw
     *  HTTP messages to the LLM runs them through RequestRedactor first.
     *  When true, raw credentials pass through verbatim. */
    private volatile boolean includeRawCredentials = false;
    /** F-1: Optional API repository for registering browser-discovered APIs. */
    private volatile ApiRepository apiRepository;
    /** FE-1: Optional AppConfig for cookie injection after browser login. */
    private volatile com.flechazo.apisentinel.config.AppConfig appConfig;
    /** FE-1: Optional LoginProfileManager for browser login profiles. */
    private volatile com.flechazo.apisentinel.config.LoginProfileManager loginProfileManager;
    /** Progressive Tool Disclosure manager for phase-aware tool filtering.
     *  Null = progressive disclosure disabled (use all tools). */
    private volatile com.flechazo.apisentinel.ai.agent.ProgressiveToolDisclosure progressiveToolDisclosure;
    /** Finding Evidence Store for persistent security findings.
     *  Null = finding store disabled. */
    private volatile com.flechazo.apisentinel.ai.agent.FindingEvidenceStore findingEvidenceStore;

    public ToolContext(ApiEntry entry, LlmProvider provider, MontoyaApi montoyaApi,
                       CodeIndexService codeIndexService, List<CodeRepo> codeRepos,
                       AnalysisConfig pipelineConfig, LeveledLogger logger) {
        this(entry, provider, montoyaApi, codeIndexService, codeRepos, pipelineConfig, logger, null);
    }

    public ToolContext(ApiEntry entry, LlmProvider provider, MontoyaApi montoyaApi,
                       CodeIndexService codeIndexService, List<CodeRepo> codeRepos,
                       AnalysisConfig pipelineConfig, LeveledLogger logger,
                       OobService oobService) {
        this.entry = entry;
        this.provider = provider;
        this.montoyaApi = montoyaApi;
        this.codeIndexService = codeIndexService;
        this.codeRepos = codeRepos;
        this.pipelineConfig = pipelineConfig;
        this.logger = logger;
        this.oobService = oobService;
        this.sessionState = new ToolSessionState();
    }

    public ApiEntry entry() { return entry; }
    /** All endpoints being analyzed in multi-endpoint mode. Empty in
     *  single-endpoint mode (use {@link #entry()} instead). */
    public List<ApiEntry> allEntries() { return allEntries; }
    public void setAllEntries(List<ApiEntry> entries) { this.allEntries = entries != null ? entries : List.of(); }
    /** True when running in multi-endpoint joint analysis mode. */
    public boolean isMultiEndpoint() { return !allEntries.isEmpty(); }
    public LlmProvider provider() { return provider; }
    public MontoyaApi montoyaApi() { return montoyaApi; }
    public CodeIndexService codeIndexService() { return codeIndexService; }
    public List<CodeRepo> codeRepos() { return codeRepos; }
    public AnalysisConfig pipelineConfig() { return pipelineConfig; }
    public LeveledLogger logger() { return logger; }
    public OobService oobService() { return oobService; }
    public ToolSessionState sessionState() { return sessionState; }
    public UserInteractionBridge userInteractionBridge() { return userInteractionBridge; }
    public void setUserInteractionBridge(UserInteractionBridge bridge) { this.userInteractionBridge = bridge; }

    /** F-1: Get browser service (null if disabled). */
    public BrowserService browserService() { return browserService; }
    /** F-1: Set browser service. */
    public void setBrowserService(BrowserService browserService) { this.browserService = browserService; }

    /** Fast/cheap model name for vision decisions in browser tools. */
    public String fastModel() { return fastModel; }
    /** Set fast model name. */
    public void setFastModel(String model) { this.fastModel = model; }

    /** Finding updater for chat follow-up (null if not in chat mode). */
    public FindingUpdater findingUpdater() { return findingUpdater; }
    /** Set finding updater. */
    public void setFindingUpdater(FindingUpdater updater) { this.findingUpdater = updater; }

    /** P1-6: Get whether raw credentials pass through to the LLM. */
    public boolean includeRawCredentials() { return includeRawCredentials; }
    /** P1-6: Set whether raw credentials pass through to the LLM. */
    public void setIncludeRawCredentials(boolean include) { this.includeRawCredentials = include; }

    /** F-1: Get API repository (null if not set). */
    public ApiRepository apiRepository() { return apiRepository; }
    /** F-1: Set API repository. */
    public void setApiRepository(ApiRepository apiRepository) { this.apiRepository = apiRepository; }

    /** FE-1: Get AppConfig (null if not set). */
    public com.flechazo.apisentinel.config.AppConfig appConfig() { return appConfig; }

    /** Cost-tiering: the low-cost model override for mechanical/breadth nodes
     *  (payload generation, exploration sub-agents), or {@code null} when
     *  tiering is disabled or unset — in which case the main model is used.
     *  Judgment/verdict nodes must ignore this and always use the main model. */
    public String cheapModelOverride() {
        if (appConfig == null || !appConfig.isModelTieringEnabled()) return null;
        // Reuse the already-configured 轻量模型 (fastModel) — no second model to set.
        return (fastModel == null || fastModel.isBlank()) ? null : fastModel;
    }
    /** FE-1: Set AppConfig. */
    public void setAppConfig(com.flechazo.apisentinel.config.AppConfig config) { this.appConfig = config; }

    /** FE-1: Get LoginProfileManager (null if not set). */
    public com.flechazo.apisentinel.config.LoginProfileManager loginProfileManager() { return loginProfileManager; }
    /** FE-1: Set LoginProfileManager. */
    public void setLoginProfileManager(com.flechazo.apisentinel.config.LoginProfileManager manager) {
        this.loginProfileManager = manager;
    }

    /** Set Progressive Tool Disclosure manager (null if disabled). */
    public com.flechazo.apisentinel.ai.agent.ProgressiveToolDisclosure progressiveToolDisclosure() {
        return progressiveToolDisclosure;
    }
    /** Set Progressive Tool Disclosure manager. */
    public void setProgressiveToolDisclosure(
            com.flechazo.apisentinel.ai.agent.ProgressiveToolDisclosure disclosure) {
        this.progressiveToolDisclosure = disclosure;
    }

    /** Tools disabled by the user (won't be registered in StandardToolRegistry). */
    private volatile java.util.Set<String> disabledTools = java.util.Set.of();

    /** Get disabled tool names. */
    public java.util.Set<String> disabledTools() { return disabledTools; }
    /** Set disabled tool names. */
    public void setDisabledTools(java.util.Set<String> tools) { this.disabledTools = tools != null ? tools : java.util.Set.of(); }
    /** Check if a tool is disabled. */
    public boolean isToolDisabled(String name) { return disabledTools.contains(name); }

    /** Get Finding Evidence Store (null if disabled). */
    public com.flechazo.apisentinel.ai.agent.FindingEvidenceStore findingEvidenceStore() {
        return findingEvidenceStore;
    }
    /** Set Finding Evidence Store. */
    public void setFindingEvidenceStore(
            com.flechazo.apisentinel.ai.agent.FindingEvidenceStore store) {
        this.findingEvidenceStore = store;
    }

    /**
     * Mutable state shared across all tools in a single analysis session.
     * Tools update this in their preExecute/postExecute hooks; other tools
     * read it in their own preExecute hooks to enforce cross-tool gates.
     */
    public static class ToolSessionState {
        private final Set<String> calledTools = new HashSet<>();
        private int generatedPayloadCount = 0;
        private int verifiedPayloadCount = 0;

        public void recordToolCall(String toolName) { calledTools.add(toolName); }
        public boolean hasCalled(String toolName) { return calledTools.contains(toolName); }
        public Set<String> calledTools() { return calledTools; }

        public void setGeneratedPayloadCount(int count) { this.generatedPayloadCount = count; }
        public int generatedPayloadCount() { return generatedPayloadCount; }

        public void setVerifiedPayloadCount(int count) { this.verifiedPayloadCount = count; }
        public int verifiedPayloadCount() { return verifiedPayloadCount; }
    }
}