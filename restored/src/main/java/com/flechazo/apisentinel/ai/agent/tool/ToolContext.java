package com.flechazo.apisentinel.ai.agent.tool;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.pipeline.PipelineConfig;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.detection.OobService;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

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
    private final LlmProvider provider;
    private final MontoyaApi montoyaApi;
    private final CodeIndexService codeIndexService;
    private final List<CodeRepo> codeRepos;
    private final PipelineConfig pipelineConfig;
    private final LeveledLogger logger;
    private final OobService oobService;
    private final ToolSessionState sessionState;
    /** Optional UI bridge letting tools ask the operator questions (sandbox
     *  confirm, ask_user). Null = no UI attached (tests, headless) — tools
     *  must degrade gracefully (fallback dialog / autonomous decision). */
    private volatile UserInteractionBridge userInteractionBridge;

    public ToolContext(ApiEntry entry, LlmProvider provider, MontoyaApi montoyaApi,
                       CodeIndexService codeIndexService, List<CodeRepo> codeRepos,
                       PipelineConfig pipelineConfig, LeveledLogger logger) {
        this(entry, provider, montoyaApi, codeIndexService, codeRepos, pipelineConfig, logger, null);
    }

    public ToolContext(ApiEntry entry, LlmProvider provider, MontoyaApi montoyaApi,
                       CodeIndexService codeIndexService, List<CodeRepo> codeRepos,
                       PipelineConfig pipelineConfig, LeveledLogger logger,
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
    public LlmProvider provider() { return provider; }
    public MontoyaApi montoyaApi() { return montoyaApi; }
    public CodeIndexService codeIndexService() { return codeIndexService; }
    public List<CodeRepo> codeRepos() { return codeRepos; }
    public PipelineConfig pipelineConfig() { return pipelineConfig; }
    public LeveledLogger logger() { return logger; }
    public OobService oobService() { return oobService; }
    public ToolSessionState sessionState() { return sessionState; }
    public UserInteractionBridge userInteractionBridge() { return userInteractionBridge; }
    public void setUserInteractionBridge(UserInteractionBridge bridge) { this.userInteractionBridge = bridge; }

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