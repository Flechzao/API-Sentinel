package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.queue.AnalysisTask.AnalysisMode;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.event.AiAnalysisCompleteEvent;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;

import javax.swing.*;


/** AI 分析 Presenter——路由 Agent/Pipeline 模式、管理各 Facade/Controller 的生命周期。 */
public class AiPresenter {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final ApiEntryTableModel tableModel;
    private final AnalysisTaskQueue analysisQueue;
    private final CodeIndexService codeIndexService;
    private final LlmProviderFactory providerFactory;
    private final LeveledLogger logger;
    private final com.flechazo.apisentinel.detection.OobService oobService;
    private ApiSentinelTab view;
    private LearnedRuleEngine learnedRuleEngine;
    private com.flechazo.apisentinel.event.EventBus.Subscription analysisCompleteSub;
    private final AnalysisContextLookup contextLookup;
    private final PipelineFacade pipelineFacade;
    private final AgentFacade agentFacade;
    private final ChatController chatController;
    private final BatchOrchestrator batchOrchestrator;

    public AiPresenter(MontoyaApi api, ConfigManager configManager,
                       ApiEntryTableModel tableModel, AnalysisTaskQueue analysisQueue,
                       CodeIndexService codeIndexService, LlmProviderFactory providerFactory,
                       EventBus eventBus, LeveledLogger logger) {
        this.api = api;
        this.configManager = configManager;
        this.tableModel = tableModel;
        this.analysisQueue = analysisQueue;
        this.codeIndexService = codeIndexService;
        this.providerFactory = providerFactory;
        this.logger = logger;
        this.oobService = new com.flechazo.apisentinel.detection.OobService(api, configManager.getConfig(), logger);
        this.oobService.setInteractionCallback(hits -> {
            for (var hit : hits) {
                logger.info("[OOB] 确认漏洞: %s @ %s %s param=%s type=%s",
                        hit.interactionType(), hit.probe().entryId(),
                        hit.probe().entryPath(), hit.probe().parameter(), hit.probe().vulnType());
            }
        });
        this.oobService.startBackgroundPolling(30_000);
        this.contextLookup = new AnalysisContextLookup(api, configManager, codeIndexService, logger);
        this.pipelineFacade = new PipelineFacade(api, configManager, tableModel, analysisQueue, codeIndexService, logger);
        // Cascade-hunting trigger chain: verified confirms flow from
        // handlePipelineComplete to AgentController via the EventBus.
        this.pipelineFacade.setEventBus(eventBus);
        // Cross-endpoint vuln attribution: cluster-hunting runs confirm vulns
        // on sibling endpoints; each must land on its own table row.
        this.pipelineFacade.setRepository(tableModel.getRepository());
        this.agentFacade = new AgentFacade(api, configManager, codeIndexService, analysisQueue, logger, pipelineFacade, oobService);
        this.chatController = new ChatController(api, configManager, codeIndexService, providerFactory,
                oobService, contextLookup, logger);
        // Claude-Code-style interaction: sandbox confirms and ask_user render
        // as inline cards in the chat flow instead of modal dialogs. The
        // supplier defers the view lookup — setView() runs later.
        ChatInteractionBridge interactionBridge =
                new ChatInteractionBridge(() -> view != null ? view.getAiChatPanel() : null);
        this.agentFacade.setInteractionBridge(interactionBridge);
        this.agentFacade.setTableModel(tableModel);
        this.chatController.setInteractionBridge(interactionBridge);
        this.batchOrchestrator = new BatchOrchestrator(tableModel, analysisQueue, providerFactory,
                contextLookup, logger, this::routeAndExecute, tableModel.getRepository());

        analysisCompleteSub = eventBus.subscribe(AiAnalysisCompleteEvent.class, batchOrchestrator::onAiAnalysisComplete);
    }

    /** MCP bridge: trigger a Pipeline analysis (method ref hides the
     *  package-private facade type from the mcp package). */
    public com.flechazo.apisentinel.mcp.McpTools.AnalysisTrigger getPipelineTrigger() {
        return pipelineFacade::executePipelineForEntry;
    }

    /** MCP bridge: trigger an Agent-mode analysis. */
    public com.flechazo.apisentinel.mcp.McpTools.AnalysisTrigger getAgentTrigger() {
        return agentFacade::executeAgentForEntry;
    }

    /** Unsubscribe EventBus listeners — call on extension unload. */
    public void shutdown() {
        if (analysisCompleteSub != null) {
            analysisCompleteSub.unsubscribe();
            analysisCompleteSub = null;
        }
        // Interrupt any in-flight analyses so their daemon threads don't keep
        // the old ClassLoader alive (would leak memory + block reload).
        oobService.shutdown();
        pipelineFacade.shutdown();
        agentFacade.shutdown();
    }

    void setView(ApiSentinelTab view) {
        this.view = view;
        pipelineFacade.setView(view);
        agentFacade.setView(view);
        chatController.setView(view);
        batchOrchestrator.setView(view);
    }
    void setLearnedRuleEngine(LearnedRuleEngine engine) {
        this.learnedRuleEngine = engine;
        pipelineFacade.setLearnedRuleEngine(engine);
        batchOrchestrator.setLearnedRuleEngine(engine);
    }

    /** Success-pattern memory (P3): PipelineFacade records verified confirms,
     *  AgentLoop injects the top patterns into each new analysis. */
    void setPatternStore(com.flechazo.apisentinel.ai.patterns.PatternStore store) {
        pipelineFacade.setPatternStore(store);
        agentFacade.setPatternStore(store);
    }
    public void setMcpTools(com.flechazo.apisentinel.mcp.McpTools tools) {
        pipelineFacade.setMcpTools(tools);
    }

    // === Delegation to ChatController ===
    public void onChatMessage(String message) { chatController.onChatMessage(message); }

    /** Chat stop button: cooperative-cancel every in-flight Pipeline/Agent
     *  run. Agent runs keep their partial evidence (fallback verdict); the
     *  Pipeline paths report via onPipelineCancelled. */
    void cancelActiveAnalyses() {
        pipelineFacade.cancelAll();
        agentFacade.cancelAll();
    }


    // === Delegation to BatchOrchestrator ===
    public void onAiAnalyze(int[] selectedRows) { batchOrchestrator.onAiAnalyze(selectedRows); }
    public void onAiAnalyze(int[] selectedRows, AnalysisMode mode) { batchOrchestrator.onAiAnalyze(selectedRows, mode); }
    public void onFullPipelineAnalyze(int[] selectedRows) { batchOrchestrator.onFullPipelineAnalyze(selectedRows); }
    public void onFullPipelineAnalyze(int[] selectedRows, AnalysisMode mode) { batchOrchestrator.onFullPipelineAnalyze(selectedRows, mode); }

    /**
     * Run full pipeline analysis for a given ApiEntry (called from context menu).
     * This is the entry point for right-click "Sentinel Pipeline 分析" in Burp's native Repeater etc.
     */
    public void runPipelineForEntry(ApiEntry entry) {
        if (entry == null) return;

        LlmProvider provider = providerFactory.getFirstAvailable();
        if (provider == null) {
            logger.error("Pipeline 启动失败: 无可用的 AI Provider");
            if (view != null) view.getAiAnalysisPanel().showPipelineError("无可用的 AI Provider，请在设置中配置。");
            return;
        }

        if (view != null) {
            view.getAiAnalysisPanel().resetPipelineProgress();
            view.switchToAnalysisResult();
        }

        routeAndExecute(entry, provider, () -> {});
    }

    /**
     * Routes to Agent mode (if enabled and supported) or Pipeline mode.
     * The only place that knows both PipelineFacade and AgentFacade exist —
     * BatchOrchestrator drives batch entries through this same method via
     * the EntryExecutor it was constructed with, so both single-entry and
     * batch analysis get identical Agent/Pipeline routing.
     */
    private void routeAndExecute(ApiEntry entry, LlmProvider provider, Runnable onDone) {
        // Route to Agent mode if enabled and provider supports tool calling
        if (view != null && view.getToolbarPanel().isAgentMode()) {
            if (provider.supportsToolCalling()) {
                agentFacade.executeAgentForEntry(entry, provider, onDone);
                return;
            } else {
                SwingUtilities.invokeLater(() ->
                        ToastNotification.show(view,
                                "当前 Provider 不支持 Agent 模式 (tool calling)，回退到 Pipeline 模式",
                                ToastNotification.ToastType.WARNING, 3000));
            }
        }
        pipelineFacade.executePipelineForEntry(entry, provider, onDone);
    }

    String lookupSourceCode(String apiPath, String domain) {
        return contextLookup.lookupSourceCode(apiPath, domain);
    }
}
