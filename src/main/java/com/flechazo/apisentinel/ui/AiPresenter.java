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
    /** Single login-profile manager shared across the internal Agent/Chat loops
     *  and the MCP layer, so browser logins persist and are reusable everywhere. */
    private final com.flechazo.apisentinel.config.LoginProfileManager loginProfileManager;
    private ApiSentinelTab view;
    private LearnedRuleEngine learnedRuleEngine;
    private com.flechazo.apisentinel.event.EventBus.Subscription analysisCompleteSub;
    private final AnalysisContextLookup contextLookup;
    private final PipelineFacade pipelineFacade;
    private final AgentFacade agentFacade;
    private final ChatController chatController;
    private final BatchOrchestrator batchOrchestrator;
    /** F-1: Browser service (null if disabled in config). */
    private com.flechazo.apisentinel.browser.BrowserService browserService;

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
        this.loginProfileManager = new com.flechazo.apisentinel.config.LoginProfileManager(logger);
        this.oobService.setInteractionCallback(hits -> {
            for (var hit : hits) {
                logger.info("[OOB] 确认漏洞: %s @ %s %s param=%s type=%s",
                        hit.interactionType(), hit.probe().entryId(),
                        hit.probe().entryPath(), hit.probe().parameter(), hit.probe().vulnType());
            }
        });
        this.oobService.startBackgroundPolling(30_000);
        this.contextLookup = new AnalysisContextLookup(api, configManager, codeIndexService, logger);
        // Shared completion handler: both Pipeline and Agent delegate their
        // post-analysis work (status, reports, SiteMap, cascade, etc.) here.
        AnalysisCompletionHandler completionHandler = new AnalysisCompletionHandler(api, configManager, tableModel, logger);
        completionHandler.setEventBus(eventBus);
        completionHandler.setRepository(tableModel.getRepository());
        this.pipelineFacade = new PipelineFacade(api, configManager, tableModel, analysisQueue, codeIndexService, logger, completionHandler);
        this.agentFacade = new AgentFacade(api, configManager, codeIndexService, analysisQueue, logger, completionHandler, oobService);
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

        // F-1: Initialize browser service if enabled in config
        if (configManager.getConfig().isBrowserEnabled()) {
            logger.debug("[Browser] 浏览器功能已启用");
            com.flechazo.apisentinel.browser.BrowserService browserService =
                    new com.flechazo.apisentinel.browser.BrowserService(logger, tableModel.getRepository());
            browserService.configure(8080, configManager.getConfig().isBrowserHeadless(),
                    configManager.getConfig().getBrowserChromePath().isEmpty()
                            ? null : configManager.getConfig().getBrowserChromePath(),
                    configManager.getConfig().getBrowserMaxPages());
            browserService.setFrontendBaseUrl(configManager.getConfig().getBrowserFrontendUrl());
            this.agentFacade.setBrowserService(browserService);
            this.chatController.setBrowserService(browserService);
            this.browserService = browserService;
            logger.debug("[Browser] BrowserService 已注入 AgentFacade + ChatController");
        } else {
            logger.info("[F-1] 浏览器功能未启用 (browserEnabled=false)");
        }
        // F-1: Set repository for browser-discovered API registration
        this.agentFacade.setRepository(tableModel.getRepository());
        this.chatController.setRepository(tableModel.getRepository());
        // Shared login-profile manager → browser_login works in Agent/Chat/MCP.
        this.agentFacade.setLoginProfileManager(loginProfileManager);
        this.chatController.setLoginProfileManager(loginProfileManager);

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

    /** The live BrowserService (null when browser disabled / Chromium not ready),
     *  so the MCP layer can expose browser tools to external clients. */
    public com.flechazo.apisentinel.browser.BrowserService getBrowserService() {
        return browserService;
    }

    /** Shared OOB collector — injected into the MCP layer so SSRF/blind tools
     *  exposed over MCP correlate against the same background poller. */
    public com.flechazo.apisentinel.detection.OobService getOobService() {
        return oobService;
    }

    /** Shared login-profile manager — injected into the MCP layer so browser
     *  logins done via the external brain persist and are reusable internally. */
    public com.flechazo.apisentinel.config.LoginProfileManager getLoginProfileManager() {
        return loginProfileManager;
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
        // F-1: Shutdown browser service to release Playwright resources
        if (browserService != null) {
            browserService.shutdown();
        }
    }

    /**
     * Reconfigure the browser service with new settings (headless, chromePath, etc.)
     * without requiring a full extension reload. Called when the user changes
     * browser config in the settings panel.
     *
     * <p>If browser was disabled at load time and is now being enabled, creates
     * the BrowserService on demand (lazy initialization).
     */
    public void reconfigureBrowser(int burpProxyPort, boolean headless,
                                    String chromePath, int maxPages, String frontendUrl) {
        if (browserService != null) {
            // Already initialized — reconfigure existing service
            browserService.reconfigure(burpProxyPort, headless, chromePath, maxPages, frontendUrl);
        } else {
            // Browser was disabled at load time, now being enabled — create on demand
            logger.info("[F-1] 浏览器功能在运行时启用，按需创建 BrowserService");
            com.flechazo.apisentinel.browser.BrowserService newService =
                    new com.flechazo.apisentinel.browser.BrowserService(logger, tableModel.getRepository());
            newService.configure(burpProxyPort, headless,
                    chromePath != null && !chromePath.isEmpty() ? chromePath : null, maxPages);
            newService.setFrontendBaseUrl(frontendUrl);
            this.browserService = newService;
            this.agentFacade.setBrowserService(newService);
            this.chatController.setBrowserService(newService);
            logger.info("[F-1] BrowserService 已按需创建并注入 AgentFacade + ChatController");
        }
    }

    /** Check if browser service is available (enabled and initialized). */
    public boolean isBrowserAvailable() {
        return browserService != null;
    }

    /** Shut down the browser service (called when user disables browser in settings). */
    public void shutdownBrowser() {
        if (browserService != null) {
            logger.info("[F-1] 浏览器功能已禁用，关闭 BrowserService");
            browserService.shutdown();
            // Don't null out browserService — AgentFacade/ChatController still
            // reference it. A reload will fully clear it. But set it to null
            // so new Agent runs won't register browser tools.
            this.browserService = null;
            this.agentFacade.setBrowserService(null);
            this.chatController.setBrowserService(null);
        }
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

    /** Toggle parallel (4 concurrent) vs serial (1) batch analysis. */
    public void setBatchConcurrent(boolean parallel) {
        batchOrchestrator.setBatchConcurrent(parallel);
    }

    /** Expose for multi-endpoint joint analysis trigger. */
    public AgentFacade getAgentFacade() { return agentFacade; }
    public LlmProvider getFirstAvailableProvider() { return providerFactory.getFirstAvailable(); }

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
