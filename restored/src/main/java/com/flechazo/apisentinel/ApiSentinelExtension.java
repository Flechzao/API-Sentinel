package com.flechazo.apisentinel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import com.flechazo.apisentinel.ai.agent.AgentController;
import com.flechazo.apisentinel.ai.budget.TokenBudgetManager;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.detection.SensitiveInfoDetector;
import com.flechazo.apisentinel.detection.UnauthorizedDetector;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.handler.HttpTrafficHandler;
import com.flechazo.apisentinel.handler.ProxyHistoryScanner;
import com.flechazo.apisentinel.handler.RateLimiter;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.matching.CompositeMatchEngine;
import com.flechazo.apisentinel.matching.FuzzyMatchEngine;
import com.flechazo.apisentinel.matching.TrieMatchEngine;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.repository.InMemoryApiRepository;
import com.flechazo.apisentinel.repository.PersistentApiRepository;
import com.flechazo.apisentinel.ui.*;

import javax.swing.*;

/**
 * Burp Suite 扩展入口类。注册套件标签页、HTTP 处理器、上下文菜单、热键、MCP Server、
 * 代码索引等。所有核心组件在此初始化和销毁。
 */
public class ApiSentinelExtension implements BurpExtension {

    private static final String NAME = "API Sentinel";
    public static final String VERSION = readVersion();

    private static String readVersion() {
        try {
            var pkg = ApiSentinelExtension.class.getPackage();
            if (pkg != null && pkg.getImplementationVersion() != null) {
                return pkg.getImplementationVersion();
            }
        } catch (Exception ignored) {}
        return "1.0"; // fallback for IDE/non-JAR mode
    }

    private PersistentApiRepository repository;
    private UnauthorizedDetector unauthorizedDetector;
    private ProxyHistoryScanner historyScanner;
    private UiEventBus uiEventBus;
    private EventBus eventBus;
    private AnalysisTaskQueue analysisQueue;
    private AgentController agentController;
    private LearnedRuleEngine learnedRuleEngine;
    private com.flechazo.apisentinel.ai.patterns.PatternStore patternStore;
    private LlmProviderFactory providerFactory;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        LeveledLogger logger = new LeveledLogger(api.logging());
        logger.info("╔═══════════════════════════════════════════════════╗");
        logger.info("║  API Sentinel v1.0                                ║");
        logger.info("║  Author: Flechazo                                 ║");
        logger.info("║  GitHub: https://github.com/Flechzao/API-Sentinel ║");
        logger.info("╚═══════════════════════════════════════════════════╝");

        // NOTE: Do NOT set global L&F — it bleeds into all Burp panels.
        // We style our own components inline instead.

        // Config
        ConfigManager configManager = new ConfigManager(logger);

        // Repository
        InMemoryApiRepository inMemoryRepo = new InMemoryApiRepository();
        repository = new PersistentApiRepository(inMemoryRepo, configManager.getConfig().getDataFilePath(), logger);
        repository.load();

        // Match engines
        TrieMatchEngine trieEngine = new TrieMatchEngine();
        FuzzyMatchEngine fuzzyEngine = new FuzzyMatchEngine();
        CompositeMatchEngine matchEngine = new CompositeMatchEngine(trieEngine, fuzzyEngine, configManager);
        matchEngine.rebuild(repository.findAll());

        // Event bus
        eventBus = new EventBus();
        eventBus.setLogger(logger);
        uiEventBus = new UiEventBus();

        // Detection
        SensitiveInfoDetector sensitiveDetector = new SensitiveInfoDetector(configManager, logger);
        RateLimiter rateLimiter = new RateLimiter(configManager.getConfig().getRateLimitPerSecond());
        unauthorizedDetector = new UnauthorizedDetector(api, rateLimiter, logger, uiEventBus, repository);

        // AI infrastructure
        providerFactory = new LlmProviderFactory();
        TokenBudgetManager budgetManager = new TokenBudgetManager();

        // Load AI config from file (auto-configure provider)
        String[] aiConfig = loadAiConfig(providerFactory, logger);
        String aiConfigProviderId = aiConfig[0];
        String aiConfigEndpoint = aiConfig[1];
        String aiConfigKey = aiConfig[2];
        String aiConfigModel = aiConfig[3];
        String aiConfigFastModel = aiConfig.length > 4 ? aiConfig[4] : "";

        analysisQueue = new AnalysisTaskQueue(providerFactory, budgetManager, eventBus, logger, 2);
        analysisQueue.setActiveProvider(aiConfigProviderId);

        // Intruder AI payload generator (Extension-generated payload type).
        // Context-aware: uses the attack's full request template in prompts.
        api.intruder().registerPayloadGeneratorProvider(
                new com.flechazo.apisentinel.intruder.AiPayloadGeneratorProvider(
                        providerFactory, configManager, logger));

        // Learned rule engine
        learnedRuleEngine = new LearnedRuleEngine(logger);

        // Success-pattern memory (cluster-hunting P3): verified confirms are
        // persisted to ~/.api-sentinel/patterns.json and replayed into new
        // analyses' initial messages.
        patternStore = new com.flechazo.apisentinel.ai.patterns.PatternStore(logger);

        // Code index service — created before AgentController because the
        // controller's cascade hunting resolves sibling routes from it.
        CodeIndexService codeIndexService = new CodeIndexService(logger);

        // Agent controller
        agentController = new AgentController(analysisQueue, eventBus, providerFactory,
                codeIndexService, logger);

        // HTTP handler
        HttpTrafficHandler httpHandler = new HttpTrafficHandler(
                api, matchEngine, repository, configManager,
                sensitiveDetector, unauthorizedDetector, uiEventBus, eventBus, logger);
        api.http().registerHttpHandler(httpHandler);

        // History scanner
        historyScanner = new ProxyHistoryScanner(api, matchEngine, uiEventBus, logger,
                configManager, repository);

        // UI
        SwingUtilities.invokeLater(() -> {
            ApiEntryTableModel tableModel = new ApiEntryTableModel(repository);

            ApiSentinelPresenter presenter = new ApiSentinelPresenter(
                    api, repository, matchEngine, configManager, tableModel,
                    historyScanner, analysisQueue, eventBus, codeIndexService, providerFactory, logger);
            presenter.setAgentController(agentController);
            // Restore persisted auto-scan state — unlike the read-on-demand
            // checkboxes (sensitiveDetection, oobEnabled, ...), AgentController
            // is stateful (subscribes/reacts based on an internal flag), so it
            // needs an explicit call to pick up the saved config on load.
            presenter.onAutoScanToggle(configManager.getConfig().isAutoScanEnabled());
            // Same restore treatment for the cascade sub-switch (P2).
            agentController.setCascadeEnabled(configManager.getConfig().isCascadeHuntEnabled());
            presenter.setLearnedRuleEngine(learnedRuleEngine);
            presenter.setPatternStore(patternStore);

            ApiSentinelTab tab = new ApiSentinelTab(api, tableModel, presenter,
                    providerFactory, configManager.getConfig().getSensitiveRules(),
                    repository, analysisQueue, learnedRuleEngine,
                    configManager.getConfig().getCodeRepos(),
                    configManager.getConfig(), configManager);
            presenter.setView(tab);

            // Agent/cascade progress forwarding (formerly the removed
            // DashboardBar's wire job): a global chat note + toast keep the
            // auto-pilot's spreading visible even when the user is looking at
            // another endpoint. The eventBus is extension-private and shut
            // down on unload, so no explicit unsubscribe is needed.
            eventBus.subscribe(com.flechazo.apisentinel.ai.agent.AgentController.AgentProgressEvent.class,
                    progress -> {
                if ("cascade".equals(progress.phase())) {
                    tab.getAiChatPanel().addGlobalNote("⚡ " + progress.message());
                    ToastNotification.show(tab, progress.message(),
                            ToastNotification.ToastType.INFO, 4000);
                } else if ("cascade_blocked".equals(progress.phase())) {
                    tab.getAiChatPanel().addGlobalNote("⛔ " + progress.message());
                    ToastNotification.show(tab, progress.message(),
                            ToastNotification.ToastType.WARNING, 5000);
                }
            });

            // Success-pattern memory management page (cluster-hunting P3).
            tab.getPatternPanel().setPatternStore(patternStore);

            uiEventBus.setTableRefreshAction(tableModel::refreshFromRepositorySync);

            api.userInterface().registerSuiteTab(NAME, tab);

            // Apply Burp's theme (dark/light) to all custom components recursively
            api.userInterface().applyThemeToComponent(tab);

            // Shared theme handle for ThemedDialogs (JOptionPane replacements).
            com.flechazo.apisentinel.ui.ThemedDialogs.init(new BurpTheme(api));

            ContextMenuProvider contextMenu = new ContextMenuProvider(
                    api, repository, matchEngine, analysisQueue, uiEventBus, logger);
            contextMenu.setPipelineAnalyzeHandler(entry -> presenter.runPipelineForEntry(entry));
            api.userInterface().registerContextMenuItemsProvider(contextMenu);

            // Register a SEPARATE settings panel instance in Burp's native Settings dialog
            // (Swing components can only have one parent — sharing the same instance
            //  removes it from our tab group)
            AiSettingsPanel burpSettingsPanel = new AiSettingsPanel(providerFactory,
                    presenter::onProviderChanged, presenter::onContextWindowChanged, new BurpTheme(api));
            burpSettingsPanel.setConfig(aiConfigProviderId, aiConfigEndpoint, aiConfigKey, aiConfigModel);
            burpSettingsPanel.setContextWindowTokens(configManager.getConfig().getContextWindowTokens());
            api.userInterface().registerSettingsPanel(burpSettingsPanel);

            // Register hotkeys for Proxy HTTP History
            api.userInterface().registerHotKeyHandler(
                    HotKeyContext.PROXY_HTTP_HISTORY,
                    HotKey.hotKey("Sentinel AI 分析", "Ctrl Shift A"),
                    event -> {
                        var selected = event.selectedRequestResponses();
                        if (!selected.isEmpty()) {
                            var reqResp = selected.get(0);
                            presenter.handleHotKeyAnalysis(reqResp);
                        }
                    }
            );

            api.userInterface().registerHotKeyHandler(
                    HotKeyContext.PROXY_HTTP_HISTORY,
                    HotKey.hotKey("Sentinel AI 对话", "Ctrl Shift D"),
                    event -> {
                        var selected = event.selectedRequestResponses();
                        if (!selected.isEmpty()) {
                            var reqResp = selected.get(0);
                            presenter.handleHotKeyChat(reqResp);
                        }
                    }
            );

            logger.info("UI 初始化完成");

            // 回显 AI 配置到设置面板
            tab.getAiSettingsPanel().setConfig(aiConfigProviderId, aiConfigEndpoint, aiConfigKey, aiConfigModel, aiConfigFastModel);
            tab.getAiSettingsPanel().setContextWindowTokens(configManager.getConfig().getContextWindowTokens());
            // 同步模型名到分析面板与聊天窗 header
            if (!aiConfigModel.isEmpty()) {
                tab.getAiAnalysisPanel().setCurrentModel(aiConfigModel);
                tab.getAiChatPanel().setModelName(aiConfigModel);
            }

            // 尝试从缓存加载代码索引，失败则重新索引
            var savedRepos = configManager.getConfig().getCodeRepos();
            if (savedRepos != null && !savedRepos.isEmpty()) {
                if (!codeIndexService.loadIndex(savedRepos)) {
                    logger.info("检测到 %d 个已保存的代码仓库，正在后台自动索引...", savedRepos.size());
                    presenter.onIndexAllRepos(savedRepos);
                } else {
                    // 更新UI显示已索引状态
                    for (var repo : savedRepos) {
                        tab.getCodeRepoPanel().updateRepoStatus(repo.getName(), repo.getRouteCount());
                    }
                }
            }

            // File watcher: auto-reindex repos on source file changes
            com.flechazo.apisentinel.codeindex.FileWatcherService fileWatcherTmp = null;
            if (configManager.getConfig().isFileWatcherEnabled()
                    && savedRepos != null && !savedRepos.isEmpty()) {
                fileWatcherTmp = new com.flechazo.apisentinel.codeindex.FileWatcherService(
                        codeIndexService, savedRepos, logger);
                fileWatcherTmp.start();
            }
            final var fileWatcher = fileWatcherTmp;

            // MCP server: expose API-Sentinel to external Claude over MCP
            // (loopback HTTP only). Started only when enabled in config; the
            // flag is read at load time, so toggling it requires an extension
            // reload to take effect.
            com.flechazo.apisentinel.mcp.McpTools mcpTools = new com.flechazo.apisentinel.mcp.McpTools(
                    repository, providerFactory, configManager, codeIndexService, logger);
            mcpTools.setAnalysisTriggers(
                    presenter.getAiPresenter().getPipelineTrigger(),
                    presenter.getAiPresenter().getAgentTrigger());
            presenter.getAiPresenter().setMcpTools(mcpTools);
            com.flechazo.apisentinel.mcp.McpServer mcpServerTmp = null;
            if (configManager.getConfig().isMcpServerEnabled()) {
                try {
                    mcpServerTmp = new com.flechazo.apisentinel.mcp.McpServer(
                            configManager.getConfig().getMcpServerPort(), mcpTools, VERSION, logger);
                    mcpServerTmp.start();
                } catch (Exception mcpEx) {
                    logger.warn("[MCP] 启动 MCP 服务失败: %s", mcpEx.getMessage());
                    mcpServerTmp = null;
                }
            }
            final com.flechazo.apisentinel.mcp.McpServer mcpServerRef = mcpServerTmp;

            // Register tab shutdown on extension unload (must capture 'tab' here)
            final ApiSentinelTab tabRef = tab;
            api.extension().registerUnloadingHandler(() -> {
                logger.info("=== %s 正在卸载 ===", NAME);
                // Each shutdown step is isolated so one failure doesn't prevent
                // the rest — a thrown exception here would otherwise leave
                // executors/timers running, leaking the old ClassLoader and
                // blocking Burp from reloading the extension.
                Runnable[] steps = {
                        // Stop file watcher and external MCP access first
                        () -> { if (fileWatcher != null) fileWatcher.shutdown(); },
                        () -> { if (mcpServerRef != null) mcpServerRef.shutdown(); },
                        tabRef::shutdown,
                        repository::shutdown,
                        httpHandler::shutdown,
                        unauthorizedDetector::shutdown,
                        historyScanner::shutdown,
                        analysisQueue::shutdown,
                        agentController::shutdown,
                        providerFactory::shutdown,
                        eventBus::shutdown,
                        uiEventBus::shutdown,
                        learnedRuleEngine::shutdown,
                        com.flechazo.apisentinel.util.SharedTaskPool::shutdown
                };
                for (Runnable step : steps) {
                    try { step.run(); }
                    catch (Exception e) { logger.warn("卸载步骤异常: %s", e.getMessage()); }
                }
                // Disconnect repository change listeners (they hold UI components
                // belonging to this extension's ClassLoader).
                try { repository.clearChangeListeners(); } catch (Exception ignored) {}
                logger.info("=== %s 卸载完成 ===", NAME);
            });
        });

        logger.info("=== %s v%s 初始化完成 ===", NAME, VERSION);
        logger.info("  AI Provider: Ollama(local) / Claude / OpenAI");
        logger.info("  匹配引擎: Trie + Aho-Corasick");
        logger.info("  已学习规则: %d 条", learnedRuleEngine.getRuleCount());
        logger.info("  持久化: %s", configManager.getConfig().getDataFilePath());
    }

    private String[] loadAiConfig(LlmProviderFactory providerFactory, LeveledLogger logger) {
        String providerId = "ollama";
        String endpoint = "";
        String apiKey = "";
        String model = "";
        String fastModel = "";
        try {
            java.nio.file.Path extFile = com.flechazo.apisentinel.config.AppPaths.aiConfigFile();
            String json = null;
            if (java.nio.file.Files.exists(extFile)) {
                json = java.nio.file.Files.readString(extFile);
                logger.info("从外部加载 AI 配置: %s", extFile);
            } else {
                var is = getClass().getResourceAsStream("/ai-config.json");
                if (is != null) {
                    json = new String(is.readAllBytes());
                    is.close();
                    logger.info("从 JAR 内置加载 AI 配置");
                }
            }
            if (json != null) {
                var gson = new com.google.gson.Gson();
                var obj = gson.fromJson(json, com.google.gson.JsonObject.class);
                providerId = obj.has("provider") ? obj.get("provider").getAsString() : "ollama";
                endpoint = obj.has("endpoint") ? obj.get("endpoint").getAsString() : "";
                apiKey = obj.has("apiKey") ? obj.get("apiKey").getAsString() : "";
                model = obj.has("model") ? obj.get("model").getAsString() : "";
                fastModel = obj.has("fastModel") ? obj.get("fastModel").getAsString() : "";
                var provider = providerFactory.get(providerId);
                if (provider != null) {
                    provider.configure(endpoint, apiKey, model);
                    logger.info("AI Provider 已配置: %s [%s]", providerId, model);
                }
            }
        } catch (Exception e) {
            logger.warn("加载 AI 配置失败: %s", e.getMessage());
        }
        return new String[]{providerId, endpoint, apiKey, model, fastModel};
    }
}
