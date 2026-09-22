package com.flechazo.apisentinel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import com.flechazo.apisentinel.ai.agent.AgentController;
import com.flechazo.apisentinel.ai.budget.TokenBudgetManager;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.browser.BrowserManager;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.detection.SensitiveInfoDetector;
import com.flechazo.apisentinel.detection.UnauthorizedDetector;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.event.UiEventBus;
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
import java.awt.*;

/**
 * Burp Suite 扩展入口类。注册套件标签页、HTTP 处理器、上下文菜单、热键、MCP Server、
 * 代码索引等。所有核心组件在此初始化和销毁。
 */
public class ApiSentinelExtension implements BurpExtension {

    private static final String NAME = "API Sentinel";
    /** All Montoya API registrations — must be explicitly deregistered on
     *  extension unload or Burp keeps the handler references alive, pinning
     *  the old ClassLoader and preventing GC. Each register*() call returns
     *  a Registration whose deregister() removes it from Burp's internal
     *  handler list. */
    private final java.util.List<Registration> registrations = new java.util.ArrayList<>();
    public static final String VERSION = readVersion();

    private static String readVersion() {
        try {
            var pkg = ApiSentinelExtension.class.getPackage();
            if (pkg != null && pkg.getImplementationVersion() != null) {
                return pkg.getImplementationVersion();
            }
        } catch (Exception ignored) {}
        return "1.1"; // fallback for IDE/non-JAR mode
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
    private com.flechazo.apisentinel.ai.budget.TokenBudgetManager budgetManager;
    // Fun features
    private com.flechazo.apisentinel.fun.AchievementManager achievementManager;
    private com.flechazo.apisentinel.fun.EffectManager effectManager;
    private com.flechazo.apisentinel.fun.VulnerabilityPokedex pokedex;
    private com.flechazo.apisentinel.fun.StatsManager statsManager;
    /** Running MCP server (loopback). Field (not a local) so the startup
     *  summary block and unload handler can both see it. */
    private final java.util.concurrent.atomic.AtomicReference<com.flechazo.apisentinel.mcp.McpServer> mcpServerHolder =
            new java.util.concurrent.atomic.AtomicReference<>();

    /** Append an MCP lifecycle line to ~/.api-sentinel/mcp-diagnostic.log.
     *  Burp's extension console isn't file-backed, so this gives a readable
     *  record of whether the server actually started and why not. */
    /** Resolve the persistent MCP bearer token: reuse the saved one, or mint
     *  and persist a fresh one on first use so it stays stable across restarts. */
    private static String resolveMcpToken(com.flechazo.apisentinel.config.ConfigManager cm) {
        String t = cm.getConfig().getMcpAuthToken();
        if (t == null || t.isBlank()) {
            t = com.flechazo.apisentinel.mcp.McpServer.mintToken();
            cm.setMcpAuthToken(t);   // persist so it survives restarts
        }
        return t;
    }

    private static void mcpDiag(String msg) {
        try {
            java.nio.file.Path base = com.flechazo.apisentinel.config.AppPaths.configFile().getParent();
            java.nio.file.Path p = base.resolve("mcp-diagnostic.log");
            String line = java.time.LocalDateTime.now() + "  " + msg + System.lineSeparator();
            java.nio.file.Files.writeString(p, line,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception ignored) {}
    }

    /**
     * Pad a (typically Chinese) label to a target display width in terminal cells.
     *
     * <p>Chinese characters take 2 cells in a monospace terminal, ASCII 1 cell.
     * {@code String.format("%-8s", ...)} gets this wrong because it counts
     * chars, not cells, so labels like "模型:" and "轻量模型:" don't line up.
     * This helper counts cells using a coarse East-Asian width heuristic
     * (CJK blocks = 2 cells, everything else = 1) and appends ASCII spaces
     * until the target width is reached.
     *
     * <p>If the label already meets or exceeds the target, it's returned
     * unchanged — we never truncate, only pad.
     */
    private static String padKey(String label, int targetCells) {
        if (label == null) label = "";
        int cells = 0;
        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            java.lang.Character.UnicodeBlock b = java.lang.Character.UnicodeBlock.of(c);
            boolean wide = b == java.lang.Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                    || b == java.lang.Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A
                    || b == java.lang.Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_B
                    || b == java.lang.Character.UnicodeBlock.CJK_COMPATIBILITY_IDEOGRAPHS
                    || b == java.lang.Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
                    || b == java.lang.Character.UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS
                    || b == java.lang.Character.UnicodeBlock.ENCLOSED_CJK_LETTERS_AND_MONTHS
                    || b == java.lang.Character.UnicodeBlock.CJK_COMPATIBILITY
                    || b == java.lang.Character.UnicodeBlock.KANGXI_RADICALS
                    || b == java.lang.Character.UnicodeBlock.HANGUL_SYLLABLES
                    || b == java.lang.Character.UnicodeBlock.HANGUL_JAMO
                    || b == java.lang.Character.UnicodeBlock.HANGUL_COMPATIBILITY_JAMO;
            cells += wide ? 2 : 1;
        }
        if (cells >= targetCells) return label;
        return label + " ".repeat(targetCells - cells);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        LeveledLogger logger = new LeveledLogger(api.logging());
        logger.info("╔═══════════════════════════════════════════════════╗");
        logger.info("║  API Sentinel v1.1                                ║");
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
        // P0-6: initialize the budget manager from persisted config so users
        // can tune the daily cap / per-call cap without editing source.
        // Values default to 500K / 50K — same as the historic hardcoded values —
        // so first-launch behavior is unchanged. loadAiConfig() further
        // below may override these from ai-config.json (the live source of
        // truth for anything AI-related).
        budgetManager = new com.flechazo.apisentinel.ai.budget.TokenBudgetManager(
                configManager.getConfig().getDailyBudgetTokens(),
                configManager.getConfig().getPerRequestMaxTokens());
        budgetManager.setBudgetMode(configManager.getConfig().getBudgetMode());
        logger.debug("[Config] Budget mode: %s (daily=%d, perReq=%d)",
                configManager.getConfig().getBudgetMode(),
                configManager.getConfig().getDailyBudgetTokens(),
                configManager.getConfig().getPerRequestMaxTokens());
        // P0-6 fix: wire the budget manager into the factory so every
        // provider handed out via get() / getFirstAvailable() — including
        // the three direct (non-queue) entry paths in AgentFacade,
        // PipelineFacade, and ChatController — enforces the daily budget
        // and records real usage. Without this, the only gate was the one
        // inside AnalysisTaskQueue.submit, which those three paths bypass.
        providerFactory.setBudgetManager(budgetManager);

        // Load AI config from file (auto-configure provider)
        String[] aiConfig = loadAiConfig(providerFactory, logger);
        String aiConfigProviderId = aiConfig[0];
        String aiConfigEndpoint = aiConfig[1];
        String aiConfigKey = aiConfig[2];
        String aiConfigModel = aiConfig[3];
        String aiConfigFastModel = aiConfig.length > 4 ? aiConfig[4] : "";

        analysisQueue = new AnalysisTaskQueue(providerFactory, budgetManager, eventBus, logger, 4);
        analysisQueue.setActiveProvider(aiConfigProviderId);

        // Intruder AI payload generator (Extension-generated payload type).
        // Context-aware: uses the attack's full request template in prompts.
        registrations.add(api.intruder().registerPayloadGeneratorProvider(
                new com.flechazo.apisentinel.intruder.AiPayloadGeneratorProvider(
                        providerFactory, configManager, logger)));

        // Learned rule engine
        learnedRuleEngine = new LearnedRuleEngine(logger);
        // P2-1: wire the rule engine into the analysis queue so learned
        // rules are checked BEFORE the LLM call — high-confidence SAFE
        // matches skip the LLM entirely, saving ~$0.05/endpoint.
        analysisQueue.setLearnedRuleEngine(learnedRuleEngine);

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
        registrations.add(api.http().registerHttpHandler(httpHandler));

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

            // === Fun features initialization ===
            boolean funEnabled = configManager.getConfig().isFunFeaturesEnabled();
            if (funEnabled) {
                achievementManager = new com.flechazo.apisentinel.fun.AchievementManager(configManager, logger);
                effectManager = new com.flechazo.apisentinel.fun.EffectManager(logger);
                effectManager.setEnabled(configManager.getConfig().isEffectsEnabled());
                pokedex = new com.flechazo.apisentinel.fun.VulnerabilityPokedex(configManager, logger);
                achievementManager.setPokedex(pokedex);
                statsManager = new com.flechazo.apisentinel.fun.StatsManager(configManager, logger);

                // Subscribe to analysis complete events
                eventBus.subscribe(com.flechazo.apisentinel.event.AiAnalysisCompleteEvent.class, event -> {
                    var result = event.result();
                    if (result != null && !result.findings().isEmpty()) {
                        String severity = result.overallRisk().name();
                        for (var finding : result.findings()) {
                            String vulnType = finding.type() != null ? finding.type() : "";
                            String findingRisk = finding.risk() != null ? finding.risk() : severity;
                            achievementManager.checkVulnerabilityAchievements(vulnType, findingRisk);
                            pokedex.markDiscovered(vulnType);
                            statsManager.recordFinding(vulnType, findingRisk);
                        }
                        if (effectManager != null) effectManager.showParticleEffectAtCenter(severity);

                    }
                });

                // Build fun features tab with 3 sub-tabs
                JPanel funPanel = new JPanel(new BorderLayout());
                JTabbedPane funTabs = new JTabbedPane();
                funTabs.addTab("统计",
                        new com.flechazo.apisentinel.fun.StatsPanel(statsManager, new BurpTheme(api)));
                funTabs.addTab("成就",
                        new com.flechazo.apisentinel.fun.AchievementPanel(achievementManager, new BurpTheme(api)));
                funTabs.addTab("漏洞图鉴",
                        new com.flechazo.apisentinel.fun.PokedexPanel(pokedex, new BurpTheme(api)));
                funPanel.add(funTabs, BorderLayout.CENTER);
                tab.addSettingsTab("🏆 成就系统", funPanel);

                // Konami Code easter egg
                com.flechazo.apisentinel.fun.EasterEggs.registerKonamiCode(tab, () -> {
                    JOptionPane.showMessageDialog(tab,
                            "🎮 KONAMI CODE 激活！\n\n你发现了隐藏彩蛋！\n↑↑↓↓←→←→BA\n\n作为奖励，所有成就已解锁。",
                            "彩蛋发现！", JOptionPane.INFORMATION_MESSAGE);
                    achievementManager.getAllAchievements().forEach(a -> {
                        if (!a.isUnlocked()) achievementManager.tryUnlock(a.getId());
                    });
                });

                // Special date message
                String specialMsg = com.flechazo.apisentinel.fun.EasterEggs.getSpecialDateMessage();
                if (specialMsg != null) {
                    logger.info("[Fun] %s", specialMsg);
                    SwingUtilities.invokeLater(() ->
                            ToastNotification.show(tab, specialMsg, ToastNotification.ToastType.INFO, 6000));
                }

                logger.info("[Fun] 成就系统已启用: 统计 + 成就 + 图鉴 + 特效 + 彩蛋");
            }

            uiEventBus.setTableRefreshAction(tableModel::refreshFromRepositorySync);

            registrations.add(api.userInterface().registerSuiteTab(NAME, tab));

            // Apply Burp's theme (dark/light) to all custom components recursively
            api.userInterface().applyThemeToComponent(tab);

            // Shared theme handle for ThemedDialogs (JOptionPane replacements).
            com.flechazo.apisentinel.ui.ThemedDialogs.init(new BurpTheme(api));

            ContextMenuProvider contextMenu = new ContextMenuProvider(
                    api, repository, matchEngine, analysisQueue, uiEventBus, logger);
            contextMenu.setPipelineAnalyzeHandler(entry -> presenter.runPipelineForEntry(entry));
            contextMenu.setExtractSessionHandler((slot, credentials) ->
                    tab.getAuthConfigPanel().setSessionFromExternal(slot, credentials, null));
            registrations.add(api.userInterface().registerContextMenuItemsProvider(contextMenu));

            // Register a SEPARATE settings panel instance in Burp's native Settings dialog
            // (Swing components can only have one parent — sharing the same instance
            //  removes it from our tab group)
            AiSettingsPanel burpSettingsPanel = new AiSettingsPanel(providerFactory,
                    presenter::onProviderChanged, presenter::onContextWindowChanged, new BurpTheme(api));
            burpSettingsPanel.setConfig(aiConfigProviderId, aiConfigEndpoint, aiConfigKey, aiConfigModel);
            burpSettingsPanel.setContextWindowTokens(configManager.getConfig().getContextWindowTokens());
            // Restore unlimited budget checkbox from persisted config
            if (budgetManager != null && budgetManager.getBudgetMode() == com.flechazo.apisentinel.ai.budget.BudgetMode.MONITOR_ONLY) {
                burpSettingsPanel.setUnlimitedBudget(true);
                tab.getAiSettingsPanel().setUnlimitedBudget(true);
            }
            registrations.add(api.userInterface().registerSettingsPanel(burpSettingsPanel));

            // Wire tool management callback — must be set on BOTH instances:
            // burpSettingsPanel (Burp settings) AND tab.getAiSettingsPanel() (tab UI)
            AiSettingsPanel.ToolConfigCallback toolCallback = new AiSettingsPanel.ToolConfigCallback() {
                private final java.util.Set<String> disabled = new java.util.HashSet<>(
                        configManager.getConfig().getDisabledTools());
                private final java.util.Set<String> auth = new java.util.HashSet<>(
                        configManager.getConfig().getToolsRequiringAuth());

                @Override
                public void onChange(java.util.Set<String> d, java.util.Set<String> a) {
                    configManager.setDisabledTools(d);
                    configManager.setToolsRequiringAuth(a);
                    disabled.clear(); disabled.addAll(d);
                    auth.clear(); auth.addAll(a);
                }

                @Override
                public java.util.Set<String> getDisabledTools() { return new java.util.HashSet<>(disabled); }

                @Override
                public java.util.Set<String> getAuthTools() { return new java.util.HashSet<>(auth); }
            };
            burpSettingsPanel.setOnToolConfigChanged(toolCallback);
            tab.getAiSettingsPanel().setOnToolConfigChanged(toolCallback);

            // Register hotkeys for Proxy HTTP History.
            // NOTE: HotKey registrations are NOT added to the deregister list
            // because Burp's internal deregister() has an NPE bug
            // (ConcurrentHashMap.remove(null)). Burp auto-cleans hotkey
            // handlers on extension unload, so explicit deregister is unnecessary.
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

            logger.debug("UI 初始化完成");

            // 回显 AI 配置到设置面板
            tab.getAiSettingsPanel().setConfig(aiConfigProviderId, aiConfigEndpoint, aiConfigKey, aiConfigModel, aiConfigFastModel);
            tab.getAiSettingsPanel().setContextWindowTokens(configManager.getConfig().getContextWindowTokens());
            // P0-6: seed the budget fields from AppConfig (the persisted
            // baseline — loadAiConfig may have already pushed more recent
            // numbers from ai-config.json into budgetManager, but the UI
            // shows the config.json baseline until the user hits Save).
            tab.getAiSettingsPanel().setDailyBudgetTokens(configManager.getConfig().getDailyBudgetTokens());
            tab.getAiSettingsPanel().setPerRequestMaxTokens(configManager.getConfig().getPerRequestMaxTokens());
            tab.getAiSettingsPanel().setOnBudgetConfigChanged((dailyBudget, perRequestMax) -> {
                // Live effect: update the shared budget manager so the
                // next LLM call uses the new gate.
                budgetManager.setDailyBudget(dailyBudget);
                budgetManager.setPerRequestMax(perRequestMax);
                // Next-launch persistence: mirror into AppConfig so
                // ConfigManager writes the values to config.json the
                // next time any other setting change triggers a save.
                configManager.getConfig().setDailyBudgetTokens(dailyBudget);
                configManager.getConfig().setPerRequestMaxTokens(perRequestMax);
                logger.info("[AI] 预算配置已更新: 日预算=%d, 单请求上限=%d",
                        dailyBudget, perRequestMax);
            });
            // 回显浏览器配置到设置面板
            tab.getBrowserConfigPanel().setBrowserConfig(
                    configManager.getConfig().isBrowserEnabled(),
                    configManager.getConfig().isBrowserHeadless(),
                    configManager.getConfig().getBrowserChromePath(),
                    configManager.getConfig().getBrowserMaxPages(),
                    configManager.getConfig().getBrowserFrontendUrl());
            // P1-6: checkbox checked = "redact on" = includeRawCredentialsInLlm = false.
            // Default includeRawCredentialsInLlm = true (no redact), so checkbox
            // starts unchecked.
            tab.getAiSettingsPanel().setIncludeRawCredentialsPersisted(
                    configManager.getConfig().isFirstRunDisclosureDone());
            tab.getAiSettingsPanel().setIncludeRawCredentials(
                    !configManager.getConfig().isIncludeRawCredentialsInLlm());
            // P1-6: checkbox callback — checked = "redact on", so
            // includeRawCredentialsInLlm = !checked (inverted).
            tab.getAiSettingsPanel().setIncludeRawCredentialsCallback(checked -> {
                configManager.setIncludeRawCredentialsInLlm(!checked);
                if (checked) {
                    configManager.setFirstRunDisclosureDone(true);
                }
            });
            // Low-cost model tiering: init from config + persist on toggle.
            tab.getAiSettingsPanel().setModelTieringEnabled(configManager.getConfig().isModelTieringEnabled());
            tab.getAiSettingsPanel().setModelTieringCallback(configManager::setModelTieringEnabled);
            // Fun features toggle
            tab.getAiSettingsPanel().setFunFeaturesEnabled(configManager.getConfig().isFunFeaturesEnabled());
            tab.getAiSettingsPanel().setOnFunFeaturesChanged(() -> {
                boolean enabled = tab.getAiSettingsPanel().isFunFeaturesEnabled();
                configManager.setFunFeaturesEnabled(enabled);
                logger.info("[Fun] 趣味功能已%s", enabled ? "启用" : "禁用");
                if (enabled) {
                    javax.swing.JOptionPane.showMessageDialog(tab,
                            "成就系统已启用！\n\n发现漏洞时将解锁成就、显示粒子特效和播放音效。\n可在主标签页「成就系统」查看成就和漏洞图鉴。",
                            "趣味功能已启用",
                            javax.swing.JOptionPane.INFORMATION_MESSAGE);
                }
            });
            // 浏览器配置变更回调 → 持久化到 ConfigManager + 动态重新配置
            tab.getBrowserConfigPanel().setOnBrowserConfigChanged((enabled, headless, chromePath, maxPages, frontendUrl) -> {
                configManager.setBrowserEnabled(enabled);
                configManager.setBrowserHeadless(headless);
                configManager.setBrowserChromePath(chromePath);
                configManager.setBrowserMaxPages(maxPages);
                configManager.setBrowserFrontendUrl(frontendUrl);
                // Dynamically reconfigure or create browser service (no reload needed)
                if (enabled && presenter.getAiPresenter() != null) {
                    presenter.getAiPresenter().reconfigureBrowser(
                            8080, headless,
                            chromePath.isEmpty() ? null : chromePath,
                            maxPages, frontendUrl);
                } else if (!enabled && presenter.getAiPresenter() != null
                        && presenter.getAiPresenter().isBrowserAvailable()) {
                    // Browser being disabled — shut down the running browser
                    presenter.getAiPresenter().shutdownBrowser();
                }
            });

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
            mcpTools.setMontoyaApi(api);
            mcpTools.setBrowserService(presenter.getAiPresenter().getBrowserService());
            mcpTools.setOobService(presenter.getAiPresenter().getOobService());
            // Login-profile manager enables browser_login / browser_auto_crawl
            // for MCP sessions (only registered when browser is also enabled).
            // Shared with the internal Agent/Chat loops so logins persist across modes.
            mcpTools.setLoginProfileManager(presenter.getAiPresenter().getLoginProfileManager());
            // Refresh the API table + detail panels after validate_findings
            // persists an external verdict (so the user sees it in history).
            mcpTools.setOnUiRefresh(() -> javax.swing.SwingUtilities.invokeLater(tab::refreshTable));
            presenter.getAiPresenter().setMcpTools(mcpTools);
            // (mcpServerHolder is a field so the startup summary + unload
            // handler can see it; started/stopped live from the MCP panel.)
            final com.flechazo.apisentinel.mcp.McpTools mcpToolsRef = mcpTools;

            // ---- Startup summary (printed here, inside the EDT lambda, so
            //      it appears BEFORE the MCP status block below — previously
            //      it ran on the main thread and interleaved inconsistently
            //      depending on whether Burp called initialize() on EDT). ----
            logger.info("=== %s v%s 初始化完成 ===", NAME, VERSION);
            // ── AI 服务 ──
            logger.info("  ── AI 服务 ──");
            logger.info("  %s %s", padKey("● 服务商:", 14), aiConfigProviderId);
            if (aiConfigModel.isEmpty()) {
                logger.info("  %s %s", padKey("✗ 模型:", 14), "⚠ 未配置（请在设置中填写 API Key 和模型名）");
            } else {
                logger.info("  %s %s", padKey("✓ 模型:", 14), aiConfigModel);
            }
            if (!aiConfigFastModel.isEmpty()) {
                logger.info("  %s %s", padKey("✓ 轻量模型:", 14), aiConfigFastModel);
            }
            // ── 检测与工具 ──
            logger.info("  ── 检测与工具 ──");
            int disabledCount = configManager.getConfig().getDisabledTools().size();
            int toolCount = com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry.getToolCatalog().size();
            if (disabledCount > 0) {
                logger.info("  %s %d（禁用 %d）", padKey("⚠ 工具:", 14), toolCount, disabledCount);
            } else {
                logger.info("  %s %d", padKey("✓ 工具:", 14), toolCount);
            }
            int sensitiveRules = configManager.getConfig().getSensitiveRules().size();
            int learnedRules = learnedRuleEngine.getRuleCount();
            logger.info("  %s %d 条敏感信息 + %d 条已学习规则",
                    padKey("✓ 检测规则:", 14), sensitiveRules, learnedRules);
            int apiCount = repository.findAll().size();
            logger.info("  %s %d 条", padKey("● 已加载 API:", 14), apiCount);
            // ── 运行时 ──
            logger.info("  ── 运行时 ──");
            // Token budget: render "不限额" when limits are at Integer.MAX_VALUE
            // (the "no cap" default), otherwise show numbers. Raw MAX_VALUE
            // values (2,147,483,647) read as noise; the user only cares whether
            // the meter is enforced.
            int dailyBudget = configManager.getConfig().getDailyBudgetTokens();
            int perReqBudget = configManager.getConfig().getPerRequestMaxTokens();
            boolean unlimited = dailyBudget == Integer.MAX_VALUE && perReqBudget == Integer.MAX_VALUE;
            if (unlimited) {
                logger.info("  %s %s（不限额）",
                        padKey("● Token 预算:", 14), configManager.getConfig().getBudgetMode());
            } else {
                logger.info("  %s %s（日=%,d, 单次=%,d）",
                        padKey("● Token 预算:", 14), configManager.getConfig().getBudgetMode(),
                        dailyBudget, perReqBudget);
            }
            boolean browserEnabled = configManager.getConfig().isBrowserEnabled();
            if (browserEnabled) {
                // Check whether the Playwright driver is bundled in this jar
                boolean driverBundled = BrowserManager.class.getClassLoader()
                        .getResource("driver/") != null;
                String mode = configManager.getConfig().isBrowserHeadless() ? "无头模式" : "有头模式";
                if (driverBundled) {
                    logger.info("  %s %s（内置驱动）",
                            padKey("✓ 浏览器:", 14), mode);
                } else {
                    logger.info("  %s %s（未内置驱动，使用系统 Playwright）",
                            padKey("⚠ 浏览器:", 14), mode);
                }
            } else {
                logger.info("  %s 未启用", padKey("✗ 浏览器:", 14));
            }
            logger.info("  %s %s", padKey("● 数据目录:", 14),
                    configManager.getConfig().getDataFilePath());
            // Login profile count — small JSON re-read; the in-load debug log
            // stays at DEBUG level so users don't see a duplicate message.
            try {
                int profileCount = new com.flechazo.apisentinel.config.LoginProfileManager(logger).getAll().size();
                logger.info("  %s %d 个 profile（~/.api-sentinel/login-profiles.json）",
                        padKey("● 登录配置:", 14), profileCount);
            } catch (Exception ignored) {
                // File missing or unreadable: log is nice-to-have, not fatal.
            }
            // ---- End of main summary. MCP status follows below as its own
            //      labeled section. ----

            // Initial start when enabled in config.
            String mcpInitError = null;
            mcpDiag("initialize(): mcpServerEnabled=" + configManager.getConfig().isMcpServerEnabled()
                    + " port=" + configManager.getConfig().getMcpServerPort());
            if (configManager.getConfig().isMcpServerEnabled()) {
                try {
                    com.flechazo.apisentinel.mcp.McpServer s = new com.flechazo.apisentinel.mcp.McpServer(
                            configManager.getConfig().getMcpServerPort(), mcpToolsRef, VERSION, logger,
                            resolveMcpToken(configManager), configManager.getConfig().isMcpRequireAuth());
                    s.start();
                    mcpServerHolder.set(s);
                    mcpDiag("load: MCP started OK on port " + configManager.getConfig().getMcpServerPort()
                            + " token=" + s.getAuthToken());
                } catch (Throwable mcpEx) {
                    mcpInitError = mcpEx.toString();
                    logger.warn("[MCP] 启动 MCP 服务失败: %s", mcpEx.toString());
                    mcpDiag("load: MCP start FAILED: " + mcpEx + " | cause=" + mcpEx.getCause());
                }
            }
            {
                int mcpPort0 = configManager.getConfig().getMcpServerPort();
                com.flechazo.apisentinel.mcp.McpServer s0 = mcpServerHolder.get();
                // MCP as its own labeled section — same style as the other
                // headers above, just for the runtime service block.
                logger.info("  ── MCP Server ──");
                if (s0 != null) {
                    tab.getMcpConfigPanel().setRuntimeInfo(true, s0.getAuthToken(), mcpPort0);
                    logger.info("  %s 运行中 http://127.0.0.1:%d/mcp", padKey("✓ 状态:", 14), mcpPort0);
                    // P0 security: never print the full auth token at INFO —
                    // Burp's output panel is visible to anyone with screen
                    // access and often forwarded/captured. Show only the
                    // prefix so users can confirm "there is a token"; the
                    // full value lives in ~/.api-sentinel/mcp-diagnostic.log
                    // and in the MCP config panel (hidden by default).
                    String fullToken = s0.getAuthToken();
                    String preview = fullToken != null && fullToken.length() > 8
                            ? fullToken.substring(0, 8) + "..." : "(empty)";
                    logger.info("  %s %s", padKey("● Auth Token:", 14), preview);
                    logger.debug("  MCP Auth Token (full): %s", fullToken);
                } else if (mcpInitError != null) {
                    tab.getMcpConfigPanel().setStartError(mcpPort0, mcpInitError);
                    logger.warn("  %s 启动失败 — %s", padKey("✗ 状态:", 14), mcpInitError);
                    logger.info("  （详细诊断见 ~/.api-sentinel/mcp-diagnostic.log）");
                } else {
                    tab.getMcpConfigPanel().setRuntimeInfo(false, null, mcpPort0);
                    logger.info("  %s 未启用", padKey("● 状态:", 14));
                }
            }
            // Live start/stop when the user toggles the switch or changes the
            // port in 设置→高级→MCP (config is already persisted by the panel).
            tab.getMcpConfigPanel().setOnMcpControl((mcpEnabled, mcpPort) -> new Thread(() -> {
                mcpDiag("toggle: request enabled=" + mcpEnabled + " port=" + mcpPort);
                com.flechazo.apisentinel.mcp.McpServer old = mcpServerHolder.getAndSet(null);
                if (old != null) old.shutdown();
                if (mcpEnabled) {
                    try {
                        com.flechazo.apisentinel.mcp.McpServer s = new com.flechazo.apisentinel.mcp.McpServer(
                                mcpPort, mcpToolsRef, VERSION, logger,
                                resolveMcpToken(configManager), configManager.getConfig().isMcpRequireAuth());
                        s.start();
                        mcpServerHolder.set(s);
                        tab.getMcpConfigPanel().setRuntimeInfo(true, s.getAuthToken(), mcpPort);
                        mcpDiag("toggle: MCP started OK on port " + mcpPort + " token=" + s.getAuthToken());
                    } catch (Throwable ex) {
                        logger.warn("[MCP] 启动 MCP 服务失败: %s", ex.toString());
                        tab.getMcpConfigPanel().setStartError(mcpPort, ex.toString());
                        mcpDiag("toggle: MCP start FAILED: " + ex + " | cause=" + ex.getCause());
                    }
                } else {
                    tab.getMcpConfigPanel().setRuntimeInfo(false, null, mcpPort);
                    mcpDiag("toggle: MCP disabled (stopped)");
                }
            }, "mcp-toggle").start());

            // Register tab shutdown on extension unload (must capture 'tab' here)
            final ApiSentinelTab tabRef = tab;
            api.extension().registerUnloadingHandler(() -> {
                logger.info("=== %s 正在卸载 ===", NAME);
                // Deregister all Montoya API handlers FIRST — Burp keeps
                // internal references to registered handlers, and without
                // explicit deregister() these references pin the old
                // ClassLoader in memory across extension reloads.
                // Note: Burp's HotKey deregister has a known NPE bug
                // (ConcurrentHashMap.remove(null)) — caught and skipped.
                for (int i = 0; i < registrations.size(); i++) {
                    try {
                        Registration reg = registrations.get(i);
                        if (reg != null && reg.isRegistered()) {
                            reg.deregister();
                        }
                    } catch (Throwable t) {
                        // Catch Throwable (not just Exception) because Burp's
                        // proxy layer can wrap NPE in InvocationTargetException
                        // which propagates through reflection.
                        logger.warn("注销注册 #%d 失败: %s", i, t.toString());
                    }
                }
                registrations.clear();
                // Each shutdown step is isolated so one failure doesn't prevent
                // the rest — a thrown exception here would otherwise leave
                // executors/timers running, leaking the old ClassLoader and
                // blocking Burp from reloading the extension.
                Runnable[] steps = {
                        // Stop file watcher and external MCP access first
                        () -> { if (fileWatcher != null) fileWatcher.shutdown(); },
                        () -> { com.flechazo.apisentinel.mcp.McpServer s = mcpServerHolder.get(); if (s != null) s.shutdown(); },
                        mcpToolsRef::closeAllSessions,
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
                // Reset browser interaction dialog session approval
                try { com.flechazo.apisentinel.ui.BrowserInteractConfirmDialog.resetSessionApproval(); } catch (Exception ignored) {}
                // Release static references that pin the old ClassLoader:
                // ThemedDialogs holds a BurpTheme instance, I18n accumulates
                // listeners across reloads — both must be cleared or the
                // extension's heap is never reclaimed by Burp's GC.
                try { com.flechazo.apisentinel.ui.ThemedDialogs.reset(); } catch (Exception ignored) {}
                try { com.flechazo.apisentinel.ui.I18n.resetForTest(); } catch (Exception ignored) {}
                logger.info("=== %s 卸载完成 ===", NAME);
            });
        });
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
                logger.debug("从外部加载 AI 配置: %s", extFile);
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
                    logger.debug("AI Provider 已配置: %s [%s]", providerId, model);
                }
                // P0-6: if the file carries budget numbers, push them into
                // the shared TokenBudgetManager immediately so the gate uses
                // the user's tuned values from this run's very first call.
                // Missing fields are a no-op — TokenBudgetManager falls
                // back to the values seeded from AppConfig.
                if (budgetManager != null) {
                    if (obj.has("unlimitedBudget") && obj.get("unlimitedBudget").getAsBoolean()) {
                        budgetManager.setBudgetMode(com.flechazo.apisentinel.ai.budget.BudgetMode.MONITOR_ONLY);
                    }
                    if (obj.has("dailyBudgetTokens")) {
                        budgetManager.setDailyBudget(obj.get("dailyBudgetTokens").getAsInt());
                    }
                    if (obj.has("perRequestMaxTokens")) {
                        budgetManager.setPerRequestMax(obj.get("perRequestMaxTokens").getAsInt());
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("加载 AI 配置失败: %s", e.getMessage());
        }
        return new String[]{providerId, endpoint, apiKey, model, fastModel};
    }
}
