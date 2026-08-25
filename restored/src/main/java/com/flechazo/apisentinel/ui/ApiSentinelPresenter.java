package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.flechazo.apisentinel.ai.agent.AgentController;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.queue.AnalysisTask;
import com.flechazo.apisentinel.ai.queue.AnalysisTask.AnalysisMode;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.config.MatchMode;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.handler.ProxyHistoryScanner;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.matching.CompositeMatchEngine;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.repository.ApiRepository;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.SwingUtilities;
import java.awt.Window;

/**
 * 主 Presenter——协调 UI 事件、分析触发（Pipeline/Agent）、上下文菜单、
 * 热键、选择监听等。连接 View 与各 Facade/Controller。
 */
public class ApiSentinelPresenter {

    private final ApiRepository repository;
    private final CompositeMatchEngine matchEngine;
    private final ConfigManager configManager;
    private final ApiEntryTableModel tableModel;
    private final ProxyHistoryScanner historyScanner;
    private final CodeIndexService codeIndexService;
    private final LeveledLogger logger;
    private final MontoyaApi api;

    private final ExportPresenter exportPresenter;
    private final AiPresenter aiPresenter;
    private final StatusPresenter statusPresenter;

    private ApiSentinelTab view;
    private AgentController agentController;

    public ApiSentinelPresenter(MontoyaApi api,
                                   ApiRepository repository,
                                   CompositeMatchEngine matchEngine,
                                   ConfigManager configManager,
                                   ApiEntryTableModel tableModel,
                                   ProxyHistoryScanner historyScanner,
                                   AnalysisTaskQueue analysisQueue,
                                   EventBus eventBus,
                                   CodeIndexService codeIndexService,
                                   LlmProviderFactory providerFactory,
                                   LeveledLogger logger) {
        this.api = api;
        this.repository = repository;
        this.matchEngine = matchEngine;
        this.configManager = configManager;
        this.tableModel = tableModel;
        this.historyScanner = historyScanner;
        this.codeIndexService = codeIndexService;
        this.logger = logger;

        this.exportPresenter = new ExportPresenter(repository);
        this.aiPresenter = new AiPresenter(api, configManager, tableModel, analysisQueue,
                codeIndexService, providerFactory, eventBus, logger);
        this.statusPresenter = new StatusPresenter(api, repository, tableModel, logger);
    }

    /** Forward to AiPresenter to unsubscribe EventBus listeners on unload. */
    public void shutdown() {
        if (aiPresenter != null) aiPresenter.shutdown();
    }

    /** MCP bridge: expose the AI presenter's analysis triggers. */
    public AiPresenter getAiPresenter() { return aiPresenter; }

    public void setView(ApiSentinelTab view) {
        this.view = view;
        exportPresenter.setView(view);
        aiPresenter.setView(view);

        // Path-column edit (identity rename) — re-index the match engine trie
        tableModel.setOnPathEdit((entry, newPath) -> {
            String oldPath = entry.getApiPath();
            ApiEntry updated = repository.updatePath(oldPath, newPath);
            if (updated == null) {
                logger.warn("修改路径失败（目标已存在或源不存在）: %s -> %s", oldPath, newPath);
                javax.swing.SwingUtilities.invokeLater(() ->
                        ThemedDialogs.warn(view,
                                "修改路径失败：目标路径已存在或源条目不存在。",
                                "修改失败"));
                return;
            }
            matchEngine.removeEntry(oldPath);
            matchEngine.addEntry(updated);
            matchEngine.clearCache();
            logger.info("修改 API 路径: %s -> %s", oldPath, newPath);
            javax.swing.SwingUtilities.invokeLater(tableModel::refreshFromRepository);
        });

        view.getTablePanel().getTable().getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = view.getTablePanel().getTable().getSelectedRow();
                int row = viewRow >= 0 ? view.getTablePanel().getTable().convertRowIndexToModel(viewRow) : -1;
                ApiEntry entry = (row >= 0) ? tableModel.getEntryAt(row) : null;
                // Sticky result panel: only re-render when a real row is
                // selected. Programmatic table refreshes (refreshFromRepository,
                // persistence) clear the JTable selection and fire this with
                // entry==null — that used to wipe a just-completed analysis
                // back to "等待分析" and, for records without a stage-1 result,
                // leave it stuck there permanently.
                if (entry != null) {
                    view.getAiAnalysisPanel().showEntryHistory(entry);
                }

                // Track current entry for Repeater per-entry caching. showEntry()
                // atomically restores a cached live state if one exists (e.g.
                // user viewed it before, switched away, now switched back — or
                // this same entry just got re-selected by a fireTableDataChanged-
                // driven selection re-fire right after a Pipeline/Agent run
                // completed) or otherwise builds fresh from the persisted
                // AnalysisRecord — never both, and never as two separate races
                // invokeLater dispatches the way the old setCurrentEntryPath()+
                // loadTestCases()+loadPayloadResults() sequence did.
                if (entry != null) {
                    if (entry.hasTrafficData()) {
                        view.getRepeaterPanel().loadFromEntry(entry);
                    }
                    var latest = entry.getLatestAnalysisRecord();
                    var persistedTestCases = latest != null ? latest.testCases() : null;
                    var persistedPayloadResults = (latest != null && latest.hasPipelineResult())
                            ? latest.pipelineResult().payloadResults() : null;
                    view.getRepeaterPanel().showEntry(entry.getApiPath(), entry.getDomain(), entry.getLastUrl(),
                            persistedTestCases, persistedPayloadResults, null);
                }

                // Source code lookup is independent of AI analysis — show it
                // on-demand whenever an entry is selected and the code index
                // has been built (no need to run analysis first).
                if (entry != null) {
                    updateSourceCodeTab(entry);
                }
            }
        });

        view.getTablePanel().setOnAnalyzeRow(row -> onFullPipelineAnalyze(new int[]{row}));
        view.getTablePanel().setOnAiChat(row -> {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry != null) {
                view.getAiChatPanel().setContext(entry);
                view.switchToChat();
            }
        });
        view.getTablePanel().setOnDeleteRows(this::onRemoveSelected);
        view.getTablePanel().setOnMarkSafe(this::onMarkSafe);
        view.getTablePanel().setOnViewTraffic(this::onViewTraffic);
        view.getTablePanel().setOnViewFindings(this::onViewFindings);
        view.getTablePanel().setOnViewPassive(this::onViewPassive);
        view.getTablePanel().setOnSendToOrganizer(this::onSendToOrganizer);

        // Repeater AI button → switch to embedded chat for the current entry
        view.getRepeaterPanel().setOnAiChatRequested(() -> {
            int viewRow = view.getTablePanel().getTable().getSelectedRow();
            int row = viewRow >= 0 ? view.getTablePanel().getTable().convertRowIndexToModel(viewRow) : -1;
            ApiEntry entry = (row >= 0) ? tableModel.getEntryAt(row) : null;
            if (entry != null) {
                view.getAiChatPanel().setContext(entry);
                view.switchToChat();
            }
        });

        view.getTablePanel().getTable().getSelectionModel().addListSelectionListener(e2 -> {
            if (!e2.getValueIsAdjusting()) {
                int chatViewRow = view.getTablePanel().getTable().getSelectedRow();
                int chatRow = chatViewRow >= 0 ? view.getTablePanel().getTable().convertRowIndexToModel(chatViewRow) : -1;
                ApiEntry chatEntry = (chatRow >= 0) ? tableModel.getEntryAt(chatRow) : null;
                // Sticky context: only ever UPGRADE the chat context, never
                // reset it. refreshFromRepository() (fires after every
                // analysis completion, status toggle, import...) clears the
                // table selection, which used to bounce the floating chat
                // back to "未选择接口" right under the user's eyes.
                if (chatEntry != null) {
                    view.getAiChatPanel().setContext(chatEntry);
                }
            }
        });
    }

    public void setAgentController(AgentController agentController) {
        this.agentController = agentController;
    }

    public void setLearnedRuleEngine(LearnedRuleEngine engine) {
        aiPresenter.setLearnedRuleEngine(engine);
    }

    /** Forward to AiPresenter: success-pattern memory wiring (P3). */
    public void setPatternStore(com.flechazo.apisentinel.ai.patterns.PatternStore store) {
        aiPresenter.setPatternStore(store);
    }

    // === Delegation to AiPresenter ===

    /**
     * Toggles AgentController's background auto-pilot (auto-analyze every
     * matched API). Deliberately separate from the toolbar's Pipeline/Agent
     * dropdown, which only picks which path a *manually* triggered analysis
     * takes — the two used to be wired together via the same "agentMode"
     * checkbox key, which meant switching to Agent mode for manual analysis
     * silently turned on continuous background auto-scanning too.
     */
    public void onAutoScanToggle(boolean enabled) {
        if (agentController != null) {
            agentController.setEnabled(enabled);
            logger.info("自动扫描: %s", enabled ? "开启" : "关闭");
        }
    }

    public void onChatMessage(String message) { aiPresenter.onChatMessage(message); }

    /** Chat-panel stop button: ask all in-flight Pipeline/Agent analyses to
     *  stop (cooperative cancel — partial Agent results are kept). */
    public void onCancelAnalyses() { aiPresenter.cancelActiveAnalyses(); }
    public void onAiAnalyze(int[] selectedRows) { aiPresenter.onAiAnalyze(selectedRows); }
    public void onAiAnalyze(int[] selectedRows, AnalysisMode mode) { aiPresenter.onAiAnalyze(selectedRows, mode); }
    public void onFullPipelineAnalyze(int[] selectedRows) { aiPresenter.onFullPipelineAnalyze(selectedRows); }
    public void onFullPipelineAnalyze(int[] selectedRows, AnalysisTask.AnalysisMode mode) { aiPresenter.onFullPipelineAnalyze(selectedRows, mode); }
    public void runPipelineForEntry(com.flechazo.apisentinel.model.ApiEntry entry) { aiPresenter.runPipelineForEntry(entry); }

    // === HotKey handlers (called from ApiSentinelExtension hotkey registration) ===

    public void handleHotKeyAnalysis(HttpRequestResponse reqResp) {
        ApiEntry entry = entryFromRequestResponse(reqResp);
        if (entry != null) {
            aiPresenter.runPipelineForEntry(entry);
        }
    }

    public void handleHotKeyChat(HttpRequestResponse reqResp) {
        ApiEntry entry = entryFromRequestResponse(reqResp);
        if (entry != null && view != null) {
            SwingUtilities.invokeLater(() -> {
                view.getAiChatPanel().setContext(entry);
                view.switchToChat();
            });
        }
    }

    private ApiEntry entryFromRequestResponse(HttpRequestResponse reqResp) {
        if (reqResp == null || reqResp.request() == null) return null;
        String path = reqResp.request().path();
        if (path != null && path.contains("?")) path = path.substring(0, path.indexOf('?'));
        String finalPath = path;
        var existing = repository.findByPath(finalPath != null ? finalPath : "/");
        if (existing.isPresent()) return existing.get();
        // Create a transient entry from the request
        String method = reqResp.request().method();
        String host = reqResp.request().headerValue("Host");
        if (host == null) host = "";
        ApiEntry entry = new ApiEntry(finalPath != null ? finalPath : "/", method != null ? method : "GET");
        entry.setDomain(host);
        if (reqResp.response() != null) {
            entry.setLastStatusCode(reqResp.response().statusCode());
        }
        entry.setLastRawRequest(reqResp.request().toString());
        if (reqResp.response() != null) {
            entry.setLastRawResponse(reqResp.response().toString());
        }
        String url = (reqResp.request().httpService().secure() ? "https://" : "http://") + host + finalPath;
        entry.setLastUrl(url);
        return entry;
    }

    // === Delegation to StatusPresenter ===

    public void onToggleStatus(int[] selectedRows) { statusPresenter.onToggleStatus(selectedRows); }
    public void onToggleVulnType(int[] selectedRows) { statusPresenter.onToggleVulnType(selectedRows); }
    public void onMoveTestedToTop() { statusPresenter.onMoveTestedToTop(); }
    public void onAddDomainsToScope(int[] selectedRows) { statusPresenter.onAddDomainsToScope(selectedRows); }

    public void onMarkSafe(int[] selectedRows) {
        if (selectedRows == null || selectedRows.length == 0) return;
        for (int row : selectedRows) {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry != null) {
                entry.updateStatus(com.flechazo.apisentinel.model.ApiStatus.PASSED, null,
                        com.flechazo.apisentinel.model.ApiStatus.PASSED.getDisplayName());
            }
        }
        tableModel.refreshFromRepository();
        logger.info("已标记 %d 个 API 为安全", selectedRows.length);
    }

    public void onViewTraffic(int[] selectedRows) {
        if (selectedRows == null || selectedRows.length == 0) return;
        // Show traffic dialog for the first selected row
        ApiEntry entry = tableModel.getEntryAt(selectedRows[0]);
        if (entry == null) return;
        SwingUtilities.invokeLater(() -> {
            Window owner = view != null ? SwingUtilities.getWindowAncestor(view) : null;
            HistoryTrafficDialog dialog = new HistoryTrafficDialog(owner, api, entry);
            if (view != null) {
                dialog.setOnExtractSession((slot, cookie) ->
                        view.getAuthConfigPanel().setSessionFromExternal(slot, cookie, null));
            }
            dialog.setVisible(true);
        });
    }

    /** Send the captured request/response of the selected entries to Burp's
     *  native Organizer for manual review. */
    public void onSendToOrganizer(int[] selectedRows) {
        if (selectedRows == null || selectedRows.length == 0) return;
        int sent = 0;
        for (int row : selectedRows) {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry == null) continue;
            var rr = PipelineFacade.buildEntryRequestResponse(entry);
            if (rr == null) continue;
            try {
                api.organizer().sendToOrganizer(rr);
                sent++;
            } catch (Exception ex) {
                logger.debug("发送到 Organizer 失败: %s", ex.getMessage());
            }
        }
        logger.info("[Organizer] 手动发送 %d 条请求到 Organizer", sent);
    }

    public void onViewFindings(int row) {
        ApiEntry entry = tableModel.getEntryAt(row);
        if (entry == null || entry.getLatestAnalysisRecord() == null
                || !entry.getLatestAnalysisRecord().hasPipelineResult()) {
            return; // nothing to show yet
        }
        SwingUtilities.invokeLater(() -> {
            Window owner = view != null ? SwingUtilities.getWindowAncestor(view) : null;
            new FindingsDetailDialog(owner, api, entry).setVisible(true);
        });
    }

    public void onViewPassive(int row) {
        ApiEntry entry = tableModel.getEntryAt(row);
        if (entry == null || !entry.hasPassiveFindings()) return;
        SwingUtilities.invokeLater(() -> {
            Window owner = view != null ? SwingUtilities.getWindowAncestor(view) : null;
            new PassiveFindingsDialog(owner, api, entry).setVisible(true);
        });
    }

    // === Delegation to ExportPresenter ===

    public void onExportCsv() { exportPresenter.onExportCsv(); }
    public void onExportMarkdown() { exportPresenter.onExportMarkdown(); }
    public void onExportFullReport() { exportPresenter.onExportFullReport(); }

    // === Import / Data Management ===

    /** Trigger a proxy history scan (called from ImportDialog after import). */
    public void scanHistory() {
        historyScanner.scanHistory();
    }

    public void onImportApis(String text) {
        if (text == null || text.isBlank()) return;

        String[] lines = text.split("\\R");
        List<ApiEntry> newEntries = new ArrayList<>();
        int skipped = 0;

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            // Strip inline comments (e.g. "GET /api/users  # description")
            if (line.contains("  #")) {
                line = line.substring(0, line.indexOf("  #")).trim();
            }

            String method = "";
            String apiPath;
            String[] parts = line.split("\\s+", 2);
            if (parts.length == 2 && isValidHttpMethod(parts[0].toUpperCase())) {
                method = parts[0].toUpperCase();
                apiPath = parts[1].trim();
            } else {
                apiPath = line;
            }

            if (apiPath.isEmpty()) { skipped++; continue; }
            if (repository.contains(method, apiPath)) {
                skipped++;
                continue;
            }

            newEntries.add(new ApiEntry(method, apiPath));
        }

        if (!newEntries.isEmpty()) {
            repository.addAll(newEntries);
            matchEngine.rebuild(repository.findAll());
            tableModel.refreshFromRepository();
            if (view != null) view.getAuthConfigPanel().clearCookies();

        }
        logger.info("导入完成: 成功 %d 个, 跳过 %d 个", newEntries.size(), skipped);

        // Friendly nudge: placeholder patterns only work under EXACT match.
        // Under FUZZY (substring search) they never hit, so offer to switch.
        if (configManager.getConfig().getMatchMode() == com.flechazo.apisentinel.config.MatchMode.FUZZY
                && newEntries.stream().anyMatch(ne -> com.flechazo.apisentinel.util.PatternUtils.hasPlaceholders(ne.getApiPath()))
                && view != null) {
            SwingUtilities.invokeLater(() -> {
                boolean yes = ThemedDialogs.confirmYesNo(view,
                        "当前是「模糊匹配」模式，但导入的路径含占位符（如 {id}、:id、<id>）。\n\n"
                                + "模糊匹配是字面子串搜索，不识别占位符，这些路径将无法命中流量。\n"
                                + "是否切换到「精确匹配」模式？",
                        "建议切换匹配模式");
                if (yes) {
                    view.getToolbarPanel().setMatchMode(com.flechazo.apisentinel.config.MatchMode.EXACT);
                }
            });
        }
    }

    public void onRemoveSelected(int[] selectedRows) {
        if (selectedRows == null || selectedRows.length == 0) return;
        java.awt.Component parent = view != null ? view.getTablePanel().getTable() : null;
        boolean confirmed = ThemedDialogs.confirm(parent,
                "确定删除 " + selectedRows.length + " 个 API 及其分析历史？此操作不可撤销。",
                "确认删除");
        if (!confirmed) return;
        List<Integer> indices = IntStream.of(selectedRows).boxed()
                .sorted(Comparator.reverseOrder()).collect(Collectors.toList());
        List<String> paths = new ArrayList<>();
        for (int idx : indices) {
            ApiEntry entry = tableModel.getEntryAt(idx);
            if (entry != null) paths.add(entry.getApiPath());
        }
        repository.removeByIndices(indices);
        paths.forEach(matchEngine::removeEntry);
        matchEngine.clearCache();
        // Deleting an API must also drop its chat conversation — otherwise the
        // removed endpoint lingers in the 历史会话 menu and its transcript
        // survives the delete ("数据删除了这里还有留存").
        if (view != null) {
            AiChatPanel chatPanel = view.getAiChatPanel();
            if (chatPanel != null) {
                for (String p : paths) {
                    chatPanel.clearHistoryForPath(p);
                }
            }
        }
        tableModel.refreshFromRepository();
        logger.info("已删除 %d 个API", paths.size());
    }

    // === Search / Config ===

    public void onFindApi(String searchText) {
        if (searchText == null || searchText.isEmpty()) return;
        String lower = searchText.toLowerCase();
        List<ApiEntry> all = repository.findAll();
        for (int i = 0; i < all.size(); i++) {
            ApiEntry entry = all.get(i);
            if (entry.getApiPath().toLowerCase().contains(lower)
                    || entry.getHttpMethod().toLowerCase().contains(lower)) {
                if (view != null) view.selectAndScrollTo(i);
                return;
            }
        }
        if (view != null) view.clearSelection();
    }

    public void onMatchModeChanged(MatchMode mode) {
        configManager.setMatchMode(mode);
        matchEngine.clearCache();
    }

    public void onProviderChanged(String providerId) {
        if (aiPresenter != null) {
            logger.info("AI Provider 切换为: %s", providerId);
        }
        if (view != null) {
            String model = view.getAiSettingsPanel().getModel();
            if (model != null && !model.isEmpty()) {
                view.getAiAnalysisPanel().setCurrentModel(model);
            }
        }
    }

    public void onContextWindowChanged(int tokens) {
        configManager.setContextWindowTokens(tokens);
        logger.info("Agent 上下文窗口预算已更新为: %d tokens", tokens);
    }

    // === Code Repo Management ===

    /** Monotonic token for source-code lookups: fast entry-switching fires a
     *  new lookup per selection, and without this an in-flight lookup for the
     *  PREVIOUS entry could land last and overwrite the current one's source
     *  (the "快速切换 entry 时源码查询结果错乱" bug). Every selection bumps the
     *  token; a completing lookup applies only if its token is still current. */
    private final java.util.concurrent.atomic.AtomicLong sourceLookupSeq =
            new java.util.concurrent.atomic.AtomicLong();

    private void updateSourceCodeTab(ApiEntry entry) {
        RSyntaxTextArea sourceArea = view != null ? view.getSourceArea() : null;
        if (sourceArea == null) return;

        // Invalidate any in-flight lookup regardless of whether the new
        // selection has an entry (null selection must not be clobbered by a
        // stale result either).
        final long mySeq = sourceLookupSeq.incrementAndGet();

        if (entry == null) {
            SwingUtilities.invokeLater(() -> sourceArea.setText("选中 API 后自动展示关联源码"));
            return;
        }

        com.flechazo.apisentinel.util.SharedTaskPool.submitInteractive(() -> {
            try {
                String sourceCode = aiPresenter.lookupSourceCode(entry.getApiPath(), entry.getDomain());
                SwingUtilities.invokeLater(() -> {
                    if (mySeq != sourceLookupSeq.get()) return; // stale — user moved on
                    if (sourceCode.isEmpty()) {
                        sourceArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
                        sourceArea.setText("未找到 " + entry.getHttpMethod() + " " + entry.getApiPath()
                                + " 的关联源码\n\n可能原因:\n"
                                + "1. 尚未在「设置 → 代码仓库」中添加并索引仓库\n"
                                + "2. 仓库未关联该域名（" + entry.getDomain() + "）\n"
                                + "3. 代码中未找到匹配的路由定义");
                    } else {
                        sourceArea.setSyntaxEditingStyle(syntaxStyleForSource(sourceCode));
                        sourceArea.setText(sourceCode);
                    }
                    sourceArea.setCaretPosition(0);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (mySeq != sourceLookupSeq.get()) return;
                    sourceArea.setText("查找源码时出错: " + ex.getMessage());
                });
            }
        });
    }

    /** AnalysisContextLookup.lookupSourceCode() prefixes each snippet with
     *  "// File: <path> Line: N" — sniff the extension off that header so
     *  the highlighter matches whatever language the indexed repo actually
     *  is, instead of assuming Java for every repo. Defaults to Java since
     *  that's the common case and a wrong-but-plausible guess beats no
     *  highlighting at all. */
    private static String syntaxStyleForSource(String sourceCode) {
        if (sourceCode == null) return SyntaxConstants.SYNTAX_STYLE_JAVA;
        int idx = sourceCode.indexOf("// File: ");
        if (idx < 0) return SyntaxConstants.SYNTAX_STYLE_JAVA;
        int end = sourceCode.indexOf('\n', idx);
        String header = (end > idx ? sourceCode.substring(idx, end) : sourceCode.substring(idx)).toLowerCase();
        if (header.contains(".py")) return SyntaxConstants.SYNTAX_STYLE_PYTHON;
        if (header.contains(".go")) return SyntaxConstants.SYNTAX_STYLE_GO;
        if (header.contains(".ts")) return SyntaxConstants.SYNTAX_STYLE_TYPESCRIPT;
        if (header.contains(".js")) return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
        if (header.contains(".rb")) return SyntaxConstants.SYNTAX_STYLE_RUBY;
        if (header.contains(".php")) return SyntaxConstants.SYNTAX_STYLE_PHP;
        if (header.contains(".cs")) return SyntaxConstants.SYNTAX_STYLE_CSHARP;
        if (header.contains(".cpp") || header.contains(".cc") || header.contains(".hpp")) return SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS;
        if (header.contains(".c")) return SyntaxConstants.SYNTAX_STYLE_C;
        return SyntaxConstants.SYNTAX_STYLE_JAVA;
    }

    public void onIndexRepo(CodeRepo repo) {
        // Serialized on the shared single-thread indexer pool — two index
        // actions can no longer race each other.
        com.flechazo.apisentinel.util.SharedTaskPool.submitIndexer(() -> {
            try {
                int count = codeIndexService.indexRepo(repo);
                if (view != null) view.getCodeRepoPanel().updateRepoStatus(repo.getName(), count);
            } catch (Exception e) {
                logger.error("索引失败: %s", e.getMessage());
                if (view != null) view.getCodeRepoPanel().setIndexError(e.getMessage());
            }
        });
    }

    public void onIndexAllRepos(List<CodeRepo> repos) {
        com.flechazo.apisentinel.util.SharedTaskPool.submitIndexer(() -> {
            try {
                codeIndexService.indexAll(repos);
                for (CodeRepo repo : repos) {
                    if (view != null) view.getCodeRepoPanel().updateRepoStatus(repo.getName(), repo.getRouteCount());
                }
            } catch (Exception e) {
                logger.error("批量索引失败: %s", e.getMessage());
                if (view != null) view.getCodeRepoPanel().setIndexError(e.getMessage());
            }
        });
    }

    public void onReposChanged(List<CodeRepo> repos) {
        configManager.getConfig().setCodeRepos(repos);
        configManager.saveConfig();
        // The 源码 tab only earns its slot once a code repo exists.
        if (view != null) {
            view.setSourceTabVisible(repos != null && !repos.isEmpty());
        }
    }

    public List<CodeRepo> getCodeRepos() {
        return configManager.getConfig().getCodeRepos();
    }

    // === Checkbox Settings ===

    public void onCheckboxChanged(String key) {
        ToolbarPanel toolbar = view != null ? view.getToolbarPanel() : null;
        if (toolbar == null) return;
        switch (key) {
            case "checkWholeRequest" -> configManager.setCheckWholeRequest(toolbar.isCheckWholeRequest());
            case "sensitiveDetection" -> configManager.setSensitiveDetectionEnabled(toolbar.isSensitiveDetection());
            case "unauthorizedDetection" -> configManager.setUnauthorizedDetectionEnabled(toolbar.isUnauthorizedDetection());
            case "oobEnabled" -> configManager.setOobEnabled(toolbar.isOobEnabled());
            case "wafDetection" -> configManager.setWafDetectionEnabled(toolbar.isWafDetection());
            case "activeProbe" -> configManager.setActiveProbeEnabled(toolbar.isActiveProbe());
            case "businessLogic" -> configManager.setBusinessLogicVerificationEnabled(toolbar.isBusinessLogic());
            case "highlightEnabled" -> configManager.setHighlightEnabled(toolbar.isHighlightEnabled());
            case "organizerAutoSend" -> configManager.setOrganizerAutoSendEnabled(toolbar.isOrganizerAutoSend());
            case "auditHighRiskOnly" -> configManager.setAuditHighRiskOnly(toolbar.isAuditHighRiskOnly());
            case "codeExecAutoApprove" -> configManager.setCodeExecutionAutoApprove(toolbar.isCodeExecAutoApprove());

            case "autoScan" -> {
                configManager.setAutoScanEnabled(toolbar.isAutoScanEnabled());
                onAutoScanToggle(toolbar.isAutoScanEnabled());
            }
            case "cascadeHunt" -> {
                configManager.setCascadeHuntEnabled(toolbar.isCascadeHuntEnabled());
                if (agentController != null) {
                    agentController.setCascadeEnabled(toolbar.isCascadeHuntEnabled());
                }
            }
        }
    }

    private boolean isValidHttpMethod(String method) {
        return switch (method) {
            case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" -> true;
            default -> false;
        };
    }
}
