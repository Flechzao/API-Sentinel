package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.config.SensitiveRule;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.repository.ApiRepository;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * Burp 套件主标签页——组装工具栏、接口表格、详情标签页（分析结果/请求测试/源码）、
 * 设置弹窗、浮动 AI 对话窗口。UI 布局和交互的中枢。
 */
public class ApiSentinelTab extends JPanel {

    private final ToolbarPanel toolbarPanel;
    private final FilterBar filterBar;
    private final DomainFilterCombo domainFilterCombo;
    private final ApiTablePanel tablePanel;
    private final AiAnalysisPanel aiAnalysisPanel;
    private final AiSettingsPanel aiSettingsPanel;
    private final SensitiveRulesPanel sensitiveRulesPanel;
    private final CodeRepoPanel codeRepoPanel;
    private final AuthConfigPanel authConfigPanel;
    private final OobConfigPanel oobConfigPanel;
    private final RepeaterPanel repeaterPanel;
    private final AiChatPanel aiChatPanel;
    private final TaskQueuePanel taskQueuePanel;
    private final PatternPanel patternPanel;
    private final JTabbedPane detailTabs;
    private final JTabbedPane settingsGroup;
    private final RSyntaxTextArea sourceArea;
    private final RTextScrollPane sourceScroll;
    /** 源码 tab is added/removed dynamically — it only earns its slot once a
     *  code repo is configured (presenter.onReposChanged keeps this in sync). */
    private boolean sourceTabVisible;
    private TaskQueueDialog taskQueueDialog;

    private JButton aiBtn;
    private JButton moreBtn;
    private JButton settingsBtn;
    private JDialog settingsDialog;

    /** Floating chat window: the AI conversation no longer occupies a
     *  detailTabs slot — it lives permanently in this top-level frame (opened
     *  from 分析结果's "AI 对话" button, the Repeater AI button, task-queue
     *  selection, or the hotkey). Closing the frame only hides it: analyses
     *  keep running in the background and the conversation is exactly where
     *  it was on the next open. Lazy — created on first showChatWindow(). */
    private JFrame chatFrame;

    private JPopupMenu moreMenu;
    private ApiSentinelPresenter presenterRef;
    private ApiEntryTableModel tableModelRef;
    private final MontoyaApi api;
    private final BurpTheme theme;

    public ApiSentinelTab(MontoyaApi api,
                             ApiEntryTableModel tableModel,
                             ApiSentinelPresenter presenter,
                             LlmProviderFactory providerFactory,
                             List<SensitiveRule> sensitiveRules,
                             ApiRepository repository,
                             AnalysisTaskQueue analysisQueue,
                             LearnedRuleEngine learnedRuleEngine,
                             List<CodeRepo> initialCodeRepos,
                             AppConfig initialConfig,
                             ConfigManager configManager) {
        setLayout(new BorderLayout());
        this.api = api;
        theme = new BurpTheme(api);

        // ====================================================================
        // Create tablePanel early so it's available for search filter binding
        // ====================================================================
        tablePanel = new ApiTablePanel(tableModel, theme);
        this.tableModelRef = tableModel;

        // ====================================================================
        // NORTH: 1 row (the KPI DashboardBar was removed — its stats duplicate
        // the table's filterable view, and its agent/cascade status cards kept
        // misleading: they tracked the auto-mode switch, not the running
        // analysis. Cascade visibility lives on via the Extension's toast +
        // global-chat-note forwarding.)
        // ====================================================================
        JPanel northPanel = new JPanel();
        northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));

        // --- Row 1: Toolbar (match mode + checkboxes) ---
        toolbarPanel = new ToolbarPanel(presenter::onMatchModeChanged, presenter::onCheckboxChanged, initialConfig, theme);

        JPanel row1 = new JPanel();
        row1.setLayout(new BoxLayout(row1, BoxLayout.X_AXIS));
        row1.setOpaque(false);
        row1.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)
        ));
        row1.add(toolbarPanel);
        row1.add(Box.createHorizontalGlue());

        this.presenterRef = presenter;

        JButton importBtn = makeBtn(I18n.get("import_api"), e -> {
            Window window = SwingUtilities.getWindowAncestor(this);
            ImportDialog dialog = new ImportDialog(window, presenter::onImportApis, presenter::scanHistory, new BurpTheme(api));
            dialog.setVisible(true);
        });
        row1.add(importBtn);
        row1.add(Box.createHorizontalStrut(4));

        aiBtn = makeBtn(I18n.get("ai_analyze"), e -> presenter.onFullPipelineAnalyze(getSelectedRows()));
        aiBtn.setFont(aiBtn.getFont().deriveFont(Font.BOLD));
        // Primary action styling: accent text + accent outline — survives any
        // LookAndFeel (filled backgrounds are frequently overridden by Burp's).
        aiBtn.setForeground(theme.accentBg());
        aiBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(theme.accentBg(), 1, true),
                aiBtn.getBorder()));
        toolbarPanel.setOnAiModeChanged(agentMode -> updateAiBtnLabel(agentMode));
        updateAiBtnLabel(toolbarPanel.isAgentMode());
        row1.add(aiBtn);
        row1.add(Box.createHorizontalStrut(4));

        moreBtn = makeBtn(I18n.get("more_actions"), e -> {});
        moreMenu = buildMoreMenu(presenter);
        moreBtn.addActionListener(e -> moreMenu.show(moreBtn, 0, moreBtn.getHeight()));
        row1.add(moreBtn);
        row1.add(Box.createHorizontalStrut(4));

        // Settings used to occupy a bottom detail-tab slot (and a duplicate
        // AI-only panel lived in Burp's Settings dialog). Now a single ⚙ entry
        // point on the toolbar opens the full settings dialog.
        settingsBtn = makeBtn("⚙ " + I18n.get("tab_settings_group"), e -> openSettingsDialog());
        row1.add(settingsBtn);

        northPanel.add(wrapRowForHorizontalOverflow(row1));

        // --- Row 2: Filters + Domain + Search + Import + AI Analyze + [More] ---
        filterBar = new FilterBar(repository, status -> tableModel.setStatusFilter(status), theme);
        filterBar.setOnRiskChanged(risk -> tableModel.setRiskFilter(risk));
        domainFilterCombo = new DomainFilterCombo(repository, domain -> tableModel.setDomainFilter(domain), theme);

        JPanel row2 = new JPanel(new BorderLayout(4, 0));
        row2.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()),
                BorderFactory.createEmptyBorder(2, 0, 2, 6)));

        row2.add(filterBar, BorderLayout.CENTER);

        JPanel row2Right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        row2Right.add(domainFilterCombo);

        // No search-icon label here — it was an emoji (🔍), same rendering-
        // consistency issue already fixed in ImportDialog; the field's own
        // tooltip explains its purpose.
        JTextField searchField = new JTextField(14);
        searchField.setFont(theme.displayFont(Font.PLAIN, 12f));
        searchField.setToolTipText("搜索 API 路径（实时过滤）");

        javax.swing.Timer searchDebounce = new javax.swing.Timer(300, evt -> {
            String text = searchField.getText().trim();
            tablePanel.setSearchFilter(text);
        });
        searchDebounce.setRepeats(false);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { searchDebounce.restart(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { searchDebounce.restart(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { searchDebounce.restart(); }
        });
        // Still support Enter for legacy jump-to behavior
        searchField.addActionListener(e -> {
            String text = searchField.getText().trim();
            if (!text.isEmpty()) presenter.onFindApi(text);
        });
        row2Right.add(searchField);

        row2.add(row2Right, BorderLayout.EAST);
        northPanel.add(wrapRowForHorizontalOverflow(row2));

        add(northPanel, BorderLayout.NORTH);

        // ====================================================================
        // CENTER: API Table + Flat Detail Tabs
        // ====================================================================
        // tablePanel already created above (needed for search filter binding)

        // --- Create all sub-panels ---
        aiAnalysisPanel = new AiAnalysisPanel(api);
        aiAnalysisPanel.setSelectedRowsSupplier(this::getSelectedRows);
        aiAnalysisPanel.setOnAnalyzeAction((rows, mode) -> presenter.onFullPipelineAnalyze(rows, mode));
        // The chat panel lives in a floating window now — 分析结果 hosts the
        // primary entry button that opens it.
        aiAnalysisPanel.setOnOpenChatRequested(this::showChatWindow);

        aiChatPanel = new AiChatPanel(api);
        aiChatPanel.setOnSendMessage((message, apiPath) -> presenter.onChatMessage(message));
        aiChatPanel.setOnCancelAnalysis(presenter::onCancelAnalyses);

        taskQueuePanel = new TaskQueuePanel(analysisQueue, theme);

        repeaterPanel = new RepeaterPanel(api);

        // When a historical analysis record is selected from the dropdown,
        // load its test cases + payload results into the Repeater.
        aiAnalysisPanel.setOnHistoryRecordSelected(record -> {
            int viewRow = tablePanel.getTable().getSelectedRow();
            int modelRow = viewRow >= 0 ? tablePanel.getTable().convertRowIndexToModel(viewRow) : -1;
            com.flechazo.apisentinel.model.ApiEntry entry = modelRow >= 0 ? tableModel.getEntryAt(modelRow) : null;
            if (entry != null) {
                var payloadResults = record.hasPipelineResult() ? record.pipelineResult().payloadResults() : null;
                repeaterPanel.showHistoricalRecord(entry.getApiPath(), entry.getDomain(), entry.getLastUrl(),
                        record.testCases(), payloadResults);
            }
        });

        // Persist after an analysis record is deleted from an entry's history,
        // and drop that endpoint's chat conversation with it — a deleted
        // analysis whose step-by-step chat log survives reads as "delete is
        // broken".
        aiAnalysisPanel.setOnAnalysisDeleted(() -> {
            tableModel.markRepositoryDirty();
            String path = aiAnalysisPanel.getCurrentApiPath();
            if (path == null) return;
            aiChatPanel.clearHistoryForPath(path);
            // The deleted run's test cases also sit in the Repeater — both as
            // visible rows and in the per-entry cache that would resurrect
            // them on the next visit. Drop the cache always; if that entry is
            // on screen, refresh it to the latest remaining record (or leave
            // it reset-to-empty when none remains).
            repeaterPanel.forgetForPath(path);
            if (repeaterPanel.isShowingEntry(path)) {
                repository.findByPath(path).ifPresent(entry -> {
                    var latest = entry.getLatestAnalysisRecord();
                    if (latest != null) {
                        repeaterPanel.showHistoricalRecord(path, entry.getDomain(), entry.getLastUrl(),
                                latest.testCases(),
                                latest.hasPipelineResult() ? latest.pipelineResult().payloadResults() : null);
                    }
                });
            }
        });

        aiSettingsPanel = new AiSettingsPanel(providerFactory, presenter::onProviderChanged,
                presenter::onContextWindowChanged, theme);
        aiSettingsPanel.setContextWindowTokens(configManager.getConfig().getContextWindowTokens());

        sensitiveRulesPanel = new SensitiveRulesPanel(sensitiveRules, configManager::reloadSensitiveRules, theme);
        if (learnedRuleEngine != null) {
            sensitiveRulesPanel.setLearnedRuleEngine(learnedRuleEngine);
            aiAnalysisPanel.setLearnedRuleEngine(learnedRuleEngine);
        }

        codeRepoPanel = new CodeRepoPanel(
                initialCodeRepos != null ? new java.util.ArrayList<>(initialCodeRepos) : new java.util.ArrayList<>(),
                presenter::onIndexRepo,
                presenter::onIndexAllRepos,
                presenter::onReposChanged,
                theme);

        authConfigPanel = new AuthConfigPanel(configManager, theme, api);
        oobConfigPanel = new OobConfigPanel(configManager,
                new com.flechazo.apisentinel.detection.OobService(api, configManager.getConfig(), null), theme);

        // --- Build flat tabs: [分析结果 | 请求测试 | 源码?] — the AI
        //     conversation lives in its own floating window (showChatWindow),
        //     settings moved to the toolbar ⚙ dialog. The 源码 tab only exists
        //     once a code repo is configured (setSourceTabVisible) — before
        //     that it would be a permanently dead placeholder. ---
        detailTabs = new JTabbedPane();

        detailTabs.addTab(I18n.get("tab_ai_result"), aiAnalysisPanel);
        detailTabs.addTab(I18n.get("tab_repeater"), repeaterPanel);

        sourceArea = new RSyntaxTextArea();
        sourceArea.setText("选中 API 后自动展示关联源码（需先在「代码仓库」中索引仓库）");
        sourceArea.setEditable(false);
        sourceArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVA);
        sourceArea.setCodeFoldingEnabled(true);
        sourceArea.setAntiAliasingEnabled(true);
        sourceArea.setFont(theme.editorFont(12f));
        sourceArea.setLineWrap(false);
        sourceScroll = new RTextScrollPane(sourceArea);
        sourceScroll.setLineNumbersEnabled(true);
        sourceScroll.setBorder(BorderFactory.createEmptyBorder());
        sourceTabVisible = initialCodeRepos != null && !initialCodeRepos.isEmpty();
        if (sourceTabVisible) {
            detailTabs.addTab(I18n.get("tab_source"), sourceScroll);
        }

        // Settings live in the toolbar ⚙ dialog (openSettingsDialog) — built
        // here as a self-contained tabbed group, deliberately NOT added to
        // detailTabs.
        settingsGroup = new JTabbedPane();
        settingsGroup.addTab(I18n.get("tab_settings"), aiSettingsPanel);
        settingsGroup.addTab(I18n.get("tab_rules"), sensitiveRulesPanel);
        settingsGroup.addTab(I18n.get("tab_repo"), codeRepoPanel);
        settingsGroup.addTab(I18n.get("tab_auth_config"), authConfigPanel);
        settingsGroup.addTab(I18n.get("tab_oob"), oobConfigPanel);

        patternPanel = new PatternPanel(theme);
        settingsGroup.addTab(I18n.get("tab_patterns"), patternPanel);

        // Task Queue row selection -> load Chat & Repeater, switch to Chat tab
        taskQueuePanel.setOnTaskSelected(record -> {
            repository.findByPath(record.getApiPath()).ifPresent(entry -> {
                aiChatPanel.setContext(entry);
                if (entry.hasTrafficData()) {
                    repeaterPanel.loadFromEntry(entry);
                }
                var latestRecord = entry.getLatestAnalysisRecord();
                var persistedTestCases = latestRecord != null ? latestRecord.testCases() : null;
                var persistedPayloadResults = (latestRecord != null && latestRecord.hasPipelineResult())
                        ? latestRecord.pipelineResult().payloadResults() : null;
                repeaterPanel.showEntry(entry.getApiPath(), entry.getDomain(), entry.getLastUrl(),
                        persistedTestCases, persistedPayloadResults, null);
                showChatWindow();
            });
        });

        // --- Split pane: table (top) + detail tabs (bottom) ---
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, detailTabs);
        mainSplit.setDividerLocation(initialConfig.getMainSplitLocation());
        // 0.0 means the bottom component (detailTabs — where Repeater/Request-
        // Response lives) absorbs all extra space on window resize, while the
        // top table keeps whatever height the user last set. With the old 0.5
        // weight, every window resize redistributed space 50/50 and grew the
        // table back up, undoing a manually-shrunk divider and forcing the
        // user to drag it small again on every resize.
        mainSplit.setResizeWeight(0.0);
        add(mainSplit, BorderLayout.CENTER);

        // Persist split pane positions with debounce
        javax.swing.Timer mainSplitTimer = new javax.swing.Timer(500, e -> {
            configManager.getConfig().setMainSplitLocation(mainSplit.getDividerLocation());
            configManager.saveConfig();
        });
        mainSplitTimer.setRepeats(false);
        mainSplit.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, e -> mainSplitTimer.restart());


    }

    private JPopupMenu buildMoreMenu(ApiSentinelPresenter presenter) {
        JPopupMenu menu = new JPopupMenu();

        menu.add(makeMenuItem(I18n.get("remove"), e -> presenter.onRemoveSelected(getSelectedRows())));
        menu.addSeparator();
        menu.add(makeMenuItem(I18n.get("toggle_status"), e -> presenter.onToggleStatus(getSelectedRows())));
        menu.add(makeMenuItem(I18n.get("toggle_vuln"), e -> presenter.onToggleVulnType(getSelectedRows())));
        menu.add(makeMenuItem(I18n.get("move_top"), e -> presenter.onMoveTestedToTop()));
        menu.add(makeMenuItem(I18n.get("add_scope"), e -> presenter.onAddDomainsToScope(getSelectedRows())));
        menu.addSeparator();
        menu.add(makeMenuItem(I18n.get("csv"), e -> presenter.onExportCsv()));
        menu.add(makeMenuItem(I18n.get("report"), e -> presenter.onExportMarkdown()));

        JMenuItem fullReport = makeMenuItem(I18n.get("full_report"), e -> presenter.onExportFullReport());
        fullReport.setFont(theme.displayFont(Font.BOLD, 12f));
        menu.add(fullReport);

        menu.addSeparator();
        menu.add(makeMenuItem(I18n.get("tab_task_center"), e -> {
            if (taskQueueDialog == null) {
                Window window = SwingUtilities.getWindowAncestor(this);
                taskQueueDialog = new TaskQueueDialog(window, taskQueuePanel);
            }
            taskQueueDialog.setVisible(true);
        }));
        menu.addSeparator();

        // Bambda code generation from selected table rows
        JMenuItem bambdaMenuItem = makeMenuItem("生成 Bambda 过滤代码", e -> {
            int[] rows = getSelectedRows();
            if (rows.length == 0) return;
            java.util.List<com.flechazo.apisentinel.model.ApiEntry> entries = new java.util.ArrayList<>();
            for (int row : rows) {
                var entry = ((com.flechazo.apisentinel.model.ApiEntryTableModel) tablePanel.getTable().getModel()).getEntryAt(row);
                if (entry != null) entries.add(entry);
            }
            if (entries.isEmpty()) return;
            String code = entries.size() == 1
                    ? com.flechazo.apisentinel.util.BambdaCodeGen.generate(entries.get(0))
                    : com.flechazo.apisentinel.util.BambdaCodeGen.generateBatch(entries);
            java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(code);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
            ThemedDialogs.info(this,
                    "已复制 Bambda 过滤代码到剪贴板（" + entries.size() + " 个 API）",
                    "Bambda");
        });
        menu.add(bambdaMenuItem);

        menu.addSeparator();
        // One-shot forensics for calibrating the palette against the user's
        // real Burp theme — run once per theme (dark/light), share the file.
        menu.add(makeMenuItem("主题诊断（导出配色信息）", e -> {
            try {
                java.nio.file.Path out = ThemeDiagnostics.dump(api);
                ThemedDialogs.info(this, "主题诊断信息已导出到:\n" + out
                        + "\n\n深色/亮色主题各导出一份即可。", "主题诊断");
            } catch (Exception ex) {
                ThemedDialogs.error(this, "导出失败: " + ex.getMessage(), "主题诊断");
            }
        }));
        menu.addSeparator();
        menu.add(makeMenuItem(I18n.get("lang_switch"), e -> {
            I18n.toggle();
            refreshI18nTexts();
        }));

        return menu;
    }

    private void updateAiBtnLabel(boolean agentMode) {
        aiBtn.setText(I18n.get("ai_analyze") + " (" + (agentMode ? "Agent" : "Pipeline") + ")");
    }

    /**
     * Refresh all I18n-bound text after locale change.
     */
    private void refreshI18nTexts() {
        // Main tabs: [分析结果, 请求测试, 源码?] — settings live in the ⚙ dialog.
        detailTabs.setTitleAt(0, I18n.get("tab_ai_result"));
        detailTabs.setTitleAt(1, I18n.get("tab_repeater"));
        if (sourceTabVisible) {
            detailTabs.setTitleAt(detailTabs.indexOfComponent(sourceScroll), I18n.get("tab_source"));
        }
        settingsBtn.setText("⚙ " + I18n.get("tab_settings_group"));
        if (settingsDialog != null) {
            settingsDialog.setTitle("API Sentinel — " + I18n.get("tab_settings_group"));
        }

        // Settings sub-tabs: [AI设置, 检测规则, 代码仓库, 越权配置, OOB, 成功模式]
        settingsGroup.setTitleAt(0, I18n.get("tab_settings"));
        settingsGroup.setTitleAt(1, I18n.get("tab_rules"));
        settingsGroup.setTitleAt(2, I18n.get("tab_repo"));
        settingsGroup.setTitleAt(3, I18n.get("tab_auth_config"));
        settingsGroup.setTitleAt(4, I18n.get("tab_oob"));
        settingsGroup.setTitleAt(5, I18n.get("tab_patterns"));

        // Row2 buttons
        updateAiBtnLabel(toolbarPanel.isAgentMode());
        moreBtn.setText(I18n.get("more_actions"));

        // Rebuild More menu (items created at build time with I18n.get)
        moreMenu = buildMoreMenu(presenterRef);

        // Toolbar checkboxes & group labels
        toolbarPanel.refreshI18n();
        patternPanel.refreshI18n();



        // Table column headers — getColumnName() resolves dynamically, just repaint header
        if (tableModelRef != null) tableModelRef.refreshI18n();
        if (tablePanel.getTable().getTableHeader() != null) {
            tablePanel.getTable().getTableHeader().repaint();
        }

        revalidate();
        repaint();
    }



    /**
     * Wraps a control row in a horizontal-only JScrollPane so a narrow
     * window makes it scrollable instead of silently clipping controls —
     * the toolbar row and the filters row both use BoxLayout/FlowLayout,
     * neither of which wraps to a second line, so anything that doesn't fit
     * was simply invisible before.
     * This doesn't change sizing/positioning for anyone whose window is wide
     * enough to show everything already — the scrollbar only appears when
     * the row's own preferred width exceeds the available space.
     */
    private JScrollPane wrapRowForHorizontalOverflow(JPanel row) {
        JScrollPane scroll = new JScrollPane(row,
                JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getHorizontalScrollBar().setPreferredSize(new Dimension(0, 8));
        // No explicit setPreferredSize here — leaving it to JScrollPane's
        // default (which tracks the view's own current preferred size)
        // avoids freezing a height snapshot taken before theme.apply(this)
        // runs at the end of this constructor, which can still change fonts.
        return scroll;
    }

    private JButton makeBtn(String text, java.awt.event.ActionListener action) {
        JButton btn = new JButton(text);
        btn.setFont(theme.displayFont(Font.PLAIN, 12f));
        btn.setMargin(new Insets(3, 8, 3, 8));
        btn.addActionListener(action);
        return btn;
    }

    private JMenuItem makeMenuItem(String text, java.awt.event.ActionListener action) {
        JMenuItem item = new JMenuItem(text);
        item.setFont(theme.displayFont(Font.PLAIN, 12f));
        item.addActionListener(action);
        return item;
    }

    private static JSeparator createVerticalSep() {
        JSeparator sep = new JSeparator(SwingConstants.VERTICAL);
        sep.setPreferredSize(new Dimension(1, 20));
        sep.setMaximumSize(new Dimension(1, 20));
        return sep;
    }

    // === Public getters (all existing references preserved) ===

    public int[] getSelectedRows() { return tablePanel.getSelectedRows(); }
    public ApiTablePanel getTablePanel() { return tablePanel; }
    public ToolbarPanel getToolbarPanel() { return toolbarPanel; }
    public FilterBar getFilterBar() { return filterBar; }
    public DomainFilterCombo getDomainFilterCombo() { return domainFilterCombo; }
    public AiAnalysisPanel getAiAnalysisPanel() { return aiAnalysisPanel; }
    public AiSettingsPanel getAiSettingsPanel() { return aiSettingsPanel; }
    public SensitiveRulesPanel getSensitiveRulesPanel() { return sensitiveRulesPanel; }
    public CodeRepoPanel getCodeRepoPanel() { return codeRepoPanel; }
    public AuthConfigPanel getAuthConfigPanel() { return authConfigPanel; }
    public RepeaterPanel getRepeaterPanel() { return repeaterPanel; }
    public AiChatPanel getAiChatPanel() { return aiChatPanel; }
    public TaskQueuePanel getTaskQueuePanel() { return taskQueuePanel; }
    public PatternPanel getPatternPanel() { return patternPanel; }
    public JTabbedPane getDetailTabs() { return detailTabs; }
    public RSyntaxTextArea getSourceArea() { return sourceArea; }
    public void selectAndScrollTo(int row) { tablePanel.selectAndScrollTo(row); }
    public void clearSelection() { tablePanel.clearSelection(); }

    /** Open (or bring forward) the floating AI-conversation window. Created
     *  once, the panel lives in this frame for the whole session — closing
     *  the frame merely hides it, so analyses keep streaming into the
     *  conversation in the background and nothing is lost. */
    public void showChatWindow() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::showChatWindow);
            return;
        }
        if (chatFrame == null) {
            chatFrame = new JFrame("API Sentinel — AI 对话");
            // A bare JFrame isn't covered by the suite-tab theming pass — the
            // floating window's decorations/input areas fell back to default
            // Swing styling. Apply Burp's theme to the frame explicitly.
            api.userInterface().applyThemeToComponent(chatFrame);
            // Same component instance for the whole session — every external
            // reference (facades, controllers, interaction bridge) keeps
            // working unchanged.
            chatFrame.setContentPane(aiChatPanel);
            chatFrame.setSize(1000, 680);
            chatFrame.setMinimumSize(new Dimension(480, 360));
            chatFrame.setLocationRelativeTo(SwingUtilities.getWindowAncestor(this));
            // Hide, don't dispose: closing the window keeps the analysis
            // running in the background — the user just stops watching it.
            chatFrame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
            chatFrame.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override public void windowClosing(java.awt.event.WindowEvent e) {
                    chatFrame.setVisible(false);
                }
            });
        }
        // Adopt the table selection when the chat has no context yet: opening
        // the window while a row is selected must not show "未选择接口".
        // (A context the user deliberately switched to is never overridden.)
        if (aiChatPanel.getCurrentApiPath() == null) {
            int viewRow = tablePanel.getTable().getSelectedRow();
            int modelRow = viewRow >= 0 ? tablePanel.getTable().convertRowIndexToModel(viewRow) : -1;
            com.flechazo.apisentinel.model.ApiEntry entry =
                    (modelRow >= 0 && tableModelRef != null) ? tableModelRef.getEntryAt(modelRow) : null;
            if (entry != null) {
                aiChatPanel.setContext(entry);
            }
        }
        chatFrame.setVisible(true);
        chatFrame.toFront();
    }

    /** Legacy alias — the chat "tab" is now the floating window. */
    public void switchToChat() {
        showChatWindow();
    }

    /** Switch to Repeater tab. */
    public void switchToRepeater() {
        detailTabs.setSelectedIndex(1);
    }

    /** Switch to 分析结果 tab. */
    public void switchToAnalysisResult() {
        detailTabs.setSelectedIndex(0);
    }

    /** Show/hide the 源码 tab — only earns its slot once a code repo is
     *  configured (called from presenter.onReposChanged and at startup). */
    public void setSourceTabVisible(boolean visible) {
        if (visible == sourceTabVisible) return;
        sourceTabVisible = visible;
        if (visible) {
            detailTabs.addTab(I18n.get("tab_source"), sourceScroll);
        } else {
            int idx = detailTabs.indexOfComponent(sourceScroll);
            if (idx >= 0) detailTabs.removeTabAt(idx);
        }
    }

    /** Settings dialog — hosts the full settings tab group that used to
     *  occupy a bottom detail-tab slot. Created once, hidden (not disposed)
     *  on close so edited state and component parents stay intact. */
    private void openSettingsDialog() {
        if (settingsDialog == null) {
            Window owner = SwingUtilities.getWindowAncestor(this);
            settingsDialog = new JDialog(owner,
                    "API Sentinel — " + I18n.get("tab_settings_group"),
                    java.awt.Dialog.ModalityType.MODELESS);
            settingsDialog.setContentPane(settingsGroup);
            settingsDialog.setSize(920, 640);
            settingsDialog.setMinimumSize(new Dimension(720, 480));
            settingsDialog.setLocationRelativeTo(owner);
            settingsDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
            new BurpTheme(api).apply(settingsDialog);
        }
        settingsDialog.setVisible(true);
        settingsDialog.toFront();
    }

    public void shutdown() {
        Runnable[] steps = {
                // Dispose the floating chat window first — Burp unloads the
                // extension's ClassLoader, and a lingering native frame would
                // keep it (and the panel inside) from being collected.
                () -> { if (chatFrame != null) { chatFrame.setVisible(false); chatFrame.dispose(); chatFrame = null; } },
                () -> { if (settingsDialog != null) { settingsDialog.setVisible(false); settingsDialog.dispose(); settingsDialog = null; } },
                () -> { if (taskQueuePanel != null) taskQueuePanel.shutdown(); },
                () -> { if (aiChatPanel != null) aiChatPanel.shutdown(); },
                () -> { if (presenterRef != null) presenterRef.shutdown(); }
        };
        for (Runnable s : steps) {
            try { s.run(); }
            catch (Exception ignored) {}
        }
    }
}
