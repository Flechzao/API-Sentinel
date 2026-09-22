package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.queue.AnalysisTask.AnalysisMode;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * 分析结果面板——展示 verdict / findings / 测试用例 / Payload 验证 / 历史记录，
 * 含进度条、Agent 步骤视图联动、报告按钮。
 */
public class AiAnalysisPanel extends JPanel
        implements com.flechazo.apisentinel.ai.agent.tool.FindingUpdater {

    private final BurpTheme theme;

    private final JLabel statusLabel;
    private final JLabel riskLabel;
    private final JLabel modelLabel;
    private final JLabel tokensLabel;
    // Removed: the top "分析结论" strip was a third, truncated copy of the
    // verdict summary already rendered in full by the 卡片视图 SummaryCard and
    // the 详情 pane. Kept as a field so setSummary() (many call sites) stays
    // a harmless no-op.
    private JLabel summaryLabel;
    private final JTable findingsTable;
    private final DefaultTableModel findingsModel;
    private final JTextArea detailArea;
    private final TimelinePanel timelinePanel;
    private final VerdictCardsPanel verdictCardsPanel;
    private final JTabbedPane bottomTabs;
    private List<VulnFinding> currentFindings = List.of();
    /** Non-null while showing a Pipeline/Agent FinalVerdict; null while
     *  showing the simple-analysis mode's VulnFindings — the findings table
     *  selection listener uses this to decide which of the two to read. */
    private FinalVerdict currentVerdict;
    private List<com.flechazo.apisentinel.ai.pipeline.PayloadResult> currentPayloadResults = List.of();
    /** The entry currently displayed — used by the replay dialog to resolve
     *  the target host/scheme for re-sending requests. */
    private ApiEntry currentEntry;

    private final JButton startAnalyzeBtn;
    private final RoundedProgressBar progressBar;

    private final JButton viewReportBtn;
    private final JButton viewJsonBtn;
    private java.nio.file.Path currentReportPath;
    private java.nio.file.Path currentJsonReportPath;
    private volatile boolean agentRunning = false;
    private JComboBox<String> historyCombo;
    private JButton openChatBtn;
    private JButton deleteAnalysisBtn;
    private List<AnalysisRecord> currentHistory = List.of();
    private AnalysisRecord currentDisplayedRecord;
    private java.util.function.Consumer<com.flechazo.apisentinel.model.AnalysisRecord> onHistoryRecordSelected;
    private Runnable onAnalysisDeleted;
    /** Opens the floating AI-conversation window (primary entry button lives
     *  in this panel now that the chat tab is gone). */
    private Runnable onOpenChatRequested;

    private BiConsumer<int[], AnalysisMode> onAnalyzeAction;
    private java.util.function.Supplier<int[]> selectedRowsSupplier;
    private com.flechazo.apisentinel.ai.rules.LearnedRuleEngine learnedRuleEngine;
    private String currentApiPath;
    private final MontoyaApi api;

    public AiAnalysisPanel(MontoyaApi api) {
        this.api = api;
        this.theme = new BurpTheme(api);

        setLayout(new BorderLayout(0, 4));

        // === TOP: Mode selector panel ===
        JPanel modePanel = new JPanel();
        modePanel.setLayout(new BoxLayout(modePanel, BoxLayout.Y_AXIS));
        modePanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));

        JPanel radioRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        startAnalyzeBtn = new JButton(I18n.get("ai_analysis_start"));
        startAnalyzeBtn.setFont(theme.displayFont(Font.BOLD, 13f));
        startAnalyzeBtn.setFocusPainted(false);
        startAnalyzeBtn.addActionListener(e -> triggerAnalysis());
        radioRow.add(startAnalyzeBtn);

        historyCombo = new JComboBox<>(new String[]{I18n.get("ai_analysis_history_placeholder")});
        historyCombo.setFont(theme.displayFont(Font.PLAIN, 11f));
        historyCombo.setToolTipText(I18n.get("ai_analysis_history_tooltip"));
        historyCombo.addActionListener(e -> {
            int idx = historyCombo.getSelectedIndex();
            if (idx > 0 && idx - 1 < currentHistory.size()) {
                AnalysisRecord rec = currentHistory.get(idx - 1);
                showAnalysisRecord(rec);
                // Notify Repeater to load this record's test cases + payload results
                if (onHistoryRecordSelected != null) onHistoryRecordSelected.accept(rec);
            }
        });
        radioRow.add(historyCombo);

        deleteAnalysisBtn = new JButton(I18n.get("ai_analysis_delete"));
        deleteAnalysisBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        deleteAnalysisBtn.setFocusPainted(false);
        deleteAnalysisBtn.setToolTipText(I18n.get("ai_analysis_delete_tooltip"));
        deleteAnalysisBtn.addActionListener(e -> deleteCurrentAnalysis());
        radioRow.add(deleteAnalysisBtn);

        // The AI conversation lives in a floating window now (no detailTabs
        // slot) — this panel is its primary entry point.
        openChatBtn = new JButton(I18n.get("ai_analysis_chat"));
        openChatBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        openChatBtn.setFocusPainted(false);
        openChatBtn.setToolTipText(I18n.get("ai_analysis_open_chat_tooltip"));
        openChatBtn.addActionListener(e -> {
            if (onOpenChatRequested != null) onOpenChatRequested.run();
        });
        radioRow.add(openChatBtn);

        modePanel.add(radioRow);

        // Status + progress row
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        statusRow.add(new JLabel(I18n.get("ai_analysis_status_label")));
        statusLabel = new JLabel(I18n.get("ai_analysis_waiting"));
        statusLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        statusRow.add(statusLabel);

        statusRow.add(Box.createHorizontalStrut(15));
        statusRow.add(new JLabel(I18n.get("ai_analysis_risk_label")));
        riskLabel = new JLabel("--");
        riskLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        statusRow.add(riskLabel);

        statusRow.add(Box.createHorizontalStrut(15));
        modelLabel = new JLabel(I18n.get("ai_model_default"));
        modelLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        statusRow.add(modelLabel);
        tokensLabel = new JLabel(I18n.get("ai_tokens_zero"));
        tokensLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        statusRow.add(tokensLabel);

        statusRow.add(Box.createHorizontalStrut(15));
        progressBar = new RoundedProgressBar(0, 6);
        progressBar.setFillColor(theme.accentBg());
        progressBar.setStringPainted(true);
        // Wider than the original 160px so the progress-bar quips
        // (ProgressQuips) have room to breathe; the full line also goes into
        // the tooltip for anything that still clips. 300px ≈ 24 CJK chars.
        progressBar.setPreferredSize(new Dimension(300, 16));
        progressBar.setVisible(false);
        statusRow.add(progressBar);

        statusRow.add(Box.createHorizontalStrut(10));
        viewReportBtn = new JButton(I18n.get("ai_analysis_view_report"));
        viewReportBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        viewReportBtn.setFocusPainted(false);
        viewReportBtn.setVisible(false);
        viewReportBtn.addActionListener(e -> openReport());
        statusRow.add(viewReportBtn);

        viewJsonBtn = new JButton(I18n.get("ai_analysis_view_json"));
        viewJsonBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        viewJsonBtn.setFocusPainted(false);
        viewJsonBtn.setVisible(false);
        viewJsonBtn.setToolTipText(I18n.get("ai_analysis_view_json_tooltip"));
        viewJsonBtn.addActionListener(e -> openJsonReport());
        statusRow.add(viewJsonBtn);
        statusRow.add(Box.createHorizontalStrut(6));

        statusRow.add(Box.createHorizontalStrut(10));
        JCheckBox showLowRiskCb = new JCheckBox(I18n.get("ai_analysis_show_low_risk"), false);
        showLowRiskCb.setFont(theme.displayFont(Font.PLAIN, 11f));
        showLowRiskCb.addActionListener(e -> applyRiskFilter(!showLowRiskCb.isSelected()));
        statusRow.add(showLowRiskCb);

        modePanel.add(statusRow);

        // No separate "Pipeline/Agent 执行进度" text log here anymore — it
        // duplicated the same tool-call/stage events already shown, better
        // formatted (collapsible, icons), in 任务中心 → AI对话, and the log's
        // own box was too short (100px) to read more than a couple of lines
        // at a time anyway. The progress bar above (in statusRow) still gives
        // an at-a-glance sense of where a run is; the detailed step-by-step
        // record lives in AI对话 where there's actually room for it.
        add(modePanel, BorderLayout.NORTH);

        // === CENTER: Findings table + detail ===
        findingsModel = new DefaultTableModel(new String[]{I18n.get("ai_analysis_col_type"), I18n.get("ai_analysis_col_risk"), I18n.get("ai_analysis_col_confidence"), I18n.get("ai_analysis_col_title"), I18n.get("ai_analysis_col_location")}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        findingsTable = new JTable(findingsModel);
        findingsTable.setRowHeight(24);
        TableRowSorter<DefaultTableModel> rowSorter = new TableRowSorter<>(findingsModel);
        findingsTable.setRowSorter(rowSorter);
        applyRiskFilter(true);
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(130);
        findingsTable.getColumnModel().getColumn(0).setMinWidth(100);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(80);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        findingsTable.getColumnModel().getColumn(2).setMaxWidth(70);

        findingsTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setHorizontalAlignment(CENTER);
                if (!s && v != null) {
                    setForeground(theme.riskColor(v.toString()));
                }
                return this;
            }
        });

        // Pipeline/Agent verdicts (currentVerdict != null) and the simple-
        // analysis mode's VulnFindings (currentFindings) are two different
        // shapes of "findings" that share this one table — route by whichever
        // is currently populated. Previously this only ever checked
        // currentFindings, which showFinalVerdict() always clears to
        // List.of(), so clicking a Pipeline/Agent finding row silently did
        // nothing (detailArea kept showing the one-shot full-verdict dump
        // from showFinalVerdict instead of that row's own payload/evidence).
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row < 0) return;
            if (currentVerdict != null) {
                showVerdictFindingDetail(row);
            } else if (row < currentFindings.size()) {
                showDetail(currentFindings.get(row));
            }
        });

        javax.swing.JPopupMenu fpMenu = new javax.swing.JPopupMenu();
        fpMenu.add(new javax.swing.AbstractAction(I18n.get("ai_analysis_evidence_compare")) {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) {
                openEvidenceCompareForSelectedRow();
            }
        });
        fpMenu.add(new javax.swing.AbstractAction(I18n.get("ai_analysis_replay_verify")) {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) {
                openReplayDialog();
            }
        });
        fpMenu.addSeparator();
        fpMenu.add(new javax.swing.AbstractAction(I18n.get("ai_analysis_mark_fp")) {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) {
                markSelectedFindingFalsePositive();
            }
        });
        findingsTable.setComponentPopupMenu(fpMenu);

        findingsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) openReplayDialog();
            }
        });

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(theme.editorFont(12f));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        timelinePanel = new TimelinePanel(api);
        verdictCardsPanel = new VerdictCardsPanel(theme);

        bottomTabs = new JTabbedPane();
        bottomTabs.setFont(theme.displayFont(Font.PLAIN, 11f));
        bottomTabs.addTab(I18n.get("ai_analysis_tab_results"), verdictCardsPanel);
        bottomTabs.addTab(I18n.get("ai_analysis_tab_timeline"), timelinePanel);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(findingsTable), bottomTabs);
        centerSplit.setDividerLocation(160);
        centerSplit.setResizeWeight(0.35);
        add(centerSplit, BorderLayout.CENTER);

        // Apply Burp theme
        theme.apply(this);

        // Auto-refresh on language toggle
        I18n.addLangListener(lang -> javax.swing.SwingUtilities.invokeLater(() -> {
            startAnalyzeBtn.setText(I18n.get("ai_analysis_start"));
            deleteAnalysisBtn.setText(I18n.get("ai_analysis_delete"));
            deleteAnalysisBtn.setToolTipText(I18n.get("ai_analysis_delete_tooltip"));
            viewReportBtn.setText(I18n.get("ai_analysis_view_report"));
            viewJsonBtn.setText(I18n.get("ai_analysis_view_json"));
            viewJsonBtn.setToolTipText(I18n.get("ai_analysis_view_json_tooltip"));
            bottomTabs.setTitleAt(0, I18n.get("ai_analysis_tab_results"));
            bottomTabs.setTitleAt(1, I18n.get("ai_analysis_tab_timeline"));
            findingsModel.setColumnIdentifiers(new Object[]{
                I18n.get("ai_analysis_col_type"), I18n.get("ai_analysis_col_risk"),
                I18n.get("ai_analysis_col_confidence"), I18n.get("ai_analysis_col_title"),
                I18n.get("ai_analysis_col_location")});
            findingsTable.getColumnModel().getColumn(4).setHeaderValue(I18n.get("ai_analysis_col_location"));
            statusLabel.setText(I18n.get("ai_analysis_waiting"));
            // History dropdown + chat button
            if (historyCombo.getItemCount() > 0) {
                historyCombo.removeItemAt(0);
                historyCombo.insertItemAt(I18n.get("ai_analysis_history_placeholder"), 0);
                historyCombo.setSelectedIndex(0);
            }
            historyCombo.setToolTipText(I18n.get("ai_analysis_history_tooltip"));
            if (openChatBtn != null) {
                openChatBtn.setText(I18n.get("ai_analysis_chat"));
                openChatBtn.setToolTipText(I18n.get("ai_analysis_open_chat_tooltip"));
            }
        }));
    }

    public void setOnAnalyzeAction(BiConsumer<int[], AnalysisMode> action) { this.onAnalyzeAction = action; }
    public void setSelectedRowsSupplier(java.util.function.Supplier<int[]> supplier) { this.selectedRowsSupplier = supplier; }
    public void setLearnedRuleEngine(com.flechazo.apisentinel.ai.rules.LearnedRuleEngine e) { this.learnedRuleEngine = e; }

    /** Called when the user picks a historical analysis record from the dropdown
     *  — lets the Repeater panel load that record's test cases + payload results. */
    public void setOnHistoryRecordSelected(java.util.function.Consumer<com.flechazo.apisentinel.model.AnalysisRecord> cb) {
        this.onHistoryRecordSelected = cb;
    }
    public AnalysisMode getSelectedMode() { return AnalysisMode.COMPREHENSIVE; }

    private void triggerAnalysis() {
        if (onAnalyzeAction != null && selectedRowsSupplier != null) {
            onAnalyzeAction.accept(selectedRowsSupplier.get(), getSelectedMode());
        }
    }

    // ======================== Public accessors ========================

    /** Returns the timeline panel so PipelineFacade / AgentFacade can push events. */
    public TimelinePanel getTimelinePanel() {
        return timelinePanel;
    }

    private void applyRiskFilter(boolean hideLow) {
        @SuppressWarnings("unchecked")
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) findingsTable.getRowSorter();
        if (sorter == null) return;
        if (hideLow) {
            sorter.setRowFilter(javax.swing.RowFilter.notFilter(
                    javax.swing.RowFilter.regexFilter("^(LOW|INFO)$", 1)));
        } else {
            sorter.setRowFilter(null);
        }
    }

    // ======================== Pipeline Progress ========================

    public void setPipelineProgress(int stage, String message, boolean isComplete) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setVisible(true);
            progressBar.setIndeterminate(false);
            progressBar.setValue(isComplete ? stage : Math.max(0, stage - 1));
            progressBar.setString(ProgressQuips.stageQuip(stage));
            progressBar.setToolTipText(I18n.get("ai_analysis_stage_prefix") + stage + "/6"
                    + (message != null && !message.isBlank() ? " — " + message : ""));
            progressBar.setStringPainted(true);
        });
    }

    private int agentToolCallCount = 0;

    public void setAgentProgress(int iteration, int maxIterations, String toolName, String message, boolean isComplete) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setVisible(true);
            if (isComplete && toolName != null && !toolName.isEmpty()) {
                agentToolCallCount++;
            }
            progressBar.setIndeterminate(true);
            String quip = ProgressQuips.quipFor(toolName, agentToolCallCount);
            String display;
            if (quip != null && !quip.isEmpty()) {
                // Keep the bar to just the quip so it fits; the tool-call
                // count + tool name move to the tooltip below (a long quip +
                // " · N 次" overflowed the bar and clipped mid-sentence).
                display = fitToBar(quip);
            } else {
                display = I18n.get("ai_analysis_agent_running");
                if (agentToolCallCount > 0) {
                    display += " — " + agentToolCallCount + I18n.get("ai_analysis_tool_calls_suffix");
                }
                if (toolName != null && !toolName.isEmpty()) {
                    display += " | " + toolName;
                }
            }
            progressBar.setString(display);
            progressBar.setStringPainted(true);
            // Tooltip carries the full, un-clipped line plus the raw tool name
            // and the running tool-call count.
            progressBar.setToolTipText(I18n.get("ai_analysis_agent_tooltip_prefix") + agentToolCallCount + I18n.get("ai_analysis_tool_calls_suffix")
                    + (toolName != null && !toolName.isEmpty() ? I18n.get("ai_analysis_current_tool") + toolName : "")
                    + (quip != null && !quip.isEmpty() ? " · " + quip : ""));
        });
    }

    /** Trim a quip to roughly what the (widened) bar can render so it never
     *  clips mid-sentence; the full text stays in the tooltip. */
    private static String fitToBar(String s) {
        int maxChars = 24;
        return s.length() <= maxChars ? s : s.substring(0, maxChars - 1) + "…";
    }

    /** Determinate terminal state for the Agent progress bar. Unlike
     *  setAgentProgress (running look, indeterminate) this can never render
     *  as a color-only bar — the indeterminate paint path ignores the
     *  string. Called from the completion callback; showFinalVerdict repeats
     *  an equivalent state later (idempotent). */
    public void finishAgentProgress() {
        SwingUtilities.invokeLater(() -> {
            progressBar.setVisible(false);
        });
    }

    /** Settle the bar into a terminal "aborted" state. Without this, an
     *  error/timeout end left the bar indeterminate on "Agent 运行中 — N 次
     *  工具调用", which read as a stuck run (the actual symptom reported). */
    public void abortAgentProgress(String reason) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setVisible(false);
            statusLabel.setText(I18n.get("ai_analysis_agent_terminated")
                    + (reason != null && !reason.isBlank() ? " — " + reason : ""));
            statusLabel.setForeground(theme.statusError());
            startAnalyzeBtn.setEnabled(true);
        });
    }

    public void setAgentRunning(boolean running) {
        this.agentRunning = running;
        // Deleting mid-run is the trap behind "deleted but everything stayed":
        // the record leaves the model, yet showEntryHistory() bails on the
        // same agentRunning flag so the panel never refreshes — and the
        // still-running agent re-adds a fresh record on completion anyway.
        // Disable the button instead of letting users fall into it.
        SwingUtilities.invokeLater(() -> {
            deleteAnalysisBtn.setEnabled(!running);
            deleteAnalysisBtn.setToolTipText(running
                    ? I18n.get("ai_analysis_delete_running") : I18n.get("ai_analysis_delete_tooltip"));
        });
    }

    /** Path whose history is currently shown — used by the delete flow to
     *  also clear that endpoint's chat conversation. */
    public String getCurrentApiPath() { return currentApiPath; }

    public void setReportPath(java.nio.file.Path path) {
        this.currentReportPath = path;
        viewReportBtn.setVisible(path != null);
    }

    public void setJsonReportPath(java.nio.file.Path path) {
        this.currentJsonReportPath = path;
        viewJsonBtn.setVisible(path != null);
    }

    /** @return the path to the most recent JSON report for the currently
     *  selected API, or null if no report has been saved yet. Used by the
     *  chat controller to append follow-up conversation data. */
    public java.nio.file.Path getJsonReportPath() {
        return currentJsonReportPath;
    }

    private void openJsonReport() {
        java.nio.file.Path path = currentJsonReportPath;
        // If path wasn't set (timing issue), find the latest report for this API
        if (path == null && currentApiPath != null) {
            path = findLatestReport(currentApiPath, false);
        }
        openFile(path);
    }

    private void openReport() {
        java.nio.file.Path path = currentReportPath;
        // If path wasn't set (timing issue), find the latest report for this API
        if (path == null && currentApiPath != null) {
            path = findLatestReport(currentApiPath, true);
        }
        openFile(path);
    }

    /**
     * Find the latest report file for the given API path.
     * Searches ~/.api-sentinel/reports/ for files matching the naming convention.
     */
    private java.nio.file.Path findLatestReport(String apiPath, boolean html) {
        try {
            java.nio.file.Path reportsDir = com.flechazo.apisentinel.config.AppPaths.reportsDir();
            if (!java.nio.file.Files.exists(reportsDir)) return null;

            String suffix = html ? ".html" : ".json";
            // Normalize API path to match filename convention:
            // /api/orders/{id}/quantity → api-orders-id-quantity
            String pathSlug = apiPath != null
                    ? apiPath.replaceAll("[^a-zA-Z0-9]", "-")
                             .replaceAll("-+", "-")      // collapse multiple dashes
                             .replaceAll("^-+|-+$", "")    // trim leading/trailing dashes
                    : "";

            java.util.List<java.nio.file.Path> matches = new java.util.ArrayList<>();
            try (var stream = java.nio.file.Files.list(reportsDir)) {
                stream.filter(p -> p.getFileName().toString().endsWith(suffix))
                     .filter(p -> pathSlug.isEmpty() || p.getFileName().toString().contains(pathSlug))
                     .forEach(matches::add);
            }

            if (matches.isEmpty()) return null;
            // Sort by last modified time, return newest
            matches.sort((a, b) -> {
                try {
                    return java.nio.file.Files.getLastModifiedTime(b)
                            .compareTo(java.nio.file.Files.getLastModifiedTime(a));
                } catch (Exception e) { return 0; }
            });
            return matches.get(0);
        } catch (Exception e) {
            return null;
        }
    }

    private void openFile(java.nio.file.Path path) {
        if (path == null) {
            ThemedDialogs.warn(this, I18n.get("ai_analysis_report_no_path"), I18n.get("ai_analysis_cannot_open_report"));
            return;
        }
        if (!java.nio.file.Files.exists(path)) {
            ThemedDialogs.warn(this, I18n.get("ai_analysis_report_not_found") + path, I18n.get("ai_analysis_file_not_exist"));
            return;
        }
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop desktop = java.awt.Desktop.getDesktop();
                if (desktop.isSupported(java.awt.Desktop.Action.OPEN)) {
                    desktop.open(path.toFile());
                } else if (desktop.isSupported(java.awt.Desktop.Action.BROWSE)) {
                    desktop.browse(path.toUri());
                } else {
                    // Fallback: copy path to clipboard
                    java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new java.awt.datatransfer.StringSelection(path.toString()), null);
                    ThemedDialogs.info(this, I18n.get("ai_analysis_no_auto_open") + path,
                            I18n.get("ai_analysis_path_copied"));
                }
            } else {
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(path.toString()), null);
                ThemedDialogs.info(this, I18n.get("ai_analysis_no_desktop") + path,
                        I18n.get("ai_analysis_path_copied"));
            }
        } catch (Exception e) {
            ThemedDialogs.error(this, I18n.get("ai_analysis_open_failed") + e.getMessage() + "\n" + path, I18n.get("ai_analysis_error_title"));
        }
    }

    public void setOnAnalysisDeleted(Runnable callback) { this.onAnalysisDeleted = callback; }

    public void setOnOpenChatRequested(Runnable callback) { this.onOpenChatRequested = callback; }

    /** Delete the analysis record currently being viewed (or the latest if none is
     *  explicitly selected), then refresh the history display. */
    private void deleteCurrentAnalysis() {
        if (currentEntry == null) return;
        if (agentRunning) {
            ThemedDialogs.info(this, I18n.get("ai_analysis_running_delete"), I18n.get("ai_analysis_running_title"));
            return;
        }
        AnalysisRecord toDelete = currentDisplayedRecord != null
                ? currentDisplayedRecord : currentEntry.getLatestAnalysisRecord();
        if (toDelete == null) {
            ThemedDialogs.info(this, I18n.get("ai_analysis_no_records"), I18n.get("ai_analysis_no_records_title"));
            return;
        }
        String when = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                .format(new java.util.Date(toDelete.timestamp()));
        boolean confirmed = ThemedDialogs.confirm(this,
                I18n.get("ai_analysis_confirm_delete") + when + I18n.get("ai_analysis_confirm_delete_suffix") + toDelete.mode()
                        + I18n.get("ai_analysis_delete_irreversible"),
                I18n.get("ai_analysis_confirm_delete_title"));
        if (!confirmed) return;

        boolean removed = currentEntry.removeAnalysisRecord(toDelete);
        if (removed) {
            currentDisplayedRecord = null;
            if (onAnalysisDeleted != null) onAnalysisDeleted.run();
            showEntryHistory(currentEntry);
        }
    }

    /** @param mode "PIPELINE" or "AGENT" — determines the status label text and
     *              whether the progress bar gets reset to Pipeline's fixed
     *              6-stage scale. Agent mode's bar was already set to its own
     *              (iteration-based) "done" state by setAgentProgress right
     *              before this call — overwriting it with Pipeline's "6"
     *              would show a wrong/mismatched max for Agent runs. */
    public void showFinalVerdict(FinalVerdict verdict, AnalysisResult trafficAnalysis, String mode) {
        showFinalVerdict(verdict, trafficAnalysis, mode, List.of());
    }

    public void showFinalVerdict(FinalVerdict verdict, AnalysisResult trafficAnalysis, String mode,
                                  List<com.flechazo.apisentinel.ai.pipeline.PayloadResult> payloadResults) {
        boolean isAgent = "AGENT".equalsIgnoreCase(mode);
        SwingUtilities.invokeLater(() -> {
            // Hide the progress bar on completion — the results are now in
            // the card/detail/timeline tabs; keeping a full-width orange bar
            // visible after completion is visual noise, not useful feedback.
            progressBar.setVisible(false);
            // Re-show report buttons — analysis is complete, reports will be
            // available (paths are set by savePipelineReport which queues its
            // own invokeLater; we can't rely on them being set yet here, so
            // show unconditionally — the button handler checks for null path).
            viewReportBtn.setVisible(true);
            viewJsonBtn.setVisible(true);
            statusLabel.setText((isAgent ? "Agent" : "Pipeline") + I18n.get("ai_analysis_complete_short"));
            statusLabel.setForeground(theme.statusOk());
            riskLabel.setText(verdict.overallRisk());
            riskLabel.setForeground(theme.riskColor(verdict.overallRisk()));
            tokensLabel.setText(String.format(I18n.get("ai_tokens_label"), verdict.totalTokensUsed()));
            if (trafficAnalysis != null && trafficAnalysis.modelUsed() != null
                    && !trafficAnalysis.modelUsed().isBlank()) {
                modelLabel.setText(String.format(I18n.get("ai_model_label"), trafficAnalysis.modelUsed()));
            }

            findingsModel.setRowCount(0);
            currentFindings = List.of();
            currentVerdict = verdict;
            currentPayloadResults = payloadResults != null ? payloadResults : List.of();
            // buildFindingsRows() puts payload text (ConfirmedVuln.payloadUsed())
            // in this column, not a code location — the header was stuck on
            // "位置" (the simple-analysis VulnFinding mode's label for the
            // same column) regardless of which mode was actually showing.
            findingsTable.getColumnModel().getColumn(4).setHeaderValue("Payload");
            findingsTable.getTableHeader().repaint();

            for (Object[] row : FindingsRenderer.buildFindingsRows(verdict)) {
                findingsModel.addRow(row);
            }

            detailArea.setText(FindingsRenderer.buildDetailText(verdict, trafficAnalysis));
            detailArea.setCaretPosition(0);
            verdictCardsPanel.showVerdict(verdict, trafficAnalysis);
            bottomTabs.setSelectedIndex(0);
            setSummary(verdict.summary());

            if (findingsModel.getRowCount() > 0) findingsTable.setRowSelectionInterval(0, 0);
            startAnalyzeBtn.setEnabled(true);
        });
    }

    public void showPipelineError(String error) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(I18n.get("ai_analysis_pipeline_failed"));
            statusLabel.setForeground(theme.statusError());
            progressBar.setVisible(false);
            startAnalyzeBtn.setEnabled(true);
            detailArea.setText(I18n.get("ai_analysis_pipeline_error") + error);
            setSummary(I18n.get("ai_analysis_failed") + error);
        });
    }

    public void resetPipelineProgress() { resetPipelineProgress(false); }

    /** Show batch-level progress: "done/total". */
    public void setBatchProgress(int done, int total) {
        SwingUtilities.invokeLater(() -> {
            if (total > 1) {
                statusLabel.setText(I18n.get("ai_analysis_batch_progress") + done + "/" + total);
                progressBar.setMaximum(total);
                progressBar.setValue(done);
            }
        });
    }

    public void resetPipelineProgress(boolean agentMode) {
        SwingUtilities.invokeLater(() -> {
            agentToolCallCount = 0;
            currentReportPath = null;
            viewReportBtn.setVisible(false);
            currentJsonReportPath = null;
            viewJsonBtn.setVisible(false);
            if (agentMode) {
                progressBar.setIndeterminate(true);
                progressBar.setString(I18n.get("ai_analysis_agent_starting"));
                progressBar.setStringPainted(true);
                statusLabel.setText(I18n.get("ai_analysis_agent_analyzing"));
            } else {
                progressBar.setIndeterminate(false);
                progressBar.setMaximum(6);
                progressBar.setValue(0);
                progressBar.setString(I18n.get("ai_analysis_stage_0"));
                statusLabel.setText(I18n.get("ai_analysis_pipeline_running"));
            }
            progressBar.setVisible(true);
            findingsModel.setRowCount(0);
            detailArea.setText("");
            timelinePanel.clear();
            setSummary("");
            statusLabel.setForeground(theme.statusPending());
            riskLabel.setText("--");
            modelLabel.setText(I18n.get("ai_model_default"));
            tokensLabel.setText(I18n.get("ai_tokens_zero"));
        });
    }

    // ======================== Existing Methods ========================

    public void showEntryHistory(ApiEntry entry) {
        this.currentApiPath = entry != null ? entry.getApiPath() : null;
        this.currentEntry = entry;
        SwingUtilities.invokeLater(() -> {
            if (agentRunning) return;

            findingsModel.setRowCount(0);
            detailArea.setText("");
            timelinePanel.clear();
            setSummary("");
            // The verdict card view used to survive record deletion and row
            // switches — the cards, the verdict backing the findings-table
            // selection listener and the payload results all had to go too.
            currentVerdict = null;
            currentPayloadResults = List.of();
            verdictCardsPanel.showVerdict(null, null);
            statusLabel.setText(I18n.get("ai_analysis_waiting"));
            statusLabel.setForeground(UIManager.getColor("Label.foreground"));
            riskLabel.setText("--");
            modelLabel.setText(I18n.get("ai_model_default"));
            tokensLabel.setText(I18n.get("ai_tokens_zero"));
            progressBar.setVisible(false);

            if (entry == null) return;

            List<AnalysisRecord> history = entry.getAnalysisHistory();
            currentHistory = history;
            // Populate history selector so users can view (and compare against)
            // prior analysis runs, not just the latest. The selection listener
            // is wired once in the constructor; here we only refresh the items.
            historyCombo.removeAllItems();
            historyCombo.addItem(I18n.get("ai_analysis_latest_record"));
            for (int i = 0; i < history.size(); i++) {
                var rec = history.get(i);
                String label = "#" + (i + 1) + " " + rec.mode()
                        + (rec.timestamp() > 0
                                ? " (" + new java.text.SimpleDateFormat("MM-dd HH:mm").format(new java.util.Date(rec.timestamp())) + ")"
                                : "");
                historyCombo.addItem(label);
            }
            historyCombo.setSelectedIndex(0);

            if (history.isEmpty()) {
                setSummary(I18n.get("ai_analysis_not_analyzed"));
                return;
            }
            showAnalysisRecord(history.get(history.size() - 1));
        });
    }

    private void showAnalysisRecord(AnalysisRecord record) {
        if (record == null) return;
        // result() is the legacy simple-analysis AnalysisResult; Agent/Pipeline
        // records carry a PipelineResult and may have result()==null (e.g. the
        // agent never ran analyze_traffic). The old result()==null early-return
        // made such records un-re-renderable — every row re-selection blanked
        // the panel back to "等待分析" and left it stuck there.
        if (record.result() == null && !record.hasPipelineResult()) return;
        currentDisplayedRecord = record;

        // Re-render the persisted call chain (if this record captured one), so the
        // 调用链 tab isn't empty when revisiting a historical analysis.
        if (record.timeline() != null && !record.timeline().isEmpty()) {
            timelinePanel.loadEvents(record.timeline());
        }
        // If record.timeline() is empty, DON'T clear — the live events from
        // the just-completed run are still showing. Clearing here was wiping
        // the call chain immediately after analysis completion. The timeline
        // is properly cleared at the start of a new run by resetPipelineProgress.

        if (record.hasPipelineResult()) {
            PipelineResult pr = record.pipelineResult();
            showFinalVerdict(pr.verdict(), pr.trafficAnalysis(), record.mode(), pr.payloadResults());
            return;
        }

        AnalysisResult result = record.result();

        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            progressBar.setVisible(false);
            startAnalyzeBtn.setEnabled(true);
        });

        if (!result.isSuccess()) {
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText(I18n.get("ai_analysis_failed_status") + result.error());
                statusLabel.setForeground(theme.statusError());
                findingsModel.setRowCount(0);
                detailArea.setText("");
                setSummary("");
            });
            return;
        }

        SwingUtilities.invokeLater(() -> {
            currentFindings = result.findings();
            currentVerdict = null;
            findingsTable.getColumnModel().getColumn(4).setHeaderValue(I18n.get("ai_analysis_col_location"));
            findingsTable.getTableHeader().repaint();
            statusLabel.setText(I18n.get("ai_analysis_complete"));
            statusLabel.setForeground(theme.statusOk());
            riskLabel.setText(result.overallRisk().name());
            riskLabel.setForeground(theme.riskColor(result.overallRisk().name()));
            modelLabel.setText(String.format(I18n.get("ai_model_label"), result.modelUsed()));
            tokensLabel.setText(String.format(I18n.get("ai_tokens_label"), result.tokensUsed()));
            setSummary(result.summary());

            findingsModel.setRowCount(0);
            for (VulnFinding f : result.findings()) {
                findingsModel.addRow(new Object[]{f.type(), f.risk(), String.format("%.0f%%", f.confidence() * 100), f.title(), f.location()});
            }
            if (!result.findings().isEmpty()) findingsTable.setRowSelectionInterval(0, 0);

            // Burp-style card view mirrors these VulnFindings.
            verdictCardsPanel.showAnalysisResult(result);
            bottomTabs.setSelectedIndex(0);
        });
    }

    public void updateResult(AnalysisResult result) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            progressBar.setVisible(false);
            startAnalyzeBtn.setEnabled(true);

            if (result == null || !result.isSuccess()) {
                statusLabel.setText(result != null ? I18n.get("ai_analysis_failed_status") + result.error() : I18n.get("ai_analysis_no_result"));
                statusLabel.setForeground(theme.statusError());
                return;
            }
            currentFindings = result.findings();
            currentVerdict = null;
            findingsTable.getColumnModel().getColumn(4).setHeaderValue(I18n.get("ai_analysis_col_location"));
            findingsTable.getTableHeader().repaint();
            statusLabel.setText(I18n.get("ai_analysis_complete"));
            statusLabel.setForeground(theme.statusOk());
            riskLabel.setText(result.overallRisk().name());
            riskLabel.setForeground(theme.riskColor(result.overallRisk().name()));
            modelLabel.setText(String.format(I18n.get("ai_model_label"), result.modelUsed()));
            tokensLabel.setText(String.format(I18n.get("ai_tokens_label"), result.tokensUsed()));
            setSummary(result.summary());

            findingsModel.setRowCount(0);
            for (VulnFinding f : result.findings()) {
                findingsModel.addRow(new Object[]{f.type(), f.risk(), String.format("%.0f%%", f.confidence() * 100), f.title(), f.location()});
            }
            if (!result.findings().isEmpty()) findingsTable.setRowSelectionInterval(0, 0);

            // Burp-style card view mirrors these VulnFindings.
            verdictCardsPanel.showAnalysisResult(result);
            bottomTabs.setSelectedIndex(0);
        });
    }

    public void refreshHistoryForEntry(ApiEntry entry) {
        SwingUtilities.invokeLater(() -> {
            if (entry == null) return;
            this.currentEntry = entry;
            List<AnalysisRecord> history = entry.getAnalysisHistory();
            if (!history.isEmpty()) showAnalysisRecord(history.get(history.size() - 1));
        });
    }

    /** Mark the currently-selected finding as a false positive (suppress future re-raise). */
    private void markSelectedFindingFalsePositive() {
        int row = findingsTable.getSelectedRow();
        if (row < 0 || row >= currentFindings.size() || learnedRuleEngine == null || currentApiPath == null) {
            ThemedDialogs.info(this, I18n.get("ai_analysis_select_finding_fp"), I18n.get("ai_analysis_cannot_operate"));
            return;
        }
        com.flechazo.apisentinel.ai.analysis.VulnFinding f = currentFindings.get(row);
        learnedRuleEngine.markFalsePositive(currentApiPath, f.type());
        // Visually mark the row
        if (row < findingsModel.getRowCount()) {
            findingsModel.setValueAt(I18n.get("ai_analysis_fp_prefix") + findingsModel.getValueAt(row, 1), row, 1);
        }
        ThemedDialogs.info(this, I18n.get("ai_analysis_marked_fp_prefix") + f.type() + I18n.get("ai_analysis_marked_fp_suffix"), I18n.get("ai_analysis_marked_title"));
    }

    public void setAnalyzing() {        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(I18n.get("ai_analysis_analyzing"));
            statusLabel.setForeground(theme.statusPending());
            progressBar.setIndeterminate(true);
            progressBar.setVisible(true);
            findingsModel.setRowCount(0);
            setSummary("");
            detailArea.setText("");
            timelinePanel.clear();
        });
    }

    public void setCurrentModel(String modelName) {
        SwingUtilities.invokeLater(() -> {
            if (modelName != null && !modelName.isEmpty()) modelLabel.setText(String.format(I18n.get("ai_model_label"), modelName));
        });
    }

    private void showVerdictFindingDetail(int row) {
        detailArea.setText(FindingsRenderer.buildSingleFindingDetailText(currentVerdict, row));
        detailArea.setCaretPosition(0);
    }

    // ======================== evidence comparison ========================

    /** Open the side-by-side evidence view for the currently-selected finding,
     *  auto-picking its two proving packets (for 越权/IDOR: the owner-session
     *  vs attacker-session requests on the same endpoint). */
    private void openEvidenceCompareForSelectedRow() {
        if (currentVerdict == null) {
            javax.swing.JOptionPane.showMessageDialog(this, I18n.get("ai_analysis_no_compare"));
            return;
        }
        int viewRow = findingsTable.getSelectedRow();
        if (viewRow < 0) {
            javax.swing.JOptionPane.showMessageDialog(this, I18n.get("ai_analysis_select_finding_first"));
            return;
        }
        int row = findingsTable.convertRowIndexToModel(viewRow);
        var confirmed = currentVerdict.confirmedVulns();
        var suspected = currentVerdict.suspectedVulns();
        String type, payloadUsed;
        int citedIdx = -1;
        if (row >= 0 && row < confirmed.size()) {
            var cv = confirmed.get(row);
            type = cv.type(); payloadUsed = cv.payloadUsed(); citedIdx = cv.citedExecutionIndex();
        } else if (row - confirmed.size() >= 0 && row - confirmed.size() < suspected.size()) {
            var sv = suspected.get(row - confirmed.size());
            type = sv.type(); payloadUsed = sv.payloadUsed();
        } else {
            return;
        }
        openEvidenceCompare(type == null ? "" : type, payloadUsed, citedIdx);
    }

    private void openEvidenceCompare(String type, String payloadUsed, int citedIdx) {
        var prs = currentPayloadResults;
        if (prs == null || prs.isEmpty()) {
            javax.swing.JOptionPane.showMessageDialog(this,
                    I18n.get("ai_analysis_no_payload")
                    + I18n.get("ai_analysis_static_analysis_note"));
            return;
        }
        boolean authClass = com.flechazo.apisentinel.ai.pipeline.VerdictValidator.isAuthClass(type);

        // Attack packet: the cited execution index, else the request carrying
        // the payload, else the last request sent.
        com.flechazo.apisentinel.ai.pipeline.PayloadResult attack = null;
        if (citedIdx >= 0) {
            for (var p : prs) if (p.executionIndex() == citedIdx) { attack = p; break; }
        }
        if (attack == null && payloadUsed != null && !payloadUsed.isBlank()) {
            String key = payloadUsed.length() > 40 ? payloadUsed.substring(0, 40) : payloadUsed;
            for (var p : prs) {
                String sr = p.sentRequest();
                if (sr != null && sr.contains(key)) { attack = p; break; }
            }
        }
        if (attack == null) attack = prs.get(prs.size() - 1);

        String attackPath = comparePath(attack);
        String attackSession = attack.authSession();

        // Baseline packet: prefer same endpoint + different session (the IDOR
        // owner side); else any other packet on the same endpoint; else any.
        com.flechazo.apisentinel.ai.pipeline.PayloadResult baseline = null;
        if (authClass && attackSession != null) {
            for (var p : prs) {
                if (p == attack) continue;
                if (!comparePath(p).equals(attackPath)) continue;
                String s = p.authSession();
                if (s != null && !s.equals(attackSession)) { baseline = p; break; }
            }
        }
        if (baseline == null) {
            for (var p : prs) if (p != attack && comparePath(p).equals(attackPath)) { baseline = p; break; }
        }
        if (baseline == null) {
            for (var p : prs) if (p != attack) { baseline = p; break; }
        }

        String attackLabel = authClass ? I18n.get("ai_analysis_attack_session") + shortSession(attack) : I18n.get("ai_analysis_attack_payload");
        if (baseline == null) {
            EvidenceCompareDialog.show(api, this, I18n.get("ai_analysis_evidence_title") + type,
                    I18n.get("ai_analysis_no_baseline"), null, null,
                    attackLabel, attack.sentRequest(), attack.receivedResponse());
            return;
        }
        String baselineLabel = authClass ? I18n.get("ai_analysis_owner_session") + shortSession(baseline) : I18n.get("ai_analysis_baseline_label");
        EvidenceCompareDialog.show(api, this, I18n.get("ai_analysis_evidence_title") + type,
                baselineLabel, baseline.sentRequest(), baseline.receivedResponse(),
                attackLabel, attack.sentRequest(), attack.receivedResponse());
    }

    /** Method + path (query stripped) for same-endpoint comparison. */
    private static String comparePath(com.flechazo.apisentinel.ai.pipeline.PayloadResult pr) {
        String req = pr.sentRequest();
        if (req == null) return "";
        int sp = req.indexOf(' ');
        if (sp < 0) return "";
        int end = req.indexOf(' ', sp + 1);
        if (end < 0) end = req.indexOf('\n', sp + 1);
        if (end < 0) end = req.length();
        String full = req.substring(sp + 1, end).trim();
        int q = full.indexOf('?');
        return q >= 0 ? full.substring(0, q) : full;
    }

    private static String shortSession(com.flechazo.apisentinel.ai.pipeline.PayloadResult pr) {
        String s = pr.authSession();
        if (s == null || s.isBlank()) return "";
        return " · " + (s.length() > 8 ? "…" + s.substring(s.length() - 6) : s);
    }

    private void showDetail(VulnFinding f) {
        detailArea.setText(String.format(I18n.get("ai_analysis_detail_format"),
                f.title(), I18n.get("ai_analysis_label_type"), f.type(), I18n.get("ai_analysis_label_risk"), f.risk(),
                I18n.get("ai_analysis_label_confidence"), f.confidence() * 100,
                I18n.get("ai_analysis_label_desc"), f.description(),
                I18n.get("ai_analysis_label_evidence"), f.evidence(),
                I18n.get("ai_analysis_label_remediation"), f.remediation()));
    }

    /** No-op since the redundant top summary strip was removed — the verdict
     *  summary is shown once, in full, by the 卡片视图 SummaryCard. Kept so the
     *  many existing call sites compile and stay stable. */
    private void setSummary(String text) {
        // intentionally empty
    }

    private void openReplayDialog() {
        int row = findingsTable.getSelectedRow();
        if (row < 0 || currentVerdict == null) {
            // Debug: show why it failed
            if (row < 0) {
                ThemedDialogs.info(this, I18n.get("ai_analysis_select_finding_first"), I18n.get("ai_analysis_no_vuln_selected"));
            } else {
                ThemedDialogs.info(this, I18n.get("ai_analysis_result_not_ready"), I18n.get("ai_analysis_no_result_title"));
            }
            return;
        }

        int confirmedCount = currentVerdict.confirmedVulns().size();
        String rawRequest = null;
        String title;

        if (row < confirmedCount) {
            com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln cv = currentVerdict.confirmedVulns().get(row);
            title = I18n.get("ai_analysis_confirmed_prefix")  + cv.title();
            com.flechazo.apisentinel.ai.pipeline.PayloadResult pr =
                    com.flechazo.apisentinel.ai.pipeline.VerdictValidator.findPayloadResult(currentPayloadResults, cv.payloadUsed());
            if (pr == null) {
                // Fallback: use the first sent payload that has a request,
                // so the replay dialog opens with a real, replayable request.
                pr = firstSentPayloadResult();
            }
            if (pr != null) rawRequest = pr.sentRequest();
        } else {
            int idx = row - confirmedCount;
            if (idx < currentVerdict.suspectedVulns().size()) {
                com.flechazo.apisentinel.ai.pipeline.SuspectedVuln sv = currentVerdict.suspectedVulns().get(idx);
                title = I18n.get("ai_analysis_suspected_prefix")  + sv.title();
                // Link the finding to its verification request: prefer an exact
                // match on its payloadUsed, then any sent payload, so the dialog
                // opens with a real, replayable request instead of "no request data".
                if (sv.payloadUsed() != null && !sv.payloadUsed().isBlank()) {
                    com.flechazo.apisentinel.ai.pipeline.PayloadResult pr =
                            com.flechazo.apisentinel.ai.pipeline.VerdictValidator.findPayloadResult(currentPayloadResults, sv.payloadUsed());
                    if (pr == null && sv.payloadUsed().contains(" / ")) {
                        // payloadUsed may be a concatenation of multiple payloads
                        // (e.g. '{"code":"SAVE10","orderTotal":"50"} / {"code":"SAVE10","orderTotal":"0"}').
                        // Try matching each individual payload.
                        for (String part : sv.payloadUsed().split(" / ")) {
                            pr = com.flechazo.apisentinel.ai.pipeline.VerdictValidator.findPayloadResult(
                                    currentPayloadResults, part.trim());
                            if (pr != null) break;
                        }
                    }
                    if (pr != null) rawRequest = pr.sentRequest();
                }
                if (rawRequest == null) {
                    com.flechazo.apisentinel.ai.pipeline.PayloadResult pr = firstSentPayloadResult();
                    if (pr != null) rawRequest = pr.sentRequest();
                }
            } else {
                return;
            }
        }
        // Final fallback: the endpoint's captured request.
        if ((rawRequest == null || rawRequest.isEmpty()) && currentEntry != null) {
            rawRequest = currentEntry.getLastRawRequest();
        }

        Window owner = SwingUtilities.getWindowAncestor(this);
        try {
            ReplayDialog dialog = new ReplayDialog(owner, api, title, rawRequest, currentEntry);
            dialog.setVisible(true);
        } catch (Exception ex) {
            ThemedDialogs.error(owner, I18n.get("ai_analysis_replay_failed") + ex.getMessage(),
                    I18n.get("ai_analysis_error_title"));
        }
    }

    /** First payload result that actually carries a sent request, or null. Used
     *  as a best-effort request source for suspected findings that lack a
     *  payloadUsed link. */
    private com.flechazo.apisentinel.ai.pipeline.PayloadResult firstSentPayloadResult() {
        if (currentPayloadResults == null) return null;
        for (com.flechazo.apisentinel.ai.pipeline.PayloadResult pr : currentPayloadResults) {
            if (pr.sentRequest() != null && !pr.sentRequest().isEmpty()) return pr;
        }
        return null;
    }

    // ======================== FindingUpdater Implementation ========================

    @Override
    public String[] getFindingSummaries() {
        if (currentVerdict == null) return null;

        var confirmed = currentVerdict.confirmedVulns();
        var suspected = currentVerdict.suspectedVulns();
        String[] summaries = new String[confirmed.size() + suspected.size()];

        for (int i = 0; i < confirmed.size(); i++) {
            var cv = confirmed.get(i);
            summaries[i] = String.format("[%d] ✅ CONFIRMED: %s — %s", i, cv.type(), cv.title());
        }
        for (int i = 0; i < suspected.size(); i++) {
            var sv = suspected.get(i);
            summaries[confirmed.size() + i] = String.format("[%d] ⚠️ SUSPECTED: %s — %s",
                    confirmed.size() + i, sv.type(), sv.title());
        }
        return summaries;
    }

    @Override
    public boolean updateFinding(int findingIndex, String newStatus,
                                  String evidence, String payloadUsed, String response) {
        if (currentVerdict == null) return false;

        var confirmed = new java.util.ArrayList<>(currentVerdict.confirmedVulns());
        var suspected = new java.util.ArrayList<>(currentVerdict.suspectedVulns());

        int confirmedCount = confirmed.size();

        // Find the target finding
        boolean isConfirmed = findingIndex < confirmedCount;
        int localIndex = isConfirmed ? findingIndex : findingIndex - confirmedCount;

        if (localIndex < 0) return false;

        if ("dismissed".equals(newStatus)) {
            // Remove from whichever list it's in
            if (isConfirmed && localIndex < confirmed.size()) {
                confirmed.remove(localIndex);
            } else if (!isConfirmed && localIndex < suspected.size()) {
                suspected.remove(localIndex);
            } else {
                return false;
            }
        } else if ("confirmed".equals(newStatus)) {
            if (isConfirmed) {
                // Update existing confirmed finding
                if (localIndex >= confirmed.size()) return false;
                var old = confirmed.get(localIndex);
                confirmed.set(localIndex, new com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln(
                        old.type(), old.title(),
                        evidence != null ? evidence : old.evidence(),
                        payloadUsed != null ? payloadUsed : old.payloadUsed(),
                        response != null ? response : old.response(),
                        old.verifyCommand(), old.identityProof(), old.cvss(), old.citedExecutionIndex()));
            } else {
                // Promote suspected → confirmed
                if (localIndex >= suspected.size()) return false;
                var sv = suspected.remove(localIndex);
                confirmed.add(new com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln(
                        sv.type(), sv.title(),
                        evidence != null ? evidence : sv.reason(),
                        payloadUsed != null ? payloadUsed : sv.payloadUsed(),
                        response != null ? response : "",
                        sv.verifyCommand()));
            }
        } else if ("suspected".equals(newStatus)) {
            if (!isConfirmed) {
                // Update existing suspected finding
                if (localIndex >= suspected.size()) return false;
                var old = suspected.get(localIndex);
                suspected.set(localIndex, new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                        old.type(), old.title(),
                        evidence != null ? evidence : old.reason(),
                        old.verifyCommand(), old.confidence(), old.escalationPath(),
                        payloadUsed != null ? payloadUsed : old.payloadUsed()));
            } else {
                // Demote confirmed → suspected
                if (localIndex >= confirmed.size()) return false;
                var cv = confirmed.remove(localIndex);
                suspected.add(new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                        cv.type(), cv.title(),
                        evidence != null ? evidence : cv.evidence(),
                        cv.verifyCommand(), "medium", "",
                        payloadUsed != null ? payloadUsed : cv.payloadUsed()));
            }
        } else {
            return false;
        }

        // Recalculate overall risk
        String overallRisk = recalculateRisk(confirmed, suspected);

        // Create new verdict with updated lists
        currentVerdict = new com.flechazo.apisentinel.ai.pipeline.FinalVerdict(
                overallRisk, confirmed, suspected,
                currentVerdict.summary(), currentVerdict.recommendations(),
                currentVerdict.totalTokensUsed(), currentVerdict.rejectionReasons());

        // Refresh the findings table on EDT
        javax.swing.SwingUtilities.invokeLater(() -> refreshFindingsTable());

        return true;
    }

    /** Refresh the findings table rows from currentVerdict (without full showFinalVerdict flow). */
    private void refreshFindingsTable() {
        if (currentVerdict == null) return;
        findingsModel.setRowCount(0);
        findingsTable.getColumnModel().getColumn(4).setHeaderValue("Payload");
        findingsTable.getTableHeader().repaint();
        for (Object[] row : com.flechazo.apisentinel.ui.FindingsRenderer.buildFindingsRows(currentVerdict)) {
            findingsModel.addRow(row);
        }
        // Update risk label
        riskLabel.setText(currentVerdict.overallRisk());
        riskLabel.setForeground(theme.riskColor(currentVerdict.overallRisk()));
    }

    /** Recalculate overall risk based on confirmed/suspected counts. */
    private String recalculateRisk(
            java.util.List<com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln> confirmed,
            java.util.List<com.flechazo.apisentinel.ai.pipeline.SuspectedVuln> suspected) {
        if (!confirmed.isEmpty()) {
            // Check for critical/high severity confirmed vulns
            boolean hasCritical = confirmed.stream()
                    .anyMatch(cv -> cv.cvss() != null && cv.cvss().startsWith("9"));
            if (hasCritical) return "CRITICAL";
            return "HIGH";
        }
        if (!suspected.isEmpty()) return "MEDIUM";
        return "LOW";
    }
}
