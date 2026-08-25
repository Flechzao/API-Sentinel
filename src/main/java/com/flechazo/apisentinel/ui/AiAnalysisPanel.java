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
public class AiAnalysisPanel extends JPanel {

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

        startAnalyzeBtn = new JButton("开始分析");
        startAnalyzeBtn.setFont(theme.displayFont(Font.BOLD, 13f));
        startAnalyzeBtn.setFocusPainted(false);
        startAnalyzeBtn.addActionListener(e -> triggerAnalysis());
        radioRow.add(startAnalyzeBtn);

        historyCombo = new JComboBox<>(new String[]{"（历史记录）"});
        historyCombo.setFont(theme.displayFont(Font.PLAIN, 11f));
        historyCombo.setToolTipText("选择查看此 API 的历次分析记录");
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

        deleteAnalysisBtn = new JButton("删除本次分析");
        deleteAnalysisBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        deleteAnalysisBtn.setFocusPainted(false);
        deleteAnalysisBtn.setToolTipText("从该接口的历史记录中删除当前查看的这次分析");
        deleteAnalysisBtn.addActionListener(e -> deleteCurrentAnalysis());
        radioRow.add(deleteAnalysisBtn);

        // The AI conversation lives in a floating window now (no detailTabs
        // slot) — this panel is its primary entry point.
        JButton openChatBtn = new JButton("AI 对话");
        openChatBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        openChatBtn.setFocusPainted(false);
        openChatBtn.setToolTipText("打开 AI 对话浮窗（分析过程、沙箱确认、提问交互都在其中；关闭窗口不会中断分析）");
        openChatBtn.addActionListener(e -> {
            if (onOpenChatRequested != null) onOpenChatRequested.run();
        });
        radioRow.add(openChatBtn);

        modePanel.add(radioRow);

        // Status + progress row
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        statusRow.add(new JLabel("状态:"));
        statusLabel = new JLabel("等待分析");
        statusLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        statusRow.add(statusLabel);

        statusRow.add(Box.createHorizontalStrut(15));
        statusRow.add(new JLabel("风险:"));
        riskLabel = new JLabel("--");
        riskLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        statusRow.add(riskLabel);

        statusRow.add(Box.createHorizontalStrut(15));
        modelLabel = new JLabel("Model: --");
        modelLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        statusRow.add(modelLabel);
        tokensLabel = new JLabel("Tokens: 0");
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
        viewReportBtn = new JButton("查看报告");
        viewReportBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        viewReportBtn.setFocusPainted(false);
        viewReportBtn.setVisible(false);
        viewReportBtn.addActionListener(e -> openReport());
        statusRow.add(viewReportBtn);

        viewJsonBtn = new JButton("完整日志(JSON)");
        viewJsonBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        viewJsonBtn.setFocusPainted(false);
        viewJsonBtn.setVisible(false);
        viewJsonBtn.setToolTipText("打开完整的 AI 分析日志（JSON，含各阶段原始数据）");
        viewJsonBtn.addActionListener(e -> openJsonReport());
        statusRow.add(viewJsonBtn);
        statusRow.add(Box.createHorizontalStrut(6));

        statusRow.add(Box.createHorizontalStrut(10));
        JCheckBox showLowRiskCb = new JCheckBox("显示低风险", false);
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
        findingsModel = new DefaultTableModel(new String[]{"类型", "风险", "置信度", "标题", "位置"}, 0) {
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
        fpMenu.add(new javax.swing.AbstractAction("重放验证") {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) {
                openReplayDialog();
            }
        });
        fpMenu.addSeparator();
        fpMenu.add(new javax.swing.AbstractAction("标为误报 (抑制未来相同发现)") {
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
        bottomTabs.addTab("卡片视图", verdictCardsPanel);
        bottomTabs.addTab("详情", new JScrollPane(detailArea));
        bottomTabs.addTab("调用链", timelinePanel);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(findingsTable), bottomTabs);
        centerSplit.setDividerLocation(160);
        centerSplit.setResizeWeight(0.35);
        add(centerSplit, BorderLayout.CENTER);

        // Apply Burp theme
        theme.apply(this);
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
            progressBar.setToolTipText("阶段 " + stage + "/6"
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
                display = "Agent 运行中";
                if (agentToolCallCount > 0) {
                    display += " — " + agentToolCallCount + " 次工具调用";
                }
                if (toolName != null && !toolName.isEmpty()) {
                    display += " | " + toolName;
                }
            }
            progressBar.setString(display);
            progressBar.setStringPainted(true);
            // Tooltip carries the full, un-clipped line plus the raw tool name
            // and the running tool-call count.
            progressBar.setToolTipText("Agent 运行中 · 已 " + agentToolCallCount + " 次工具调用"
                    + (toolName != null && !toolName.isEmpty() ? " · 当前: " + toolName : "")
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
            int n = Math.max(1, agentToolCallCount);
            progressBar.setIndeterminate(false);
            progressBar.setMaximum(n);
            progressBar.setValue(n);
            progressBar.setString(agentToolCallCount > 0
                    ? "分析完成 — " + agentToolCallCount + " 次工具调用"
                    : "分析完成");
            progressBar.setStringPainted(true);
            progressBar.setVisible(true);
        });
    }

    /** Settle the bar into a terminal "aborted" state. Without this, an
     *  error/timeout end left the bar indeterminate on "Agent 运行中 — N 次
     *  工具调用", which read as a stuck run (the actual symptom reported). */
    public void abortAgentProgress(String reason) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            int n = Math.max(1, agentToolCallCount);
            progressBar.setMaximum(n);
            progressBar.setValue(n);
            progressBar.setString(ProgressQuips.abortQuip());
            progressBar.setToolTipText("已终止 — " + agentToolCallCount + " 次工具调用"
                    + (reason != null && !reason.isBlank() ? " · " + reason : ""));
            progressBar.setStringPainted(true);
            progressBar.setVisible(true);
            statusLabel.setText("Agent 已终止");
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
                    ? "分析进行中，结束后才能删除记录"
                    : "从该接口的历史记录中删除当前查看的这次分析");
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

    private void openReport() {
        openFile(currentReportPath);
    }

    private void openJsonReport() {
        openFile(currentJsonReportPath);
    }

    private void openFile(java.nio.file.Path path) {
        if (path == null) return;
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop desktop = java.awt.Desktop.getDesktop();
                if (desktop.isSupported(java.awt.Desktop.Action.BROWSE)) {
                    desktop.browse(path.toUri());
                } else if (desktop.isSupported(java.awt.Desktop.Action.OPEN)) {
                    desktop.open(path.toFile());
                }
            }
        } catch (Exception ignored) {}
    }

    public void setOnAnalysisDeleted(Runnable callback) { this.onAnalysisDeleted = callback; }

    public void setOnOpenChatRequested(Runnable callback) { this.onOpenChatRequested = callback; }

    /** Delete the analysis record currently being viewed (or the latest if none is
     *  explicitly selected), then refresh the history display. */
    private void deleteCurrentAnalysis() {
        if (currentEntry == null) return;
        if (agentRunning) {
            ThemedDialogs.info(this, "分析正在进行中，等分析结束后再删除记录。", "分析运行中");
            return;
        }
        AnalysisRecord toDelete = currentDisplayedRecord != null
                ? currentDisplayedRecord : currentEntry.getLatestAnalysisRecord();
        if (toDelete == null) {
            ThemedDialogs.info(this, "当前没有可删除的分析记录。", "无记录");
            return;
        }
        String when = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                .format(new java.util.Date(toDelete.timestamp()));
        boolean confirmed = ThemedDialogs.confirm(this,
                "确定删除这次分析记录吗？\n\n时间: " + when + "\n模式: " + toDelete.mode()
                        + "\n\n删除后不可恢复。",
                "删除分析记录");
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
            // setVisible(true) is load-bearing: completion triggers a table
            // refresh whose selection-clear fires showEntryHistory(null),
            // which hides the bar. This method is the LAST settle on the EDT
            // queue, so it must re-show the bar or it stays hidden/color-only.
            progressBar.setVisible(true);
            progressBar.setStringPainted(true);
            progressBar.setIndeterminate(false);
            int confirmedN = verdict.confirmedVulns() != null ? verdict.confirmedVulns().size() : 0;
            int suspectedN = verdict.suspectedVulns() != null ? verdict.suspectedVulns().size() : 0;
            if (!isAgent) {
                progressBar.setMaximum(6);
                progressBar.setValue(6);
            } else {
                progressBar.setMaximum(agentToolCallCount > 0 ? agentToolCallCount : 1);
                progressBar.setValue(progressBar.getMaximum());
            }
            progressBar.setString(ProgressQuips.completionQuip(confirmedN, suspectedN));
            progressBar.setToolTipText("分析完成 — " + (isAgent ? agentToolCallCount + " 次工具调用" : "6 阶段流水线")
                    + " · 确认 " + confirmedN + " / 疑似 " + suspectedN);
            statusLabel.setText((isAgent ? "Agent" : "Pipeline") + " 完成");
            statusLabel.setForeground(theme.statusOk());
            riskLabel.setText(verdict.overallRisk());
            riskLabel.setForeground(theme.riskColor(verdict.overallRisk()));
            tokensLabel.setText("Tokens: " + verdict.totalTokensUsed());

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
            statusLabel.setText("Pipeline 失败");
            statusLabel.setForeground(theme.statusError());
            progressBar.setVisible(false);
            startAnalyzeBtn.setEnabled(true);
            detailArea.setText("Pipeline 执行失败:\n\n" + error);
            setSummary("分析失败: " + error);
        });
    }

    public void resetPipelineProgress() { resetPipelineProgress(false); }

    /** Show batch-level progress: "done/total". */
    public void setBatchProgress(int done, int total) {
        SwingUtilities.invokeLater(() -> {
            if (total > 1) {
                statusLabel.setText("批量分析进度: " + done + "/" + total);
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
                progressBar.setString("Agent 启动中...");
                progressBar.setStringPainted(true);
                statusLabel.setText("Agent 分析中...");
            } else {
                progressBar.setIndeterminate(false);
                progressBar.setMaximum(6);
                progressBar.setValue(0);
                progressBar.setString("阶段 0/6");
                statusLabel.setText("Pipeline 执行中...");
            }
            progressBar.setVisible(true);
            findingsModel.setRowCount(0);
            detailArea.setText("");
            timelinePanel.clear();
            setSummary("");
            statusLabel.setForeground(theme.statusPending());
            riskLabel.setText("--");
            modelLabel.setText("Model: --");
            tokensLabel.setText("Tokens: 0");
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
            statusLabel.setText("等待分析");
            statusLabel.setForeground(UIManager.getColor("Label.foreground"));
            riskLabel.setText("--");
            modelLabel.setText("Model: --");
            tokensLabel.setText("Tokens: 0");
            progressBar.setVisible(false);

            if (entry == null) return;

            List<AnalysisRecord> history = entry.getAnalysisHistory();
            currentHistory = history;
            // Populate history selector so users can view (and compare against)
            // prior analysis runs, not just the latest. The selection listener
            // is wired once in the constructor; here we only refresh the items.
            historyCombo.removeAllItems();
            historyCombo.addItem("最新记录");
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
                setSummary("未分析 - 点击「开始分析」按钮开始");
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
        } else {
            timelinePanel.clear();
        }

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
                statusLabel.setText("失败: " + result.error());
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
            findingsTable.getColumnModel().getColumn(4).setHeaderValue("位置");
            findingsTable.getTableHeader().repaint();
            statusLabel.setText("分析完成");
            statusLabel.setForeground(theme.statusOk());
            riskLabel.setText(result.overallRisk().name());
            riskLabel.setForeground(theme.riskColor(result.overallRisk().name()));
            modelLabel.setText("Model: " + result.modelUsed());
            tokensLabel.setText("Tokens: " + result.tokensUsed());
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
                statusLabel.setText(result != null ? "失败: " + result.error() : "无结果");
                statusLabel.setForeground(theme.statusError());
                return;
            }
            currentFindings = result.findings();
            currentVerdict = null;
            findingsTable.getColumnModel().getColumn(4).setHeaderValue("位置");
            findingsTable.getTableHeader().repaint();
            statusLabel.setText("分析完成");
            statusLabel.setForeground(theme.statusOk());
            riskLabel.setText(result.overallRisk().name());
            riskLabel.setForeground(theme.riskColor(result.overallRisk().name()));
            modelLabel.setText("Model: " + result.modelUsed());
            tokensLabel.setText("Tokens: " + result.tokensUsed());
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
            javax.swing.JOptionPane.showMessageDialog(this,
                    "请先选中一条 finding 再标为误报。", "无法操作", javax.swing.JOptionPane.WARNING_MESSAGE);
            return;
        }
        com.flechazo.apisentinel.ai.analysis.VulnFinding f = currentFindings.get(row);
        learnedRuleEngine.markFalsePositive(currentApiPath, f.type());
        // Visually mark the row
        if (row < findingsModel.getRowCount()) {
            findingsModel.setValueAt("[误报] " + findingsModel.getValueAt(row, 1), row, 1);
        }
        javax.swing.JOptionPane.showMessageDialog(this,
                "已将 [" + f.type() + "] 标记为误报并持久化。后续分析将抑制该组合的重复发现。",
                "已标记", javax.swing.JOptionPane.INFORMATION_MESSAGE);
    }

    public void setAnalyzing() {        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("分析中...");
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
            if (modelName != null && !modelName.isEmpty()) modelLabel.setText("Model: " + modelName);
        });
    }

    private void showVerdictFindingDetail(int row) {
        detailArea.setText(FindingsRenderer.buildSingleFindingDetailText(currentVerdict, row));
        detailArea.setCaretPosition(0);
    }

    private void showDetail(VulnFinding f) {
        detailArea.setText(String.format("=== %s ===\n类型: %s | 风险: %s | 置信度: %.0f%%\n\n描述:\n%s\n\n证据:\n%s\n\n修复建议:\n%s",
                f.title(), f.type(), f.risk(), f.confidence() * 100, f.description(), f.evidence(), f.remediation()));
    }

    /** No-op since the redundant top summary strip was removed — the verdict
     *  summary is shown once, in full, by the 卡片视图 SummaryCard. Kept so the
     *  many existing call sites compile and stay stable. */
    private void setSummary(String text) {
        // intentionally empty
    }

    private void openReplayDialog() {
        int row = findingsTable.getSelectedRow();
        if (row < 0 || currentVerdict == null) return;

        int confirmedCount = currentVerdict.confirmedVulns().size();
        String rawRequest = null;
        String title;

        if (row < confirmedCount) {
            com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln cv = currentVerdict.confirmedVulns().get(row);
            title = "[已确认] " + cv.title();
            com.flechazo.apisentinel.ai.pipeline.PayloadResult pr =
                    com.flechazo.apisentinel.ai.pipeline.VerdictValidator.findPayloadResult(currentPayloadResults, cv.payloadUsed());
            if (pr != null) rawRequest = pr.sentRequest();
        } else {
            int idx = row - confirmedCount;
            if (idx < currentVerdict.suspectedVulns().size()) {
                com.flechazo.apisentinel.ai.pipeline.SuspectedVuln sv = currentVerdict.suspectedVulns().get(idx);
                title = "[疑似] " + sv.title();
                // Link the finding to its verification request: prefer an exact
                // match on its payloadUsed, then any sent payload, so the dialog
                // opens with a real, replayable request instead of "no request data".
                if (sv.payloadUsed() != null && !sv.payloadUsed().isBlank()) {
                    com.flechazo.apisentinel.ai.pipeline.PayloadResult pr =
                            com.flechazo.apisentinel.ai.pipeline.VerdictValidator.findPayloadResult(currentPayloadResults, sv.payloadUsed());
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
        ReplayDialog dialog = new ReplayDialog(owner, api, title, rawRequest, currentEntry);
        dialog.setVisible(true);
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
}
