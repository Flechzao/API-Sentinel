package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

/**
 * Standalone, resizable window showing the full findings + detail text for
 * an API entry's latest Pipeline/Agent analysis — for reading a single
 * entry's results without fighting the cramped main-window split panes.
 * Modeless, mirrors HistoryTrafficDialog's pattern.
 */
public class FindingsDetailDialog extends JDialog {

    private final BurpTheme theme;

    public FindingsDetailDialog(Window owner, burp.api.montoya.MontoyaApi api, ApiEntry entry) {
        super(owner, "分析详情 — " + entry.getHttpMethod() + " " + entry.getApiPath(),
                ModalityType.MODELESS);
        this.theme = new BurpTheme(api);
        setSize(950, 700);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout(0, 0));
        theme.apply(this);

        AnalysisRecord record = entry.getLatestAnalysisRecord();
        if (record == null || !record.hasPipelineResult()) {
            add(new JLabel("暂无分析结果", SwingConstants.CENTER), BorderLayout.CENTER);
            return;
        }

        FinalVerdict verdict = record.pipelineResult().verdict();

        // ── Top info bar ──
        JPanel infoBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        infoBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));

        JLabel methodPathLabel = new JLabel(entry.getHttpMethod() + "  " + entry.getApiPath());
        methodPathLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        infoBar.add(methodPathLabel);

        JLabel riskLabel = new JLabel(verdict.overallRisk());
        riskLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        riskLabel.setForeground(riskColor(verdict.overallRisk()));
        infoBar.add(riskLabel);

        JLabel tokensLabel = new JLabel(String.format(I18n.get("ai_tokens_label"), verdict.totalTokensUsed()));
        tokensLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        tokensLabel.setForeground(theme.mutedText());
        infoBar.add(tokensLabel);

        add(infoBar, BorderLayout.NORTH);

        // ── Persistent summary/recommendations strip — same regardless of
        //    which finding row is selected below ──
        JTextArea summaryArea = new JTextArea(FindingsRenderer.buildSummaryText(verdict));
        summaryArea.setEditable(false);
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setFont(theme.displayFont(Font.PLAIN, 11f));
        summaryArea.setBackground(theme.contextBg());
        JScrollPane summaryScroll = new JScrollPane(summaryArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        summaryScroll.setPreferredSize(new Dimension(0, 90));
        summaryScroll.setBorder(BorderFactory.createTitledBorder("AI 总结 / 修复建议"));

        // ── Center: findings table (top) + per-finding detail text (bottom) ──
        DefaultTableModel findingsModel = new DefaultTableModel(
                new Object[]{"类型", "严重度", "状态", "标题", "Payload"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        for (Object[] row : FindingsRenderer.buildFindingsRows(verdict)) {
            findingsModel.addRow(row);
        }

        JTable findingsTable = new JTable(findingsModel);
        findingsTable.setRowHeight(22);
        findingsTable.setFont(theme.displayFont(Font.PLAIN, 11f));
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(130);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(80);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        findingsTable.getColumnModel().getColumn(2).setMaxWidth(90);

        findingsTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                if (!s && v != null) setForeground(riskColor(v.toString()));
                return this;
            }
        });

        JTextArea detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(theme.editorFont(12f));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row < 0) return;
            detailArea.setText(FindingsRenderer.buildSingleFindingDetailText(verdict, row));
            detailArea.setCaretPosition(0);
        });

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(findingsTable), new JScrollPane(detailArea));
        centerSplit.setResizeWeight(0.3);
        centerSplit.setDividerLocation(180);
        centerSplit.setOneTouchExpandable(true);

        JPanel centerPanel = new JPanel(new BorderLayout(0, 0));
        centerPanel.add(summaryScroll, BorderLayout.NORTH);
        centerPanel.add(centerSplit, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);

        if (findingsModel.getRowCount() > 0) {
            findingsTable.setRowSelectionInterval(0, 0);
        } else {
            detailArea.setText("本次分析没有产出确认或疑似漏洞。");
        }
    }

    private Color riskColor(String risk) {
        if (risk == null) return theme.mutedText();
        return switch (risk.toUpperCase()) {
            case "HIGH" -> theme.riskHigh();
            case "MEDIUM" -> theme.riskMedium();
            case "LOW" -> theme.riskLow();
            case "SAFE", "INFO" -> theme.riskSafe();
            default -> theme.mutedText();
        };
    }
}
