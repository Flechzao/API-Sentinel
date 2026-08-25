package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.PassiveFinding;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Standalone, resizable window listing an entry's local passive-detection
 * findings (sensitive-info / heuristic / unauthorized probe) with per-finding
 * evidence + remediation detail. Modeless, mirrors FindingsDetailDialog's
 * pattern. The main table's "被动" column deliberately shows only a one-line
 * summary; this dialog carries the depth.
 */
public class PassiveFindingsDialog extends JDialog {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final BurpTheme theme;

    public PassiveFindingsDialog(Window owner, burp.api.montoya.MontoyaApi api, ApiEntry entry) {
        super(owner, "被动检测详情 — " + entry.getHttpMethod() + " " + entry.getApiPath(),
                ModalityType.MODELESS);
        this.theme = new BurpTheme(api);
        setSize(800, 550);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout(0, 0));
        theme.apply(this);

        List<PassiveFinding> findings = entry.getPassiveFindings();

        // ── Top info bar ──
        JPanel infoBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        infoBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        JLabel methodPathLabel = new JLabel(entry.getHttpMethod() + "  " + entry.getApiPath());
        methodPathLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        infoBar.add(methodPathLabel);
        JLabel countLabel = new JLabel(findings.size() + " 条被动发现");
        countLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        countLabel.setForeground(theme.mutedText());
        infoBar.add(countLabel);
        String maxRisk = entry.getMaxPassiveRisk();
        if (!maxRisk.isEmpty()) {
            JLabel riskLabel = new JLabel("最高 " + maxRisk);
            riskLabel.setFont(theme.displayFont(Font.BOLD, 12f));
            riskLabel.setForeground(riskColor(maxRisk));
            infoBar.add(riskLabel);
        }
        add(infoBar, BorderLayout.NORTH);

        // ── Findings table (top) ──
        DefaultTableModel model = new DefaultTableModel(
                new Object[]{"来源", "风险", "类别", "标题", "时间"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        for (PassiveFinding f : findings) {
            model.addRow(new Object[]{
                    sourceName(f.source()), f.risk(),
                    f.category() == null || f.category().isEmpty() ? "--" : f.category(),
                    f.title(),
                    f.detectedAt() > 0 ? TIME_FMT.format(Instant.ofEpochMilli(f.detectedAt())) : "--"
            });
        }
        JTable table = new JTable(model);
        table.setFont(theme.displayFont(Font.PLAIN, 11f));
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(60);
        table.getColumnModel().getColumn(2).setPreferredWidth(120);
        table.getColumnModel().getColumn(3).setPreferredWidth(280);
        table.getColumnModel().getColumn(4).setPreferredWidth(90);
        table.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                if (!s) setForeground(riskColor(v != null ? v.toString() : ""));
                return this;
            }
        });
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("被动检测发现"));

        // ── Detail area (bottom): evidence + remediation of selected row ──
        JTextArea detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setFont(theme.displayFont(Font.PLAIN, 11f));
        detailArea.setBackground(theme.contextBg());
        JScrollPane detailScroll = new JScrollPane(detailArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        detailScroll.setBorder(BorderFactory.createTitledBorder("证据 / 修复建议"));

        table.getSelectionModel().addListSelectionListener(ev -> {
            if (ev.getValueIsAdjusting()) return;
            int row = table.getSelectedRow();
            if (row < 0 || row >= findings.size()) return;
            PassiveFinding f = findings.get(row);
            StringBuilder sb = new StringBuilder();
            sb.append("[").append(sourceName(f.source())).append("][").append(f.risk()).append("] ")
              .append(f.category() == null || f.category().isEmpty() ? "" : f.category() + " / ")
              .append(f.title()).append("\n\n");
            sb.append("证据：\n")
              .append(f.evidence() == null || f.evidence().isEmpty() ? "（无）" : f.evidence())
              .append("\n");
            if (f.remediation() != null && !f.remediation().isEmpty()) {
                sb.append("\n修复建议：\n").append(f.remediation()).append("\n");
            }
            detailArea.setText(sb.toString());
            detailArea.setCaretPosition(0);
        });

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        split.setResizeWeight(0.55);
        split.setDividerLocation(240);
        add(split, BorderLayout.CENTER);

        if (!findings.isEmpty()) {
            table.setRowSelectionInterval(0, 0);
        }
    }

    private static String sourceName(PassiveFinding.Source s) {
        return switch (s) {
            case SENSITIVE_INFO -> "敏感信息";
            case HEURISTIC -> "启发式";
            case UNAUTHORIZED -> "越权探测";
        };
    }

    private Color riskColor(String risk) {
        return switch (risk) {
            case "HIGH" -> theme.riskHigh();
            case "MEDIUM" -> theme.riskMedium();
            case "LOW" -> theme.riskLow();
            default -> theme.mutedText();
        };
    }
}
