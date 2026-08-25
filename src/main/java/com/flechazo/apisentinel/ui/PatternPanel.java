package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.patterns.PatternStore;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Management page for the success-pattern memory (cluster-hunting P3):
 * every VERIFIED confirmed vuln becomes a reusable pattern that is injected
 * into new analyses' initial messages. This panel makes that memory visible
 * and manageable — what the agent has learned, how often each play paid off,
 * and a hard reset when the corpus goes stale.
 */
public class PatternPanel extends JPanel {

    private final BurpTheme theme;
    private final PatternTableModel model = new PatternTableModel();
    private final JTable table;
    private final JLabel summaryLabel;
    private final JButton refreshBtn;
    private final JButton clearBtn;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("MM-dd HH:mm");

    private PatternStore patternStore;

    public PatternPanel(BurpTheme theme) {
        this.theme = theme;
        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Header: explanation + actions
        JPanel header = new JPanel(new BorderLayout(8, 0));
        header.setOpaque(false);

        // Two stacked labels instead of an <html> label — Burp's theme sets
        // html.disable on JLabels, which would render the <html>/<span> tags as
        // literal text. Same root cause as the toast/sandbox-card HTML leak.
        JPanel titleCol = new JPanel();
        titleCol.setLayout(new BoxLayout(titleCol, BoxLayout.Y_AXIS));
        titleCol.setOpaque(false);
        JLabel title = new JLabel(I18n.get("patterns_title"));
        title.setFont(theme.displayFont(Font.BOLD, 12f));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        JTextArea hint = new JTextArea(I18n.get("patterns_hint"));
        hint.setEditable(false);
        hint.setLineWrap(true);
        hint.setWrapStyleWord(true);
        hint.setOpaque(false);
        hint.setBorder(null);
        hint.setFont(theme.displayFont(Font.PLAIN, 10f));
        hint.setForeground(theme.mutedText());
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleCol.add(title);
        titleCol.add(hint);
        header.add(titleCol, BorderLayout.CENTER);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        actions.setOpaque(false);
        refreshBtn = new JButton(I18n.get("patterns_refresh"));
        refreshBtn.setFont(theme.displayFont(Font.PLAIN, 12f));
        refreshBtn.addActionListener(e -> refresh());
        clearBtn = new JButton(I18n.get("patterns_clear"));
        clearBtn.setFont(theme.displayFont(Font.PLAIN, 12f));
        clearBtn.addActionListener(e -> confirmClear());
        actions.add(refreshBtn);
        actions.add(clearBtn);
        header.add(actions, BorderLayout.EAST);

        add(header, BorderLayout.NORTH);

        // Table
        table = new JTable(model);
        table.setFillsViewportHeight(true);
        table.setRowHeight(24);
        table.setFont(theme.displayFont(Font.PLAIN, 12f));
        table.getTableHeader().setFont(theme.displayFont(Font.BOLD, 11f));
        table.setGridColor(theme.separator());
        table.setShowGrid(true);
        table.setAutoCreateRowSorter(true);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(theme.separator()));
        add(scroll, BorderLayout.CENTER);

        summaryLabel = new JLabel(" ");
        summaryLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        summaryLabel.setForeground(theme.statLabelFg());
        summaryLabel.setBorder(BorderFactory.createEmptyBorder(4, 2, 0, 2));
        add(summaryLabel, BorderLayout.SOUTH);

        applyColumnWidths();

        refresh();
    }

    /** Column widths — reapplied after i18n refresh because
     *  fireTableStructureChanged rebuilds the column model. */
    private void applyColumnWidths() {
        table.getColumnModel().getColumn(0).setPreferredWidth(110); // vulnType
        table.getColumnModel().getColumn(1).setPreferredWidth(220); // technique
        table.getColumnModel().getColumn(2).setPreferredWidth(220); // apiPattern
        table.getColumnModel().getColumn(3).setPreferredWidth(130); // domain
        table.getColumnModel().getColumn(4).setPreferredWidth(50);  // hits
        table.getColumnModel().getColumn(5).setPreferredWidth(100); // lastSeen
    }

    public void setPatternStore(PatternStore store) {
        this.patternStore = store;
        refresh();
    }

    public void refresh() {
        if (patternStore == null) {
            model.setRows(new ArrayList<>());
            summaryLabel.setText(I18n.get("patterns_unavailable"));
            return;
        }
        List<PatternStore.SuccessPattern> rows = patternStore.allPatterns();
        model.setRows(rows);
        summaryLabel.setText(String.format(I18n.get("patterns_summary"), rows.size()));
    }

    private void confirmClear() {
        if (patternStore == null || patternStore.size() == 0) return;
        boolean confirmed = ThemedDialogs.confirm(this,
                I18n.get("patterns_clear_confirm"),
                I18n.get("patterns_clear"));
        if (confirmed) {
            patternStore.clear();
            refresh();
        }
    }

    public void refreshI18n() {
        refreshBtn.setText(I18n.get("patterns_refresh"));
        clearBtn.setText(I18n.get("patterns_clear"));
        model.fireTableStructureChanged();
        applyColumnWidths();
        refresh();
    }

    private class PatternTableModel extends AbstractTableModel {
        private List<PatternStore.SuccessPattern> rows = new ArrayList<>();

        void setRows(List<PatternStore.SuccessPattern> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 6; }

        @Override public String getColumnName(int col) {
            return switch (col) {
                case 0 -> I18n.get("patterns_col_type");
                case 1 -> I18n.get("patterns_col_technique");
                case 2 -> I18n.get("patterns_col_endpoint");
                case 3 -> I18n.get("patterns_col_domain");
                case 4 -> I18n.get("patterns_col_hits");
                case 5 -> I18n.get("patterns_col_last_seen");
                default -> "";
            };
        }

        @Override public Object getValueAt(int row, int col) {
            PatternStore.SuccessPattern p = rows.get(row);
            // LLM-provided fields can carry HTML/markdown fragments (XSS
            // titles quoting "<script>" payloads etc.) — cells render plain
            // text, so strip markup for display. Covers patterns persisted
            // before recording started sanitizing.
            return switch (col) {
                case 0 -> PatternStore.stripMarkup(p.vulnType());
                case 1 -> PatternStore.stripMarkup(p.technique());
                case 2 -> p.apiPattern();
                case 3 -> p.domain() == null ? "" : p.domain();
                case 4 -> p.hits();
                case 5 -> p.lastSeenMs() > 0 ? dateFormat.format(new Date(p.lastSeenMs())) : "";
                default -> "";
            };
        }

        @Override public Class<?> getColumnClass(int col) {
            return col == 4 ? Integer.class : String.class;
        }
    }
}
