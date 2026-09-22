package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry.ToolCatalogEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Dialog for managing Agent tools — shows all tools in a table with
 * enable/disable/requires-authorization status.
 *
 * <p>Opened from AiSettingsPanel's "管理工具" button.
 */
public class ToolManagementDialog {

    /**
     * Show the tool management dialog (blocking, modal).
     *
     * @param owner       parent frame
     * @param theme       BurpTheme for styling
     * @param disabledTools  currently disabled tool names
     * @param authTools      currently auth-required tool names
     * @param onConfirm      callback when user clicks "保存"
     */
    public static void showDialog(Frame owner, BurpTheme theme,
                                    Set<String> disabledTools, Set<String> authTools,
                                    BiConsumer<Set<String>, Set<String>> onConfirm) {
        // Build catalog
        List<ToolCatalogEntry> catalog = com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry.getToolCatalog();

        // Create dialog
        JDialog dialog = new JDialog(owner, String.format(I18n.get("tool_mgmt_title"), catalog.size()), true);
        dialog.setSize(800, 600);
        dialog.setLocationRelativeTo(owner);
        dialog.setLayout(new BorderLayout(0, 0));

        // Table model
        ToolTableModel model = new ToolTableModel(catalog, disabledTools, authTools);
        JTable table = new JTable(model);
        table.setRowHeight(32);
        table.getColumnModel().getColumn(0).setPreferredWidth(180);
        table.getColumnModel().getColumn(1).setPreferredWidth(400);
        table.getColumnModel().getColumn(2).setPreferredWidth(100);
        table.getColumnModel().getColumn(3).setPreferredWidth(50);
        table.getColumnModel().getColumn(4).setPreferredWidth(60);

        // Status column renderer
        table.getColumnModel().getColumn(2).setCellRenderer((tbl, value, isSelected, hasFocus, row, col) -> {
            JLabel label = new JLabel(String.valueOf(value));
            label.setOpaque(true);
            label.setHorizontalAlignment(SwingConstants.CENTER);
            String status = String.valueOf(value);
            // P1-8: only two states now — the "Locked" branch is gone
            // (the setting had no runtime effect, so rendering it was
            // actively misleading).
            if ("Disabled".equals(status)) {
                label.setBackground(new Color(248, 215, 218));
                label.setForeground(new Color(114, 28, 36));
            } else {
                label.setBackground(new Color(212, 237, 218));
                label.setForeground(new Color(21, 87, 36));
            }
            if (isSelected) label.setBackground(tbl.getSelectionBackground());
            return label;
        });

        // Status column editor (dropdown). P1-8: two states; the previous
        // "Locked" option is gone — the runtime never consulted
        // AppConfig.toolRequiresAuth(), so surfacing the setting was
        // shipping a broken feature.
        String[] statuses = {"Enabled", "Disabled"};
        table.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(new JComboBox<>(statuses)));

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));
        dialog.add(scroll, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton enableAll = new JButton(I18n.get("tool_mgmt_enable_all"));
        JButton disableAll = new JButton(I18n.get("tool_mgmt_disable_all"));
        JButton resetBtn = new JButton(I18n.get("tool_mgmt_reset"));
        JButton saveBtn = new JButton(I18n.get("btn_save"));
        JButton cancelBtn = new JButton(I18n.get("btn_cancel"));

        enableAll.addActionListener(e -> model.setAllStatuses("Enabled"));
        disableAll.addActionListener(e -> model.setAllStatuses("Disabled"));
        resetBtn.addActionListener(e -> model.resetToDefault());
        saveBtn.addActionListener(e -> {
            onConfirm.accept(model.getDisabledTools(), model.getAuthTools());
            dialog.dispose();
        });
        cancelBtn.addActionListener(e -> dialog.dispose());

        buttonPanel.add(enableAll);
        buttonPanel.add(disableAll);
        buttonPanel.add(resetBtn);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(saveBtn);
        buttonPanel.add(cancelBtn);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        if (theme != null) theme.apply(dialog);
        dialog.setVisible(true);
    }

    // ========== Table Model ==========

    static class ToolTableModel extends AbstractTableModel {
        private final List<ToolCatalogEntry> tools;
        private final List<String> statuses = new ArrayList<>();
        private final Set<String> authTools;
        private static final String[] COLUMNS = {
            I18n.get("tool_mgmt_col_name"),
            I18n.get("tool_mgmt_col_desc"),
            I18n.get("tool_mgmt_col_status"),
            I18n.get("tool_mgmt_col_free"),
            I18n.get("tool_mgmt_col_auth")
        };

        ToolTableModel(List<ToolCatalogEntry> tools, Set<String> disabled, Set<String> auth) {
            this.tools = tools;
            this.authTools = auth != null ? auth : Set.of();
            // P1-8 hardening: the "Locked" state was dead UI — the
            // setting was accepted, saved, and rendered, but nothing in
            // the agent runtime ever consulted toolRequiresAuth(), so
            // marking a tool as needing authorization had exactly zero
            // effect. Rather than ship a setting that silently fails
            // (worse than no setting, per the §3.7 P1-8 audit), the
            // third state is dropped from the model. The {@code auth}
            // parameter is retained on the signature so the call site
            // keeps compiling; the data it carries is ignored.
            for (ToolCatalogEntry t : tools) {
                if (disabled.contains(t.name())) {
                    statuses.add("Disabled");
                } else {
                    statuses.add("Enabled");
                }
            }
        }

        @Override public int getRowCount() { return tools.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int col) { return COLUMNS[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            ToolCatalogEntry t = tools.get(row);
            String desc = t.description();
            // Strip inline cost markers — they're shown in the "免费" column
            desc = desc.replace("Free.", "").replace("Costs AI.", "").strip();
            if (desc.length() > 120) desc = desc.substring(0, 120) + "...";
            return switch (col) {
                case 0 -> t.name();
                case 1 -> desc;
                case 2 -> statuses.get(row);
                case 3 -> t.description().contains("free") ? I18n.get("tool_mgmt_yes") : I18n.get("tool_mgmt_no");
                case 4 -> authTools.contains(t.name()) ? I18n.get("tool_mgmt_yes") : I18n.get("tool_mgmt_no");
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            if (col == 2) {
                statuses.set(row, String.valueOf(value));
                fireTableCellUpdated(row, col);
            }
        }

        @Override public boolean isCellEditable(int row, int col) { return col == 2; }

        void setAllStatuses(String status) {
            for (int i = 0; i < statuses.size(); i++) statuses.set(i, status);
            fireTableDataChanged();
        }

        void resetToDefault() {
            // P1-8: reset now only distinguishes enabled / disabled. The
            // previous behaviour that pre-marked browser_interact and
            // run_sandboxed_code as "Locked" is gone — that setting
            // had no runtime effect, so surfacing it here made the
            // dialog actively misleading.
            for (int i = 0; i < tools.size(); i++) {
                statuses.set(i, "Enabled");
            }
            fireTableDataChanged();
        }

        Set<String> getDisabledTools() {
            Set<String> result = new HashSet<>();
            for (int i = 0; i < tools.size(); i++)
                if ("Disabled".equals(statuses.get(i))) result.add(tools.get(i).name());
            return result;
        }

        Set<String> getAuthTools() {
            Set<String> result = new HashSet<>();
            for (int i = 0; i < tools.size(); i++)
                if ("Locked".equals(statuses.get(i))) result.add(tools.get(i).name());
            return result;
        }
    }
}
