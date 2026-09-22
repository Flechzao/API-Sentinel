package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.config.SensitiveRule;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel for managing sensitive information detection rules (regex-based).
 */
public class SensitiveRulesPanel extends JPanel {

    private final DefaultTableModel rulesModel;
    private final JTable rulesTable;
    private final JLabel countLabel;
    private List<SensitiveRule> rules;
    /** Invoked after user rules are saved so the detector picks them up. */
    private final Runnable onRulesSaved;
    private final BurpTheme theme;

    private static final Path USER_RULES_FILE = com.flechazo.apisentinel.config.AppPaths.sensitiveRulesFile();
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public SensitiveRulesPanel(List<SensitiveRule> initialRules, Runnable onRulesSaved, BurpTheme theme) {
        this.onRulesSaved = onRulesSaved;
        this.theme = theme;
        List<SensitiveRule> userRules = loadUserRules();
        this.rules = userRules != null ? userRules : new ArrayList<>(initialRules);
        setLayout(new BorderLayout(0, 4));

        // Header
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JLabel title = new JLabel(I18n.get("rules_title"));
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        header.add(title);
        countLabel = new JLabel("(" + rules.size() + " 条规则已加载)");
        countLabel.setFont(theme.displayFont(Font.PLAIN, 12f));
        countLabel.setForeground(Color.GRAY);
        header.add(countLabel);
        add(header, BorderLayout.NORTH);

        // Rules table
        rulesModel = new DefaultTableModel(new String[]{"名称", "分组", "正则表达式"}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        rulesTable = new JTable(rulesModel);
        rulesTable.setRowHeight(24);
        rulesTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        rulesTable.getColumnModel().getColumn(0).setMaxWidth(200);
        rulesTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        rulesTable.getColumnModel().getColumn(1).setMaxWidth(160);
        rulesTable.getColumnModel().getColumn(2).setPreferredWidth(500);

        loadRulesToTable();
        add(new JScrollPane(rulesTable), BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton addButton = new JButton(I18n.get("rules_add"));
        addButton.addActionListener(e -> addRule());
        JButton removeButton = new JButton("删除选中");
        removeButton.addActionListener(e -> removeSelected());
        JButton reloadButton = new JButton(I18n.get("rules_reload"));
        reloadButton.addActionListener(e -> loadRulesToTable());
        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(reloadButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    /** No-op stub — LearnedRuleEngine integration removed. */
    public void setLearnedRuleEngine(Object engine) { /* ignored */ }

    private void loadRulesToTable() {
        rulesModel.setRowCount(0);
        for (SensitiveRule rule : rules) {
            rulesModel.addRow(new Object[]{
                    rule.getName(), rule.getGroup(), rule.getCompiledRegex().pattern()
            });
        }
        countLabel.setText("(" + rules.size() + " 条规则已加载)");
    }

    private void addRule() {
        JTextField nameField = new JTextField(20);
        JTextField regexField = new JTextField(40);
        JTextField groupField = new JTextField("Sensitive Information", 20);

        JPanel panel = new JPanel(new GridLayout(3, 2, 4, 4));
        panel.add(new JLabel(I18n.get("rules_name"))); panel.add(nameField);
        panel.add(new JLabel(I18n.get("rules_regex"))); panel.add(regexField);
        panel.add(new JLabel(I18n.get("rules_group"))); panel.add(groupField);

        int result = JOptionPane.showConfirmDialog(this, panel, I18n.get("rules_add"),
                JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String regex = regexField.getText().trim();
            String group = groupField.getText().trim();
            if (!name.isEmpty() && !regex.isEmpty()) {
                try {
                    SensitiveRule rule = new SensitiveRule(name, regex, group);
                    rules.add(rule);
                    rulesModel.addRow(new Object[]{name, group, regex});
                    saveUserRules();
                    countLabel.setText("(" + rules.size() + " 条规则已加载)");
                } catch (Exception ex) {
                    ThemedDialogs.error(this, "无效正则: " + ex.getMessage(), "错误");
                }
            }
        }
    }

    private void removeSelected() {
        int[] selected = rulesTable.getSelectedRows();
        if (selected.length == 0) return;
        for (int i = selected.length - 1; i >= 0; i--) {
            int row = selected[i];
            if (row >= 0 && row < rules.size()) {
                rules.remove(row);
                rulesModel.removeRow(row);
            }
        }
        saveUserRules();
        countLabel.setText("(" + rules.size() + " 条规则已加载)");
    }

    public List<SensitiveRule> getRules() {
        return rules;
    }

    private void saveUserRules() {
        try {
            Path dir = USER_RULES_FILE.getParent();
            if (dir != null) Files.createDirectories(dir);

            JsonArray arr = new JsonArray();
            for (SensitiveRule rule : rules) {
                JsonObject obj = new JsonObject();
                obj.addProperty("name", rule.getName());
                obj.addProperty("regex", rule.getCompiledRegex().pattern());
                obj.addProperty("group", rule.getGroup());
                arr.add(obj);
            }
            Files.writeString(USER_RULES_FILE, GSON.toJson(arr));
            // Broken-chain fix: the detector reads rules from ConfigManager,
            // which previously never saw this file — reload so user rules
            // take effect immediately.
            if (onRulesSaved != null) onRulesSaved.run();
        } catch (Exception ignored) {}
    }

    private List<SensitiveRule> loadUserRules() {
        try {
            if (!Files.exists(USER_RULES_FILE)) return null;
            String json = Files.readString(USER_RULES_FILE);
            JsonArray arr = JsonParser.parseString(json).getAsJsonArray();
            List<SensitiveRule> loaded = new ArrayList<>();
            for (var elem : arr) {
                JsonObject obj = elem.getAsJsonObject();
                String name = obj.get("name").getAsString();
                String regex = obj.get("regex").getAsString();
                String group = obj.has("group") ? obj.get("group").getAsString() : "default";
                try {
                    loaded.add(new SensitiveRule(name, regex, group));
                } catch (Exception ignored) {}
            }
            return loaded;
        } catch (Exception e) {
            return null;
        }
    }
}
