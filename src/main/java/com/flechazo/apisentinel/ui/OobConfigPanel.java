package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.detection.OobService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Settings sub-tab for the OOB (blind SSRF) callback platform.
 *
 * <p>The on/off switch lives in the top toolbar (next to 敏感信息/越权检查);
 * this panel configures which platform and how to reach it:
 * <ul>
 *   <li><b>collaborator</b> — Burp Pro built-in; needs no extra fields.</li>
 *   <li><b>internal</b> — a self-managed dnslog; requires a base domain,
 *       optionally a reachability-check URL.</li>
 * </ul>
 *
 * <p>No token field — most dnslog platforms don't use one. Per design, the
 * service does not query echo results; the "测试平台可用性" button only
 * verifies the platform is reachable / usable.
 */
public class OobConfigPanel extends JPanel {

    private final ConfigManager configManager;
    private final OobService oobService;
    private final JComboBox<String> providerCombo;
    private final JTextField baseDomainField;
    private final JTextField testUrlField;
    private final JLabel baseDomainLabel;
    private final JLabel testUrlLabel;
    private final JButton testButton;
    private final JLabel statusLabel;
    private final BurpTheme theme;

    private static final int FIELD_WIDTH = 320;

    public OobConfigPanel(ConfigManager cm, OobService oobService, BurpTheme theme) {
        this.configManager = cm;
        this.oobService = oobService;
        this.theme = theme;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(16, 18, 18, 18));

        JPanel form = new JPanel(new GridBagLayout());
        // Opaque (the JPanel default) + a rounded LineBorder is the same
        // "square fill peeking out from under a rounded stroke" bug already
        // fixed elsewhere (FilterBar/ToastNotification) — setOpaque(false)
        // removes the square fill entirely, leaving only the rounded stroke.
        form.setOpaque(false);
        form.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(theme.separator(), 1, true),
                "回连平台配置",
                TitledBorder.LEADING, TitledBorder.TOP,
                theme.displayFont(Font.BOLD, 13f),
                theme.mutedText()));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 8, 6, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        int row = 0;

        // Description (plain text area — no <html> rendering issues)
        JTextArea desc = new JTextArea(
                "总开关在顶部工具栏「OOB探针」复选框。本页配置回连平台类型与参数。\n"
                + "生成探针后，回连命中需在对应平台手动查询（本工具不自动查回显）。\n"
                + "collaborator 需 Burp 专业版；internal 需填写基础域名。");
        desc.setEditable(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setOpaque(false);
        desc.setFont(theme.displayFont(Font.PLAIN, 12f));
        desc.setForeground(theme.mutedText());
        desc.setBorder(new EmptyBorder(0, 0, 8, 0));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        form.add(desc, gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridwidth = 1;
        row++;

        // Provider row
        gbc.gridx = 0; gbc.gridy = row;
        form.add(label("回连平台:"), gbc);
        providerCombo = new JComboBox<>(new String[]{"collaborator", "internal"});
        providerCombo.setFont(theme.displayFont(Font.PLAIN, 12f));
        providerCombo.setPreferredSize(new Dimension(FIELD_WIDTH, 26));
        providerCombo.addActionListener(e -> { applyToConfig(); toggleInternalFields(); });
        gbc.gridx = 1; gbc.gridy = row;
        form.add(providerCombo, gbc);
        row++;

        // Base domain row (internal only)
        baseDomainLabel = label("基础域名:");
        gbc.gridx = 0; gbc.gridy = row;
        form.add(baseDomainLabel, gbc);
        baseDomainField = new JTextField("xxx.dnslog.cn");
        baseDomainField.setFont(theme.displayFont(Font.PLAIN, 12f));
        baseDomainField.setPreferredSize(new Dimension(FIELD_WIDTH, 26));
        baseDomainField.addActionListener(e -> applyToConfig());
        gbc.gridx = 1; gbc.gridy = row;
        form.add(baseDomainField, gbc);
        row++;

        // Test URL row (internal only)
        testUrlLabel = label("平台测试URL:");
        gbc.gridx = 0; gbc.gridy = row;
        form.add(testUrlLabel, gbc);
        testUrlField = new JTextField("https://your-dnslog/api/check");
        testUrlField.setFont(theme.displayFont(Font.PLAIN, 12f));
        testUrlField.setPreferredSize(new Dimension(FIELD_WIDTH, 26));
        testUrlField.addActionListener(e -> applyToConfig());
        gbc.gridx = 1; gbc.gridy = row;
        form.add(testUrlField, gbc);
        row++;

        // Test button + status row
        testButton = new JButton("测试平台可用性");
        testButton.setFont(theme.displayFont(Font.PLAIN, 12f));
        testButton.setMargin(new Insets(4, 10, 4, 10));
        testButton.addActionListener(e -> testPlatform());
        gbc.gridx = 0; gbc.gridy = row;
        form.add(testButton, gbc);

        statusLabel = new JLabel(" ");
        statusLabel.setFont(theme.displayFont(Font.ITALIC, 12f));
        gbc.gridx = 1; gbc.gridy = row; gbc.fill = GridBagConstraints.HORIZONTAL;
        form.add(statusLabel, gbc);
        gbc.fill = GridBagConstraints.NONE;
        row++;

        // Vertical glue to keep content top-aligned
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        form.add(Box.createVerticalGlue(), gbc);

        add(form, BorderLayout.CENTER);

        loadFromConfig();
        toggleInternalFields();
    }

    private JLabel label(String text) {
        JLabel l = new JLabel(text);
        l.setFont(theme.displayFont(Font.PLAIN, 12f));
        l.setPreferredSize(new Dimension(90, 26));
        l.setHorizontalAlignment(SwingConstants.RIGHT);
        return l;
    }

    /** Show/hide the internal-only fields (base domain + test URL). */
    private void toggleInternalFields() {
        boolean internal = "internal".equals(providerCombo.getSelectedItem());
        baseDomainLabel.setVisible(internal);
        baseDomainField.setVisible(internal);
        testUrlLabel.setVisible(internal);
        testUrlField.setVisible(internal);
        revalidate();
        repaint();
    }

    private void loadFromConfig() {
        AppConfig cfg = configManager != null ? configManager.getConfig() : null;
        if (cfg == null) return;
        providerCombo.setSelectedItem("internal".equalsIgnoreCase(cfg.getOobProvider()) ? "internal" : "collaborator");
        baseDomainField.setText(cfg.getOobInternalBaseDomain());
        testUrlField.setText(cfg.getOobInternalTestUrl());
    }

    private void applyToConfig() {
        if (configManager == null) return;
        AppConfig cfg = configManager.getConfig();
        cfg.setOobProvider((String) providerCombo.getSelectedItem());
        cfg.setOobInternalBaseDomain(baseDomainField.getText());
        cfg.setOobInternalTestUrl(testUrlField.getText());
        configManager.saveConfig();
    }

    private void testPlatform() {
        if (oobService == null) {
            statusLabel.setText("OOB 服务未注入");
            statusLabel.setForeground(theme.statusError());
            return;
        }
        applyToConfig();
        testButton.setEnabled(false);
        testButton.setText("测试中...");
        statusLabel.setText("正在验证平台可用性...");
        statusLabel.setForeground(theme.statusPending());

        oobService.testConnection().thenAccept(result -> SwingUtilities.invokeLater(() -> {
            statusLabel.setText(result.message);
            statusLabel.setForeground(result.success ? theme.statusOk() : theme.statusError());
            testButton.setText("测试平台可用性");
            testButton.setEnabled(true);
        })).exceptionally(ex -> {
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("验证异常: " + ex.getMessage());
                statusLabel.setForeground(theme.statusError());
                testButton.setText("测试平台可用性");
                testButton.setEnabled(true);
            });
            return null;
        });
    }
}
