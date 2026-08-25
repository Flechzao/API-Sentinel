package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.ConfigManager;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.List;

/**
 * Settings panel for manual auth session configuration.
 * Users can paste two sets of cookies (Session A / Session B) and label them
 * (e.g. "管理员" / "普通用户"). When auto-discovery can't find 2 sessions,
 * the pipeline falls back to these manual entries.
 */
public class AuthConfigPanel extends JPanel {

    private final JTextField labelAField;
    private final JTextArea cookieAArea;
    private final JTextField labelBField;
    private final JTextArea cookieBArea;
    private final JLabel statusLabel;

    private final ConfigManager configManager;
    private final BurpTheme theme;
    private final burp.api.montoya.MontoyaApi api;

    public AuthConfigPanel(ConfigManager configManager, BurpTheme theme) {
        this(configManager, theme, null);
    }

    public AuthConfigPanel(ConfigManager configManager, BurpTheme theme,
                           burp.api.montoya.MontoyaApi api) {
        this.configManager = configManager;
        this.theme = theme;
        this.api = api;
        setLayout(new BorderLayout(0, 8));

        // Header
        JPanel header = new JPanel(new BorderLayout(8, 0));
        JLabel title = new JLabel("越权检测 — 会话配置");
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        header.add(title, BorderLayout.WEST);

        statusLabel = new JLabel("");
        statusLabel.setFont(theme.displayFont(Font.PLAIN, 12f));
        statusLabel.setForeground(theme.statusOk());
        header.add(statusLabel, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);

        // Hint
        JPanel hintPanel = new JPanel(new BorderLayout());
        JTextArea hint = new JTextArea(
                "手动配置两组会话的 Cookie，用于越权检测。\n"
                + "如果 Proxy History 中能自动发现多个会话，则优先使用自动发现的结果。\n"
                + "粘贴格式：key1=val1; key2=val2; key3=val3\n"
                + "也可通过「查看历史流量」右键 → 提取为会话 A/B 快速填入。");
        hint.setEditable(false);
        hint.setLineWrap(true);
        hint.setWrapStyleWord(true);
        hint.setFont(theme.displayFont(Font.PLAIN, 12f));
        hint.setForeground(theme.mutedText());
        hint.setOpaque(false);
        hint.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        hintPanel.add(hint, BorderLayout.NORTH);

        // Center: two session panels side by side
        JPanel sessionsPanel = new JPanel(new GridLayout(1, 2, 12, 0));

        sessionsPanel.add(buildSessionPanel("会话 A（如：管理员 / 用户 A）",
                labelAField = new JTextField(),
                cookieAArea = new JTextArea(6, 30)));

        sessionsPanel.add(buildSessionPanel("会话 B（如：普通用户 / 用户 B）",
                labelBField = new JTextField(),
                cookieBArea = new JTextArea(6, 30)));

        hintPanel.add(sessionsPanel, BorderLayout.CENTER);
        add(hintPanel, BorderLayout.CENTER);

        // Bottom buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton autoDetectBtn = new JButton("从流量自动识别会话");
        JButton saveBtn = new JButton("保存");
        JButton clearBtn = new JButton("清空");

        autoDetectBtn.setToolTipText("扫描 Proxy History，自动发现不同的已认证会话并填入会话 A/B");
        autoDetectBtn.addActionListener(e -> autoDetectSessions());
        saveBtn.addActionListener(e -> saveConfig());
        clearBtn.addActionListener(e -> clearAll());

        buttons.add(autoDetectBtn);
        buttons.add(clearBtn);
        buttons.add(saveBtn);
        add(buttons, BorderLayout.SOUTH);

        // Load existing config
        loadConfig();
    }

    private JPanel buildSessionPanel(String title, JTextField labelField, JTextArea cookieArea) {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        // Rounded line border (matches ToolbarPanel/OobConfigPanel's
        // group style) instead of the old etched 3D relief, which reads as a
        // decade-old dialog style next to the rest of the app's rounded cards.
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(theme.separator(), 1, true), title,
                TitledBorder.LEFT, TitledBorder.TOP,
                theme.displayFont(Font.PLAIN, 12f), theme.mutedText()));

        JPanel labelRow = new JPanel(new BorderLayout(4, 0));
        labelRow.add(new JLabel("标签: "), BorderLayout.WEST);
        labelField.setToolTipText("例如：管理员、用户A、测试账号");
        labelRow.add(labelField, BorderLayout.CENTER);
        panel.add(labelRow, BorderLayout.NORTH);

        cookieArea.setLineWrap(true);
        cookieArea.setWrapStyleWord(true);
        cookieArea.setFont(theme.editorFont(12f));
        cookieArea.setToolTipText("粘贴 Cookie 值，格式: key1=val1; key2=val2");
        JScrollPane scroll = new JScrollPane(cookieArea);
        scroll.setBorder(BorderFactory.createTitledBorder("Cookie"));
        panel.add(scroll, BorderLayout.CENTER);

        return panel;
    }

    private void loadConfig() {
        AppConfig config = configManager.getConfig();
        labelAField.setText(config.getAuthSessionALabel());
        cookieAArea.setText(config.getAuthSessionACookie());
        labelBField.setText(config.getAuthSessionBLabel());
        cookieBArea.setText(config.getAuthSessionBCookie());
    }

    private void saveConfig() {
        AppConfig config = configManager.getConfig();
        config.setAuthSessionALabel(labelAField.getText().trim());
        config.setAuthSessionACookie(cookieAArea.getText().trim());
        config.setAuthSessionBLabel(labelBField.getText().trim());
        config.setAuthSessionBCookie(cookieBArea.getText().trim());
        configManager.saveConfig();

        if (config.hasManualAuthSessions()) {
            statusLabel.setText("已保存（2 组会话已配置）");
            statusLabel.setForeground(theme.statusOk());
        } else {
            statusLabel.setText("已保存（未完整配置）");
            statusLabel.setForeground(theme.statusPending());
        }
    }

    private void clearAll() {
        labelAField.setText("会话 A");
        cookieAArea.setText("");
        labelBField.setText("会话 B");
        cookieBArea.setText("");
        saveConfig();
        statusLabel.setText("已清空");
        statusLabel.setForeground(theme.mutedText());
    }

    public void clearCookies() {
        SwingUtilities.invokeLater(() -> {
            cookieAArea.setText("");
            cookieBArea.setText("");
            saveConfig();
            statusLabel.setText("已清空（数据导入时自动重置）");
            statusLabel.setForeground(theme.mutedText());
        });
    }

    /** Scan recent proxy history for distinct authenticated sessions and fill the
     *  two most active into Session A/B. Gives users a one-click way to populate
     *  the cookies instead of copy-pasting manually. */
    private void autoDetectSessions() {
        if (api == null) {
            statusLabel.setText("Burp API 不可用");
            statusLabel.setForeground(theme.statusError());
            return;
        }
        new Thread(() -> {
            List<com.flechazo.apisentinel.auth.SessionInfo> sessions;
            try {
                sessions = new com.flechazo.apisentinel.auth.SessionDiscovery(api)
                        .discoverRecentSessions();
            } catch (Exception e) {
                sessions = List.of();
            }
            final List<com.flechazo.apisentinel.auth.SessionInfo> found = sessions;
            SwingUtilities.invokeLater(() -> {
                if (found.isEmpty()) {
                    statusLabel.setText("未在 Proxy History 中发现带认证信息的会话");
                    statusLabel.setForeground(theme.statusError());
                    return;
                }
                if (found.size() >= 1) {
                    cookieAArea.setText(found.get(0).toCookieHeaderValue());
                    labelAField.setText("自动识别会话 A（" + found.get(0).getRequests().size() + " 请求）");
                }
                if (found.size() >= 2) {
                    cookieBArea.setText(found.get(1).toCookieHeaderValue());
                    labelBField.setText("自动识别会话 B（" + found.get(1).getRequests().size() + " 请求）");
                }
                saveConfig();
                if (found.size() >= 2) {
                    statusLabel.setText("已自动识别 " + found.size() + " 个会话，填入 A/B（共发现 " + found.size() + "）");
                    statusLabel.setForeground(theme.statusOk());
                } else {
                    statusLabel.setText("仅识别到 1 个会话（已填入 A）；越权检测需要至少 2 个，请用另一账户再访问");
                    statusLabel.setForeground(theme.riskMedium());
                }
            });
        }, "auth-autodetect").start();
    }

    /**
     * Programmatically set a session's cookie from external source (e.g. right-click menu).
     *
     * @param sessionSlot "A" or "B"
     * @param cookie      the raw Cookie header value
     * @param label       optional label (null = keep existing)
     */
    public void setSessionFromExternal(String sessionSlot, String cookie, String label) {
        SwingUtilities.invokeLater(() -> {
            if ("A".equals(sessionSlot)) {
                cookieAArea.setText(cookie);
                if (label != null && !label.isBlank()) labelAField.setText(label);
            } else {
                cookieBArea.setText(cookie);
                if (label != null && !label.isBlank()) labelBField.setText(label);
            }
            saveConfig();
        });
    }
}
