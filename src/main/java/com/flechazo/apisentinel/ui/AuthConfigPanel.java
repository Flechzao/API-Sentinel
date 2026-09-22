package com.flechazo.apisentinel.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.auth.SessionCredentials;
import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.ConfigManager;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Settings panel for manual auth session configuration.
 *
 * <p>Supports up to 3 sessions (A/B/C) for multi-tier privilege testing.
 * Each session has: label, domain scope, privilege level, Cookie textarea,
 * Auth Headers textarea, and an LED status indicator.
 *
 * <p>The LED indicator shows session validation status:
 * <ul>
 *   <li>Gray: not validated</li>
 *   <li>Green: alive (2xx/3xx response)</li>
 *   <li>Red: expired (401/403 response)</li>
 *   <li>Yellow: unreachable (connection error or no domain configured)</li>
 * </ul>
 *
 * <p>Auto-detect runs when the panel first becomes visible. Auto-validate
 * runs after save and on panel open (if sessions are configured).
 */
public class AuthConfigPanel extends JPanel {

    private static final String[] LEVEL_OPTIONS = {"", "HIGH", "MEDIUM", "LOW"};
    private static final String[] LEVEL_LABELS = {
            I18n.get("auth_level_unknown"), I18n.get("auth_level_high"),
            I18n.get("auth_level_medium"), I18n.get("auth_level_low")};

    private static final int LED_SIZE = 12;

    /** LED status colors. */
    private static final Color LED_GRAY = new Color(160, 160, 160);
    private static final Color LED_GREEN = new Color(40, 180, 50);
    private static final Color LED_RED = new Color(200, 40, 40);
    private static final Color LED_YELLOW = new Color(220, 180, 20);

    // Session A
    private final JTextField labelAField;
    private final JTextField domainAField;
    private final JComboBox<String> levelACombo;
    private final JTextField groupAField;
    private final JTextArea cookieAArea;
    private final JTextArea authHeadersAArea;
    private final JLabel ledA;

    // Session B
    private final JTextField labelBField;
    private final JTextField domainBField;
    private final JComboBox<String> levelBCombo;
    private final JTextField groupBField;
    private final JTextArea cookieBArea;
    private final JTextArea authHeadersBArea;
    private final JLabel ledB;

    // Session C
    private final JTextField labelCField;
    private final JTextField domainCField;
    private final JComboBox<String> levelCCombo;
    private final JTextField groupCField;
    private final JTextArea cookieCArea;
    private final JTextArea authHeadersCArea;
    private final JLabel ledC;

    private final JLabel statusLabel;
    private boolean autoDetectDone = false;

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
        JLabel title = new JLabel(I18n.get("auth_title"));
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        header.add(title, BorderLayout.WEST);

        statusLabel = new JLabel("");
        statusLabel.setFont(theme.displayFont(Font.PLAIN, 12f));
        statusLabel.setForeground(theme.statusOk());
        header.add(statusLabel, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);

        // Hint
        JPanel hintPanel = new JPanel(new BorderLayout());
        JTextArea hint = new JTextArea(I18n.get("auth_hint"));
        hint.setEditable(false);
        hint.setLineWrap(true);
        hint.setWrapStyleWord(true);
        hint.setFont(theme.displayFont(Font.PLAIN, 12f));
        hint.setForeground(theme.mutedText());
        hint.setOpaque(false);
        hint.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        hintPanel.add(hint, BorderLayout.NORTH);

        // Center: three session panels side by side
        JPanel sessionsPanel = new JPanel(new GridLayout(1, 3, 8, 0));

        // Session A
        labelAField = new JTextField();
        domainAField = new JTextField();
        levelACombo = new JComboBox<>(LEVEL_LABELS);
        groupAField = new JTextField();
        cookieAArea = new JTextArea(3, 15);
        authHeadersAArea = new JTextArea(3, 15);
        ledA = new JLabel(createLedIcon(LED_GRAY));
        ledA.setToolTipText(I18n.get("auth_led_unknown"));
        sessionsPanel.add(buildSessionPanel(I18n.get("auth_session_a_border"),
                labelAField, domainAField, levelACombo, groupAField, cookieAArea, authHeadersAArea, ledA));

        // Session B
        labelBField = new JTextField();
        domainBField = new JTextField();
        levelBCombo = new JComboBox<>(LEVEL_LABELS);
        groupBField = new JTextField();
        cookieBArea = new JTextArea(3, 15);
        authHeadersBArea = new JTextArea(3, 15);
        ledB = new JLabel(createLedIcon(LED_GRAY));
        ledB.setToolTipText(I18n.get("auth_led_unknown"));
        sessionsPanel.add(buildSessionPanel(I18n.get("auth_session_b_border"),
                labelBField, domainBField, levelBCombo, groupBField, cookieBArea, authHeadersBArea, ledB));

        // Session C
        labelCField = new JTextField();
        domainCField = new JTextField();
        levelCCombo = new JComboBox<>(LEVEL_LABELS);
        groupCField = new JTextField();
        cookieCArea = new JTextArea(3, 15);
        authHeadersCArea = new JTextArea(3, 15);
        ledC = new JLabel(createLedIcon(LED_GRAY));
        ledC.setToolTipText(I18n.get("auth_led_unknown"));
        sessionsPanel.add(buildSessionPanel(I18n.get("auth_session_c_border"),
                labelCField, domainCField, levelCCombo, groupCField, cookieCArea, authHeadersCArea, ledC));

        hintPanel.add(sessionsPanel, BorderLayout.CENTER);
        add(hintPanel, BorderLayout.CENTER);

        // Bottom buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton saveBtn = new JButton(I18n.get("btn_save"));
        JButton clearBtn = new JButton(I18n.get("btn_clear"));
        JButton reDetectBtn = new JButton(I18n.get("auth_auto_detect"));
        JButton validateBtn = new JButton(I18n.get("auth_validate"));
        reDetectBtn.setToolTipText(I18n.get("auth_auto_detect_tip"));
        validateBtn.setToolTipText(I18n.get("auth_validate_tip"));

        reDetectBtn.addActionListener(e -> { autoDetectDone = false; autoDetectSessions(); });
        validateBtn.addActionListener(e -> validateAllSessions());
        saveBtn.addActionListener(e -> { saveConfig(); validateAllSessions(); });
        clearBtn.addActionListener(e -> clearAll());

        buttons.add(reDetectBtn);
        buttons.add(validateBtn);
        buttons.add(clearBtn);
        buttons.add(saveBtn);
        add(buttons, BorderLayout.SOUTH);

        // Load existing config
        loadConfig();
    }

    /** Trigger auto-detect when the panel first becomes visible. */
    @Override
    public void addNotify() {
        super.addNotify();
        if (!autoDetectDone && api != null) {
            autoDetectSessions();
        }
    }

    private JPanel buildSessionPanel(String title, JTextField labelField,
                                     JTextField domainField, JComboBox<String> levelCombo,
                                     JTextField groupField,
                                     JTextArea cookieArea, JTextArea authHeadersArea,
                                     JLabel ledLabel) {
        JPanel panel = new JPanel(new BorderLayout(0, 3));
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(theme.separator(), 1, true), title,
                TitledBorder.LEFT, TitledBorder.TOP,
                theme.displayFont(Font.PLAIN, 12f), theme.mutedText()));

        // Top: LED + label + domain + level
        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 0, 2, 2);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: LED + Label
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        topPanel.add(ledLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 0;
        topPanel.add(new JLabel(I18n.get("label_colon")), gbc);
        gbc.gridx = 2; gbc.weightx = 1;
        labelField.setToolTipText(I18n.get("auth_label_tip"));
        topPanel.add(labelField, gbc);

        // Row 1: Domain
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        JLabel spacer1 = new JLabel(" ");
        spacer1.setPreferredSize(new Dimension(LED_SIZE, 1));
        topPanel.add(spacer1, gbc);
        gbc.gridx = 1;
        topPanel.add(new JLabel(I18n.get("auth_domain_colon")), gbc);
        gbc.gridx = 2; gbc.weightx = 1;
        domainField.setToolTipText(I18n.get("auth_domain_tip"));
        topPanel.add(domainField, gbc);

        // Row 2: Level
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        JLabel spacer2 = new JLabel(" ");
        spacer2.setPreferredSize(new Dimension(LED_SIZE, 1));
        topPanel.add(spacer2, gbc);
        gbc.gridx = 1;
        topPanel.add(new JLabel(I18n.get("auth_level_colon")), gbc);
        gbc.gridx = 2; gbc.weightx = 1;
        levelCombo.setToolTipText(I18n.get("auth_level_tip"));
        topPanel.add(levelCombo, gbc);

        // Row 3: Group
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        JLabel spacer3 = new JLabel(" ");
        spacer3.setPreferredSize(new Dimension(LED_SIZE, 1));
        topPanel.add(spacer3, gbc);
        gbc.gridx = 1;
        topPanel.add(new JLabel(I18n.get("auth_group_colon")), gbc);
        gbc.gridx = 2; gbc.weightx = 1;
        groupField.setToolTipText(I18n.get("auth_group_tip"));
        topPanel.add(groupField, gbc);

        panel.add(topPanel, BorderLayout.NORTH);

        // Center: two textareas stacked
        JPanel areasPanel = new JPanel(new GridLayout(2, 1, 0, 3));

        cookieArea.setLineWrap(true);
        cookieArea.setWrapStyleWord(true);
        cookieArea.setFont(theme.editorFont(11f));
        cookieArea.setToolTipText(I18n.get("auth_cookie_tip"));
        JScrollPane cookieScroll = new JScrollPane(cookieArea);
        cookieScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(theme.separator(), 1, true),
                I18n.get("auth_cookie_border"),
                TitledBorder.LEFT, TitledBorder.TOP,
                theme.displayFont(Font.PLAIN, 10f), theme.mutedText()));
        areasPanel.add(cookieScroll);

        authHeadersArea.setLineWrap(true);
        authHeadersArea.setWrapStyleWord(true);
        authHeadersArea.setFont(theme.editorFont(11f));
        authHeadersArea.setToolTipText(I18n.get("auth_headers_tip"));
        JScrollPane headersScroll = new JScrollPane(authHeadersArea);
        headersScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(theme.separator(), 1, true),
                I18n.get("auth_headers_border"),
                TitledBorder.LEFT, TitledBorder.TOP,
                theme.displayFont(Font.PLAIN, 10f), theme.mutedText()));
        areasPanel.add(headersScroll);

        panel.add(areasPanel, BorderLayout.CENTER);

        return panel;
    }

    /** Create a small colored circle icon for the LED indicator. */
    private static Icon createLedIcon(Color color) {
        BufferedImage img = new BufferedImage(LED_SIZE, LED_SIZE, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        // Outer ring (darker shade)
        g.setColor(color.darker());
        g.fillOval(0, 0, LED_SIZE, LED_SIZE);
        // Inner glow (lighter shade)
        g.setColor(color.brighter());
        g.fillOval(2, 2, LED_SIZE - 4, LED_SIZE - 4);
        g.dispose();
        return new ImageIcon(img);
    }

    private void loadConfig() {
        AppConfig config = configManager.getConfig();
        loadSession(config.getAuthSessionALabel(), config.getAuthSessionADomain(),
                config.getAuthSessionALevel(), config.getAuthSessionAGroup(),
                config.getAuthSessionACookie(), config.getAuthSessionAAuthHeaders(),
                labelAField, domainAField, levelACombo, groupAField, cookieAArea, authHeadersAArea);
        loadSession(config.getAuthSessionBLabel(), config.getAuthSessionBDomain(),
                config.getAuthSessionBLevel(), config.getAuthSessionBGroup(),
                config.getAuthSessionBCookie(), config.getAuthSessionBAuthHeaders(),
                labelBField, domainBField, levelBCombo, groupBField, cookieBArea, authHeadersBArea);
        loadSession(config.getAuthSessionCLabel(), config.getAuthSessionCDomain(),
                config.getAuthSessionCLevel(), config.getAuthSessionCGroup(),
                config.getAuthSessionCCookie(), config.getAuthSessionCAuthHeaders(),
                labelCField, domainCField, levelCCombo, groupCField, cookieCArea, authHeadersCArea);
    }

    private void loadSession(String label, String domain, String level, String group,
                             String cookie, String headers,
                             JTextField labelField, JTextField domainField,
                             JComboBox<String> levelCombo, JTextField groupField,
                             JTextArea cookieArea, JTextArea headersArea) {
        labelField.setText(label);
        domainField.setText(domain);
        selectLevel(levelCombo, level);
        groupField.setText(group);
        cookieArea.setText(cookie);
        headersArea.setText(headers);
    }

    private void selectLevel(JComboBox<String> combo, String level) {
        if (level == null || level.isBlank()) { combo.setSelectedIndex(0); return; }
        switch (level.toUpperCase()) {
            case "HIGH" -> combo.setSelectedIndex(1);
            case "MEDIUM" -> combo.setSelectedIndex(2);
            case "LOW" -> combo.setSelectedIndex(3);
            default -> combo.setSelectedIndex(0);
        }
    }

    private String getSelectedLevel(JComboBox<String> combo) {
        return switch (combo.getSelectedIndex()) {
            case 1 -> "HIGH";
            case 2 -> "MEDIUM";
            case 3 -> "LOW";
            default -> "";
        };
    }

    private void saveConfig() {
        AppConfig config = configManager.getConfig();
        saveSession(config, "A", labelAField, domainAField, levelACombo, groupAField, cookieAArea, authHeadersAArea);
        saveSession(config, "B", labelBField, domainBField, levelBCombo, groupBField, cookieBArea, authHeadersBArea);
        saveSession(config, "C", labelCField, domainCField, levelCCombo, groupCField, cookieCArea, authHeadersCArea);
        configManager.saveConfig();

        int count = config.countConfiguredSessions();
        if (count >= 2) {
            statusLabel.setText(String.format(I18n.get("auth_saved_ok_n"), count));
            statusLabel.setForeground(theme.statusOk());
        } else if (count == 1) {
            statusLabel.setText(I18n.get("auth_saved_partial"));
            statusLabel.setForeground(theme.statusPending());
        } else {
            statusLabel.setText(I18n.get("auth_saved_empty"));
            statusLabel.setForeground(theme.mutedText());
        }
    }

    private void saveSession(AppConfig config, String slot,
                             JTextField labelField, JTextField domainField,
                             JComboBox<String> levelCombo, JTextField groupField,
                             JTextArea cookieArea, JTextArea headersArea) {
        switch (slot) {
            case "A" -> {
                config.setAuthSessionALabel(labelField.getText().trim());
                config.setAuthSessionADomain(domainField.getText().trim());
                config.setAuthSessionALevel(getSelectedLevel(levelCombo));
                config.setAuthSessionAGroup(groupField.getText().trim());
                config.setAuthSessionACookie(cookieArea.getText().trim());
                config.setAuthSessionAAuthHeaders(headersArea.getText().trim());
            }
            case "B" -> {
                config.setAuthSessionBLabel(labelField.getText().trim());
                config.setAuthSessionBDomain(domainField.getText().trim());
                config.setAuthSessionBLevel(getSelectedLevel(levelCombo));
                config.setAuthSessionBGroup(groupField.getText().trim());
                config.setAuthSessionBCookie(cookieArea.getText().trim());
                config.setAuthSessionBAuthHeaders(headersArea.getText().trim());
            }
            case "C" -> {
                config.setAuthSessionCLabel(labelField.getText().trim());
                config.setAuthSessionCDomain(domainField.getText().trim());
                config.setAuthSessionCLevel(getSelectedLevel(levelCombo));
                config.setAuthSessionCGroup(groupField.getText().trim());
                config.setAuthSessionCCookie(cookieArea.getText().trim());
                config.setAuthSessionCAuthHeaders(headersArea.getText().trim());
            }
        }
    }

    private void clearAll() {
        clearSession(labelAField, domainAField, levelACombo, groupAField, cookieAArea, authHeadersAArea, "会话 A");
        clearSession(labelBField, domainBField, levelBCombo, groupBField, cookieBArea, authHeadersBArea, "会话 B");
        clearSession(labelCField, domainCField, levelCCombo, groupCField, cookieCArea, authHeadersCArea, "会话 C");
        ledA.setIcon(createLedIcon(LED_GRAY)); ledA.setToolTipText(I18n.get("auth_led_unknown"));
        ledB.setIcon(createLedIcon(LED_GRAY)); ledB.setToolTipText(I18n.get("auth_led_unknown"));
        ledC.setIcon(createLedIcon(LED_GRAY)); ledC.setToolTipText(I18n.get("auth_led_unknown"));
        saveConfig();
        statusLabel.setText(I18n.get("auth_cleared"));
        statusLabel.setForeground(theme.mutedText());
    }

    private void clearSession(JTextField labelField, JTextField domainField,
                              JComboBox<String> levelCombo, JTextField groupField,
                              JTextArea cookieArea, JTextArea headersArea, String defaultLabel) {
        labelField.setText(defaultLabel);
        domainField.setText("");
        levelCombo.setSelectedIndex(0);
        groupField.setText("");
        cookieArea.setText("");
        headersArea.setText("");
    }

    public void clearCookies() {
        SwingUtilities.invokeLater(() -> {
            cookieAArea.setText(""); authHeadersAArea.setText("");
            cookieBArea.setText(""); authHeadersBArea.setText("");
            cookieCArea.setText(""); authHeadersCArea.setText("");
            ledA.setIcon(createLedIcon(LED_GRAY)); ledA.setToolTipText(I18n.get("auth_led_unknown"));
            ledB.setIcon(createLedIcon(LED_GRAY)); ledB.setToolTipText(I18n.get("auth_led_unknown"));
            ledC.setIcon(createLedIcon(LED_GRAY)); ledC.setToolTipText(I18n.get("auth_led_unknown"));
            saveConfig();
            statusLabel.setText(I18n.get("auth_cleared_on_import"));
            statusLabel.setForeground(theme.mutedText());
        });
    }

    /**
     * Auto-detect sessions from Burp Proxy History.
     */
    private void autoDetectSessions() {
        autoDetectDone = true;
        if (api == null) {
            statusLabel.setText(I18n.get("auth_burp_unavailable"));
            statusLabel.setForeground(theme.statusError());
            return;
        }
        statusLabel.setText(I18n.get("auth_auto_scanning"));
        statusLabel.setForeground(theme.statusPending());

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
                    statusLabel.setText(I18n.get("auth_no_sessions"));
                    statusLabel.setForeground(theme.statusError());
                    return;
                }
                if (found.size() >= 1) fillFromDetected(found.get(0), "A",
                        labelAField, domainAField, cookieAArea, authHeadersAArea);
                if (found.size() >= 2) fillFromDetected(found.get(1), "B",
                        labelBField, domainBField, cookieBArea, authHeadersBArea);
                if (found.size() >= 3) fillFromDetected(found.get(2), "C",
                        labelCField, domainCField, cookieCArea, authHeadersCArea);
                saveConfig();
                statusLabel.setText(String.format(I18n.get("auth_auto_ok"), found.size()));
                statusLabel.setForeground(theme.statusOk());
                // Auto-validate detected sessions
                validateAllSessions();
            });
        }, "auth-autodetect").start();
    }

    private void fillFromDetected(com.flechazo.apisentinel.auth.SessionInfo info, String slot,
                                  JTextField labelField, JTextField domainField,
                                  JTextArea cookieArea, JTextArea headersArea) {
        cookieArea.setText(info.toCookieHeaderValue());
        headersArea.setText(info.toCredentials().authHeadersToText());
        labelField.setText(String.format(I18n.get("auth_auto_label_n"),
                slot, info.getRequests().size()));
        if (!info.getRequests().isEmpty()) {
            try {
                String url = info.getRequests().get(0).finalRequest().url();
                String host = com.flechazo.apisentinel.util.UrlUtils.extractHost(url);
                domainField.setText(com.flechazo.apisentinel.util.UrlUtils.stripPort(host).toLowerCase());
            } catch (Exception ignored) {}
        }
    }

    /**
     * Programmatically set a session's credentials from an external source.
     */
    public void setSessionFromExternal(String sessionSlot, SessionCredentials credentials, String label) {
        SwingUtilities.invokeLater(() -> {
            JTextField labelField; JTextField domainField; JComboBox<String> levelCombo;
            JTextArea cookieArea; JTextArea headersArea; JLabel led;
            switch (sessionSlot) {
                case "A" -> { labelField = this.labelAField; domainField = this.domainAField;
                    levelCombo = this.levelACombo; cookieArea = this.cookieAArea;
                    headersArea = this.authHeadersAArea; led = this.ledA; }
                case "B" -> { labelField = this.labelBField; domainField = this.domainBField;
                    levelCombo = this.levelBCombo; cookieArea = this.cookieBArea;
                    headersArea = this.authHeadersBArea; led = this.ledB; }
                case "C" -> { labelField = this.labelCField; domainField = this.domainCField;
                    levelCombo = this.levelCCombo; cookieArea = this.cookieCArea;
                    headersArea = this.authHeadersCArea; led = this.ledC; }
                default -> { return; }
            }
            cookieArea.setText(credentials.toCookieHeaderValue());
            headersArea.setText(credentials.authHeadersToText());
            if (label != null && !label.isBlank()) labelField.setText(label);
            // Reset LED — credentials changed, needs re-validation
            led.setIcon(createLedIcon(LED_GRAY));
            led.setToolTipText(I18n.get("auth_led_unknown"));
            saveConfig();
        });
    }

    @Deprecated
    public void setSessionFromExternal(String sessionSlot, String cookie, String label) {
        Map<String, String> cookieMap = com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(cookie);
        setSessionFromExternal(sessionSlot, new SessionCredentials(cookieMap, Map.of()), label);
    }

    // ======================== Session Validation ========================

    /**
     * Validate all configured sessions by sending a test request to each
     * session's domain with its credentials. Runs in a background thread.
     * Updates LED indicators: green = alive, red = expired, yellow = unreachable.
     */
    private void validateAllSessions() {
        if (api == null) return;
        AppConfig config = configManager.getConfig();

        // Reset LEDs to "checking" state (yellow pulsing — just yellow for now)
        setLedChecking(ledA, hasCredentials(config.getAuthSessionACookie(), config.getAuthSessionAAuthHeaders()));
        setLedChecking(ledB, hasCredentials(config.getAuthSessionBCookie(), config.getAuthSessionBAuthHeaders()));
        setLedChecking(ledC, hasCredentials(config.getAuthSessionCCookie(), config.getAuthSessionCAuthHeaders()));

        new Thread(() -> {
            SessionValidation resultA = validateSession(config.getAuthSessionADomain(),
                    config.getAuthSessionACookie(), config.getAuthSessionAAuthHeaders());
            SessionValidation resultB = validateSession(config.getAuthSessionBDomain(),
                    config.getAuthSessionBCookie(), config.getAuthSessionBAuthHeaders());
            SessionValidation resultC = validateSession(config.getAuthSessionCDomain(),
                    config.getAuthSessionCCookie(), config.getAuthSessionCAuthHeaders());

            SwingUtilities.invokeLater(() -> {
                applyValidationResult(ledA, resultA, "A");
                applyValidationResult(ledB, resultB, "B");
                applyValidationResult(ledC, resultC, "C");
                updateValidationStatus(resultA, resultB, resultC);
            });
        }, "auth-validate").start();
    }

    private static boolean hasCredentials(String cookie, String headers) {
        return (cookie != null && !cookie.isBlank()) || (headers != null && !headers.isBlank());
    }

    private void setLedChecking(JLabel led, boolean hasCredentials) {
        if (!hasCredentials) {
            led.setIcon(createLedIcon(LED_GRAY));
            led.setToolTipText(I18n.get("auth_led_unknown"));
        } else {
            led.setIcon(createLedIcon(LED_YELLOW));
            led.setToolTipText(I18n.get("auth_led_checking"));
        }
    }

    /**
     * Validate a single session by sending a GET request to the domain root
     * with the session's credentials attached.
     */
    private SessionValidation validateSession(String domain, String cookie, String authHeadersText) {
        if (!hasCredentials(cookie, authHeadersText)) {
            return new SessionValidation(ValidationState.EMPTY, 0, "");
        }
        if (domain == null || domain.isBlank()) {
            return new SessionValidation(ValidationState.NO_DOMAIN, 0, "");
        }

        try {
            // Build a simple GET request to the domain root
            String url = "https://" + domain + "/";
            HttpRequest req = HttpRequest.httpRequest(
                    burp.api.montoya.http.HttpService.httpService(domain, 443, true),
                    buildRawRequest("GET", "/", domain, cookie, authHeadersText));

            HttpRequestResponse resp = api.http().sendRequest(req);
            if (resp.response() == null) {
                return new SessionValidation(ValidationState.UNREACHABLE, 0, "No response");
            }
            int status = resp.response().statusCode();
            if (status == 401 || status == 403) {
                return new SessionValidation(ValidationState.EXPIRED, status,
                        "HTTP " + status + " — token may be expired");
            }
            if (status >= 200 && status < 400) {
                return new SessionValidation(ValidationState.ALIVE, status,
                        "HTTP " + status + " — session active");
            }
            // 4xx/5xx other than 401/403 — probably alive but endpoint-specific
            return new SessionValidation(ValidationState.ALIVE, status,
                    "HTTP " + status);
        } catch (Exception e) {
            return new SessionValidation(ValidationState.UNREACHABLE, 0,
                    e.getMessage() != null ? e.getMessage() : "Connection failed");
        }
    }

    /** Build a raw HTTP request string with session credentials. */
    private static String buildRawRequest(String method, String path, String host,
                                          String cookie, String authHeadersText) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        if (cookie != null && !cookie.isBlank()) {
            sb.append("Cookie: ").append(cookie).append("\r\n");
        }
        if (authHeadersText != null && !authHeadersText.isBlank()) {
            for (String line : authHeadersText.split("\\r?\\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    sb.append(trimmed).append("\r\n");
                }
            }
        }
        sb.append("\r\n");
        return sb.toString();
    }

    private void applyValidationResult(JLabel led, SessionValidation result, String slot) {
        switch (result.state()) {
            case ALIVE -> {
                led.setIcon(createLedIcon(LED_GREEN));
                led.setToolTipText(String.format(I18n.get("auth_led_alive"), slot, result.statusCode()));
            }
            case EXPIRED -> {
                led.setIcon(createLedIcon(LED_RED));
                led.setToolTipText(String.format(I18n.get("auth_led_expired"), slot, result.statusCode()));
            }
            case UNREACHABLE -> {
                led.setIcon(createLedIcon(LED_YELLOW));
                led.setToolTipText(String.format(I18n.get("auth_led_unreachable"), slot, result.detail()));
            }
            case NO_DOMAIN -> {
                led.setIcon(createLedIcon(LED_YELLOW));
                led.setToolTipText(I18n.get("auth_led_no_domain"));
            }
            case EMPTY -> {
                led.setIcon(createLedIcon(LED_GRAY));
                led.setToolTipText(I18n.get("auth_led_unknown"));
            }
        }
    }

    private void updateValidationStatus(SessionValidation a, SessionValidation b, SessionValidation c) {
        int alive = 0, expired = 0, total = 0;
        for (SessionValidation v : List.of(a, b, c)) {
            if (v.state() == ValidationState.EMPTY) continue;
            total++;
            if (v.state() == ValidationState.ALIVE) alive++;
            if (v.state() == ValidationState.EXPIRED) expired++;
        }
        if (total == 0) {
            statusLabel.setText(I18n.get("auth_validate_none"));
            statusLabel.setForeground(theme.mutedText());
        } else if (expired > 0) {
            statusLabel.setText(String.format(I18n.get("auth_validate_expired"), expired, total));
            statusLabel.setForeground(theme.statusError());
        } else if (alive == total) {
            statusLabel.setText(String.format(I18n.get("auth_validate_ok"), alive));
            statusLabel.setForeground(theme.statusOk());
        } else {
            statusLabel.setText(String.format(I18n.get("auth_validate_partial"), alive, total));
            statusLabel.setForeground(theme.statusPending());
        }
    }

    // ======================== Validation Types ========================

    private enum ValidationState { EMPTY, NO_DOMAIN, ALIVE, EXPIRED, UNREACHABLE }

    private record SessionValidation(ValidationState state, int statusCode, String detail) {}
}
