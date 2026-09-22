package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.ConfigManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Settings sub-tab (设置 → 高级 → MCP) for the MCP Server / 外脑模式.
 *
 * <p>Lets the user enable the loopback MCP server and pick its port, and — once
 * the server is running — shows the endpoint URL, the Bearer auth token and a
 * ready-to-paste client config (Claude Code / Codex / Qoder).
 *
 * <p>The enable flag and port are read by {@code ApiSentinelExtension} at
 * <b>load time</b>, so a change here is persisted immediately but only takes
 * effect after the extension is reloaded. Runtime info (running state + token)
 * is pushed in via {@link #setRuntimeInfo} after the server actually starts.
 */
public class McpConfigPanel extends JPanel {

    private final ConfigManager configManager;
    private final BurpTheme theme;

    private final JCheckBox enabledCheck;
    private final JCheckBox activeToolsCheck;
    private final JCheckBox requireAuthCheck;
    private final JButton regenTokenButton;
    private final JTextField portField;
    private final JButton restartButton;
    private final JLabel statusLabel;
    private final JTextField tokenField;
    private final JButton copyTokenButton;
    private final JTextArea configPreview;
    private final JButton copyConfigButton;

    // Burp 官方 MCP（流量桥）检测
    private final JTextField burpMcpPortField;
    private final JLabel burpMcpStatusLabel;
    private final JButton redetectBurpButton;
    private volatile boolean burpMcpDetected = false;

    /** Fired (on EDT) when an async Burp-MCP detection completes, so the
     *  welcome page can refresh its status chip. */
    public interface BurpMcpDetectionCallback {
        void onBurpMcpDetected(boolean detected, int port);
    }
    private BurpMcpDetectionCallback onBurpMcpDetected;
    public void setOnBurpMcpDetected(BurpMcpDetectionCallback cb) { this.onBurpMcpDetected = cb; }
    public boolean isBurpMcpDetected() { return burpMcpDetected; }

    /** Fired when the user toggles enable / changes port — the extension
     *  starts/stops the MCP server live (no extension reload needed). */
    public interface McpControlCallback {
        void onMcpControlChanged(boolean enabled, int port);
    }
    private McpControlCallback onMcpControl;

    public void setOnMcpControl(McpControlCallback cb) { this.onMcpControl = cb; }

    /** Runtime state pushed by the extension after the server starts. */
    private boolean running = false;
    private String runtimeToken = null;
    private int runtimePort = 9877;

    private static final int FIELD_WIDTH = 320;

    public McpConfigPanel(ConfigManager cm, BurpTheme theme) {
        this.configManager = cm;
        this.theme = theme;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(16, 18, 18, 18));

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        form.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(theme.separator(), 1, true),
                I18n.get("mcp_config_title"),
                TitledBorder.LEADING, TitledBorder.TOP,
                theme.displayFont(Font.BOLD, 13f),
                theme.mutedText()));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 8, 6, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        int row = 0;

        JTextArea desc = new JTextArea(
                I18n.get("mcp_config_desc"));
        desc.setEditable(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setOpaque(false);
        desc.setFont(theme.displayFont(Font.PLAIN, 12f));
        desc.setForeground(theme.mutedText());
        desc.setBorder(new EmptyBorder(0, 0, 8, 0));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        form.add(desc, gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.gridwidth = 1;
        row++;

        // Enable checkbox
        enabledCheck = new JCheckBox(I18n.get("mcp_enable"));
        enabledCheck.setFont(theme.displayFont(Font.PLAIN, 12f));
        enabledCheck.setOpaque(false);
        enabledCheck.addActionListener(e -> { applyToConfig(); fireControl(); });
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        form.add(enabledCheck, gbc);
        gbc.gridwidth = 1;
        row++;

        // Active-tools gate: expose the full agent arsenal (send_request,
        // active probes, browser login/interact, verify_*) to MCP clients.
        // Off by default — this lets the external brain drive attack traffic
        // through Burp, so it's an explicit opt-in.
        activeToolsCheck = new JCheckBox(I18n.get("mcp_active_tools"));
        activeToolsCheck.setFont(theme.displayFont(Font.PLAIN, 12f));
        activeToolsCheck.setOpaque(false);
        activeToolsCheck.setToolTipText(I18n.get("mcp_active_tools_tooltip"));
        activeToolsCheck.addActionListener(e -> applyToConfig());
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        form.add(activeToolsCheck, gbc);
        gbc.gridwidth = 1;
        row++;

        // Require-auth gate: our MCP is Bearer-token authenticated by default.
        // Turn off to match Burp's native MCP (loopback + Origin/Host only).
        requireAuthCheck = new JCheckBox(I18n.get("mcp_require_auth"));
        requireAuthCheck.setFont(theme.displayFont(Font.PLAIN, 12f));
        requireAuthCheck.setOpaque(false);
        requireAuthCheck.setToolTipText(I18n.get("mcp_require_auth_tooltip"));
        requireAuthCheck.addActionListener(e -> { applyToConfig(); refreshRuntimeUI(); fireControl(); });
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        form.add(requireAuthCheck, gbc);
        gbc.gridwidth = 1;
        row++;

        // Port row
        gbc.gridx = 0; gbc.gridy = row;
        form.add(label(I18n.get("mcp_port_label")), gbc);
        portField = new JTextField("9877");
        portField.setFont(theme.displayFont(Font.PLAIN, 12f));
        portField.setPreferredSize(new Dimension(120, 26));
        portField.addActionListener(e -> { applyToConfig(); fireControl(); });
        gbc.gridx = 1; gbc.gridy = row;
        form.add(portField, gbc);
        row++;

        // Explicit (re)start button — a deterministic trigger that doesn't
        // depend on toggling the checkbox or pressing Enter in the port field.
        restartButton = new JButton(I18n.get("mcp_restart"));
        restartButton.setFont(theme.displayFont(Font.PLAIN, 12f));
        restartButton.setMargin(new Insets(3, 10, 3, 10));
        restartButton.addActionListener(e -> { applyToConfig(); fireControl(); });
        gbc.gridx = 1; gbc.gridy = row;
        form.add(restartButton, gbc);
        row++;

        // Runtime status row
        gbc.gridx = 0; gbc.gridy = row;
        form.add(label(I18n.get("mcp_status_label")), gbc);
        statusLabel = new JLabel(" ");
        statusLabel.setFont(theme.displayFont(Font.PLAIN, 12f));
        gbc.gridx = 1; gbc.gridy = row; gbc.fill = GridBagConstraints.HORIZONTAL;
        form.add(statusLabel, gbc);
        gbc.fill = GridBagConstraints.NONE;
        row++;

        // Token row
        gbc.gridx = 0; gbc.gridy = row;
        form.add(label(I18n.get("mcp_auth_token")), gbc);
        JPanel tokenRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        tokenRow.setOpaque(false);
        tokenField = new JTextField();
        tokenField.setEditable(false);
        tokenField.setFont(theme.editorFont(12f));
        tokenField.setPreferredSize(new Dimension(FIELD_WIDTH, 26));
        copyTokenButton = new JButton(I18n.get("mcp_copy"));
        copyTokenButton.setFont(theme.displayFont(Font.PLAIN, 12f));
        copyTokenButton.setMargin(new Insets(2, 8, 2, 8));
        copyTokenButton.addActionListener(e -> copyToClipboard(runtimeToken, I18n.get("mcp_token_copied")));
        regenTokenButton = new JButton(I18n.get("mcp_regen_token"));
        regenTokenButton.setFont(theme.displayFont(Font.PLAIN, 12f));
        regenTokenButton.setMargin(new Insets(2, 8, 2, 8));
        regenTokenButton.setToolTipText(I18n.get("mcp_regen_tooltip"));
        regenTokenButton.addActionListener(e -> {
            if (configManager != null) {
                configManager.setMcpAuthToken(com.flechazo.apisentinel.mcp.McpServer.mintToken());
                fireControl();   // restart so the new token takes effect
            }
        });
        tokenRow.add(tokenField);
        tokenRow.add(copyTokenButton);
        tokenRow.add(regenTokenButton);
        gbc.gridx = 1; gbc.gridy = row;
        form.add(tokenRow, gbc);
        row++;

        // ===== Burp 官方 MCP（流量桥）检测 =====
        JLabel burpSection = new JLabel(I18n.get("mcp_burp_section"));
        burpSection.setFont(theme.displayFont(Font.BOLD, 12f));
        burpSection.setForeground(theme.mutedText());
        burpSection.setBorder(new EmptyBorder(10, 0, 2, 0));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        form.add(burpSection, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0; gbc.gridy = row;
        form.add(label(I18n.get("mcp_burp_port_label")), gbc);
        burpMcpPortField = new JTextField("9876");
        burpMcpPortField.setFont(theme.displayFont(Font.PLAIN, 12f));
        burpMcpPortField.setPreferredSize(new Dimension(120, 26));
        burpMcpPortField.setToolTipText(I18n.get("mcp_burp_port_tooltip"));
        burpMcpPortField.addActionListener(e -> detectBurpMcpAsync());
        gbc.gridx = 1; gbc.gridy = row;
        form.add(burpMcpPortField, gbc);
        row++;

        gbc.gridx = 0; gbc.gridy = row;
        form.add(label(I18n.get("mcp_bridge_label")), gbc);
        JPanel burpStatusRow = new JPanel(new BorderLayout(6, 0));
        burpStatusRow.setOpaque(false);
        burpMcpStatusLabel = new JLabel(I18n.get("mcp_detecting"));
        burpMcpStatusLabel.setFont(theme.displayFont(Font.PLAIN, 12f));
        burpMcpStatusLabel.setForeground(theme.statusPending());
        burpStatusRow.add(burpMcpStatusLabel, BorderLayout.CENTER);
        redetectBurpButton = new JButton(I18n.get("mcp_redetect"));
        redetectBurpButton.setFont(theme.displayFont(Font.PLAIN, 12f));
        redetectBurpButton.setMargin(new Insets(2, 8, 2, 8));
        redetectBurpButton.addActionListener(e -> detectBurpMcpAsync());
        burpStatusRow.add(redetectBurpButton, BorderLayout.EAST);
        gbc.gridx = 1; gbc.gridy = row; gbc.fill = GridBagConstraints.HORIZONTAL;
        form.add(burpStatusRow, gbc);
        gbc.fill = GridBagConstraints.NONE;
        row++;

        add(form, BorderLayout.NORTH);

        // Client config preview + copy
        JPanel previewPanel = new JPanel(new BorderLayout(0, 6));
        previewPanel.setOpaque(false);
        previewPanel.setBorder(new EmptyBorder(12, 2, 0, 2));

        // Build the preview area first so the copy button's listener can
        // safely reference the (blank-final) configPreview field.
        configPreview = new JTextArea(8, 40);
        configPreview.setEditable(false);
        configPreview.setFont(theme.editorFont(12f));
        configPreview.setLineWrap(false);
        JScrollPane previewScroll = new JScrollPane(configPreview);
        previewScroll.setBorder(BorderFactory.createLineBorder(theme.separator(), 1, true));

        JPanel previewHeader = new JPanel(new BorderLayout());
        previewHeader.setOpaque(false);
        JLabel previewTitle = new JLabel(I18n.get("mcp_client_config_title"));
        previewTitle.setFont(theme.displayFont(Font.BOLD, 12f));
        previewTitle.setForeground(theme.mutedText());
        previewHeader.add(previewTitle, BorderLayout.WEST);
        copyConfigButton = new JButton(I18n.get("mcp_copy_config"));
        copyConfigButton.setFont(theme.displayFont(Font.PLAIN, 12f));
        copyConfigButton.setMargin(new Insets(2, 10, 2, 10));
        copyConfigButton.addActionListener(e -> copyToClipboard(configPreview.getText(), I18n.get("mcp_config_copied")));
        previewHeader.add(copyConfigButton, BorderLayout.EAST);

        previewPanel.add(previewHeader, BorderLayout.NORTH);
        previewPanel.add(previewScroll, BorderLayout.CENTER);

        // Wrap the whole panel (form + preview) in a scroll pane so the long
        // config never overflows the settings dialog when height is limited.
        JPanel body = new JPanel(new BorderLayout());
        body.setOpaque(false);
        body.add(form, BorderLayout.NORTH);
        body.add(previewPanel, BorderLayout.CENTER);
        JScrollPane outerScroll = new JScrollPane(body);
        outerScroll.setBorder(null);
        outerScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        outerScroll.getVerticalScrollBar().setUnitIncrement(16);
        add(outerScroll, BorderLayout.CENTER);

        loadFromConfig();
        refreshRuntimeUI();
        // Burp-MCP detection is driven by ApiSentinelTab after it wires the
        // detection callback, so the welcome-page chip gets the first result.

        // Auto-refresh on language toggle
        I18n.addLangListener(lang -> javax.swing.SwingUtilities.invokeLater(() -> {
            enabledCheck.setText(I18n.get("mcp_enable"));
            activeToolsCheck.setText(I18n.get("mcp_active_tools"));
            requireAuthCheck.setText(I18n.get("mcp_require_auth"));
            restartButton.setText(I18n.get("mcp_restart"));
            copyTokenButton.setText(I18n.get("mcp_copy"));
            regenTokenButton.setText(I18n.get("mcp_regen_token"));
        }));
    }

    private JLabel label(String text) {
        JLabel l = new JLabel(text);
        l.setFont(theme.displayFont(Font.PLAIN, 12f));
        l.setPreferredSize(new Dimension(90, 26));
        l.setHorizontalAlignment(SwingConstants.RIGHT);
        return l;
    }

    private void loadFromConfig() {
        AppConfig cfg = configManager != null ? configManager.getConfig() : null;
        if (cfg == null) return;
        enabledCheck.setSelected(cfg.isMcpServerEnabled());
        activeToolsCheck.setSelected(cfg.isMcpAllowActiveTools());
        requireAuthCheck.setSelected(cfg.isMcpRequireAuth());
        portField.setText(String.valueOf(cfg.getMcpServerPort() > 0 ? cfg.getMcpServerPort() : 9877));
    }

    private void applyToConfig() {
        if (configManager == null) return;
        configManager.setMcpServerEnabled(enabledCheck.isSelected());
        configManager.setMcpAllowActiveTools(activeToolsCheck.isSelected());
        configManager.setMcpRequireAuth(requireAuthCheck.isSelected());
        configManager.setMcpServerPort(parsedPort());
    }

    /** Ask the extension to start/stop the server live to match the controls. */
    private void fireControl() {
        if (onMcpControl != null) {
            statusLabel.setText(I18n.get("mcp_applying"));
            statusLabel.setForeground(theme.statusPending());
            onMcpControl.onMcpControlChanged(enabledCheck.isSelected(), parsedPort());
        } else {
            refreshRuntimeUI();
        }
    }

    private int parsedPort() {
        try {
            int p = Integer.parseInt(portField.getText().trim());
            return p > 0 && p <= 65535 ? p : 9877;
        } catch (NumberFormatException e) {
            return 9877;
        }
    }

    private int getBurpMcpPort() {
        try {
            int p = Integer.parseInt(burpMcpPortField.getText().trim());
            return p > 0 && p <= 65535 ? p : 9876;
        } catch (NumberFormatException e) {
            return 9876;
        }
    }

    /**
     * Probe whether the official Burp MCP Server BApp is installed AND enabled,
     * by checking that 127.0.0.1:&lt;port&gt; speaks the MCP SSE handshake
     * (emits an {@code event: endpoint} / sessionId). Uses only {@link java.net.Socket}
     * ({@code java.base}) so it works under Burp's trimmed JRE.
     */
    public static boolean probeBurpMcp(int port) {
        if (port <= 0 || port > 65535) return false;
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress("127.0.0.1", port), 600);
            s.setSoTimeout(800);
            java.io.OutputStream os = s.getOutputStream();
            os.write(("GET / HTTP/1.1\r\nHost: 127.0.0.1:" + port
                    + "\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n\r\n")
                    .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            os.flush();
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[1024];
            int n;
            // SSE streams stay open after the initial endpoint event — so read()
            // eventually blocks until soTimeout. A SocketTimeoutException is NOT
            // an error here; it just means "no more data right now", and the
            // endpoint event is already in buf. Check buf content, not the
            // exception, to decide whether the MCP handshake succeeded.
            try {
                while ((n = s.getInputStream().read(b)) > 0) {
                    buf.write(b, 0, n);
                    if (buf.size() > 4096) break;
                }
            } catch (java.net.SocketTimeoutException ste) {
                // expected — fall through to check what we already read
            }
            String resp = buf.toString(java.nio.charset.StandardCharsets.UTF_8);
            return resp.contains("event: endpoint") || resp.contains("text/event-stream");
        } catch (Exception e) {
            return false;
        }
    }

    /** Async (background-thread) detection; updates the label + config preview
     *  on the EDT and fires the detection callback for the welcome page.
     *  Retries a few times because the official BApp may load after us. */
    public void detectBurpMcpAsync() {
        final int port = getBurpMcpPort();
        burpMcpStatusLabel.setText(I18n.get("mcp_detecting"));
        burpMcpStatusLabel.setForeground(theme.statusPending());
        redetectBurpButton.setEnabled(false);
        new Thread(() -> {
            boolean ok = false;
            for (int i = 0; i < 3 && !ok; i++) {
                ok = probeBurpMcp(port);
                if (!ok && i < 2) try { Thread.sleep(500); } catch (InterruptedException ie) { break; }
            }
            final boolean detected = ok;
            burpMcpDetected = detected;
            SwingUtilities.invokeLater(() -> {
                refreshBurpMcpUI();
                redetectBurpButton.setEnabled(true);
                if (onBurpMcpDetected != null) onBurpMcpDetected.onBurpMcpDetected(detected, port);
            });
        }, "mcp-burp-probe").start();
    }

    private void refreshBurpMcpUI() {
        int port = getBurpMcpPort();
        if (burpMcpDetected) {
            burpMcpStatusLabel.setText(I18n.get("mcp_connected") + port + " (SSE)");
            burpMcpStatusLabel.setForeground(theme.statusOk());
        } else {
            burpMcpStatusLabel.setText(I18n.get("mcp_not_detected"));
            burpMcpStatusLabel.setForeground(theme.mutedText());
        }
        refreshRuntimeUI(); // config preview now includes/excludes accordingly
    }

    /**
     * Pushed by the extension after (attempting to) start the server.
     * @param running true if the MCP server is actually listening
     * @param token   the Bearer token (null when not running)
     * @param port    the port the server bound to
     */
    public void setRuntimeInfo(boolean running, String token, int port) {
        this.running = running;
        this.runtimeToken = token;
        this.runtimePort = port > 0 ? port : 9877;
        SwingUtilities.invokeLater(this::refreshRuntimeUI);
    }

    /** Surface a start failure reason directly in the panel (not just the
     *  Burp console) so the user can see WHY the server didn't come up. */
    public void setStartError(int port, String reason) {
        this.running = false;
        this.runtimeToken = null;
        this.runtimePort = port > 0 ? port : 9877;
        SwingUtilities.invokeLater(() -> {
            refreshRuntimeUI();
            statusLabel.setText(I18n.get("mcp_start_failed") + (reason == null || reason.isBlank() ? I18n.get("mcp_unknown_error") : reason));
            statusLabel.setForeground(theme.statusError());
        });
    }

    private void refreshRuntimeUI() {
        boolean enabled = enabledCheck.isSelected();
        int port = running ? runtimePort : parsedPort();

        if (running) {
            statusLabel.setText(String.format(I18n.get("mcp_running"), port));
            statusLabel.setForeground(theme.statusOk());
        } else if (enabled) {
            statusLabel.setText(String.format(I18n.get("mcp_enabled_not_running"), port));
            statusLabel.setForeground(theme.statusError());
        } else {
            statusLabel.setText(I18n.get("mcp_disabled"));
            statusLabel.setForeground(theme.mutedText());
        }

        boolean requireAuth = requireAuthCheck.isSelected();
        boolean hasToken = runtimeToken != null && !runtimeToken.isBlank();
        tokenField.setText(!requireAuth ? I18n.get("mcp_token_disabled")
                : hasToken ? runtimeToken : I18n.get("mcp_token_placeholder"));
        tokenField.setEnabled(requireAuth);
        copyTokenButton.setEnabled(requireAuth && hasToken);
        regenTokenButton.setEnabled(requireAuth);

        String tokenForCfg = hasToken ? runtimeToken : "<view token in Burp extension console>";
        configPreview.setText(buildClientConfig(port, tokenForCfg, getBurpMcpPort(), burpMcpDetected, requireAuth));
        configPreview.setCaretPosition(0);
    }

    /** Client config emitting BOTH MCP servers: the official Burp流量桥 (SSE,
     *  no token) + this plugin (HTTP + Bearer). The burp entry is always
     *  included so the user has the template; it just won't connect until the
     *  BApp is enabled (the panel's status line shows whether it's up). */
    private static String buildClientConfig(int port, String token, int burpPort,
                                            boolean burpDetected, boolean requireAuth) {
        String sentinel = requireAuth
                ? "    \"api-sentinel\": {\n"
                + "      \"type\": \"http\",\n"
                + "      \"url\": \"http://127.0.0.1:" + port + "/mcp\",\n"
                + "      \"headers\": { \"Authorization\": \"Bearer " + token + "\" }\n"
                + "    }\n"
                : "    \"api-sentinel\": {\n"
                + "      \"type\": \"http\",\n"
                + "      \"url\": \"http://127.0.0.1:" + port + "/mcp\"\n"
                + "    }\n";
        return "{\n"
                + "  \"mcpServers\": {\n"
                + "    \"burp\": {\n"
                + "      \"type\": \"sse\",\n"
                + "      \"url\": \"http://127.0.0.1:" + burpPort + "\"\n"
                + "    },\n"
                + sentinel
                + "  }\n"
                + "}\n";
    }

    private void copyToClipboard(String text, String okMsg) {
        if (text == null || text.isBlank()) return;
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
            statusLabel.setText(okMsg);
            statusLabel.setForeground(theme.statusOk());
        } catch (Exception ignored) {
            // Clipboard may be unavailable in headless/sandboxed envs — ignore.
        }
    }
}
