package com.flechazo.apisentinel.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

/**
 * Modern empty-state panel — full-bleed centered layout with:
 * - Status indicator bar
 * - 3-step workflow with arrows
 * - "Import API" prominent CTA button
 * - 2-column quick-setup grid with status indicators
 * - Footer with version/author/GitHub
 *
 * <p><b>Responsive fit-to-height:</b> when the hosting Burp panel is shorter
 * than the content's natural height, the whole onboarding view is scaled down
 * uniformly ({@link #uiScale}) so it fits without forcing the user to scroll.
 * Fonts stay crisp (vector) and mouse hit-testing is preserved (real layout,
 * not an {@code AffineTransform}). A scroll pane remains as a fallback once the
 * minimum scale is reached.
 */
public class EmptyStateView extends JPanel {

    private static final String VERSION = "1.1";
    private static final String AUTHOR = "Flechazo";
    private static final String GITHUB = "github.com/Flechzao/API-Sentinel";

    /** Below this we stop shrinking and let the scroll pane take over. */
    private static final double MIN_SCALE = 0.70;
    /** Ignore sub-threshold scale deltas to avoid resize thrash. */
    private static final double SCALE_DEADBAND = 0.02;

    private final BurpTheme theme;
    private Consumer<String> setupActionHandler;

    /** Uniform density factor driven by available height (≤ 1.0). */
    private double uiScale = 1.0;
    /** References kept so {@link #recomputeScale()} can measure/refit. */
    private JPanel contentPanel;
    private JPanel footerPanel;
    /** Reentrancy guard — suppress resize handling while rebuilding. */
    private boolean rebuilding;

    /** Status data for the setup indicators. */
    public record SetupStatus(
            boolean llmConfigured,
            String llmProvider,
            String llmModel,
            boolean authConfigured,
            boolean codeRepoConfigured,
            boolean browserEnabled,
            String browserStatus,
            int sensitiveRuleCount,
            boolean oobEnabled,
            boolean sensitiveDetectionEnabled,
            boolean activeProbeEnabled,
            boolean agentMode,
            int totalTools,
            int disabledTools,
            boolean mcpServerEnabled,
            boolean burpMcpDetected
    ) {
        public static SetupStatus defaults() {
            return new SetupStatus(false, "", "", false, false, false,
                    I18n.get("empty_not_enabled"), 0, false, false, false, true, 0, 0, false, false);
        }
    }

    private SetupStatus status = SetupStatus.defaults();

    public EmptyStateView(BurpTheme theme) {
        super(new BorderLayout());
        this.theme = theme;
        setOpaque(true);
        setBackground(theme.stepPanelBg());

        // Refit whenever the hosting panel is resized (Burp tab dragged/split).
        addComponentListener(new ComponentAdapter() {
            @Override public void componentResized(ComponentEvent e) {
                recomputeScale();
            }
        });
    }

    /** Set the current setup status and rebuild the view. */
    public void setStatus(SetupStatus s) {
        this.status = s != null ? s : SetupStatus.defaults();
        rebuild();
        // After first layout, fit to the current viewport height.
        SwingUtilities.invokeLater(this::recomputeScale);
    }

    // ── Density-scaling helpers ───────────────────────────────
    // Every font size / inset / fixed dimension in this view flows through
    // these so a single uiScale factor rescales the whole layout coherently.

    private Font dfont(int style, float size) {
        return theme.displayFont(style, (float) (size * uiScale));
    }

    private Font efont(float size) {
        return theme.editorFont((float) (size * uiScale));
    }

    /** Scale a pixel dimension (rounded, min 1 so borders never vanish). */
    private int s(double v) {
        return Math.max(1, (int) Math.round(v * uiScale));
    }

    private EmptyBorder eb(double t, double l, double b, double r) {
        return new EmptyBorder(s(t), s(l), s(b), s(r));
    }

    private Insets ins(double t, double l, double b, double r) {
        return new Insets(s(t), s(l), s(b), s(r));
    }

    /**
     * Recompute {@link #uiScale} from the available height and, if it changed
     * meaningfully, rebuild at the new density. Uses this panel's own size
     * (not the scroll viewport) so content-driven reflows can't feed back.
     */
    private void recomputeScale() {
        if (rebuilding || contentPanel == null) return;
        int h = getHeight();
        int w = getWidth();
        if (h <= 0 || w <= 0) return;

        int footerH = footerPanel != null ? footerPanel.getPreferredSize().height : 0;
        int avail = h - footerH;
        if (avail <= 0) return;

        int contentH = contentPanel.getPreferredSize().height;
        if (contentH <= 0) return;

        // Content height scales ~linearly with uiScale, so normalize to the
        // natural (scale=1) height before deriving the target factor.
        double naturalH = contentH / uiScale;
        double target = Math.min(1.0, avail / naturalH);
        target = Math.max(MIN_SCALE, target);

        if (Math.abs(target - uiScale) > SCALE_DEADBAND) {
            uiScale = target;
            rebuild();
        }
    }

    private void rebuild() {
        rebuilding = true;
        try {
            removeAll();

            // Scrollable wrapper — fallback once MIN_SCALE is hit.
            JPanel content = new JPanel(new GridBagLayout());
            content.setOpaque(false);
            content.setBorder(eb(20, 60, 16, 60));
            this.contentPanel = content;

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.weightx = 1.0;

            // ── Header ──

            gbc.gridy = 0;
            gbc.insets = ins(0, 0, 8, 0);
            JLabel icon = new JLabel(IconFactory.of(IconFactory.Kind.SHIELD, s(48), theme.accentBg()));
            icon.setHorizontalAlignment(SwingConstants.CENTER);
            content.add(icon, gbc);

            gbc.gridy = 1;
            gbc.insets = ins(0, 0, 4, 0);
            JLabel title = new JLabel("API Sentinel", SwingConstants.CENTER);
            title.setFont(dfont(Font.BOLD, 24f));
            title.setForeground(theme.headerFg());
            content.add(title, gbc);

            gbc.gridy = 2;
            gbc.insets = ins(0, 0, 24, 0);
            JLabel subtitle = new JLabel(I18n.get("empty_subtitle"),
                    SwingConstants.CENTER);
            subtitle.setFont(dfont(Font.PLAIN, 14f));
            subtitle.setForeground(theme.mutedText());
            content.add(subtitle, gbc);

            // ── Status indicator bar ──

            gbc.gridy = 3;
            gbc.insets = ins(0, 0, 24, 0);
            content.add(buildStatusBar(), gbc);

            // ── Workflow: 3 steps with arrows ──

            gbc.gridy = 4;
            gbc.insets = ins(0, 0, 20, 0);
            content.add(buildWorkflowSection(), gbc);

            // ── Import CTA button ──

            gbc.gridy = 5;
            gbc.insets = ins(0, 0, 24, 0);
            content.add(buildImportCTA(), gbc);

            // ── Quick setup: 2-column grid with status ──

            gbc.gridy = 6;
            gbc.insets = ins(0, 0, 20, 0);
            content.add(buildSetupSection(), gbc);

            // ── Advanced config: browser ──

            gbc.gridy = 7;
            gbc.insets = ins(0, 0, 0, 0);
            content.add(buildAdvancedSection(), gbc);

            JScrollPane scroll = new JScrollPane(content);
            scroll.setBorder(null);
            scroll.setOpaque(false);
            scroll.getViewport().setOpaque(false);
            scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            scroll.getVerticalScrollBar().setUnitIncrement(16);
            add(scroll, BorderLayout.CENTER);

            // ── Footer ──

            JPanel footer = new JPanel(new FlowLayout(FlowLayout.CENTER, s(14), s(10)));
            footer.setOpaque(false);
            footer.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, theme.separator()));
            this.footerPanel = footer;

            footer.add(footerLabel("v" + VERSION));
            footer.add(footerDot());
            footer.add(footerLabel("by " + AUTHOR));
            footer.add(footerDot());

            JLabel ghLink = footerLabel(GITHUB);
            ghLink.setForeground(theme.accentBg());
            ghLink.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            ghLink.addMouseListener(new MouseAdapter() {
                @Override public void mouseClicked(MouseEvent e) {
                    try {
                        Desktop.getDesktop().browse(
                                java.net.URI.create("https://" + GITHUB));
                    } catch (Exception ignored) {}
                }

                @Override public void mouseEntered(MouseEvent e) {
                    ghLink.setForeground(theme.mutedText());
                }

                @Override public void mouseExited(MouseEvent e) {
                    ghLink.setForeground(theme.accentBg());
                }
            });
            footer.add(ghLink);

            add(footer, BorderLayout.SOUTH);

            revalidate();
            repaint();
        } finally {
            rebuilding = false;
        }
    }

    // ── Status indicator bar ──

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.CENTER, s(20), 0));
        bar.setOpaque(false);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()),
                eb(8, 0, 10, 0)));

        bar.add(statusChip("LLM",
                status.llmConfigured,
                status.llmConfigured ? status.llmProvider : I18n.get("empty_not_configured")));
        bar.add(statusChip(I18n.get("empty_rules"),
                status.sensitiveRuleCount > 0,
                status.sensitiveRuleCount + I18n.get("empty_rules_count_suffix")));
        bar.add(statusChip(I18n.get("empty_auth_session"),
                status.authConfigured,
                status.authConfigured ? I18n.get("empty_configured") : I18n.get("empty_not_configured")));
        bar.add(statusChip(I18n.get("empty_source"),
                status.codeRepoConfigured,
                status.codeRepoConfigured ? I18n.get("empty_linked") : I18n.get("empty_not_linked")));
        bar.add(statusChip(I18n.get("empty_mode"),
                true,
                status.agentMode ? "Agent" : "Pipeline"));

        return bar;
    }

    private JPanel statusChip(String label, boolean ok, String value) {
        JPanel chip = new JPanel(new FlowLayout(FlowLayout.LEFT, s(4), 0));
        chip.setOpaque(false);

        JLabel dot = new JLabel(ok ? "●" : "○");
        dot.setFont(dfont(Font.PLAIN, 10f));
        dot.setForeground(ok ? theme.statusOk() : theme.mutedText());
        chip.add(dot);

        JLabel text = new JLabel(label + ": " + value);
        text.setFont(dfont(Font.PLAIN, 11f));
        text.setForeground(ok ? theme.headerFg() : theme.mutedText());
        chip.add(text);

        return chip;
    }

    // ── Workflow: 3 steps with arrows ──

    private JPanel buildWorkflowSection() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        panel.setOpaque(false);

        panel.add(buildStep("1", I18n.get("empty_step1")));
        panel.add(buildArrow());
        panel.add(buildStep("2", I18n.get("empty_step2")));
        panel.add(buildArrow());
        panel.add(buildStep("3", I18n.get("empty_step3")));

        return panel;
    }

    private JPanel buildStep(String number, String title) {
        JPanel step = new JPanel(new FlowLayout(FlowLayout.CENTER, s(8), 0));
        step.setOpaque(false);
        step.setBorder(eb(10, 14, 10, 14));

        final int dia = s(26);
        JLabel numLabel = new JLabel(number, SwingConstants.CENTER) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(theme.accentBg());
                g2.fillOval(0, 0, dia, dia);
                g2.dispose();
                setForeground(Color.WHITE);
                super.paintComponent(g);
            }

            @Override
            public Dimension getPreferredSize() {
                return new Dimension(dia, dia);
            }
        };
        numLabel.setFont(dfont(Font.BOLD, 14f));
        numLabel.setVerticalAlignment(SwingConstants.CENTER);
        step.add(numLabel);

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(dfont(Font.BOLD, 15f));
        titleLabel.setForeground(theme.headerFg());
        step.add(titleLabel);

        return step;
    }

    private JLabel buildArrow() {
        JLabel arrow = new JLabel("→");
        arrow.setFont(dfont(Font.PLAIN, 18f));
        arrow.setForeground(theme.separator());
        arrow.setBorder(eb(0, 8, 0, 8));
        return arrow;
    }

    // ── Import CTA button ──

    private JPanel buildImportCTA() {
        JPanel wrapper = new JPanel(new FlowLayout(FlowLayout.CENTER));
        wrapper.setOpaque(false);

        JButton btn = new JButton(I18n.get("empty_step1")) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                if (getModel().isPressed() || getModel().isRollover()) {
                    g2.setColor(theme.accentHover());
                } else {
                    g2.setColor(theme.accentBg());
                }
                g2.fillRoundRect(0, 0, getWidth(), getHeight(),
                        BurpTheme.RADIUS_MD, BurpTheme.RADIUS_MD);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        btn.setFont(dfont(Font.BOLD, 15f));
        btn.setForeground(theme.accentFg());
        btn.setIcon(IconFactory.of(IconFactory.Kind.IMPORT, s(16), theme.accentFg()));
        btn.setIconTextGap(s(8));
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setMargin(ins(12, 32, 12, 32));
        btn.addActionListener(e -> {
            if (setupActionHandler != null) {
                setupActionHandler.accept("import");
            }
        });

        wrapper.add(btn);
        return wrapper;
    }

    // ── Quick setup: 2-column grid with status indicators ──

    private JPanel buildSetupSection() {
        JPanel wrapper = new JPanel(new BorderLayout(0, s(10)));
        wrapper.setOpaque(false);
        wrapper.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, theme.separator()),
                eb(16, 0, 0, 0)));

        JLabel header = new JLabel(I18n.get("empty_quick_config"),
                IconFactory.of(IconFactory.Kind.GEAR, s(14), theme.mutedText()), SwingConstants.CENTER);
        header.setHorizontalAlignment(SwingConstants.CENTER);
        header.setIconTextGap(s(6));
        header.setFont(dfont(Font.BOLD, 13f));
        header.setForeground(theme.mutedText());
        wrapper.add(header, BorderLayout.NORTH);

        JPanel grid = new JPanel(new GridLayout(4, 2, s(24), s(4)));
        grid.setOpaque(false);

        // Row 1
        grid.add(buildSetupItem(I18n.get("empty_step1"),
                "Swagger / OpenAPI / Text list", "import", null));
        grid.add(buildSetupItem(I18n.get("empty_llm_provider"),
                statusLLMDesc(), "llm", status.llmConfigured));

        // Row 2
        grid.add(buildSetupItem(I18n.get("empty_auth_session_setup"),
                status.authConfigured ? I18n.get("empty_session_ab_set") : I18n.get("empty_auth_unavailable"),
                "auth", status.authConfigured));
        grid.add(buildSetupItem(I18n.get("empty_detection_config"),
                I18n.get("empty_detection_config_desc"),
                "detection", status.sensitiveDetectionEnabled));

        // Row 3
        grid.add(buildSetupItem(I18n.get("empty_source_code"),
                status.codeRepoConfigured ? I18n.get("empty_code_audit_ready") : I18n.get("empty_code_audit_unavailable"),
                "code", status.codeRepoConfigured));
        grid.add(buildSetupItem(I18n.get("empty_tool_management"),
                status.totalTools + I18n.get("empty_tools_suffix")
                + (status.disabledTools > 0 ? I18n.get("empty_tools_disabled_prefix") + status.disabledTools + ")" : ""),
                "tools", status.disabledTools == 0));

        // Row 4
        grid.add(buildSetupItem(I18n.get("empty_rules"),
                status.sensitiveRuleCount + I18n.get("empty_sensitive_rules_suffix"),
                "rules", status.sensitiveRuleCount > 0));
        grid.add(buildSetupItem(I18n.get("empty_analysis_mode"),
                status.agentMode ? I18n.get("empty_agent_autonomous") : I18n.get("empty_pipeline_6stage"),
                "mode", status.agentMode));

        // Pack the 2 columns to their natural width instead of letting the
        // grid stretch to the full content width — a stretched GridLayout
        // splits the width in half and the left-packed items leave a wide
        // empty gutter down the middle. Centered so the two columns sit as a
        // balanced block (symmetric margins) under the centered header,
        // matching the centered hero above, instead of hugging one side.
        JPanel gridWrap = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        gridWrap.setOpaque(false);
        gridWrap.add(grid);
        wrapper.add(gridWrap, BorderLayout.CENTER);
        return wrapper;
    }

    // ── Advanced config: browser setup ──

    private JPanel buildAdvancedSection() {
        JPanel wrapper = new JPanel(new BorderLayout(0, s(10)));
        wrapper.setOpaque(false);
        wrapper.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, theme.separator()),
                eb(16, 0, 0, 0)));

        JLabel header = new JLabel(I18n.get("empty_advanced_config"),
                IconFactory.of(IconFactory.Kind.GEAR, s(14), theme.mutedText()), SwingConstants.CENTER);
        header.setHorizontalAlignment(SwingConstants.CENTER);
        header.setIconTextGap(s(6));
        header.setFont(dfont(Font.BOLD, 13f));
        header.setForeground(theme.mutedText());
        wrapper.add(header, BorderLayout.NORTH);

        JPanel body = new JPanel(new BorderLayout(0, s(8)));
        body.setOpaque(false);

        // Browser status row
        JPanel browserRow = new JPanel(new BorderLayout(s(10), 0));
        browserRow.setOpaque(false);
        browserRow.setBorder(eb(8, 8, 8, 8));
        browserRow.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        JLabel emoji = new JLabel(IconFactory.of(IconFactory.Kind.GLOBE, s(20), theme.headerFg()));
        browserRow.add(emoji, BorderLayout.WEST);

        JPanel text = new JPanel(new BorderLayout(0, s(2)));
        text.setOpaque(false);
        JLabel titleLabel = new JLabel(I18n.get("empty_browser_features"));
        titleLabel.setFont(dfont(Font.BOLD, 13f));
        titleLabel.setForeground(theme.headerFg());
        text.add(titleLabel, BorderLayout.NORTH);

        boolean ready = status.browserEnabled && I18n.get("empty_browser_ready").equals(status.browserStatus);
        String descText;
        if (!status.browserEnabled) {
            descText = I18n.get("empty_browser_not_enabled");
        } else if (ready) {
            descText = I18n.get("empty_browser_ready");
        } else {
            descText = I18n.get("empty_browser_not_installed");
        }
        JLabel descLabel = new JLabel(descText);
        descLabel.setFont(dfont(Font.PLAIN, 11f));
        descLabel.setForeground(ready ? theme.statusOk() : theme.mutedText());
        descLabel.setIcon(IconFactory.status(theme, s(12), status.browserEnabled ? ready : null));
        descLabel.setIconTextGap(s(5));
        text.add(descLabel, BorderLayout.CENTER);

        // Version info on a second line when ready
        if (ready) {
            JLabel versionLabel = new JLabel("Playwright 1.49.0 · Chromium");
            versionLabel.setFont(dfont(Font.PLAIN, 10f));
            versionLabel.setForeground(theme.mutedText());
            text.add(versionLabel, BorderLayout.SOUTH);
        }
        browserRow.add(text, BorderLayout.CENTER);

        JLabel arrow = new JLabel("→");
        arrow.setFont(dfont(Font.PLAIN, 14f));
        arrow.setForeground(theme.mutedText());
        browserRow.add(arrow, BorderLayout.EAST);

        browserRow.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) {
                browserRow.setBackground(theme.stepHoverBg());
                browserRow.setOpaque(true);
                browserRow.repaint();
                arrow.setForeground(theme.accentBg());
            }

            @Override public void mouseExited(MouseEvent e) {
                browserRow.setOpaque(false);
                browserRow.repaint();
                arrow.setForeground(theme.mutedText());
            }

            @Override public void mouseClicked(MouseEvent e) {
                if (setupActionHandler != null) {
                    setupActionHandler.accept("browser");
                }
            }
        });

        // ── OOB (带外 / DNSLog) row ──
        // Advanced, opt-in capability paired with the browser row (both need
        // external setup). The "oob" action was already wired in ApiSentinelTab
        // but had no onboarding entry point until now.
        JPanel oobRow = new JPanel(new BorderLayout(s(10), 0));
        oobRow.setOpaque(false);
        oobRow.setBorder(eb(8, 8, 8, 8));
        oobRow.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        JLabel oobIcon = new JLabel(IconFactory.of(IconFactory.Kind.SIGNAL, s(20), theme.headerFg()));
        oobRow.add(oobIcon, BorderLayout.WEST);

        JPanel oobText = new JPanel(new BorderLayout(0, s(2)));
        oobText.setOpaque(false);
        JLabel oobTitle = new JLabel(I18n.get("empty_oob_title"));
        oobTitle.setFont(dfont(Font.BOLD, 13f));
        oobTitle.setForeground(theme.headerFg());
        oobText.add(oobTitle, BorderLayout.NORTH);
        JLabel oobDesc = new JLabel(status.oobEnabled
                ? I18n.get("empty_oob_enabled_desc")
                : I18n.get("empty_oob_disabled_desc"));
        oobDesc.setFont(dfont(Font.PLAIN, 11f));
        oobDesc.setForeground(status.oobEnabled ? theme.statusOk() : theme.mutedText());
        oobDesc.setIcon(IconFactory.status(theme, s(12), status.oobEnabled ? Boolean.TRUE : null));
        oobDesc.setIconTextGap(s(5));
        oobText.add(oobDesc, BorderLayout.CENTER);
        oobRow.add(oobText, BorderLayout.CENTER);

        JLabel oobArrow = new JLabel("→");
        oobArrow.setFont(dfont(Font.PLAIN, 14f));
        oobArrow.setForeground(theme.mutedText());
        oobRow.add(oobArrow, BorderLayout.EAST);

        oobRow.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) {
                oobRow.setBackground(theme.stepHoverBg());
                oobRow.setOpaque(true);
                oobRow.repaint();
                oobArrow.setForeground(theme.accentBg());
            }

            @Override public void mouseExited(MouseEvent e) {
                oobRow.setOpaque(false);
                oobRow.repaint();
                oobArrow.setForeground(theme.mutedText());
            }

            @Override public void mouseClicked(MouseEvent e) {
                if (setupActionHandler != null) {
                    setupActionHandler.accept("oob");
                }
            }
        });

        // ── MCP（外脑模式）row ──
        // External-brain mode: expose the plugin as an MCP server so Claude
        // Code / Codex / Qoder can drive analysis and validate_findings.
        JPanel mcpRow = new JPanel(new BorderLayout(s(10), 0));
        mcpRow.setOpaque(false);
        mcpRow.setBorder(eb(8, 8, 8, 8));
        mcpRow.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        JLabel mcpIcon = new JLabel(IconFactory.of(IconFactory.Kind.ROBOT, s(20), theme.headerFg()));
        mcpRow.add(mcpIcon, BorderLayout.WEST);

        JPanel mcpText = new JPanel(new BorderLayout(0, s(2)));
        mcpText.setOpaque(false);
        JLabel mcpTitleLabel = new JLabel(I18n.get("empty_mcp_title"));
        mcpTitleLabel.setFont(dfont(Font.BOLD, 13f));
        mcpTitleLabel.setForeground(theme.headerFg());
        mcpText.add(mcpTitleLabel, BorderLayout.NORTH);
        JLabel mcpDesc = new JLabel(status.mcpServerEnabled
                ? (status.burpMcpDetected
                        ? I18n.get("empty_mcp_enabled_bridge")
                        : I18n.get("empty_mcp_enabled_no_bridge"))
                : I18n.get("empty_mcp_disabled_desc"));
        mcpDesc.setFont(dfont(Font.PLAIN, 11f));
        mcpDesc.setForeground(status.mcpServerEnabled
                ? (status.burpMcpDetected ? theme.statusOk() : theme.statusPending())
                : theme.mutedText());
        mcpDesc.setIcon(IconFactory.status(theme, s(12), status.mcpServerEnabled ? Boolean.TRUE : null));
        mcpDesc.setIconTextGap(s(5));
        mcpText.add(mcpDesc, BorderLayout.CENTER);
        mcpRow.add(mcpText, BorderLayout.CENTER);

        JLabel mcpArrow = new JLabel("→");
        mcpArrow.setFont(dfont(Font.PLAIN, 14f));
        mcpArrow.setForeground(theme.mutedText());
        mcpRow.add(mcpArrow, BorderLayout.EAST);

        mcpRow.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) {
                mcpRow.setBackground(theme.stepHoverBg());
                mcpRow.setOpaque(true);
                mcpRow.repaint();
                mcpArrow.setForeground(theme.accentBg());
            }

            @Override public void mouseExited(MouseEvent e) {
                mcpRow.setOpaque(false);
                mcpRow.repaint();
                mcpArrow.setForeground(theme.mutedText());
            }

            @Override public void mouseClicked(MouseEvent e) {
                if (setupActionHandler != null) {
                    setupActionHandler.accept("mcp");
                }
            }
        });

        // Three equal-width columns (browser | OOB | MCP), mirroring the
        // quick-setup grid and saving vertical height for fit-to-height scaling.
        // The install guide below stays full-width (body's CENTER region).
        JPanel advGrid = new JPanel(new GridLayout(1, 3, s(24), 0));
        advGrid.setOpaque(false);
        advGrid.add(browserRow);
        advGrid.add(oobRow);
        advGrid.add(mcpRow);

        JPanel advWrap = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        advWrap.setOpaque(false);
        advWrap.add(advGrid);
        body.add(advWrap, BorderLayout.NORTH);

        // Installation guide — only shown when driver is not ready
        if (!ready && status.browserEnabled) {
            JPanel guide = new JPanel(new BorderLayout(0, s(4)));
            guide.setOpaque(false);
            guide.setBorder(eb(4, 36, 8, 8));

            JLabel guideTitle = new JLabel(I18n.get("empty_setup_steps"));
            guideTitle.setFont(dfont(Font.BOLD, 11f));
            guideTitle.setForeground(theme.mutedText());
            guide.add(guideTitle, BorderLayout.NORTH);

            JTextArea steps = new JTextArea(
                    "1. Download CLI: curl -L -o playwright-cli.jar\n2. Install Chromium: java -cp playwright-cli.jar com.microsoft.playwright.CLI install chromium\n"
                    + I18n.get("empty_restart_hint"));
            steps.setEditable(false);
            steps.setLineWrap(true);
            steps.setWrapStyleWord(true);
            steps.setOpaque(false);
            steps.setBorder(null);
            steps.setFont(efont(11f));
            steps.setForeground(theme.mutedText());
            guide.add(steps, BorderLayout.CENTER);

            body.add(guide, BorderLayout.CENTER);
        }

        wrapper.add(body, BorderLayout.CENTER);
        return wrapper;
    }

    private String statusLLMDesc() {
        if (!status.llmConfigured) return I18n.get("empty_no_api_key");
        String model = status.llmModel != null && !status.llmModel.isEmpty()
                ? status.llmModel : I18n.get("empty_default_model");
        return status.llmProvider + " / " + model;
    }

    private JPanel buildSetupItem(String title, String desc,
                                  String actionId, Boolean configured) {
        JPanel row = new JPanel(new BorderLayout(s(10), 0));
        row.setOpaque(false);
        row.setBorder(eb(8, 8, 8, 8));
        row.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        // Status indicator — vector badge (ok ✓ / warn ! / neutral ring)
        JLabel statusLabel = new JLabel(IconFactory.status(theme, s(15), configured));
        statusLabel.setBorder(eb(0, 2, 0, 4));
        row.add(statusLabel, BorderLayout.WEST);

        JPanel text = new JPanel(new BorderLayout(0, s(2)));
        text.setOpaque(false);
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(dfont(Font.BOLD, 13f));
        titleLabel.setForeground(theme.headerFg());
        text.add(titleLabel, BorderLayout.NORTH);
        JLabel descLabel = new JLabel(desc);
        descLabel.setFont(dfont(Font.PLAIN, 11f));
        descLabel.setForeground(theme.mutedText());
        text.add(descLabel, BorderLayout.CENTER);

        JLabel arrow = new JLabel("→");
        arrow.setFont(dfont(Font.PLAIN, 14f));
        arrow.setForeground(theme.mutedText());

        // Text fills the cell; the chevron pins to the cell's right edge so the
        // arrows line up in a column across rows. Now that the grid is packed to
        // its natural width (not full-bleed), that right edge sits close to the
        // text — aligned without the far-flung gap the old full-width EAST had.
        row.add(text, BorderLayout.CENTER);
        row.add(arrow, BorderLayout.EAST);

        row.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) {
                row.setBackground(theme.stepHoverBg());
                row.setOpaque(true);
                row.repaint();
                arrow.setForeground(theme.accentBg());
            }

            @Override public void mouseExited(MouseEvent e) {
                row.setOpaque(false);
                row.repaint();
                arrow.setForeground(theme.mutedText());
            }

            @Override public void mouseClicked(MouseEvent e) {
                if (setupActionHandler != null) {
                    setupActionHandler.accept(actionId);
                }
            }
        });

        return row;
    }

    // ── Helpers ──

    private JLabel footerLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(dfont(Font.PLAIN, 11f));
        l.setForeground(theme.mutedText());
        return l;
    }

    private JLabel footerDot() {
        JLabel d = new JLabel("·");
        d.setFont(dfont(Font.PLAIN, 11f));
        d.setForeground(theme.separator());
        return d;
    }

    public void setSetupActionHandler(Consumer<String> handler) {
        this.setupActionHandler = handler;
    }
}
