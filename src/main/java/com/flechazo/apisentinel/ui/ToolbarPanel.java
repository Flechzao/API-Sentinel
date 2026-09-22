package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.config.AppConfig;

import com.flechazo.apisentinel.config.MatchMode;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

/**
 * Toolbar panel with grouped controls: Match | Detection | Agent.
 * Groups render as label + controls with thin vertical dividers between
 * them — no boxed titled borders, which read dated and add visual noise
 * inside an otherwise flat Burp UI.
 */
public class ToolbarPanel extends JPanel {

    /* ── Fonts — derived from Burp's display font, not raw AWT names ── */
    private final Font CTRL_FONT;
    private final Font GROUP_FONT;

    private final BurpTheme theme;

    /* ── Match modes ───────────────────────────────────── */
    private static final MatchMode[] MATCH_MODES = {
            MatchMode.EXACT, MatchMode.FUZZY
    };

    /* ── Controls ──────────────────────────────────────── */
    private final JComboBox<String> matchModeCombo;
    private final JCheckBox checkWholeRequestCb;
    // Detection toggles live in a popup menu (see detectMenuBtn) to keep the
    // toolbar compact; JCheckBoxMenuItem keeps the menu open while toggling.
    private final JCheckBoxMenuItem sensitiveCheckCb;
    private final JCheckBoxMenuItem unauthorizedCheckCb;
    private final JCheckBoxMenuItem oobCheckCb;
    private final JCheckBoxMenuItem wafCheckCb;
    private final JCheckBoxMenuItem activeProbeCb;
    private final JCheckBoxMenuItem businessLogicCb;
    private final JCheckBoxMenuItem organizerAutoSendCb;
    private final JCheckBoxMenuItem auditHighRiskOnlyCb;
    private final JCheckBoxMenuItem skipAllPermissionsCb;
    private final JCheckBoxMenuItem highlightCb;
    private final JCheckBoxMenuItem autoScanCb;
    private final JCheckBoxMenuItem cascadeHuntCb;
    private JCheckBoxMenuItem batchParallelCb;
    private final JButton detectMenuBtn;
    private final JPopupMenu detectMenu;
    private final JComboBox<String> aiModeCombo;

    private final JPanel matchGroup;
    private final JPanel detectGroup;
    private final JPanel aiModeGroup;
    private final JLabel matchGroupLabel;
    private final JLabel detectGroupLabel;
    private final JLabel aiModeGroupLabel;
    private Consumer<Boolean> onAiModeChanged;

    public ToolbarPanel(Consumer<MatchMode> onMatchModeChanged,
                        Consumer<String> onCheckboxChanged,
                        AppConfig initialConfig,
                        BurpTheme theme) {
        this.theme = theme;
        this.CTRL_FONT = theme.displayFont(Font.PLAIN, 12f);
        this.GROUP_FONT = theme.displayFont(Font.PLAIN, 10f);

        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        setOpaque(false);

        // ═══════════════════════════════════════════════════
        //  Group 1: 匹配
        // ═══════════════════════════════════════════════════
        matchGroup = createGroup(I18n.get("match_mode").replace(":", ""));
        matchGroupLabel = groupLabelOf(matchGroup);

        matchModeCombo = new JComboBox<>(new String[]{
                MatchMode.EXACT.getDisplayName(),
                MatchMode.FUZZY.getDisplayName()
        });
        MatchMode savedMode = initialConfig.getMatchMode().normalize();
        int savedIdx = java.util.Arrays.asList(MATCH_MODES).indexOf(savedMode);
        matchModeCombo.setSelectedIndex(Math.max(savedIdx, 0));
        matchModeCombo.setFont(CTRL_FONT);
        matchModeCombo.setPreferredSize(new Dimension(95, 22));
        matchModeCombo.setMaximumSize(new Dimension(95, 22));
        matchModeCombo.addActionListener(e -> {
            int idx = matchModeCombo.getSelectedIndex();
            if (idx >= 0 && idx < MATCH_MODES.length) {
                onMatchModeChanged.accept(MATCH_MODES[idx]);
            }
        });
        matchGroup.add(matchModeCombo);
        matchGroup.add(Box.createHorizontalStrut(6));

        checkWholeRequestCb = styledCb(I18n.get("check_full"), "checkWholeRequest", onCheckboxChanged);
        checkWholeRequestCb.setToolTipText(I18n.get("toolbar_whole_req_tip"));
        checkWholeRequestCb.setSelected(initialConfig.isCheckWholeRequest());
        matchGroup.add(checkWholeRequestCb);

        add(matchGroup);
        add(makeGroupDivider());

        // ═══════════════════════════════════════════════════
        //  Group 2: 检测（开关收纳进弹出菜单，工具栏只留一个按钮）
        // ═══════════════════════════════════════════════════
        detectGroup = createGroup(I18n.get("detection"));
        detectGroupLabel = groupLabelOf(detectGroup);
        detectMenu = new JPopupMenu();

        sensitiveCheckCb = styledMenuItem(I18n.get("sensitive"), "sensitiveDetection", onCheckboxChanged);
        sensitiveCheckCb.setSelected(initialConfig.isSensitiveDetectionEnabled());
        detectMenu.add(sensitiveCheckCb);

        unauthorizedCheckCb = styledMenuItem(I18n.get("unauth"), "unauthorizedDetection", onCheckboxChanged);
        unauthorizedCheckCb.setSelected(initialConfig.isUnauthorizedDetectionEnabled());
        detectMenu.add(unauthorizedCheckCb);

        oobCheckCb = styledMenuItem(I18n.get("oob_probe"), "oobEnabled", onCheckboxChanged);
        oobCheckCb.setToolTipText("Enable OOB blind SSRF probes (callback platform must be configured in Settings → OOB)");
        oobCheckCb.setSelected(initialConfig.isOobEnabled());
        detectMenu.add(oobCheckCb);

        wafCheckCb = styledMenuItem(I18n.get("waf_detect"), "wafDetection", onCheckboxChanged);
        wafCheckCb.setToolTipText("Identify WAF block pages in payload responses (passive fingerprint, no extra requests). Blocked payloads are marked 🛡 and not used as vuln/safe evidence; auto-retry with encoding variants.");
        wafCheckCb.setSelected(initialConfig.isWafDetectionEnabled());
        detectMenu.add(wafCheckCb);

        activeProbeCb = styledMenuItem(I18n.get("active_probe"), "activeProbe", onCheckboxChanged);
        activeProbeCb.setToolTipText("Programmatic active probes: CORS Origin variant reflection, JWT alg:none forgery replay, CRLF canary, NoSQL diff/timing (triggered conditionally, ≤17 extra requests per API).");
        activeProbeCb.setSelected(initialConfig.isActiveProbeEnabled());
        detectMenu.add(activeProbeCb);

        businessLogicCb = styledMenuItem(I18n.get("business_logic"), "businessLogic", onCheckboxChanged);
        businessLogicCb.setToolTipText("Business logic programmatic verification (price tamper/coupon replay/negative attack/step skip). ⚠ Real business operations, enable only for authorized test environments.");
        businessLogicCb.setSelected(initialConfig.isBusinessLogicVerificationEnabled());
        detectMenu.add(businessLogicCb);

        // ── 显示 ──
        detectMenu.addSeparator();

        highlightCb = styledMenuItem(I18n.get("highlight"), "highlightEnabled", onCheckboxChanged);
        highlightCb.setToolTipText("When off, no color marking in Proxy History (tested APIs no longer show red/green)");
        highlightCb.setSelected(initialConfig.isHighlightEnabled());
        detectMenu.add(highlightCb);

        // ── 自动化 ──
        detectMenu.addSeparator();

        autoScanCb = styledMenuItem(I18n.get("auto_scan"), "autoScan", onCheckboxChanged);
        autoScanCb.setToolTipText("When on, automatically runs comprehensive analysis on all matched traffic (continuously consumes LLM calls). Independent of the Pipeline/Agent dropdown — that only affects which analysis path runs when you manually click AI Analyze.");
        autoScanCb.setSelected(initialConfig.isAutoScanEnabled());
        detectMenu.add(autoScanCb);

        cascadeHuntCb = styledMenuItem(I18n.get("cascade_hunt"), "cascadeHunt", onCheckboxChanged);
        cascadeHuntCb.setToolTipText("Independent toggle (not dependent on auto mode): after any analysis confirms a vuln, automatically cascades to sibling routes (same controller/resource prefix). Requires indexed code repo; cascade has budget limits and circuit-breaking, never sends real requests.");
        cascadeHuntCb.setSelected(initialConfig.isCascadeHuntEnabled());
        detectMenu.add(cascadeHuntCb);

        organizerAutoSendCb = styledMenuItem(I18n.get("organizer_auto_send"), "organizerAutoSend", onCheckboxChanged);
        organizerAutoSendCb.setToolTipText("After analysis finds a vuln, auto-sends evidence to Burp native Organizer. Can also right-click in API table to send to Organizer.");
        organizerAutoSendCb.setSelected(initialConfig.isOrganizerAutoSendEnabled());
        detectMenu.add(organizerAutoSendCb);

        auditHighRiskOnlyCb = styledMenuItem(I18n.get("audit_high_risk_only"), "auditHighRiskOnly", onCheckboxChanged);
        auditHighRiskOnlyCb.setToolTipText("When on, audit_codebase global audit only returns high-risk sinks (command/SQL/deserialization), saving tokens. Default off = audit all sinks (finding vulns is worth more than saving tokens).");
        auditHighRiskOnlyCb.setSelected(initialConfig.isAuditHighRiskOnly());
        detectMenu.add(auditHighRiskOnlyCb);

        // ── 批量 ──
        detectMenu.addSeparator();

        batchParallelCb = styledMenuItem("Parallel Batch (4 concurrent)", "batchConcurrent", onCheckboxChanged);
        batchParallelCb.setToolTipText(
                "When checked, batch analysis runs up to 4 APIs concurrently (fast but more tokens). Unchecked = sequential (one at a time, cheaper but slower).");
        batchParallelCb.setSelected(initialConfig.isBatchConcurrent());
        detectMenu.add(batchParallelCb);

        // ── 权限 ──
        detectMenu.addSeparator();

        skipAllPermissionsCb = styledMenuItem("Skip All Permission Prompts (use with caution)", "skipAllPermissions", onCheckboxChanged);
        skipAllPermissionsCb.setToolTipText(
                "⚠ Dangerous: when enabled, Agent auto-executes all operations (code execution, browser, user interaction) without confirmation. Equivalent to --dangerously-skip-permissions. Use only in fully trusted test environments.");
        skipAllPermissionsCb.setSelected(initialConfig.isSkipAllPermissions());
        detectMenu.add(skipAllPermissionsCb);

        detectMenuBtn = new JButton();
        detectMenuBtn.setFont(CTRL_FONT);
        detectMenuBtn.setFocusPainted(false);
        detectMenuBtn.setToolTipText("Detection options: sensitive/authz/OOB/WAF/active probe/business logic/highlight/auto scan");
        detectMenuBtn.addActionListener(e ->
                detectMenu.show(detectMenuBtn, 0, detectMenuBtn.getHeight()));
        updateDetectBtnLabel();
        detectGroup.add(detectMenuBtn);

        add(detectGroup);
        add(makeGroupDivider());



        // ═══════════════════════════════════════════════════
        //  Group 4: AI分析模式
        // ═══════════════════════════════════════════════════
        aiModeGroup = createGroup(I18n.get("ai_mode_group"));
        aiModeGroupLabel = groupLabelOf(aiModeGroup);

        aiModeCombo = new JComboBox<>(new String[]{"Pipeline", "Agent"});
        // Default to Agent — it is the more capable autonomous path; Pipeline
        // stays available from the dropdown for the fixed 6-stage flow.
        aiModeCombo.setSelectedIndex(initialConfig.isAgentMode() ? 1 : 0);
        aiModeCombo.setFont(CTRL_FONT);
        aiModeCombo.setPreferredSize(new Dimension(95, 22));
        aiModeCombo.setMaximumSize(new Dimension(95, 22));
        aiModeCombo.setToolTipText(I18n.get("toolbar_ai_mode_tip"));
        aiModeCombo.addActionListener(e -> {
            onCheckboxChanged.accept("agentMode");
            if (onAiModeChanged != null) onAiModeChanged.accept(isAgentMode());
        });
        aiModeGroup.add(aiModeCombo);

        add(aiModeGroup);
        add(Box.createHorizontalStrut(4));
    }

    /* ── Factory: create a borderless group panel with a small muted
     *  prefix label. Replaces the old boxed TitledBorder groups: flat
     *  label + thin divider reads cleaner against Burp's flat UI. ── */
    private JPanel createGroup(String title) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));

        JLabel label = new JLabel(title);
        label.setName("groupLabel");
        label.setFont(GROUP_FONT);
        label.setForeground(theme.statLabelFg());
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 6));
        panel.add(label);
        return panel;
    }

    /** The group's prefix label, for i18n refresh. */
    private static JLabel groupLabelOf(JPanel group) {
        for (Component c : group.getComponents()) {
            if (c instanceof JLabel l && "groupLabel".equals(l.getName())) return l;
        }
        return null;
    }

    /** Thin vertical divider between groups. */
    private Component makeGroupDivider() {
        JPanel divider = new JPanel();
        divider.setOpaque(false);
        divider.setLayout(new BoxLayout(divider, BoxLayout.Y_AXIS));
        divider.add(Box.createVerticalGlue());
        divider.add(new JSeparator(SwingConstants.VERTICAL) {
            @Override public Dimension getPreferredSize() { return new Dimension(1, 18); }
            @Override public Dimension getMaximumSize() { return new Dimension(1, 18); }
            @Override public Dimension getMinimumSize() { return new Dimension(1, 18); }
        });
        divider.add(Box.createVerticalGlue());
        divider.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        return divider;
    }

    /* ── Factory: styled checkbox ─────────────────────── */
    private JCheckBox styledCb(String label, String key, Consumer<String> callback) {
        JCheckBox cb = new JCheckBox(label);
        cb.setFont(CTRL_FONT);
        cb.setOpaque(false);
        cb.setFocusPainted(false);
        cb.addActionListener(e -> callback.accept(key));
        return cb;
    }

    /* ── Factory: styled checkbox menu item (for the detection popup) ── */
    private JCheckBoxMenuItem styledMenuItem(String label, String key, Consumer<String> callback) {
        JCheckBoxMenuItem mi = new JCheckBoxMenuItem(label);
        mi.setFont(CTRL_FONT);
        // Persist the toggle AND refresh the button's enabled-count badge.
        mi.addActionListener(e -> {
            callback.accept(key);
            updateDetectBtnLabel();
        });
        return mi;
    }

    /** Refresh the detection button label to show how many toggles are on. */
    private void updateDetectBtnLabel() {
        int on = 0;
        for (JCheckBoxMenuItem mi : new JCheckBoxMenuItem[]{
                sensitiveCheckCb, unauthorizedCheckCb, oobCheckCb, wafCheckCb,
                activeProbeCb, businessLogicCb, highlightCb, autoScanCb, cascadeHuntCb,
                organizerAutoSendCb, auditHighRiskOnlyCb, skipAllPermissionsCb}) {
            if (mi != null && mi.isSelected()) on++;
        }
        detectMenuBtn.setText(I18n.get("detect_options") + " ⚙ (" + on + ")");
    }

    /* ── Public getters ───────────────────────────────── */
    public boolean isCheckWholeRequest()    { return checkWholeRequestCb.isSelected(); }
    public boolean isSensitiveDetection()   { return sensitiveCheckCb.isSelected(); }
    public boolean isUnauthorizedDetection(){ return unauthorizedCheckCb.isSelected(); }
    public boolean isOobEnabled()           { return oobCheckCb.isSelected(); }
    public boolean isWafDetection()         { return wafCheckCb.isSelected(); }
    public boolean isActiveProbe()          { return activeProbeCb.isSelected(); }
    public boolean isBusinessLogic()        { return businessLogicCb.isSelected(); }
    public boolean isOrganizerAutoSend()    { return organizerAutoSendCb.isSelected(); }
    public boolean isAuditHighRiskOnly()    { return auditHighRiskOnlyCb.isSelected(); }
    public boolean isSkipAllPermissions() { return skipAllPermissionsCb.isSelected(); }
    public boolean isHighlightEnabled()     { return highlightCb.isSelected(); }
    public boolean isAutoScanEnabled()      { return autoScanCb.isSelected(); }
    public boolean isCascadeHuntEnabled()   { return cascadeHuntCb != null && cascadeHuntCb.isSelected(); }
    public boolean isBatchParallel()        { return batchParallelCb != null && batchParallelCb.isSelected(); }
    public boolean isAgentMode()            { return aiModeCombo.getSelectedIndex() == 1; }

    /** Notified with the new isAgentMode() value whenever the Pipeline/Agent
     *  combo changes — lets the main "AI 分析" trigger button (which lives in
     *  a different row) show which mode it'll actually run, instead of the
     *  two controls being visually disconnected. */
    public void setOnAiModeChanged(Consumer<Boolean> callback) { this.onAiModeChanged = callback; }

    public MatchMode getSelectedMatchMode() {
        int idx = matchModeCombo.getSelectedIndex();
        if (idx >= 0 && idx < MATCH_MODES.length) {
            return MATCH_MODES[idx];
        }
        return MatchMode.EXACT;
    }

    /** Show the detection settings popup menu below the detection button. */
    public void showDetectionMenu() {
        detectMenu.show(detectMenuBtn, 0, detectMenuBtn.getHeight());
    }

    /** Toggle between Agent and Pipeline mode. */
    public void toggleAgentMode() {
        aiModeCombo.setSelectedIndex(aiModeCombo.getSelectedIndex() == 0 ? 1 : 0);
    }

    /** Programmatically select the match-mode combo (fires the change callback). */
    public void setMatchMode(MatchMode mode) {
        int idx = java.util.Arrays.asList(MATCH_MODES).indexOf(mode);
        if (idx >= 0 && idx < MATCH_MODES.length) {
            matchModeCombo.setSelectedIndex(idx);
        }
    }



    public void refreshI18n() {
        checkWholeRequestCb.setText(I18n.get("check_full"));
        sensitiveCheckCb.setText(I18n.get("sensitive"));
        unauthorizedCheckCb.setText(I18n.get("unauth"));
        oobCheckCb.setText(I18n.get("oob_probe"));
        wafCheckCb.setText(I18n.get("waf_detect"));
        activeProbeCb.setText(I18n.get("active_probe"));
        businessLogicCb.setText(I18n.get("business_logic"));
        highlightCb.setText(I18n.get("highlight"));
        autoScanCb.setText(I18n.get("auto_scan"));
        cascadeHuntCb.setText(I18n.get("cascade_hunt"));

        // Group prefix labels
        if (matchGroupLabel != null) matchGroupLabel.setText(I18n.get("match_mode").replace(":", ""));
        if (detectGroupLabel != null) detectGroupLabel.setText(I18n.get("detection"));
        if (aiModeGroupLabel != null) aiModeGroupLabel.setText(I18n.get("ai_mode_group"));

        // Match mode combo
        int matchSel = matchModeCombo.getSelectedIndex();
        matchModeCombo.removeAllItems();
        for (MatchMode m : MATCH_MODES) matchModeCombo.addItem(m.getDisplayName());
        matchModeCombo.setSelectedIndex(matchSel);

        matchGroup.repaint();
        detectGroup.repaint();
        aiModeGroup.repaint();
        updateDetectBtnLabel();
    }
}
