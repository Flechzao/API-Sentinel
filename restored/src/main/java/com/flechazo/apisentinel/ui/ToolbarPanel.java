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
    private final JCheckBoxMenuItem codeExecAutoApproveCb;
    private final JCheckBoxMenuItem highlightCb;
    private final JCheckBoxMenuItem autoScanCb;
    private final JCheckBoxMenuItem cascadeHuntCb;
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
        checkWholeRequestCb.setToolTipText("仅模糊匹配模式下生效：在请求体中也搜索 API 关键词");
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
        oobCheckCb.setToolTipText("启用 OOB 盲 SSRF 探针（回连平台需在 设置 → 回连平台 中配置）");
        oobCheckCb.setSelected(initialConfig.isOobEnabled());
        detectMenu.add(oobCheckCb);

        wafCheckCb = styledMenuItem(I18n.get("waf_detect"), "wafDetection", onCheckboxChanged);
        wafCheckCb.setToolTipText("识别 payload 响应中的 WAF 拦截页（被动指纹，不发额外请求）。"
                + "被拦截的 payload 将标记 🛡 并不作为漏洞/安全证据；拦截时自动用编码变体重试。");
        wafCheckCb.setSelected(initialConfig.isWafDetectionEnabled());
        detectMenu.add(wafCheckCb);

        activeProbeCb = styledMenuItem(I18n.get("active_probe"), "activeProbe", onCheckboxChanged);
        activeProbeCb.setToolTipText("程序化主动探针：CORS Origin 变体反射、JWT alg:none 伪造重放、"
                + "CRLF canary、NoSQL 差分/时序（按触发条件发送，每接口 ≤17 个额外请求）。");
        activeProbeCb.setSelected(initialConfig.isActiveProbeEnabled());
        detectMenu.add(activeProbeCb);

        businessLogicCb = styledMenuItem(I18n.get("business_logic"), "businessLogic", onCheckboxChanged);
        businessLogicCb.setToolTipText("业务逻辑程序化验证（价格篡改/优惠券重放/负数攻击/步骤跳过）。"
                + "⚠ 真实业务操作，仅对授权测试环境开启。");
        businessLogicCb.setSelected(initialConfig.isBusinessLogicVerificationEnabled());
        detectMenu.add(businessLogicCb);

        highlightCb = styledMenuItem(I18n.get("highlight"), "highlightEnabled", onCheckboxChanged);
        highlightCb.setToolTipText("关闭后不在 Proxy History 标记颜色（已测老接口不再红/绿干扰）");
        highlightCb.setSelected(initialConfig.isHighlightEnabled());
        detectMenu.add(highlightCb);

        autoScanCb = styledMenuItem(I18n.get("auto_scan"), "autoScan", onCheckboxChanged);
        autoScanCb.setToolTipText("开启后后台自动对所有匹配到的流量跑综合分析（持续消耗 LLM 调用）。"
                + "独立于下方 Pipeline/Agent 下拉框——那个只影响你手动点\"AI 分析\"时走哪条分析路径。");
        autoScanCb.setSelected(initialConfig.isAutoScanEnabled());
        detectMenu.add(autoScanCb);

        cascadeHuntCb = styledMenuItem(I18n.get("cascade_hunt"), "cascadeHunt", onCheckboxChanged);
        cascadeHuntCb.setToolTipText("独立开关（不依赖自动模式）：任何分析确认漏洞后，自动对兄弟路由（同控制器/同资源前缀）扩散分析。"
                + "需已索引代码仓库；级联有预算上限与熔断保护，且从不发送真实请求。");
        cascadeHuntCb.setSelected(initialConfig.isCascadeHuntEnabled());
        detectMenu.add(cascadeHuntCb);

        organizerAutoSendCb = styledMenuItem(I18n.get("organizer_auto_send"), "organizerAutoSend", onCheckboxChanged);
        organizerAutoSendCb.setToolTipText("分析发现漏洞后，自动把证据请求/响应存入 Burp 原生 Organizer，便于复查。"
                + "也可在 API 表格右键手动\"发送到 Organizer\"。");
        organizerAutoSendCb.setSelected(initialConfig.isOrganizerAutoSendEnabled());
        detectMenu.add(organizerAutoSendCb);

        auditHighRiskOnlyCb = styledMenuItem(I18n.get("audit_high_risk_only"), "auditHighRiskOnly", onCheckboxChanged);
        auditHighRiskOnlyCb.setToolTipText("开启后 audit_codebase 全局审计只返回高危 sink（命令执行/SQL/反序列化），省 token。"
                + "默认关闭＝审计全部 sink（发现漏洞比省 token 更值）。");
        auditHighRiskOnlyCb.setSelected(initialConfig.isAuditHighRiskOnly());
        detectMenu.add(auditHighRiskOnlyCb);

        codeExecAutoApproveCb = styledMenuItem(I18n.get("code_exec_auto_approve"), "codeExecAutoApprove", onCheckboxChanged);
        codeExecAutoApproveCb.setToolTipText("开启后 run_sandboxed_code 工具跳过每次执行前的人工确认弹窗，自动运行 Agent"
                + "生成的脚本。沙箱不能保证隔离网络/真实文件系统访问，跳过确认意味着把这个安全边界完全让渡给模型，"
                + "存在被响应内容注入误导执行恶意代码的风险，请自行评估后再开启。默认关闭＝每次弹窗确认。");
        codeExecAutoApproveCb.setSelected(initialConfig.isCodeExecutionAutoApprove());
        detectMenu.add(codeExecAutoApproveCb);

        detectMenuBtn = new JButton();
        detectMenuBtn.setFont(CTRL_FONT);
        detectMenuBtn.setFocusPainted(false);
        detectMenuBtn.setToolTipText("检测选项：敏感/越权/OOB/WAF/主动探针/业务逻辑/高亮/自动扫描");
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
        aiModeCombo.setSelectedIndex(1);
        aiModeCombo.setFont(CTRL_FONT);
        aiModeCombo.setPreferredSize(new Dimension(95, 22));
        aiModeCombo.setMaximumSize(new Dimension(95, 22));
        aiModeCombo.setToolTipText("Pipeline: 固定6阶段分析流程 | Agent: AI自主决策分析工具调用");
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
                organizerAutoSendCb, auditHighRiskOnlyCb, codeExecAutoApproveCb}) {
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
    public boolean isCodeExecAutoApprove()  { return codeExecAutoApproveCb.isSelected(); }
    public boolean isHighlightEnabled()     { return highlightCb.isSelected(); }
    public boolean isAutoScanEnabled()      { return autoScanCb.isSelected(); }
    public boolean isCascadeHuntEnabled()   { return cascadeHuntCb != null && cascadeHuntCb.isSelected(); }
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
        codeExecAutoApproveCb.setText(I18n.get("code_exec_auto_approve"));

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
