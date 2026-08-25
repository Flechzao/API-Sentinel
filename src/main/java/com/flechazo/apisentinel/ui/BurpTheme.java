package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;

import java.awt.*;

/**
 * Burp 主题桥接——从 Montoya 取显示/编辑器字体和 DARK/LIGHT 主题，
 * 提供 UI 配色令牌（聊天背景/卡片/强调/风险色等）和组件主题应用。
 */
public final class BurpTheme {

    /** Design tokens — corner radii kept in one place so cards/buttons/chips
     *  share a consistent geometry ("premium" reads as consistency first). */
    public static final int RADIUS_SM = 6;
    public static final int RADIUS_MD = 10;
    public static final int RADIUS_LG = 14;

    private final MontoyaApi api;
    private final boolean dark;

    public BurpTheme(MontoyaApi api) {
        this.api = api;
        this.dark = api.userInterface().currentTheme() == Theme.DARK;
    }

    public boolean isDark() { return dark; }

    public void apply(Component component) {
        api.userInterface().applyThemeToComponent(component);
    }

    public Font displayFont() {
        return api.userInterface().currentDisplayFont();
    }

    public Font displayFont(int style, float size) {
        return api.userInterface().currentDisplayFont().deriveFont(style, size);
    }

    public Font editorFont() {
        return api.userInterface().currentEditorFont();
    }

    public Font editorFont(float size) {
        return api.userInterface().currentEditorFont().deriveFont(size);
    }

    public Frame suiteFrame() {
        return api.userInterface().swingUtils().suiteFrame();
    }

    // ── Chat colors ──

    public Color chatBg() {
        return dark ? new Color(43, 43, 43) : new Color(252, 252, 252);
    }

    public Color userMsgColor() {
        return dark ? new Color(255, 140, 80) : new Color(200, 80, 30);
    }

    public Color aiMsgColor() {
        return dark ? new Color(90, 200, 120) : new Color(0, 120, 50);
    }

    public Color aiTextColor() {
        return dark ? new Color(210, 210, 210) : new Color(40, 40, 40);
    }

    public Color toolColor() {
        return dark ? new Color(140, 140, 140) : new Color(100, 100, 100);
    }

    public Color systemColor() {
        return dark ? new Color(120, 120, 120) : new Color(150, 150, 150);
    }

    public Color errorColor() {
        return dark ? new Color(255, 100, 100) : new Color(206, 66, 58);
    }

    // ── Header / context panel ──

    public Color headerBg() {
        return dark ? new Color(50, 50, 50) : new Color(240, 240, 240);
    }

    public Color headerFg() {
        return dark ? new Color(220, 220, 220) : new Color(40, 40, 40);
    }

    public Color contextBg() {
        return dark ? new Color(35, 38, 45) : new Color(248, 248, 248);
    }

    public Color contextFg() {
        return dark ? new Color(180, 186, 200) : new Color(60, 60, 60);
    }

    public Color endpointColor() {
        return dark ? new Color(160, 160, 160) : new Color(100, 100, 100);
    }

    // ── Buttons — Burp orange accent ──

    public Color accentBg() {
        return dark ? new Color(230, 90, 40) : new Color(255, 102, 51);
    }

    public Color accentFg() {
        return Color.WHITE;
    }

    public Color sendBtnBg() {
        return accentBg();
    }

    // ── Input ──

    public Color inputBorder() {
        return dark ? new Color(80, 80, 80) : new Color(200, 200, 200);
    }

    public Color inputBg() {
        return dark ? new Color(55, 55, 55) : Color.WHITE;
    }

    public Color inputFg() {
        return dark ? new Color(210, 210, 210) : Color.BLACK;
    }

    // ── Status / risk colors ──

    // Softened light-mode risk palette — pure Color.RED/ORANGE read as harsh;
    // these sit closer to the Burp orange family and are easier on the eyes.
    public Color riskHigh() { return dark ? new Color(255, 90, 90) : new Color(214, 69, 65); }
    public Color riskMedium() { return dark ? new Color(230, 170, 50) : new Color(226, 137, 44); }
    public Color riskLow() { return dark ? new Color(200, 180, 50) : new Color(160, 145, 45); }
    public Color riskSafe() { return dark ? new Color(60, 180, 90) : new Color(26, 138, 68); }
    public Color riskInfo() { return dark ? new Color(140, 140, 140) : new Color(130, 130, 130); }

    public Color riskColor(String risk) {
        return switch (risk) {
            case "HIGH" -> riskHigh();
            case "MEDIUM" -> riskMedium();
            case "LOW" -> riskLow();
            case "SAFE" -> riskSafe();
            case "INFO" -> riskInfo();
            default -> accentBg();
        };
    }

    public Color statusOk() { return riskSafe(); }
    public Color statusError() { return riskHigh(); }
    public Color statusPending() { return dark ? new Color(220, 180, 50) : Color.ORANGE; }

    // ── API table columns (method / status code / muted placeholder text) ──
    // ApiTablePanel/TaskQueuePanel used to hard-code plain AWT constants
    // (Color.RED, Color.LIGHT_GRAY, etc.) for these — same value regardless
    // of Burp's light/dark theme, so contrast was noticeably off (esp. light
    // gray placeholder text against a dark background) in dark mode.
    public Color methodGet() { return dark ? new Color(100, 175, 230) : new Color(0, 120, 200); }
    public Color methodPost() { return dark ? new Color(110, 200, 130) : new Color(40, 140, 50); }
    public Color methodPut() { return dark ? new Color(230, 180, 70) : new Color(180, 130, 0); }
    public Color methodDelete() { return dark ? new Color(255, 110, 110) : new Color(200, 50, 50); }
    public Color redirectColor() { return dark ? new Color(100, 175, 230) : new Color(0, 120, 200); }
    public Color mutedText() { return dark ? new Color(140, 140, 140) : new Color(150, 150, 150); }

    // ── Dashboard / stat cards ─────────────────────────────

    /** Slightly raised surface for stat cards, distinct from the bar behind. */
    public Color statCardBg() {
        return dark ? new Color(52, 54, 60) : Color.WHITE;
    }

    public Color statCardBorder() {
        return dark ? new Color(72, 74, 82) : new Color(222, 224, 228);
    }

    /** Small caps-style label under/next to a stat value. */
    public Color statLabelFg() {
        return dark ? new Color(150, 153, 162) : new Color(125, 128, 136);
    }

    /** Cascade-hunting accent — violet family, deliberately distinct from
     *  the orange accent and the risk palette so cascade activity is
     *  identifiable at a glance in the dashboard. */
    public Color cascadeColor() {
        return dark ? new Color(170, 140, 255) : new Color(120, 90, 220);
    }

    /** Soft fill for the accent family (hover/tinted chips). */
    public Color accentSoft() {
        return dark ? new Color(80, 52, 40) : new Color(255, 236, 228);
    }

    public Color accentHover() {
        return dark ? new Color(245, 110, 55) : new Color(230, 88, 35);
    }

    /** Status dot green (agent on). */
    public Color agentOnColor() {
        return dark ? new Color(90, 200, 120) : new Color(26, 148, 72);
    }

    /** Live activity text ("正在自动分析 ...") in the dashboard. */
    public Color activityFg() {
        return dark ? new Color(170, 178, 192) : new Color(90, 96, 108);
    }

    // ── Dialog surfaces ────────────────────────────────────

    /** Header strip for destructive/warning confirmations (sandbox approval,
     *  batch-cost guards). Distinct from every card so the risk reads first. */
    public Color warningStripBg() {
        return dark ? new Color(68, 44, 42) : new Color(255, 238, 236);
    }

    public Color warningStripFg() {
        return dark ? new Color(255, 145, 135) : new Color(188, 58, 48);
    }

    /** Neutral raised surface inside dialogs (code panes, hint panels). */
    public Color dialogCardBg() {
        return dark ? new Color(48, 50, 56) : new Color(250, 250, 251);
    }

    public Color dialogCardBorder() {
        return dark ? new Color(70, 72, 80) : new Color(220, 222, 226);
    }

    // ── Separator / border ──

    public Color separator() {
        return dark ? new Color(70, 70, 70) : new Color(210, 210, 210);
    }

    // ── Quick prompt chip colors — neutral gray ──

    public Color chipBg() {
        return dark ? new Color(55, 55, 58) : new Color(245, 245, 245);
    }

    public Color chipFg() {
        return dark ? new Color(180, 180, 180) : new Color(80, 80, 80);
    }

    public Color chipBorder() {
        return dark ? new Color(80, 80, 80) : new Color(200, 200, 200);
    }

    // ── Message card backgrounds ──

    public Color userCardBg() {
        return dark ? new Color(45, 55, 65) : new Color(232, 240, 255);
    }

    public Color aiCardBg() {
        return dark ? new Color(50, 50, 50) : new Color(245, 245, 245);
    }

    // ── Code block rendering ──

    public Color codeBlockBg() {
        return dark ? new Color(30, 30, 35) : new Color(240, 240, 240);
    }

    public Color codeBlockBorder() {
        return dark ? new Color(60, 60, 65) : new Color(210, 210, 210);
    }

    public Color inlineCodeBg() {
        return dark ? new Color(55, 55, 60) : new Color(232, 232, 236);
    }

    // ── Tool call section ──

    public Color toolHeaderBg() {
        return dark ? new Color(40, 42, 48) : new Color(248, 248, 250);
    }

    public Color toolRunningColor() {
        return dark ? new Color(200, 170, 50) : new Color(180, 140, 0);
    }

    public Color toolDoneColor() {
        return dark ? new Color(60, 180, 90) : new Color(0, 140, 60);
    }

    // ── Markdown headings ──

    public Color headingColor() {
        return dark ? new Color(230, 230, 230) : new Color(30, 30, 30);
    }

    // Step progress panel colors — aligned with Burp orange accent
    public Color stepSelectedBg()  { return dark ? new Color(50, 45, 40)  : new Color(255, 245, 235); }
    public Color stepAccentBar()   { return dark ? new Color(230, 90, 40) : new Color(255, 102, 51); }
    public Color stepHeaderColor() { return dark ? new Color(240, 140, 80) : new Color(200, 80, 30); }
    public Color stepCompletedColor() { return dark ? new Color(60, 180, 90)  : new Color(0, 140, 60); }
    public Color stepRunningColor()   { return dark ? new Color(230, 170, 50) : new Color(200, 140, 0); }
    public Color stepHoverBg()     { return dark ? new Color(48, 48, 48)  : new Color(248, 248, 248); }
    /** Card "bubble" fill — distinct from the panel behind it so cards read as
     *  soft raised bubbles instead of blending into the background. */
    public Color stepCardBg()      { return dark ? new Color(52, 53, 57)  : Color.WHITE; }
    /** Muted canvas behind the step/verdict cards. */
    public Color stepPanelBg()     { return dark ? new Color(38, 39, 43)  : new Color(246, 247, 248); }
    public Color stepCountFg()     { return dark ? new Color(140, 140, 140) : new Color(120, 120, 120); }
    public Color stepTypeBg()      { return dark ? new Color(60, 50, 42)  : new Color(255, 240, 230); }
    public Color stepTypeFg()      { return dark ? new Color(230, 140, 80) : new Color(200, 80, 30); }
}
