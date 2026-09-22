package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Blocking human-approval gate for browser_interact tool.
 *
 * <p>When the Agent wants to open a visible browser and execute UI actions
 * (click, fill, submit forms), this dialog shows the planned actions and
 * asks for confirmation — similar to {@link CodeExecutionConfirmDialog}
 * for run_sandboxed_code.
 *
 * <p><b>Session-level approval:</b> Once the user checks "不再询问" and approves,
 * all subsequent browser_interact calls in the same extension session proceed
 * without prompting. This avoids repetitive confirmations during a multi-step
 * analysis while still giving the user control over the first interaction.
 *
 * <p>Safety: timeout auto-rejects, ESC rejects, Enter rejects, closing window rejects.
 */
public final class BrowserInteractConfirmDialog {

    private static final long AWAIT_TIMEOUT_SECONDS = 3 * 60;

    /** Session-level flag: once approved with "don't ask again", skip future prompts. */
    private static volatile boolean sessionAutoApproved = false;

    // Fallback colors (when MontoyaApi/BurpTheme unavailable)
    private static final Color FB_STRIP_BG = new Color(42, 58, 80);
    private static final Color FB_STRIP_FG = new Color(120, 180, 255);
    private static final Color FB_CARD_BG = new Color(48, 50, 56);
    private static final Color FB_TEXT = new Color(210, 210, 210);
    private static final Color FB_MUTED = new Color(150, 153, 162);
    private static final Color FB_CODE_BG = new Color(30, 30, 35);

    private BrowserInteractConfirmDialog() {}

    /**
     * Reset session auto-approval (called on extension unload).
     */
    public static void resetSessionApproval() {
        sessionAutoApproved = false;
    }

    /**
     * Check if session-level auto-approval is active.
     */
    public static boolean isSessionAutoApproved() {
        return sessionAutoApproved;
    }

    /**
     * Show the confirmation dialog and block until user responds.
     *
     * <p>If the user previously approved with "不再询问", returns true immediately
     * without showing the dialog.
     *
     * @param owner   parent frame
     * @param api     MontoyaApi for theme (may be null)
     * @param url     target page URL
     * @param actions list of action descriptions (type + selector/value)
     * @param purpose why the Agent needs this interaction
     * @return true if approved, false if rejected or timed out
     */
    public static boolean confirmBlocking(Frame owner, MontoyaApi api,
                                          String url, List<ActionDesc> actions, String purpose) {
        // Session-level skip
        if (sessionAutoApproved) {
            return true;
        }
        // Global skip-all-permissions toggle (--dangerously-skip-permissions)
        if (Boolean.getBoolean("api-sentinel.skip-permissions")) {
            return true;
        }

        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean approved = new AtomicBoolean(false);

        SwingUtilities.invokeLater(() -> showDialog(owner, api, url, actions, purpose, latch, approved));

        try {
            boolean responded = latch.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return responded && approved.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Simple action description for display in the dialog.
     */
    public record ActionDesc(String type, String detail) {
        @Override
        public String toString() {
            return type + ": " + detail;
        }
    }

    private static void showDialog(Frame owner, MontoyaApi api, String url,
                                   List<ActionDesc> actions, String purpose,
                                   CountDownLatch latch, AtomicBoolean approved) {
        BurpTheme theme = null;
        if (api != null) {
            try { theme = new BurpTheme(api); } catch (Exception ignored) {}
        }
        final BurpTheme t = theme;

        JDialog dialog = new JDialog(owner, "确认浏览器操作", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setSize(640, 480);
        dialog.setLocationRelativeTo(owner);
        dialog.setLayout(new BorderLayout(0, 0));

        Color stripBg = t != null ? t.warningStripBg() : FB_STRIP_BG;
        Color stripFg = t != null ? t.warningStripFg() : FB_STRIP_FG;
        Color cardBg = t != null ? t.dialogCardBg() : FB_CARD_BG;
        Color textFg = t != null ? t.aiTextColor() : FB_TEXT;
        Color mutedFg = t != null ? t.mutedText() : FB_MUTED;
        Color codeBg = t != null ? t.codeBlockBg() : FB_CODE_BG;

        // ── Info strip ──
        JPanel strip = new JPanel(new BorderLayout(10, 0));
        strip.setBackground(stripBg);
        strip.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        JLabel icon = new JLabel("🌐");
        icon.setFont(new Font("SansSerif", Font.BOLD, 18));
        icon.setForeground(stripFg);
        strip.add(icon, BorderLayout.WEST);

        JTextArea warn = new JTextArea("Agent 请求打开浏览器执行 UI 操作。\n"
                + "浏览器将通过 Burp 代理，所有流量可被捕获和审查。\n"
                + "确认操作序列与你的分析目标相符后再批准。");
        warn.setEditable(false);
        warn.setLineWrap(true);
        warn.setWrapStyleWord(true);
        warn.setOpaque(false);
        warn.setBorder(null);
        warn.setFont(t != null ? t.displayFont(Font.PLAIN, 12f) : new Font("SansSerif", Font.PLAIN, 12));
        warn.setForeground(stripFg);
        strip.add(warn, BorderLayout.CENTER);
        dialog.add(strip, BorderLayout.NORTH);

        // ── Body ──
        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setBorder(BorderFactory.createEmptyBorder(12, 14, 8, 14));
        body.setOpaque(false);

        // Target URL + purpose
        JPanel headerRow = new JPanel(new BorderLayout(10, 0));
        headerRow.setOpaque(false);

        JPanel urlPanel = new JPanel(new BorderLayout(4, 0));
        urlPanel.setOpaque(false);
        JLabel urlLabel = new JLabel("目标页面:");
        urlLabel.setFont(t != null ? t.displayFont(Font.BOLD, 12f) : new Font("SansSerif", Font.BOLD, 12));
        urlLabel.setForeground(mutedFg);
        JTextField urlField = new JTextField(url != null ? url : "");
        urlField.setEditable(false);
        urlField.setFont(t != null ? t.editorFont(12f) : new Font("Monospaced", Font.PLAIN, 12));
        urlField.setForeground(textFg);
        urlField.setBackground(codeBg);
        urlField.setCaretColor(textFg);
        urlPanel.add(urlLabel, BorderLayout.NORTH);
        urlPanel.add(urlField, BorderLayout.CENTER);

        headerRow.add(urlPanel, BorderLayout.CENTER);

        if (purpose != null && !purpose.isBlank()) {
            JLabel purposeLabel = new JLabel("用途: " + purpose);
            purposeLabel.setFont(t != null ? t.displayFont(Font.PLAIN, 11f) : new Font("SansSerif", Font.PLAIN, 11));
            purposeLabel.setForeground(mutedFg);
            headerRow.add(purposeLabel, BorderLayout.SOUTH);
        }

        body.add(headerRow, BorderLayout.NORTH);

        // Actions list card
        RoundedPanel actionsCard = new RoundedPanel(new BorderLayout(0, 0));
        actionsCard.setCornerRadius(BurpTheme.RADIUS_MD);
        actionsCard.setBackground(cardBg);
        actionsCard.setBorder(BorderFactory.createEmptyBorder(8, 10, 10, 10));

        int actionCount = actions != null ? actions.size() : 0;
        JLabel metaLabel = new JLabel("操作序列 · " + actionCount + " 步");
        metaLabel.setFont(t != null ? t.displayFont(Font.PLAIN, 11f) : new Font("SansSerif", Font.PLAIN, 11));
        metaLabel.setForeground(mutedFg);
        metaLabel.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 2));
        actionsCard.add(metaLabel, BorderLayout.NORTH);

        // Build actions text
        StringBuilder sb = new StringBuilder();
        if (actions != null) {
            for (int i = 0; i < actions.size(); i++) {
                ActionDesc a = actions.get(i);
                sb.append(String.format("%d. %s\n", i + 1, a));
            }
        }
        JTextArea actionsArea = new JTextArea(sb.toString());
        actionsArea.setFont(t != null ? t.editorFont(12f) : new Font("Monospaced", Font.PLAIN, 12));
        actionsArea.setForeground(textFg);
        actionsArea.setCaretColor(textFg);
        actionsArea.setEditable(false);
        actionsArea.setLineWrap(false);
        actionsArea.setBackground(codeBg);
        JScrollPane scroll = new JScrollPane(actionsArea);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(codeBg);
        actionsCard.add(scroll, BorderLayout.CENTER);

        body.add(actionsCard, BorderLayout.CENTER);
        dialog.add(body, BorderLayout.CENTER);

        // ── South: checkbox + countdown + buttons ──
        JPanel south = new JPanel(new BorderLayout(0, 6));
        south.setBorder(BorderFactory.createEmptyBorder(0, 14, 12, 14));
        south.setOpaque(false);

        JCheckBox dontAskAgain = new JCheckBox("本次会话不再询问（后续 browser_interact 自动批准）");
        dontAskAgain.setFont(t != null ? t.displayFont(Font.PLAIN, 11f) : new Font("SansSerif", Font.PLAIN, 11));
        dontAskAgain.setForeground(textFg);
        dontAskAgain.setOpaque(false);
        dontAskAgain.setToolTipText("勾选后，本次扩展运行期间所有浏览器交互操作将自动批准，不再弹窗确认。");
        south.add(dontAskAgain, BorderLayout.NORTH);

        JLabel countdownLabel = new JLabel();
        countdownLabel.setFont(t != null ? t.displayFont(Font.PLAIN, 11f) : new Font("SansSerif", Font.PLAIN, 11));
        countdownLabel.setForeground(mutedFg);
        countdownLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        south.add(countdownLabel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttonPanel.setOpaque(false);

        JButton rejectBtn = new JButton("拒绝");
        rejectBtn.setFont(t != null ? t.displayFont(Font.BOLD, 12f) : new Font("SansSerif", Font.BOLD, 12));
        JButton approveBtn = new JButton("允许打开浏览器");
        approveBtn.setFont(t != null ? t.displayFont(Font.BOLD, 12f) : new Font("SansSerif", Font.BOLD, 12));
        approveBtn.setForeground(stripFg);
        approveBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(stripFg, 1, true),
                UIManager.getBorder("Button.border") != null
                        ? UIManager.getBorder("Button.border") : BorderFactory.createEmptyBorder(4, 12, 4, 12)));

        buttonPanel.add(rejectBtn);
        buttonPanel.add(approveBtn);
        south.add(buttonPanel, BorderLayout.SOUTH);
        dialog.add(south, BorderLayout.SOUTH);

        // ── Countdown ──
        long deadline = System.currentTimeMillis() + AWAIT_TIMEOUT_SECONDS * 1000L;
        Timer countdown = new Timer(1000, null);
        countdown.addActionListener(e -> {
            long remainMs = deadline - System.currentTimeMillis();
            if (remainMs <= 0) {
                countdown.stop();
                approved.set(false);
                dialog.dispose();
                latch.countDown();
            } else {
                long remain = remainMs / 1000;
                countdownLabel.setText(String.format("⏱ %d:%02d 后未响应将自动拒绝", remain / 60, remain % 60));
            }
        });
        countdown.setInitialDelay(0);
        countdown.start();

        Runnable reject = () -> {
            countdown.stop();
            approved.set(false);
            dialog.dispose();
            latch.countDown();
        };

        rejectBtn.addActionListener(e -> reject.run());
        approveBtn.addActionListener(e -> {
            countdown.stop();
            approved.set(true);
            if (dontAskAgain.isSelected()) {
                sessionAutoApproved = true;
            }
            dialog.dispose();
            latch.countDown();
        });

        // ESC rejects; Enter rejects (safe default)
        dialog.getRootPane().setDefaultButton(rejectBtn);
        dialog.getRootPane().registerKeyboardAction(e -> reject.run(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);

        dialog.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { reject.run(); }
            @Override public void windowClosed(WindowEvent e) { countdown.stop(); }
        });

        if (t != null) t.apply(dialog);
        // Re-assert colors after L&F pass
        strip.setBackground(stripBg);
        warn.setForeground(stripFg);
        icon.setForeground(stripFg);
        actionsCard.setBackground(cardBg);
        actionsArea.setBackground(codeBg);
        urlField.setBackground(codeBg);
        countdownLabel.setForeground(mutedFg);
        metaLabel.setForeground(mutedFg);
        approveBtn.setForeground(stripFg);
        dontAskAgain.setForeground(textFg);
        actionsArea.setForeground(textFg);
        urlField.setForeground(textFg);

        dialog.setVisible(true);
        SwingUtilities.invokeLater(rejectBtn::requestFocusInWindow);
    }
}
