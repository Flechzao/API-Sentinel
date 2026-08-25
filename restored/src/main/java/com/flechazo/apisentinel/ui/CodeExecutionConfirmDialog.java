package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Blocking human-approval gate for RunSandboxedCodeTool. Unlike every other
 * dialog in this codebase (ReplayDialog is MODELESS+SwingWorker, ImportDialog
 * is APPLICATION_MODAL but only ever opened from the EDT, TaskQueueDialog is
 * MODELESS), this one is invoked from the Agent's background tool-execution
 * thread and must block that thread until the user responds — there is no
 * existing "show modal from a background thread and wait" pattern in this
 * project to reuse, so this introduces it via a CountDownLatch.
 *
 * The dialog itself, and the calling thread's wait, both carry an explicit
 * caveat in the UI text: approving this does NOT mean the code is running in
 * a network/filesystem-isolated sandbox — see RunSandboxedCodeTool's
 * description for the actual (limited) isolation guarantees. This dialog is
 * the real safety boundary in default (non-autonomous) mode, so its text
 * must let the user make an informed call, not imply a false sense of safety.
 *
 * Safety semantics baked in here:
 *  - timeout auto-DISMISSES the dialog (the old version kept a dead dialog
 *    on screen — clicking "allow" after the await had expired silently
 *    returned reject, so the UI lied about what the click would do);
 *  - ESC and Enter both map to REJECT (the safe default);
 *  - a live countdown makes the 5-minute deadline visible instead of a
 *    silent refusal.
 */
public final class CodeExecutionConfirmDialog {

    private static final long AWAIT_TIMEOUT_SECONDS = 5 * 60;

    // Fallbacks for the (defensive) case where no MontoyaApi is available —
    // dark palette, matching Burp's dominant dark theme.
    private static final Color FB_STRIP_BG = new Color(68, 44, 42);
    private static final Color FB_STRIP_FG = new Color(255, 145, 135);
    private static final Color FB_CARD_BG = new Color(48, 50, 56);
    private static final Color FB_CARD_BORDER = new Color(70, 72, 80);
    private static final Color FB_TEXT = new Color(210, 210, 210);
    private static final Color FB_MUTED = new Color(150, 153, 162);
    private static final Color FB_CODE_BG = new Color(30, 30, 35);

    private CodeExecutionConfirmDialog() {}

    /**
     * Shows the dialog and blocks the calling thread until the user clicks a
     * button, or the timeout elapses (treated as reject — an unattended
     * timeout must never fall through to "approved").
     */
    public static boolean confirmBlocking(Frame owner, MontoyaApi api,
                                          String purpose, String interpreter, String code) {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean approved = new AtomicBoolean(false);

        SwingUtilities.invokeLater(() -> showDialog(owner, api, purpose, interpreter, code, latch, approved));

        try {
            boolean responded = latch.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return responded && approved.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void showDialog(Frame owner, MontoyaApi api, String purpose,
                                   String interpreter, String code,
                                   CountDownLatch latch, AtomicBoolean approved) {
        BurpTheme theme = null;
        if (api != null) {
            try { theme = new BurpTheme(api); } catch (Exception ignored) {}
        }
        final BurpTheme t = theme;

        JDialog dialog = new JDialog(owner, "确认执行代码", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setSize(680, 500);
        dialog.setLocationRelativeTo(owner);
        dialog.setLayout(new BorderLayout(0, 0));

        Color stripBg = t != null ? t.warningStripBg() : FB_STRIP_BG;
        Color stripFg = t != null ? t.warningStripFg() : FB_STRIP_FG;
        Color cardBg = t != null ? t.dialogCardBg() : FB_CARD_BG;
        Color cardBorder = t != null ? t.dialogCardBorder() : FB_CARD_BORDER;
        Color textFg = t != null ? t.aiTextColor() : FB_TEXT;
        Color mutedFg = t != null ? t.mutedText() : FB_MUTED;
        Color codeBg = t != null ? t.codeBlockBg() : FB_CODE_BG;

        // ── Warning strip (risk reads first) ──
        JPanel strip = new JPanel(new BorderLayout(10, 0));
        strip.setBackground(stripBg);
        strip.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        JLabel icon = new JLabel("⚠");
        icon.setFont(new Font("SansSerif", Font.BOLD, 18));
        icon.setForeground(stripFg);
        strip.add(icon, BorderLayout.WEST);

        // Wrapping JTextArea instead of an <html> JLabel — Burp's theme sets
        // html.disable on JLabels, which rendered the <html>/<br> tags as
        // literal text in this dialog (the "沙箱待确认有 html 标签" symptom).
        JTextArea warn = new JTextArea("Agent 请求在本机执行以下代码。\n"
                + "该沙箱不能保证隔离网络访问或本机真实文件系统——是否执行完全由你判断，"
                + "请确认代码内容与用途相符再批准。");
        warn.setEditable(false);
        warn.setLineWrap(true);
        warn.setWrapStyleWord(true);
        warn.setOpaque(false);
        warn.setBorder(null);
        warn.setFont(t != null ? t.displayFont(Font.PLAIN, 12f) : new Font("SansSerif", Font.PLAIN, 12));
        warn.setForeground(stripFg);
        strip.add(warn, BorderLayout.CENTER);
        dialog.add(strip, BorderLayout.NORTH);

        // ── Body: purpose row + code card ──
        JPanel body = new JPanel(new BorderLayout(0, 8));
        body.setBorder(BorderFactory.createEmptyBorder(12, 14, 8, 14));
        body.setOpaque(false);

        JPanel purposeRow = new JPanel(new BorderLayout(10, 0));
        purposeRow.setOpaque(false);
        JLabel purposeLabel = new JLabel("用途: " + (purpose != null && !purpose.isBlank() ? purpose : "(未说明)"));
        purposeLabel.setFont(t != null ? t.displayFont(Font.BOLD, 12f) : new Font("SansSerif", Font.BOLD, 12));
        purposeLabel.setForeground(textFg);
        purposeRow.add(purposeLabel, BorderLayout.CENTER);

        // Interpreter badge — one glance tells you which runtime will run.
        JLabel badge = new JLabel(" " + interpreter + " ");
        badge.setOpaque(true);
        badge.setBackground(cardBg);
        badge.setForeground(stripFg);
        badge.setFont(t != null ? t.displayFont(Font.BOLD, 11f) : new Font("SansSerif", Font.BOLD, 11));
        badge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(stripFg, 1, true),
                BorderFactory.createEmptyBorder(1, 4, 1, 4)));
        purposeRow.add(badge, BorderLayout.EAST);
        body.add(purposeRow, BorderLayout.NORTH);

        // Code card: rounded surface, header meta row (line count + countdown),
        // monospaced body.
        RoundedPanel codeCard = new RoundedPanel(new BorderLayout(0, 0));
        codeCard.setCornerRadius(BurpTheme.RADIUS_MD);
        codeCard.setBackground(cardBg);
        codeCard.setBorder(BorderFactory.createEmptyBorder(8, 10, 10, 10));

        int lineCount = code == null ? 0 : code.split("\n", -1).length;
        JLabel metaLabel = new JLabel("待执行代码 · 共 " + lineCount + " 行 · "
                + (code == null ? 0 : code.length()) + " 字符");
        metaLabel.setFont(t != null ? t.displayFont(Font.PLAIN, 11f) : new Font("SansSerif", Font.PLAIN, 11));
        metaLabel.setForeground(mutedFg);
        metaLabel.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 2));
        codeCard.add(metaLabel, BorderLayout.NORTH);

        JTextArea codeArea = new JTextArea(code == null ? "" : code);
        codeArea.setFont(t != null ? t.editorFont(12f) : new Font("Monospaced", Font.PLAIN, 12));
        codeArea.setForeground(textFg);
        codeArea.setCaretColor(textFg);
        codeArea.setEditable(false);
        codeArea.setLineWrap(false);
        codeArea.setBackground(codeBg);
        JScrollPane codeScroll = new JScrollPane(codeArea);
        codeScroll.setBorder(BorderFactory.createEmptyBorder());
        codeScroll.getViewport().setBackground(codeBg);
        codeCard.add(codeScroll, BorderLayout.CENTER);

        body.add(codeCard, BorderLayout.CENTER);
        dialog.add(body, BorderLayout.CENTER);

        // ── Buttons + countdown ──
        JPanel south = new JPanel(new BorderLayout(0, 6));
        south.setBorder(BorderFactory.createEmptyBorder(0, 14, 12, 14));
        south.setOpaque(false);

        JLabel countdownLabel = new JLabel();
        countdownLabel.setFont(t != null ? t.displayFont(Font.PLAIN, 11f) : new Font("SansSerif", Font.PLAIN, 11));
        countdownLabel.setForeground(mutedFg);
        countdownLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        south.add(countdownLabel, BorderLayout.NORTH);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttonPanel.setOpaque(false);

        JButton rejectBtn = new JButton("拒绝");
        rejectBtn.setFont(t != null ? t.displayFont(Font.BOLD, 12f) : new Font("SansSerif", Font.BOLD, 12));
        JButton approveBtn = new JButton("允许执行");
        approveBtn.setFont(t != null ? t.displayFont(Font.BOLD, 12f) : new Font("SansSerif", Font.BOLD, 12));
        // The dangerous action gets an accent outline but NOT the default
        // button slot — Enter must never approve code execution by reflex.
        approveBtn.setForeground(stripFg);
        approveBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(stripFg, 1, true),
                UIManager.getBorder("Button.border") != null
                        ? UIManager.getBorder("Button.border") : BorderFactory.createEmptyBorder(4, 12, 4, 12)));

        buttonPanel.add(rejectBtn);
        buttonPanel.add(approveBtn);
        south.add(buttonPanel, BorderLayout.CENTER);
        dialog.add(south, BorderLayout.SOUTH);

        // ── Countdown: auto-dismiss at the deadline ──
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
            dialog.dispose();
            latch.countDown();
        });

        // ESC rejects; Enter rejects (default button). Closing the window
        // (OS close button) rejects. Every path lands on the safe side.
        dialog.getRootPane().setDefaultButton(rejectBtn);
        dialog.getRootPane().registerKeyboardAction(e -> reject.run(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);

        dialog.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { reject.run(); }
            @Override public void windowClosed(WindowEvent e) { countdown.stop(); }
        });

        if (t != null) t.apply(dialog);
        // Re-assert strip/card colors after the L&F pass — apply() may reset
        // child backgrounds belonging to the plain JDialog content pane.
        strip.setBackground(stripBg);
        warn.setForeground(stripFg);
        icon.setForeground(stripFg);
        badge.setBackground(cardBg);
        badge.setForeground(stripFg);
        codeCard.setBackground(cardBg);
        codeArea.setBackground(codeBg);
        countdownLabel.setForeground(mutedFg);
        metaLabel.setForeground(mutedFg);
        purposeLabel.setForeground(textFg);
        codeArea.setForeground(textFg);
        approveBtn.setForeground(stripFg);

        dialog.setVisible(true);
        // Focus the safe action when shown.
        SwingUtilities.invokeLater(rejectBtn::requestFocusInWindow);
    }
}
