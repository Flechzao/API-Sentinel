package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.agent.tool.UserInteractionBridge;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * UI implementation of {@link UserInteractionBridge}: renders the question as
 * an inline card in the conversation flow (Claude-Code style) and blocks the
 * calling agent/tool thread until the operator answers or the timeout lapses.
 *
 * This replaces the always-modal CodeExecutionConfirmDialog as the PRIMARY
 * path for sandbox approvals — the user asked for confirmations to happen in
 * the conversation itself, no separate window. The dialog survives as the
 * fallback for when no bridge is attached (headless/tests).
 *
 * Cards are appended to the currently visible conversation (and the panel is
 * flipped to chat view if an analysis left it in step view) so the card is
 * always on screen; a toast also fires in case the user is looking at another
 * tab. Answered cards stay in the flow as an audit trail — they get disabled
 * and stamped with the outcome, never removed.
 */
class ChatInteractionBridge implements UserInteractionBridge {

    /** Stores the user's free-text answer when askChoice returns -2. */
    private volatile String lastCustomAnswer;

    @Override
    public String getLastCustomAnswer() {
        return lastCustomAnswer;
    }

    private final Supplier<AiChatPanel> chatPanelSupplier;

    ChatInteractionBridge(Supplier<AiChatPanel> chatPanelSupplier) {
        this.chatPanelSupplier = chatPanelSupplier;
    }

    @Override
    public Boolean askConfirmation(String title, String detail, String code,
                                    String approveLabel, String rejectLabel,
                                    long timeoutSeconds) {
        AiChatPanel panel = chatPanelSupplier.get();
        if (panel == null) return null;

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Boolean> answer = new AtomicReference<>();
        JLabel status = new JLabel(" ");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        buttons.setOpaque(false);

        SwingUtilities.invokeLater(() -> {
            BurpTheme theme = panel.theme();
            RoundedPanel card = new RoundedPanel(new BorderLayout(0, 6));
            card.setCornerRadius(BurpTheme.RADIUS_LG);
            card.setBackground(theme.aiCardBg());
            card.setBorder(new EmptyBorder(10, 12, 10, 12));
            card.setAlignmentX(Component.LEFT_ALIGNMENT);

            JLabel titleLabel = new JLabel("⚠ " + title);
            titleLabel.setFont(theme.displayFont(Font.BOLD, 12f));
            titleLabel.setForeground(theme.headingColor());

            JPanel body = new JPanel();
            body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
            body.setOpaque(false);
            body.setAlignmentX(Component.LEFT_ALIGNMENT);
            if (detail != null && !detail.isBlank()) {
                body.add(wrappedArea(detail, 420, theme, false, 12f));
            }
            if (code != null && !code.isBlank()) {
                JTextArea codeArea = new JTextArea(code);
                codeArea.setFont(theme.editorFont(12f));
                codeArea.setEditable(false);
                codeArea.setLineWrap(true);
                codeArea.setWrapStyleWord(true);
                codeArea.setRows(Math.min(12, Math.max(2, code.split("\n", -1).length)));
                codeArea.setBackground(theme.chatBg());
                codeArea.setBorder(new EmptyBorder(6, 8, 6, 8));
                codeArea.setAlignmentX(Component.LEFT_ALIGNMENT);
                body.add(Box.createVerticalStrut(4));
                body.add(codeArea);
            }

            status.setFont(theme.displayFont(Font.PLAIN, 11f));
            status.setForeground(theme.systemColor());

            JButton approve = flatButton(theme, approveLabel);
            approve.addActionListener(e -> {
                answer.set(Boolean.TRUE);
                status.setText("✅ " + approveLabel);
                disableAll(buttons);
                latch.countDown();
            });
            JButton reject = flatButton(theme, rejectLabel);
            reject.addActionListener(e -> {
                answer.set(Boolean.FALSE);
                status.setText("⛔ " + rejectLabel);
                disableAll(buttons);
                latch.countDown();
            });
            buttons.add(approve);
            buttons.add(reject);

            card.add(titleLabel, BorderLayout.NORTH);
            card.add(body, BorderLayout.CENTER);
            JPanel south = new JPanel(new BorderLayout());
            south.setOpaque(false);
            south.add(status, BorderLayout.WEST);
            south.add(buttons, BorderLayout.EAST);
            card.add(south, BorderLayout.SOUTH);

            panel.addInteractionCard(card);
            panel.toast("Agent 请求确认: " + title, true);
        });

        return await(latch, answer, timeoutSeconds, buttons, status, "⏱ 确认超时（已自动拒绝）");
    }

    @Override
    public Integer askChoice(String question, String context, List<String> options,
                             long timeoutSeconds) {
        AiChatPanel panel = chatPanelSupplier.get();
        if (panel == null) return null;

        CountDownLatch latch = new CountDownLatch(1);
        AtomicInteger answer = new AtomicInteger(-1);
        JLabel status = new JLabel(" ");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        buttons.setOpaque(false);

        SwingUtilities.invokeLater(() -> {
            BurpTheme theme = panel.theme();
            RoundedPanel card = new RoundedPanel(new BorderLayout(0, 6));
            card.setCornerRadius(BurpTheme.RADIUS_LG);
            card.setBackground(theme.aiCardBg());
            card.setBorder(new EmptyBorder(10, 12, 10, 12));
            card.setAlignmentX(Component.LEFT_ALIGNMENT);

            JLabel titleLabel = new JLabel("❓ Agent 提问");
            titleLabel.setFont(theme.displayFont(Font.BOLD, 12f));
            titleLabel.setForeground(theme.headingColor());

            JPanel body = new JPanel();
            body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
            body.setOpaque(false);
            body.setAlignmentX(Component.LEFT_ALIGNMENT);
            body.add(wrappedArea(question, 420, theme, false, 12f));
            if (context != null && !context.isBlank()) {
                JTextArea ctx = wrappedArea(context, 420, theme, true, 11f);
                ctx.setForeground(theme.systemColor());
                body.add(ctx);
            }

            status.setFont(theme.displayFont(Font.PLAIN, 11f));
            status.setForeground(theme.systemColor());

            for (int i = 0; i < options.size(); i++) {
                JButton opt = flatButton(theme, options.get(i));
                int idx = i;
                opt.addActionListener(e -> {
                    answer.set(idx);
                    status.setText("✅ 已选择: " + options.get(idx));
                    disableAll(buttons);
                    latch.countDown();
                });
                buttons.add(opt);
            }

            // Free-text input for custom answers not covered by the options
            JTextField customInput = new JTextField(24);
            customInput.setFont(theme.displayFont(Font.PLAIN, 12f));
            JButton customBtn = flatButton(theme, "提交自定义答案");
            customBtn.addActionListener(e -> {
                String text = customInput.getText().trim();
                if (text.isEmpty()) {
                    status.setText("⚠ 请输入内容后再提交");
                    return;
                }
                lastCustomAnswer = text;
                answer.set(-2);
                status.setText("✅ 已提交自定义答案");
                disableAll(buttons);
                customInput.setEnabled(false);
                customBtn.setEnabled(false);
                latch.countDown();
            });
            // Enter key submits
            customInput.addActionListener(e -> customBtn.doClick());

            JPanel customRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            customRow.setOpaque(false);
            customRow.add(customInput);
            customRow.add(customBtn);

            JButton skip = flatButton(theme, "跳过（让 Agent 自主决策）");
            skip.addActionListener(e -> {
                answer.set(-1);
                status.setText("⏭ 已跳过");
                disableAll(buttons);
                latch.countDown();
            });
            buttons.add(skip);

            card.add(titleLabel, BorderLayout.NORTH);
            card.add(body, BorderLayout.CENTER);
            JPanel south = new JPanel(new BorderLayout());
            south.setOpaque(false);
            south.add(status, BorderLayout.WEST);
            south.add(buttons, BorderLayout.SOUTH);
            card.add(south, BorderLayout.SOUTH);

            // Insert the custom text row between body and south
            card.add(customRow, BorderLayout.EAST);

            panel.addInteractionCard(card);
            panel.toast("Agent 有问题要问你（见对话面板）", false);
        });

        boolean answered;
        try {
            answered = latch.await(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            answered = latch.getCount() == 0;
        }
        if (answered && answer.get() != -1) {
            // Returns the option index (>=0) or -2 for custom free-text answer.
            return answer.get();
        }
        if (!answered) {
            // Stamp the dead card so the UI doesn't lie about being clickable.
            SwingUtilities.invokeLater(() -> {
                status.setText("⏱ 未响应（Agent 将自主决策）");
                disableAll(buttons);
            });
        }
        return null;
    }

    // ======================== helpers ========================

    /** Blocking wait shared by the confirmation path; stamps the card on timeout. */
    private Boolean await(CountDownLatch latch, AtomicReference<Boolean> answer,
                          long timeoutSeconds, JPanel buttons, JLabel status, String timeoutText) {
        boolean answered;
        try {
            answered = latch.await(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            answered = latch.getCount() == 0;
        }
        if (answered) {
            Boolean v = answer.get();
            return v != null ? v : Boolean.FALSE;
        }
        // Timed out: stamp the dead card so the UI doesn't lie about being clickable.
        SwingUtilities.invokeLater(() -> {
            status.setText(timeoutText);
            disableAll(buttons);
        });
        return null;
    }

    private static void disableAll(java.awt.Container c) {
        for (java.awt.Component child : c.getComponents()) {
            if (child instanceof JButton b) b.setEnabled(false);
            else if (child instanceof java.awt.Container cc) disableAll(cc);
        }
    }

    private static JButton flatButton(BurpTheme theme, String text) {
        JButton btn = new JButton(text);
        btn.setFont(theme.displayFont(Font.PLAIN, 11f));
        btn.setFocusPainted(false);
        btn.setMargin(new Insets(3, 10, 3, 10));
        return btn;
    }

    /** Wrapping text component that does NOT rely on HTML rendering. Burp's
     *  theme sets the {@code html.disable} client property on JLabels, which
     *  makes any {@code <html>...} text render as raw literal tags — the
     *  symptom users saw ("沙箱待确认弹窗有 html 标签"). A line-wrapping,
     *  non-editable JTextArea wraps at a fixed width without any HTML, so it's
     *  immune. Mirrors MarkdownRenderer's deliberate avoidance of html labels. */
    private static JTextArea wrappedArea(String text, int widthPx, BurpTheme theme,
                                          boolean italic, float size) {
        JTextArea area = new JTextArea(text == null ? "" : text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setBorder(null);
        area.setFont(theme.displayFont(italic ? Font.ITALIC : Font.PLAIN, size));
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Give it the target width, then ask for the wrapped height.
        area.setSize(widthPx, Integer.MAX_VALUE);
        Dimension pref = area.getPreferredSize();
        area.setPreferredSize(new Dimension(widthPx, Math.max(pref.height, 16)));
        return area;
    }
}
