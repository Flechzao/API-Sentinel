package com.flechazo.apisentinel.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.geom.Arc2D;

public final class ChatMessagePanel extends JPanel {

    private final BurpTheme theme;

    private ChatMessagePanel(BurpTheme theme) {
        this.theme = theme;
        setLayout(new BorderLayout());
        setOpaque(false);
        setBorder(new EmptyBorder(6, 0, 6, 0));
        setAlignmentX(Component.LEFT_ALIGNMENT);
    }

    /** Small muted role caption above a bubble ("我" right-aligned for the
     *  user, "AI" left-aligned) — gives the transcript a visible speaker
     *  column like modern chat apps, cheap and timestamp-schema-free. */
    private JLabel roleCaption(String text, int align) {
        JLabel caption = new JLabel(text);
        caption.setFont(theme.displayFont(Font.PLAIN, 10.5f));
        caption.setForeground(theme.mutedText());
        JPanel row = new JPanel(new FlowLayout(align, 0, 0));
        row.setOpaque(false);
        row.add(caption);
        row.setBorder(new EmptyBorder(0, 4, 2, 4));
        add(row, BorderLayout.NORTH);
        return caption;
    }

    @Override
    public Dimension getMaximumSize() {
        Dimension pref = getPreferredSize();
        Container parent = getParent();
        int width = parent != null ? parent.getWidth() : pref.width;
        if (width <= 0) width = pref.width;
        return new Dimension(width, pref.height);
    }

    // ── Factory: user message ──

    public static ChatMessagePanel userMessage(String text, BurpTheme theme) {
        ChatMessagePanel panel = new ChatMessagePanel(theme);

        RoundedPanel card = new RoundedPanel(new BorderLayout()) {
            // Cap the bubble at ~72% of the chat width; right-aligned below.
            @Override public Dimension getPreferredSize() {
                Dimension d = super.getPreferredSize();
                int max = maxUserBubbleWidth(panel);
                return d.width > max ? new Dimension(max, d.height) : d;
            }
            @Override public Dimension getMaximumSize() {
                return new Dimension(maxUserBubbleWidth(panel), Integer.MAX_VALUE);
            }
        };
        card.setCornerRadius(16);
        card.setBackground(theme.userCardBg());
        card.setBorderColor(theme.accentSoft());
        card.setBorder(new EmptyBorder(9, 13, 9, 13));

        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFont(theme.displayFont(Font.PLAIN, 13f));
        area.setForeground(theme.aiTextColor());
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(null);
        card.add(area, BorderLayout.CENTER);

        // Right-align the capped bubble inside the full row width — user
        // speech reads as a distinct column instead of the same full-width
        // block as AI replies (modern chat convention: you right, AI left).
        JPanel wrapper = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        wrapper.setOpaque(false);
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);
        wrapper.add(card);

        panel.roleCaption("我", FlowLayout.RIGHT);
        panel.add(wrapper, BorderLayout.CENTER);
        return panel;
    }

    private static int maxUserBubbleWidth(ChatMessagePanel panel) {
        Container parent = panel.getParent();
        int w = parent != null ? parent.getWidth() : 0;
        if (w <= 0) w = 560;
        return Math.max(200, (int) (w * 0.72));
    }

    // ── Factory: AI message (Markdown rendered) ──

    public static ChatMessagePanel aiMessage(String markdown, BurpTheme theme) {
        ChatMessagePanel panel = new ChatMessagePanel(theme);

        RoundedPanel card = new RoundedPanel(new BorderLayout());
        card.setCornerRadius(16);
        card.setBackground(theme.aiCardBg());
        card.setBorderColor(theme.separator());
        card.setBorder(new EmptyBorder(9, 13, 9, 13));

        MarkdownRenderer renderer = new MarkdownRenderer(theme);
        JPanel content = renderer.renderToPanel(markdown);
        card.add(content, BorderLayout.CENTER);

        panel.roleCaption("AI", FlowLayout.LEFT);
        panel.add(card, BorderLayout.CENTER);
        return panel;
    }

    // ── Factory: system / event note with a semantic accent bar ──

    /** System and event notes (pipeline phases, agent status, cascade
     *  triggers) used to render as flat grey italics — every run-level event
     *  looked identical, hiding what just happened. A thin colored accent
     *  bar keyed off the note's leading glyph (⚡ cascade, ✅ success, ❌
     *  failure, ▶ phase) makes the event stream scannable at a glance. */
    public static ChatMessagePanel noteMessage(String text, BurpTheme theme, Color accent) {
        ChatMessagePanel panel = new ChatMessagePanel(theme);

        JPanel row = new JPanel(new BorderLayout(0, 0));
        row.setOpaque(false);

        JPanel bar = new JPanel();
        bar.setBackground(accent);
        bar.setPreferredSize(new Dimension(3, 0));
        row.add(bar, BorderLayout.WEST);

        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFont(theme.displayFont(Font.ITALIC, 12f));
        area.setForeground(theme.systemColor());
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(new EmptyBorder(4, 10, 4, 2));
        row.add(area, BorderLayout.CENTER);

        panel.add(row, BorderLayout.CENTER);
        return panel;
    }

    // ── Factory: animated "thinking" note ──

    /** The agent/LLM "思考中…" placeholder. Previously a flat static line — now
     *  a self-drawn rotating arc spinner (reusing the {@link IconFactory}
     *  RUNNING arc geometry) driven by a Swing {@link Timer}. The timer is
     *  stashed as the {@code "anim-timer"} client property so {@code AiChatPanel}
     *  can stop it when the run ends; the spinner also stops itself on
     *  {@code removeNotify()} as a safety net. */
    public static ChatMessagePanel thinkingMessage(BurpTheme theme) {
        ChatMessagePanel panel = new ChatMessagePanel(theme);

        JPanel row = new JPanel(new BorderLayout(0, 0));
        row.setOpaque(false);

        JPanel bar = new JPanel();
        bar.setBackground(theme.stepRunningColor());
        bar.setPreferredSize(new Dimension(3, 0));
        row.add(bar, BorderLayout.WEST);

        JPanel line = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        line.setOpaque(false);
        line.setBorder(new EmptyBorder(4, 10, 4, 2));

        Spinner spinner = new Spinner(14, theme.stepRunningColor());
        line.add(spinner);

        JLabel label = new JLabel("思考中…");
        label.setFont(theme.displayFont(Font.ITALIC, 12f));
        label.setForeground(theme.systemColor());
        line.add(label);

        row.add(line, BorderLayout.CENTER);
        panel.add(row, BorderLayout.CENTER);
        // AiChatPanel's cleanup reads this to stop the animation on run end.
        panel.putClientProperty("anim-timer", spinner.timer());
        return panel;
    }

    /** Self-drawn rotating spinner — a 300° arc spun by a Swing Timer. Vector,
     *  crisp at any size, theme-colored; no emoji, no image asset. */
    public static final class Spinner extends JComponent {
        private final Timer timer;
        private final int sz;
        private final Color color;
        private double angle;

        public Spinner(int sz, Color color) {
            this.sz = sz;
            this.color = color != null ? color : Color.GRAY;
            setOpaque(false);
            setPreferredSize(new Dimension(sz, sz));
            // ~14 fps rotation; each tick advances 30° for a smooth spin.
            timer = new Timer(70, e -> { angle += Math.PI / 6; repaint(); });
            timer.start();
        }

        public Timer timer() { return timer; }

        @Override public void removeNotify() {
            super.removeNotify();
            timer.stop(); // safety net beyond AiChatPanel's explicit cleanup
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL,
                        RenderingHints.VALUE_STROKE_PURE);
                g2.rotate(angle, sz / 2.0, sz / 2.0);
                double s = sz / 24.0;
                g2.scale(s, s);
                g2.setColor(color);
                g2.setStroke(new BasicStroke(2.6f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.draw(new Arc2D.Double(3, 3, 18, 18, 90, 300, Arc2D.OPEN));
            } finally {
                g2.dispose();
            }
        }
    }

    /** Map a note's leading glyph to its semantic accent color. */
    public static Color classifyNoteColor(String text, BurpTheme theme) {
        if (text == null || text.isEmpty()) return theme.systemColor();
        return switch (text.charAt(0)) {
            case '⚡' -> theme.cascadeColor();
            case '⛔', '❌', '⚠' -> theme.errorColor();
            case '✅', '✓' -> theme.toolDoneColor();
            case '▶' -> theme.stepHeaderColor();
            default -> supplementaryAccent(text.codePointAt(0), theme);
        };
    }

    // 🚀 🔍 🤖 live in the supplementary plane and can't be `char` cases.
    private static Color supplementaryAccent(int codePoint, BurpTheme theme) {
        if (codePoint == 0x1F680 || codePoint == 0x1F50D || codePoint == 0x1F916) {
            return theme.stepHeaderColor();
        }
        return theme.systemColor();
    }
}
