package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Vertical timeline view of agent execution events.
 * Each event is rendered as a row with a colored dot, timestamp, type icon,
 * summary, and an expandable detail area.
 */
public class TimelinePanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

    private final List<TimelineEvent> events = new ArrayList<>();
    private final JPanel contentPanel;
    private final JLabel summaryLabel;
    private final BurpTheme theme;
    private final Color bg;

    private int totalLlmCalls = 0;
    private int totalTokens = 0;
    private int totalIterations = 0;

    public TimelinePanel(MontoyaApi api) {
        this.theme = new BurpTheme(api);
        this.bg = UIManager.getColor("Panel.background");
        setLayout(new BorderLayout());
        setBackground(bg);

        // Summary bar at top
        summaryLabel = new JLabel("暂无事件");
        summaryLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        summaryLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        summaryLabel.setForeground(theme.mutedText());
        add(summaryLabel, BorderLayout.NORTH);

        // Scrollable event list
        contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBackground(bg);

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    /** Add a new event and refresh the display. */
    public void addEvent(TimelineEvent event) {
        SwingUtilities.invokeLater(() -> {
            events.add(event);
            if (event.type() == TimelineEvent.Type.TOOL_CALL
                    && "1 LLM".equals(event.cost())) {
                totalLlmCalls++;
            }
            if (event.type() == TimelineEvent.Type.ITERATION) {
                totalIterations++;
            }
            rebuildContent();
            scrollToBottom();
        });
    }

    /** Add multiple events at once. */
    public void addEvents(List<TimelineEvent> batch) {
        SwingUtilities.invokeLater(() -> {
            for (TimelineEvent e : batch) {
                events.add(e);
                if (e.type() == TimelineEvent.Type.TOOL_CALL && "1 LLM".equals(e.cost())) {
                    totalLlmCalls++;
                }
                if (e.type() == TimelineEvent.Type.ITERATION) {
                    totalIterations++;
                }
            }
            rebuildContent();
            scrollToBottom();
        });
    }

    /** Snapshot of the current events (for persisting into the AnalysisRecord). */
    public List<TimelineEvent> getEvents() {
        return new ArrayList<>(events);
    }

    /** Replace all events with a stored list (re-render a persisted call chain,
     *  e.g. when viewing a historical analysis record). */
    public void loadEvents(List<TimelineEvent> stored) {
        SwingUtilities.invokeLater(() -> {
            events.clear();
            totalLlmCalls = 0;
            totalIterations = 0;
            if (stored != null) {
                for (TimelineEvent e : stored) {
                    events.add(e);
                    if (e.type() == TimelineEvent.Type.TOOL_CALL && "1 LLM".equals(e.cost())) {
                        totalLlmCalls++;
                    }
                    if (e.type() == TimelineEvent.Type.ITERATION) {
                        totalIterations++;
                    }
                }
            }
            rebuildContent();
        });
    }

    /** Set the final token count (arrives with verdict). */
    public void setTotalTokens(int tokens) {
        this.totalTokens = tokens;
        SwingUtilities.invokeLater(this::updateSummary);
    }

    /** Clear all events (new analysis starting). */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            events.clear();
            totalLlmCalls = 0;
            totalTokens = 0;
            totalIterations = 0;
            contentPanel.removeAll();
            contentPanel.revalidate();
            contentPanel.repaint();
            updateSummary();
        });
    }

    private void updateSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("事件: ").append(events.size());
        if (totalIterations > 0) sb.append(" | 迭代: ").append(totalIterations);
        if (totalLlmCalls > 0) sb.append(" | LLM调用: ").append(totalLlmCalls);
        if (totalTokens > 0) sb.append(" | Tokens: ").append(formatTokens(totalTokens));
        summaryLabel.setText(sb.toString());
    }

    private void rebuildContent() {
        contentPanel.removeAll();

        for (int i = 0; i < events.size(); i++) {
            TimelineEvent event = events.get(i);
            boolean isLast = (i == events.size() - 1);
            contentPanel.add(createEventRow(event, isLast));
        }

        updateSummary();
        contentPanel.revalidate();
        contentPanel.repaint();
    }

    private JPanel createEventRow(TimelineEvent event, boolean isLast) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setBackground(bg);
        row.setBorder(new EmptyBorder(2, 8, 2, 8));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));

        // Left: timeline dot + line
        JPanel leftPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                int w = getWidth();
                int h = getHeight();

                // Vertical line
                g.setColor(theme.separator());
                int lineX = w / 2;
                if (!isLast) {
                    g.drawLine(lineX, h / 2 + 6, lineX, h);
                }

                // Dot
                Color dotColor = colorForHint(event.colorHint());
                g.setColor(dotColor);
                int dotSize = event.type() == TimelineEvent.Type.ITERATION
                        || event.type() == TimelineEvent.Type.STAGE ? 8 : 6;
                g.fillOval(lineX - dotSize / 2, h / 2 - dotSize / 2, dotSize, dotSize);

                // Ring for anomaly/error
                if (event.colorHint() == TimelineEvent.ColorHint.ANOMALY
                        || event.colorHint() == TimelineEvent.ColorHint.ERROR) {
                    g.setColor(dotColor.darker());
                    g.drawOval(lineX - dotSize / 2 - 1, h / 2 - dotSize / 2 - 1,
                            dotSize + 2, dotSize + 2);
                }
            }
        };
        leftPanel.setPreferredSize(new Dimension(24, 28));
        leftPanel.setMinimumSize(new Dimension(24, 28));
        leftPanel.setMaximumSize(new Dimension(24, 28));
        leftPanel.setBackground(bg);
        row.add(leftPanel, BorderLayout.WEST);

        // Center: timestamp + icon + summary
        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        centerPanel.setBackground(bg);

        // Timestamp
        JLabel timeLabel = new JLabel(TIME_FMT.format(event.timestamp()));
        timeLabel.setFont(theme.editorFont(10f));
        timeLabel.setForeground(theme.mutedText());
        centerPanel.add(timeLabel);

        // Type icon
        JLabel iconLabel = new JLabel(iconForType(event.type(), event.colorHint()));
        centerPanel.add(iconLabel);

        // Summary text
        JLabel summaryText = new JLabel(event.summary());
        summaryText.setFont(theme.editorFont(11f));
        Color textColor = event.colorHint() == TimelineEvent.ColorHint.ANOMALY
                ? theme.riskColor("HIGH")
                : event.colorHint() == TimelineEvent.ColorHint.WAF
                ? new Color(180, 130, 0)
                : event.colorHint() == TimelineEvent.ColorHint.ERROR
                ? theme.statusError()
                : UIManager.getColor("Label.foreground");
        summaryText.setForeground(textColor);
        centerPanel.add(summaryText);

        // Cost badge
        if (event.cost() != null && !event.cost().isEmpty()) {
            JLabel costLabel = new JLabel(event.cost());
            costLabel.setFont(theme.editorFont(9f));
            costLabel.setForeground(theme.mutedText());
            costLabel.setBorder(new EmptyBorder(1, 4, 1, 4));
            centerPanel.add(costLabel);
        }

        row.add(centerPanel, BorderLayout.CENTER);

        // Right: expand button (if detail exists)
        if (event.detail() != null && !event.detail().isEmpty()) {
            JButton expandBtn = new JButton("▶");
            expandBtn.setFont(theme.editorFont(8f));
            expandBtn.setFocusPainted(false);
            expandBtn.setBorderPainted(false);
            expandBtn.setContentAreaFilled(false);
            expandBtn.setPreferredSize(new Dimension(20, 20));
            expandBtn.setToolTipText("展开详情");
            expandBtn.addActionListener(e -> showDetailDialog(event));
            row.add(expandBtn, BorderLayout.EAST);
        }

        return row;
    }

    private void showDetailDialog(TimelineEvent event) {
        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(owner, "事件详情", Dialog.ModalityType.MODELESS);
        dialog.setSize(600, 400);
        dialog.setLocationRelativeTo(owner);

        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(theme.editorFont(12f));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setText(event.detail());
        textArea.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(textArea);
        dialog.add(scrollPane);
        dialog.setVisible(true);
    }

    private void scrollToBottom() {
        SwingUtilities.invokeLater(() -> {
            Container parent = contentPanel.getParent();
            if (parent instanceof javax.swing.JViewport) {
                JScrollPane sp = (JScrollPane) parent.getParent();
                JScrollBar bar = sp.getVerticalScrollBar();
                bar.setValue(bar.getMaximum());
            }
        });
    }

    // === Color helpers ===

    private Color colorForHint(TimelineEvent.ColorHint hint) {
        return switch (hint) {
            case FREE -> new Color(70, 130, 180);
            case LLM -> new Color(210, 130, 40);
            case ANOMALY -> theme.riskColor("HIGH");
            case WAF -> new Color(180, 150, 0);
            case SUCCESS -> new Color(40, 160, 80);
            case ERROR -> theme.statusError();
            default -> new Color(150, 150, 150);
        };
    }

    /** 矢量类型图标（取代 emoji）；颜色沿用事件的 colorHint，与时间线圆点一致。 */
    private Icon iconForType(TimelineEvent.Type type, TimelineEvent.ColorHint hint) {
        int sz = 14;
        Color c = colorForHint(hint);
        return switch (type) {
            case THINKING -> IconFactory.of(IconFactory.Kind.ROBOT, sz, c);
            case TOOL_CALL -> IconFactory.of(IconFactory.Kind.TOOLS, sz, c);
            case TOOL_RESULT -> IconFactory.of(IconFactory.Kind.RULES, sz, c);
            case ITERATION -> IconFactory.of(IconFactory.Kind.NEUTRAL, sz, c);
            case STAGE -> IconFactory.of(IconFactory.Kind.NEUTRAL, sz, c);
            case VERDICT -> IconFactory.of(IconFactory.Kind.OK, sz, theme.statusOk());
            case ERROR -> IconFactory.of(IconFactory.Kind.FAIL, sz, theme.statusError());
        };
    }

    private String formatTokens(int tokens) {
        if (tokens >= 1000) return String.format("%.1fk", tokens / 1000.0);
        return String.valueOf(tokens);
    }
}