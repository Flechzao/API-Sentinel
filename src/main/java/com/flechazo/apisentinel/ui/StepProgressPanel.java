package com.flechazo.apisentinel.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * AI analysis step view rendered as a vertical, conversational flow of
 * collapsible cards (Burp AT style). Each tool call / thinking / response is a
 * card: a compact header (icon + name + status) shown by default, expanding on
 * click to reveal the detail. This replaces the older left-list + right-detail
 * master/detail split so the whole run reads top-to-bottom like a transcript.
 */
/** 步骤进度面板——Agent/Chat 模式的步骤视图，卡片流式展示 Prompt/Thinking/ToolCall/Response。 */
public class StepProgressPanel extends JPanel {

    public enum StepStatus { RUNNING, COMPLETED, ERROR }
    public enum StepType { PROMPT, THINKING, TOOL_CALL, RESPONSE }

    public record StepItem(String name, StepStatus status, StepType type,
                           String summary, String detail, String rawRequest, String rawResponse,
                           long startedMs, long durationMs) {
        @Override
        public String toString() { return name; }
    }

    private final BurpTheme theme;
    private final MarkdownRenderer markdownRenderer;
    private final List<StepItem> steps = new ArrayList<>();
    private final List<StepCard> cards = new ArrayList<>();
    private final JPanel cardsPanel;
    private final JScrollPane scroll;
    private final JLabel progressLabel;
    private final RoundedProgressBar progressBar;
    private Timer animTimer;
    private Consumer<StepItem> onStepSelected;

    private static final String[] SPIN = {"◐", "◓", "◑", "◒"};
    private int spinIndex = 0;

    public StepProgressPanel(BurpTheme theme) {
        super(new BorderLayout(0, 0));
        this.theme = theme;
        this.markdownRenderer = new MarkdownRenderer(theme);
        setOpaque(false);

        // Top header: title + progress counter + a slim overall progress bar
        // (the plain "3/7" counter alone made run progress invisible at a
        // glance; the bar fills as steps complete).
        JPanel header = new JPanel(new BorderLayout(0, 0));
        header.setBackground(theme.stepPanelBg());
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()));

        JPanel headerTop = new JPanel(new BorderLayout(0, 0));
        headerTop.setOpaque(false);
        headerTop.setBorder(new EmptyBorder(10, 14, 6, 14));
        JLabel title = new JLabel(I18n.get("step_title"));
        title.setFont(theme.displayFont(Font.BOLD, 12f));
        title.setForeground(theme.headerFg());
        headerTop.add(title, BorderLayout.WEST);
        progressLabel = new JLabel("0/0");
        progressLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        progressLabel.setForeground(theme.stepCountFg());
        headerTop.add(progressLabel, BorderLayout.EAST);

        progressBar = new RoundedProgressBar(0, 100);
        progressBar.setFillColor(theme.accentBg());
        progressBar.setBackground(theme.separator());
        progressBar.setPreferredSize(new Dimension(0, 5));
        JPanel barWrap = new JPanel(new BorderLayout());
        barWrap.setOpaque(false);
        barWrap.setBorder(new EmptyBorder(0, 14, 10, 14));
        barWrap.add(progressBar, BorderLayout.CENTER);

        header.add(headerTop, BorderLayout.NORTH);
        header.add(barWrap, BorderLayout.CENTER);
        add(header, BorderLayout.NORTH);

        // Vertical flow of step cards. Scrollable so it tracks viewport width
        // (cards stretch full-width and long text wraps instead of scrolling X).
        cardsPanel = new ScrollablePanel(null);
        cardsPanel.setLayout(new BoxLayout(cardsPanel, BoxLayout.Y_AXIS));
        cardsPanel.setBackground(theme.stepPanelBg());
        cardsPanel.setBorder(new EmptyBorder(12, 14, 20, 14));

        scroll = new JScrollPane(cardsPanel);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setBackground(theme.stepPanelBg());
        add(scroll, BorderLayout.CENTER);

        // Spinner animation for running steps
        animTimer = new Timer(350, e -> {
            spinIndex = (spinIndex + 1) % SPIN.length;
            boolean hasRunning = steps.stream().anyMatch(s -> s.status() == StepStatus.RUNNING);
            if (hasRunning) {
                for (StepCard c : cards) if (c.item.status() == StepStatus.RUNNING) c.updateIcon();
                cardsPanel.repaint();
            }
        });
        animTimer.start();
    }

    public void setOnStepSelected(Consumer<StepItem> listener) {
        this.onStepSelected = listener;
    }

    public void addStep(String name, StepType type, String summary) {
        SwingUtilities.invokeLater(() -> {
            String displayName = simplifyName(name, type);
            StepItem item = new StepItem(displayName, StepStatus.RUNNING, type, summary, summary,
                    null, null, System.currentTimeMillis(), 0);
            steps.add(item);
            StepCard card = new StepCard(item, true); // running step starts expanded
            cards.add(card);
            cardsPanel.add(card);
            cardsPanel.add(Box.createVerticalStrut(10));
            refresh();
            scrollToBottom();
        });
    }

    public void completeCurrentStep(String detail) {
        completeCurrentStep(detail, null, null);
    }

    public void completeCurrentStep(String detail, String rawRequest, String rawResponse) {
        SwingUtilities.invokeLater(() -> {
            if (steps.isEmpty()) return;
            int idx = steps.size() - 1;
            StepItem old = steps.get(idx);
            String safeDetail = detail != null ? detail : old.detail();
            if (safeDetail != null && safeDetail.length() > 10000) {
                safeDetail = safeDetail.substring(0, 10000) + "\n...[truncated]";
            }
            StepItem updated = new StepItem(old.name(), StepStatus.COMPLETED, old.type(),
                    old.summary(), safeDetail,
                    rawRequest != null ? rawRequest : old.rawRequest(),
                    rawResponse != null ? rawResponse : old.rawResponse(),
                    old.startedMs(),
                    old.startedMs() > 0 ? System.currentTimeMillis() - old.startedMs() : 0);
            steps.set(idx, updated);
            if (idx < cards.size()) {
                cards.get(idx).setItem(updated);
            }
            refresh();
        });
    }

    public void completeCurrentStep() {
        completeCurrentStep(null, null, null);
    }

    /** Settle every still-RUNNING step to COMPLETED. Called when a run ends
     *  (success, error, or cancel). Without it, steps whose completion event
     *  never arrived — e.g. tool calls queued after an accepted submit_report
     *  that the short-circuit never executes, or a run cut off mid-turn —
     *  spin forever and the counter sticks at "34/44". */
    public void finishAllSteps() {
        SwingUtilities.invokeLater(() -> {
            boolean changed = false;
            for (int i = 0; i < steps.size(); i++) {
                StepItem it = steps.get(i);
                if (it.status() != StepStatus.RUNNING) continue;
                StepItem done = new StepItem(it.name(), StepStatus.COMPLETED, it.type(),
                        it.summary(), it.detail(), it.rawRequest(), it.rawResponse(),
                        it.startedMs(),
                        it.startedMs() > 0 ? System.currentTimeMillis() - it.startedMs() : 0);
                steps.set(i, done);
                if (i < cards.size()) cards.get(i).setItem(done);
                changed = true;
            }
            if (changed) refresh();
        });
    }

    public void addCompletedStep(String name, StepType type, String detail) {
        SwingUtilities.invokeLater(() -> {
            String displayName = simplifyName(name, type);
            StepItem item = new StepItem(displayName, StepStatus.COMPLETED, type,
                    detail != null ? detail : "", detail != null ? detail : "", null, null,
                    System.currentTimeMillis(), 0);
            steps.add(item);
            StepCard card = new StepCard(item, defaultExpanded(item));
            cards.add(card);
            cardsPanel.add(card);
            cardsPanel.add(Box.createVerticalStrut(10));
            refresh();
            scrollToBottom();
        });
    }

    public void clear() {
        SwingUtilities.invokeLater(() -> {
            steps.clear();
            cards.clear();
            cardsPanel.removeAll();
            refresh();
        });
    }

    public void dispose() {
        if (animTimer != null) { animTimer.stop(); animTimer = null; }
    }

    /** Completed tool calls / prompts collapse by default; responses & thinking
     *  stay open because that's the content the user wants to read. */
    private boolean defaultExpanded(StepItem item) {
        if (item.status() == StepStatus.RUNNING) return true;
        return item.type() == StepType.RESPONSE || item.type() == StepType.THINKING;
    }

    private void refresh() {
        long completed = steps.stream().filter(s -> s.status() == StepStatus.COMPLETED).count();
        progressLabel.setText(completed + "/" + steps.size());
        progressBar.setValue(steps.isEmpty() ? 0
                : (int) Math.round(completed * 100.0 / steps.size()));
        cardsPanel.revalidate();
        cardsPanel.repaint();
    }

    private void scrollToBottom() {
        SwingUtilities.invokeLater(() -> {
            JScrollBar v = scroll.getVerticalScrollBar();
            v.setValue(v.getMaximum());
        });
    }

    /** " 1.2s" style duration suffix for the card status label; empty for
     *  unknown (0) or sub-100ms steps where the number is just noise. */
    private static String formatDuration(long ms) {
        if (ms < 100) return "";
        return String.format(" %.1fs", ms / 1000.0);
    }

    private String simplifyName(String name, StepType type) {
        return switch (type) {
            case PROMPT -> I18n.get("step_prompt");
            case THINKING -> I18n.get("step_thinking");
            case RESPONSE -> I18n.get("step_response");
            // Full Chinese mapping of the AgentToolRegistry names — a missing
            // entry falls back to the raw snake_case name, so newly added
            // tools degrade visibly instead of silently staying English.
            case TOOL_CALL -> switch (name) {
                case "send_request" -> "Send Request";
                case "heuristic_scan" -> "Heuristic Scan";
                case "analyze_traffic" -> "Traffic Analysis";
                case "search_source_code" -> "Code Search";
                case "generate_payloads" -> "Generate Payloads";
                case "test_auth_bypass" -> "Authz Test";
                case "list_sessions" -> "Session List";
                case "generate_oob_probe" -> "OOB Probe";
                case "check_oob_results" -> "OOB Callback Check";
                case "read_file" -> "Read File";
                case "grep_repo" -> "Repo Text Search";
                case "audit_codebase" -> "Codebase Audit";
                case "search_traffic" -> "Traffic Search";
                case "active_probe" -> "Active Probe";
                case "fingerprint_components" -> "Component Fingerprint";
                case "verify_boolean_blind" -> "Boolean Blind Verify";
                case "verify_timing_blind" -> "Timing Blind Verify";
                case "waf_bypass_retry" -> "WAF Bypass Retry";
                case "verify_business_logic" -> "Business Logic Verify";
                case "find_definition" -> "Find Definition";
                case "find_callers" -> "Find Callers";
                case "verify_xss_reflection" -> "XSS Reflection Verify";
                case "verify_ssti" -> "SSTI Verify";
                case "verify_path_traversal" -> "Path Traversal Verify";
                case "verify_xxe" -> "XXE Verify";
                case "diff_responses" -> "Response Diff";
                case "map_sibling_endpoints" -> "Map Sibling Endpoints";
                case "dispatch_explore_agent" -> "Dispatch Explore Agent";
                case "chain_hunter" -> "Chain Hunter";
                case "run_sandboxed_code" -> "Sandbox Code Verify";
                case "trace_taint_source" -> "Taint Source Trace";
                case "ask_user" -> "Ask User";
                case "submit_report" -> "Submit Report";
                default -> name;
            };
        };
    }

    private String typeLabel(StepType type) {
        return switch (type) {
            case PROMPT -> I18n.get("step_prompt");
            case THINKING -> I18n.get("step_thinking");
            case TOOL_CALL -> I18n.get("step_tool");
            case RESPONSE -> I18n.get("step_response");
        };
    }

    /** Small vector icon identifying the step kind, shown as the card icon
     *  (replaces the old emoji glyphs). Color is applied per call-site so a
     *  completed step tints the whole set with the completion color. */
    private Icon typeIcon(StepType type, Color color) {
        int sz = 15;
        return switch (type) {
            case PROMPT -> IconFactory.of(IconFactory.Kind.INFO, sz, color);
            case THINKING -> IconFactory.of(IconFactory.Kind.ROBOT, sz, color);
            case TOOL_CALL -> IconFactory.of(IconFactory.Kind.TOOLS, sz, color);
            case RESPONSE -> IconFactory.of(IconFactory.Kind.RULES, sz, color);
        };
    }

    /** A single collapsible step card: clickable header + expandable body. */
    private class StepCard extends JPanel {
        private StepItem item;
        private boolean expanded;
        private boolean hovered;
        private final JLabel iconLabel = new JLabel();
        private final JLabel nameLabel = new JLabel();
        private final JLabel typeTag = new JLabel();
        private final JLabel summaryLine = new JLabel();
        private final JLabel statusLabel = new JLabel();
        private final JLabel chevron = new JLabel();
        private final JPanel headerPanel;
        private final JPanel bodyPanel;
        private final JPanel bodyContent;

        StepCard(StepItem item, boolean expanded) {
            this.item = item;
            this.expanded = expanded;
            setLayout(new BorderLayout(0, 0));
            setOpaque(false); // paint a rounded fill ourselves (see paintComponent)
            setBorder(new EmptyBorder(0, 0, 0, 0));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
            setAlignmentX(LEFT_ALIGNMENT);

            // ── Header ──
            headerPanel = new JPanel(new BorderLayout(6, 0));
            headerPanel.setOpaque(false);
            headerPanel.setBorder(new EmptyBorder(10, 12, 10, 12));
            headerPanel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            iconLabel.setFont(theme.displayFont(Font.PLAIN, 13f));
            iconLabel.setPreferredSize(new Dimension(18, 18));

            nameLabel.setFont(theme.displayFont(Font.BOLD, 13f));
            nameLabel.setForeground(theme.headerFg());

            typeTag.setFont(theme.displayFont(Font.PLAIN, 11f));
            typeTag.setForeground(theme.stepCountFg());

            // One-line result preview shown while the card is collapsed.
            summaryLine.setFont(theme.displayFont(Font.PLAIN, 11f));
            summaryLine.setForeground(theme.stepCountFg());

            chevron.setFont(theme.displayFont(Font.PLAIN, 11f));
            chevron.setForeground(theme.stepCountFg());

            statusLabel.setFont(theme.displayFont(Font.BOLD, 12f));

            JPanel leftFlow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            leftFlow.setOpaque(false);
            leftFlow.add(iconLabel);
            leftFlow.add(nameLabel);
            leftFlow.add(typeTag);
            leftFlow.add(summaryLine);

            JPanel eastFlow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
            eastFlow.setOpaque(false);
            eastFlow.add(statusLabel);
            eastFlow.add(chevron);

            headerPanel.add(leftFlow, BorderLayout.CENTER);
            headerPanel.add(eastFlow, BorderLayout.EAST);

            headerPanel.addMouseListener(new MouseAdapter() {
                @Override public void mousePressed(MouseEvent e) { toggle(); }
                @Override public void mouseEntered(MouseEvent e) { hovered = true;  repaint(); }
                @Override public void mouseExited(MouseEvent e)  { hovered = false; repaint(); }
            });

            // ── Body ──
            bodyContent = new ScrollablePanel(new BorderLayout());
            bodyContent.setOpaque(false); // let the rounded card bg show through
            bodyContent.setBorder(new EmptyBorder(4, 14, 12, 14));
            bodyPanel = new JPanel(new BorderLayout());
            bodyPanel.setOpaque(false);
            bodyPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, theme.separator()));
            bodyPanel.add(bodyContent, BorderLayout.CENTER);

            add(headerPanel, BorderLayout.NORTH);
            add(bodyPanel, BorderLayout.CENTER);

            updateIcon();
            applyExpansion();
        }

        void setItem(StepItem newItem) {
            this.item = newItem;
            updateIcon();
            // On completion collapse transient tool/prompt steps, keep responses open
            if (newItem.status() == StepStatus.COMPLETED) {
                this.expanded = defaultExpanded(newItem);
            }
            if (expanded) renderBody();
            applyExpansion();
        }

        void updateIcon() {
            switch (item.status()) {
                case COMPLETED -> {
                    iconLabel.setText("");
                    iconLabel.setIcon(typeIcon(item.type(), theme.stepCompletedColor()));
                    statusLabel.setText("✓" + formatDuration(item.durationMs()));
                    statusLabel.setForeground(theme.stepCompletedColor());
                }
                case RUNNING -> {
                    // 旋转字符仍用文本（几何符号跨平台一致，非 emoji）
                    iconLabel.setIcon(null);
                    iconLabel.setText(SPIN[spinIndex]);
                    iconLabel.setForeground(theme.stepRunningColor());
                    statusLabel.setText("");
                }
                case ERROR -> {
                    iconLabel.setText("");
                    iconLabel.setIcon(IconFactory.of(IconFactory.Kind.WARN, 15, theme.errorColor()));
                    statusLabel.setText("✕" + formatDuration(item.durationMs()));
                    statusLabel.setForeground(theme.errorColor());
                }
            }
        }

        private void toggle() {
            expanded = !expanded;
            if (expanded) {
                renderBody();
                if (onStepSelected != null) onStepSelected.accept(item);
            }
            applyExpansion();
            SwingUtilities.invokeLater(() -> {
                cardsPanel.revalidate();
                cardsPanel.repaint();
            });
        }

        private void applyExpansion() {
            nameLabel.setText(item.name());
            typeTag.setText(typeLabel(item.type()));
            chevron.setText(expanded ? "▼" : "▶");
            // Progressive disclosure: show a one-line result preview only while
            // collapsed so a run can be scanned without opening every card.
            summaryLine.setText(expanded ? "" : collapsedSummary());
            bodyPanel.setVisible(expanded);
            if (expanded) renderBody();
        }

        /** First meaningful line of the step detail, shortened for the collapsed
         *  header preview. Returns "" when there's nothing useful to preview. */
        private String collapsedSummary() {
            String d = item.detail();
            if (d == null || d.isBlank()) return "";
            String line = d.strip().split("\\r?\\n", 2)[0].strip();
            if (line.isEmpty()) return "";
            if (line.length() > 70) line = line.substring(0, 70) + "…";
            return "  " + line;
        }

        private void renderBody() {
            bodyContent.removeAll();
            String detail = item.detail();
            if (detail == null || detail.isEmpty()) {
                JLabel none = new JLabel(I18n.get("step_no_content"));
                none.setForeground(theme.stepCountFg());
                none.setFont(theme.displayFont(Font.ITALIC, 12f));
                bodyContent.add(none, BorderLayout.CENTER);
            } else if (item.type() == StepType.RESPONSE || item.type() == StepType.THINKING) {
                JPanel rendered = markdownRenderer.renderToPanel(detail);
                rendered.setOpaque(false);
                bodyContent.add(rendered, BorderLayout.CENTER);
            } else {
                JTextArea ta = new JTextArea(detail);
                ta.setEditable(false);
                ta.setLineWrap(true);
                ta.setWrapStyleWord(true);
                ta.setFont(theme.editorFont(12.5f));
                ta.setOpaque(false);
                ta.setForeground(theme.aiTextColor());
                ta.setBorder(new EmptyBorder(2, 0, 2, 0));
                bodyContent.add(ta, BorderLayout.CENTER);
            }
            // Append captured request/response for tool calls when available
            if (item.type() == StepType.TOOL_CALL) {
                if (item.rawRequest() != null && !item.rawRequest().isEmpty()) {
                    bodyContent.add(httpBlock("Request", item.rawRequest()), BorderLayout.SOUTH);
                }
            }
            bodyContent.revalidate();
            bodyContent.repaint();
        }

        private JPanel httpBlock(String label, String text) {
            JPanel wrap = new JPanel(new BorderLayout());
            wrap.setOpaque(false);
            wrap.setBorder(new EmptyBorder(8, 0, 0, 0));
            JLabel lbl = new JLabel(label);
            lbl.setFont(theme.displayFont(Font.BOLD, 11f));
            lbl.setForeground(theme.stepCountFg());
            JTextArea ta = new JTextArea(text.length() > 2000 ? text.substring(0, 2000) + "\n...[truncated]" : text);
            ta.setEditable(false);
            ta.setLineWrap(false);
            ta.setFont(theme.editorFont(11.5f));
            ta.setOpaque(false);
            ta.setForeground(theme.contextFg());
            ta.setBorder(new EmptyBorder(6, 8, 6, 8));
            wrap.add(lbl, BorderLayout.NORTH);
            wrap.add(ta, BorderLayout.CENTER);
            return wrap;
        }

        private Color cardBg() {
            return theme.stepCardBg();
        }

        /** Paint a soft rounded card (Burp AT style) instead of a boxy opaque
         *  rect — an opaque square background would poke out past the rounded
         *  corners. Also draws the Burp-orange left accent and a faint outline. */
        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int arc = 14;
                g2.setColor(hovered ? theme.stepHoverBg() : cardBg());
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), arc, arc);
                g2.setColor(theme.stepAccentBar());
                g2.fillRoundRect(0, 0, 4, getHeight(), arc, arc);
                g2.setColor(theme.separator());
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            } finally {
                g2.dispose();
            }
        }
    }

    private static class ScrollablePanel extends JPanel implements Scrollable {
        ScrollablePanel(LayoutManager layout) { super(layout); }
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) { return visibleRect.height; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
