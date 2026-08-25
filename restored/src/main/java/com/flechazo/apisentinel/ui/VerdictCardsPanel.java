package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * Renders a final verdict as a vertical flow of Burp-style rounded cards:
 * one summary card (overall risk + summary), then one card per confirmed vuln
 * (red accent) and per suspected vuln (orange accent). This is the card-based
 * counterpart of the findings table, aligned with the chat step-view look.
 */
public class VerdictCardsPanel extends JPanel {

    private final BurpTheme theme;
    private final MarkdownRenderer markdownRenderer;
    private final JPanel cardsPanel;

    public VerdictCardsPanel(BurpTheme theme) {
        super(new BorderLayout(0, 0));
        this.theme = theme;
        this.markdownRenderer = new MarkdownRenderer(theme);
        setOpaque(false);

        cardsPanel = new ScrollablePanel(null);
        cardsPanel.setLayout(new BoxLayout(cardsPanel, BoxLayout.Y_AXIS));
        cardsPanel.setBackground(theme.stepPanelBg());
        cardsPanel.setBorder(new EmptyBorder(12, 14, 20, 14));

        JScrollPane scroll = new JScrollPane(cardsPanel);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        add(scroll, BorderLayout.CENTER);
    }

    public void showVerdict(FinalVerdict verdict, AnalysisResult trafficAnalysis) {
        cardsPanel.removeAll();
        if (verdict == null) {
            cardsPanel.add(emptyLabel("暂无分析结果"));
        } else {
            cardsPanel.add(new SummaryCard(verdict.overallRisk(), verdict.summary()));
            cardsPanel.add(Box.createVerticalStrut(10));
            List<ConfirmedVuln> confirmed = verdict.confirmedVulns();
            if (confirmed != null) {
                for (ConfirmedVuln cv : confirmed) {
                    cardsPanel.add(new FindingCard(cv));
                    cardsPanel.add(Box.createVerticalStrut(10));
                }
            }
            List<SuspectedVuln> suspected = verdict.suspectedVulns();
            if (suspected != null) {
                for (SuspectedVuln sv : suspected) {
                    cardsPanel.add(new FindingCard(sv));
                    cardsPanel.add(Box.createVerticalStrut(10));
                }
            }
            if ((confirmed == null || confirmed.isEmpty()) && (suspected == null || suspected.isEmpty())) {
                cardsPanel.add(emptyLabel("未发现 confirmed / suspected 漏洞"));
            }
        }
        cardsPanel.revalidate();
        cardsPanel.repaint();
    }

    /** Render the single-stage (traffic-only) analysis result — used by the
     *  table "开始分析"/"AI 分析" path, which produces VulnFindings rather than
     *  a full pipeline FinalVerdict. */
    public void showAnalysisResult(AnalysisResult result) {
        cardsPanel.removeAll();
        if (result == null || !result.isSuccess()) {
            cardsPanel.add(emptyLabel(result != null ? ("分析失败: " + result.error()) : "无分析结果"));
        } else {
            cardsPanel.add(new SummaryCard(result.overallRisk().name(), result.summary()));
            cardsPanel.add(Box.createVerticalStrut(10));
            for (com.flechazo.apisentinel.ai.analysis.VulnFinding f : result.findings()) {
                cardsPanel.add(new FindingCard(f));
                cardsPanel.add(Box.createVerticalStrut(10));
            }
            if (result.findings().isEmpty()) {
                cardsPanel.add(emptyLabel("未发现漏洞"));
            }
        }
        cardsPanel.revalidate();
        cardsPanel.repaint();
    }

    private JLabel emptyLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(theme.stepCountFg());
        l.setFont(theme.displayFont(Font.ITALIC, 12.5f));
        l.setAlignmentX(LEFT_ALIGNMENT);
        l.setBorder(new EmptyBorder(12, 4, 12, 4));
        return l;
    }

    /** Base rounded card with a colored left accent bar. */
    private abstract class Card extends JPanel {
        protected Card() {
            setLayout(new BorderLayout(0, 0));
            setOpaque(false);
            setBorder(new EmptyBorder(0, 0, 0, 0));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
            setAlignmentX(LEFT_ALIGNMENT);
        }
        protected abstract Color accent();
        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int arc = 14;
                g2.setColor(theme.stepCardBg());
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), arc, arc);
                g2.setColor(accent());
                g2.fillRoundRect(0, 0, 4, getHeight(), arc, arc);
                g2.setColor(theme.separator());
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            } finally {
                g2.dispose();
            }
        }
        protected JTextArea mono(String text) {
            JTextArea ta = new JTextArea(text);
            ta.setEditable(false);
            ta.setLineWrap(true);
            ta.setWrapStyleWord(true);
            ta.setFont(theme.editorFont(12f));
            ta.setOpaque(false);
            ta.setForeground(theme.aiTextColor());
            return ta;
        }
        protected JLabel caption(String text) {
            JLabel l = new JLabel(text);
            l.setFont(theme.displayFont(Font.BOLD, 10.5f));
            l.setForeground(theme.stepCountFg());
            l.setBorder(new EmptyBorder(6, 0, 2, 0));
            return l;
        }
    }

    /** Overall risk + summary. */
    private class SummaryCard extends Card {
        SummaryCard(String risk, String summaryText) {
            JPanel inner = new JPanel(new BorderLayout(8, 0));
            inner.setOpaque(false);
            inner.setBorder(new EmptyBorder(11, 14, 11, 14));

            JLabel riskLbl = new JLabel(risk != null ? risk : "");
            riskLbl.setFont(theme.displayFont(Font.BOLD, 14f));
            riskLbl.setForeground(theme.riskColor(risk != null ? risk : "LOW"));

            JPanel body = new JPanel();
            body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
            body.setOpaque(false);
            String summary = summaryText != null ? summaryText : "";
            if (summary.length() > 1500) summary = summary.substring(0, 1500) + "\n...[截断]";
            JPanel md = markdownRenderer.renderToPanel(summary);
            md.setOpaque(false);
            body.add(md);

            inner.add(riskLbl, BorderLayout.WEST);
            inner.add(body, BorderLayout.CENTER);
            add(inner, BorderLayout.CENTER);
        }
        @Override protected Color accent() { return theme.stepAccentBar(); }
    }

    /** A finding card. Badge text + accent color are driven by the constructor,
     *  so it can render confirmed vulns (red), suspected vulns (orange), and
     *  traffic-only VulnFindings (risk-colored). */
    private class FindingCard extends Card {
        private final Color accentColor;
        private final String badgeText;

        FindingCard(ConfirmedVuln cv) {
            accentColor = theme.errorColor();
            badgeText = "CONFIRMED";
            JPanel inner = new JPanel();
            inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));
            inner.setOpaque(false);
            inner.setBorder(new EmptyBorder(11, 14, 11, 14));
            inner.add(headerRow(cv.type(), cv.title()));
            if (notBlank(cv.evidence())) { inner.add(caption("证据")); inner.add(mono(cv.evidence())); }
            if (notBlank(cv.payloadUsed())) { inner.add(caption("触发 Payload")); inner.add(mono(cv.payloadUsed())); }
            if (notBlank(cv.verifyCommand())) { inner.add(caption("验证命令")); inner.add(mono(cv.verifyCommand())); }
            add(inner, BorderLayout.CENTER);
        }

        FindingCard(SuspectedVuln sv) {
            accentColor = theme.stepAccentBar();
            badgeText = "SUSPECTED";
            JPanel inner = new JPanel();
            inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));
            inner.setOpaque(false);
            inner.setBorder(new EmptyBorder(11, 14, 11, 14));
            inner.add(headerRow(sv.type(), sv.title()));
            if (notBlank(sv.reason())) { inner.add(caption("疑似原因")); inner.add(mono(sv.reason())); }
            if (notBlank(sv.verifyCommand())) { inner.add(caption("验证命令")); inner.add(mono(sv.verifyCommand())); }
            add(inner, BorderLayout.CENTER);
        }

        FindingCard(com.flechazo.apisentinel.ai.analysis.VulnFinding f) {
            accentColor = theme.riskColor(f.risk() != null ? f.risk() : "LOW");
            badgeText = (f.risk() != null ? f.risk() : "INFO")
                    + "  " + String.format("%.0f%%", f.confidence() * 100);
            JPanel inner = new JPanel();
            inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));
            inner.setOpaque(false);
            inner.setBorder(new EmptyBorder(11, 14, 11, 14));
            inner.add(headerRow(f.type(), f.title()));
            if (notBlank(f.description())) { inner.add(caption("描述")); inner.add(mono(f.description())); }
            if (notBlank(f.evidence())) { inner.add(caption("证据")); inner.add(mono(f.evidence())); }
            if (notBlank(f.location())) { inner.add(caption("位置")); inner.add(mono(f.location())); }
            if (notBlank(f.remediation())) { inner.add(caption("修复建议")); inner.add(mono(f.remediation())); }
            add(inner, BorderLayout.CENTER);
        }

        private JPanel headerRow(String type, String title) {
            JPanel row = new JPanel(new BorderLayout(6, 0));
            row.setOpaque(false);
            JLabel badge = new JLabel(" " + badgeText + " ");
            badge.setFont(theme.displayFont(Font.BOLD, 10.5f));
            badge.setForeground(Color.WHITE);
            badge.setOpaque(true);
            badge.setBackground(accentColor);
            JLabel ttl = new JLabel((type != null ? "[" + type + "] " : "") + (title != null ? title : ""));
            ttl.setFont(theme.displayFont(Font.BOLD, 13f));
            ttl.setForeground(theme.headerFg());
            row.add(badge, BorderLayout.WEST);
            row.add(ttl, BorderLayout.CENTER);
            return row;
        }
        private boolean notBlank(String s) { return s != null && !s.isBlank(); }
        @Override protected Color accent() { return accentColor; }
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
