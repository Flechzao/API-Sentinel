package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.ui.BurpTheme;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.RoundRectangle2D;
import java.text.SimpleDateFormat;
import java.util.Random;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * 漏洞图鉴 - 卡片网格风格
 */
public class PokedexPanel extends JPanel {

    private final VulnerabilityPokedex pokedex;
    private final BurpTheme theme;
    private final SimpleDateFormat sdf = new SimpleDateFormat("MM/dd");
    private final JPanel content;
    private final JLabel statsText;

    // 严重度颜色
    private Color sevColor(String s) {
        if (s == null) return Color.GRAY;
        switch (s.toUpperCase()) {
            case "CRITICAL": return new Color(220, 38, 38);
            case "HIGH":     return new Color(239, 68, 68);
            case "MEDIUM":   return new Color(245, 158, 11);
            case "LOW":      return new Color(107, 114, 128);
            default:         return Color.GRAY;
        }
    }

    public PokedexPanel(VulnerabilityPokedex pokedex, BurpTheme theme) {
        this.pokedex = pokedex;
        this.theme = theme;
        setLayout(new BorderLayout(0, 0));
        setOpaque(false);

        // ── 顶部统计栏 ──
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        header.setOpaque(false);
        header.setBorder(BorderFactory.createEmptyBorder(16, 20, 12, 20));

        statsText = new JLabel();
        statsText.setFont(theme.displayFont(Font.BOLD, 15f));
        header.add(statsText);


        add(header, BorderLayout.NORTH);

        // ── 内容区 ──
        content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setOpaque(false);
        content.setBorder(BorderFactory.createEmptyBorder(0, 16, 16, 16));

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        scroll.getVerticalScrollBar().setUnitIncrement(20);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        add(scroll, BorderLayout.CENTER);

        refresh();
    }

    public void refresh() {
        content.removeAll();

        int discovered = pokedex.getDiscoveredCount();
        int total = pokedex.getTotalCount();
        double pct = total > 0 ? discovered * 100.0 / total : 0;

        statsText.setText(String.format("已发现 %d / %d", discovered, total));
        statsText.setForeground(pct >= 80 ? new Color(250, 204, 21)
                : pct >= 50 ? new Color(74, 222, 128) : new Color(96, 165, 250));

        Map<String, List<VulnerabilityEntry>> cats = pokedex.getByCategory();
        for (Map.Entry<String, List<VulnerabilityEntry>> cat : cats.entrySet()) {
            int found = (int) cat.getValue().stream().filter(VulnerabilityEntry::isDiscovered).count();
            content.add(buildCategory(cat.getKey(), found, cat.getValue().size()));

            JPanel grid = new JPanel(new GridLayout(0, 2, 8, 8));
            grid.setOpaque(false);
            grid.setAlignmentX(LEFT_ALIGNMENT);
            grid.setMaximumSize(new Dimension(Integer.MAX_VALUE, grid.getPreferredSize().height));
            for (VulnerabilityEntry e : cat.getValue()) {
                grid.add(buildCard(e));
            }
            content.add(grid);
            content.add(Box.createVerticalStrut(10));
        }

        content.revalidate();
        content.repaint();
    }

    // ── 类别标题 ──
    private JPanel buildCategory(String name, int found, int total) {
        JPanel p = new JPanel(new BorderLayout(6, 0));
        p.setOpaque(false);
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));

        JLabel label = new JLabel(name);
        label.setFont(theme.displayFont(Font.BOLD, 12f));
        label.setForeground(theme.contextFg());
        p.add(label, BorderLayout.WEST);

        JLabel count = new JLabel(found + "/" + total);
        count.setFont(theme.displayFont(Font.PLAIN, 11f));
        count.setForeground(found == total ? theme.statusOk() : Color.GRAY);
        p.add(count, BorderLayout.EAST);

        return p;
    }

    // ── 单张卡片 ──
    private JPanel buildCard(VulnerabilityEntry e) {
        boolean found = e.isDiscovered();
        Color accent = found ? sevColor(e.getSeverity()) : new Color(55, 55, 55);

        JPanel card = new JPanel(new BorderLayout(0, 3)) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(found ? theme.contextBg().brighter() : theme.contextBg());
                g2.fill(new RoundRectangle2D.Double(0, 0, getWidth() - 1, getHeight() - 1, 8, 8));
                g2.setColor(found ? accent : theme.inputBorder());
                g2.draw(new RoundRectangle2D.Double(0.5, 0.5, getWidth() - 2, getHeight() - 2, 8, 8));
                // 左侧色条
                g2.setColor(accent);
                g2.fillRoundRect(0, 2, 4, getHeight() - 4, 4, 4);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        card.setOpaque(false);
        card.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 10));

        // 第一行：名称 + 严重度徽章
        JPanel row1 = new JPanel(new BorderLayout());
        row1.setOpaque(false);

        JLabel name = new JLabel(found ? e.getName() : "???");
        name.setFont(theme.displayFont(Font.BOLD, 12f));
        name.setForeground(found ? theme.contextFg() : Color.GRAY);
        row1.add(name, BorderLayout.WEST);

        // 严重度徽章
        JLabel badge = new JLabel(e.getSeverity(), SwingConstants.CENTER);
        badge.setFont(theme.displayFont(Font.BOLD, 8f));
        badge.setForeground(Color.WHITE);
        badge.setOpaque(true);
        badge.setBackground(found ? sevColor(e.getSeverity()) : Color.DARK_GRAY);
        badge.setBorder(BorderFactory.createEmptyBorder(1, 6, 1, 6));
        row1.add(badge, BorderLayout.EAST);

        card.add(row1, BorderLayout.NORTH);

        // 第二行：描述
        JLabel desc = new JLabel(found ? e.getDescription() : "尚未发现此类型漏洞");
        desc.setFont(theme.displayFont(Font.PLAIN, 10f));
        desc.setForeground(found ? theme.contextFg().brighter() : Color.DARK_GRAY);
        card.add(desc, BorderLayout.CENTER);

        // 第三行：次数 + 日期
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row3.setOpaque(false);
        if (found) {
            JLabel count = new JLabel(e.getDiscoveryCount() + " 次");
            count.setFont(theme.displayFont(Font.BOLD, 10f));
            count.setForeground(theme.statusOk());
            row3.add(count);

            if (e.getFirstDiscoveredTime() > 0) {
                JLabel date = new JLabel(sdf.format(new Date(e.getFirstDiscoveredTime())));
                date.setFont(theme.displayFont(Font.PLAIN, 9f));
                date.setForeground(Color.GRAY);
                row3.add(date);
            }
        }
        card.add(row3, BorderLayout.SOUTH);

        return card;
    }
}
