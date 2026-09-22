package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.ui.BurpTheme;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;

public class StatsPanel extends JPanel {
    private final StatsManager stats;
    private final BurpTheme theme;

    public StatsPanel(StatsManager stats, BurpTheme theme) {
        this.stats = stats;
        this.theme = theme;
        setLayout(new BorderLayout(0, 12));
        setOpaque(false);
        setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));
        refresh();
    }

    public void refresh() {
        removeAll();

        // ── 顶部大数字 ──
        JPanel topPanel = new JPanel(new GridLayout(1, 3, 16, 0));
        topPanel.setOpaque(false);
        topPanel.add(buildBigNumber("总发现", String.valueOf(stats.getTotalFindings()), new Color(96, 165, 250)));
        topPanel.add(buildBigNumber("今日", String.valueOf(stats.getTodayFindings()), new Color(74, 222, 128)));
        topPanel.add(buildBigNumber("连续天数", stats.getConsecutiveDays() + " 天",
                stats.getConsecutiveDays() >= 7 ? new Color(250, 204, 21) : new Color(160, 160, 160)));
        add(topPanel, BorderLayout.NORTH);

        // ── 中间：类型分布条形图 ──
        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
        center.setOpaque(false);

        JLabel distTitle = new JLabel("漏洞类型分布");
        distTitle.setFont(theme.displayFont(Font.BOLD, 13f));
        distTitle.setForeground(theme.contextFg());
        distTitle.setAlignmentX(LEFT_ALIGNMENT);
        center.add(distTitle);
        center.add(Box.createVerticalStrut(8));

        Map<String, Integer> types = stats.getTypeCounts();
        List<Map.Entry<String, Integer>> sorted = new ArrayList<>(types.entrySet());
        sorted.sort(Map.Entry.<String, Integer>comparingByValue().reversed());
        int maxVal = sorted.isEmpty() ? 1 : sorted.get(0).getValue();

        Color[] barColors = {
            new Color(239, 68, 68), new Color(245, 158, 11), new Color(74, 222, 128),
            new Color(96, 165, 250), new Color(167, 139, 250), new Color(244, 114, 182),
            new Color(45, 212, 191), new Color(251, 146, 60)
        };

        int shown = Math.min(sorted.size(), 8);
        for (int i = 0; i < shown; i++) {
            Map.Entry<String, Integer> e = sorted.get(i);
            center.add(buildBar(e.getKey(), e.getValue(), maxVal, barColors[i % barColors.length]));
            center.add(Box.createVerticalStrut(4));
        }

        if (sorted.isEmpty()) {
            JLabel empty = new JLabel("暂无数据，开始分析接口后自动统计");
            empty.setFont(theme.displayFont(Font.PLAIN, 11f));
            empty.setForeground(Color.GRAY);
            empty.setAlignmentX(LEFT_ALIGNMENT);
            center.add(empty);
        }

        add(center, BorderLayout.CENTER);

        // ── 底部：个人最佳 + 重置 ──
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setOpaque(false);
        bottom.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));

        JLabel best = new JLabel(String.format("个人最佳: %d 个/天  |  最擅长: %s",
                stats.getBestDay(), stats.getBestType()));
        best.setFont(theme.displayFont(Font.PLAIN, 11f));
        best.setForeground(Color.GRAY);
        bottom.add(best, BorderLayout.WEST);

        JButton reset = new JButton("重置统计");
        reset.setFont(theme.displayFont(Font.PLAIN, 10f));
        reset.setMargin(new Insets(2, 8, 2, 8));
        reset.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "确定重置所有统计数据？", "确认", JOptionPane.YES_NO_OPTION) == 0) {
                stats.reset();
                refresh();
            }
        });
        bottom.add(reset, BorderLayout.EAST);
        add(bottom, BorderLayout.SOUTH);

        revalidate();
        repaint();
    }

    private JPanel buildBigNumber(String label, String value, Color color) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setOpaque(false);
        p.setAlignmentX(LEFT_ALIGNMENT);

        JLabel num = new JLabel(value);
        num.setFont(theme.displayFont(Font.BOLD, 28f));
        num.setForeground(color);
        num.setAlignmentX(LEFT_ALIGNMENT);
        p.add(num);

        JLabel lbl = new JLabel(label);
        lbl.setFont(theme.displayFont(Font.PLAIN, 11f));
        lbl.setForeground(Color.GRAY);
        lbl.setAlignmentX(LEFT_ALIGNMENT);
        p.add(lbl);

        return p;
    }

    private JPanel buildBar(String name, int count, int max, Color color) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setOpaque(false);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
        row.setAlignmentX(LEFT_ALIGNMENT);

        JLabel lbl = new JLabel(name.length() > 12 ? name.substring(0, 12) : name);
        lbl.setFont(theme.displayFont(Font.PLAIN, 10f));
        lbl.setForeground(theme.contextFg());
        lbl.setPreferredSize(new Dimension(110, 20));
        row.add(lbl, BorderLayout.WEST);

        // 条形
        JPanel barBg = new JPanel(new BorderLayout()) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(45, 45, 45));
                g2.fillRoundRect(0, 4, getWidth(), getHeight() - 8, 6, 6);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        barBg.setOpaque(false);

        double ratio = max > 0 ? (double) count / max : 0;
        JPanel barFill = new JPanel() {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(color);
                g2.fillRoundRect(0, 4, (int)(getWidth() * ratio), getHeight() - 8, 6, 6);
                g2.dispose();
            }
        };
        barFill.setOpaque(false);
        barBg.add(barFill, BorderLayout.CENTER);
        row.add(barBg, BorderLayout.CENTER);

        JLabel countLbl = new JLabel(String.valueOf(count));
        countLbl.setFont(theme.displayFont(Font.BOLD, 10f));
        countLbl.setForeground(color);
        countLbl.setPreferredSize(new Dimension(30, 20));
        countLbl.setHorizontalAlignment(SwingConstants.RIGHT);
        row.add(countLbl, BorderLayout.EAST);

        return row;
    }
}
