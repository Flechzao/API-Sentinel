package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.ui.BurpTheme;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.RoundRectangle2D;
import java.text.SimpleDateFormat;
import java.util.Date;

public class AchievementPanel extends JPanel {

    private final AchievementManager manager;
    private final BurpTheme theme;
    private final SimpleDateFormat sdf = new SimpleDateFormat("MM/dd");
    private final JPanel content;
    private final JLabel statsText;

    public AchievementPanel(AchievementManager manager, BurpTheme theme) {
        this.manager = manager;
        this.theme = theme;
        setLayout(new BorderLayout());
        setOpaque(false);

        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        header.setOpaque(false);
        header.setBorder(BorderFactory.createEmptyBorder(16, 20, 12, 20));
        statsText = new JLabel();
        statsText.setFont(theme.displayFont(Font.BOLD, 15f));
        header.add(statsText);
        add(header, BorderLayout.NORTH);

        content = new JPanel(new GridLayout(0, 2, 8, 8));
        content.setOpaque(false);
        content.setBorder(BorderFactory.createEmptyBorder(0, 16, 16, 16));
        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        scroll.getVerticalScrollBar().setUnitIncrement(20);
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        add(scroll, BorderLayout.CENTER);

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 8));
        footer.setOpaque(false);
        footer.setBorder(BorderFactory.createEmptyBorder(0, 16, 8, 16));
        JButton reset = new JButton("重置成就");
        reset.setFont(theme.displayFont(Font.PLAIN, 11f));
        reset.setMargin(new Insets(3, 10, 3, 10));
        reset.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "确定重置所有成就？", "确认", JOptionPane.YES_NO_OPTION) == 0) {
                manager.resetAll();
                refresh();
            }
        });
        footer.add(reset);
        add(footer, BorderLayout.SOUTH);

        refresh();
    }

    public void refresh() {
        content.removeAll();
        for (Achievement a : manager.getAllAchievements()) {
            content.add(buildCard(a));
        }
        content.revalidate();

        int u = manager.getUnlockedCount(), t = manager.getTotalCount();
        double pct = t > 0 ? u * 100.0 / t : 0;
        Color c = pct >= 80 ? new Color(250, 204, 21) : pct >= 50 ? new Color(74, 222, 128) : new Color(96, 165, 250);
        statsText.setText(String.format("已解锁 %d / %d", u, t));
        statsText.setForeground(c);
    }

    private JPanel buildCard(Achievement a) {
        boolean unlocked = a.isUnlocked();
        Color accent = unlocked ? Color.decode(a.getRarity().getColor()) : new Color(55, 55, 55);

        JPanel card = new JPanel(new BorderLayout(0, 3)) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(unlocked ? theme.contextBg().brighter() : theme.contextBg());
                g2.fill(new RoundRectangle2D.Double(0, 0, getWidth() - 1, getHeight() - 1, 8, 8));
                g2.setColor(unlocked ? accent : theme.inputBorder());
                g2.draw(new RoundRectangle2D.Double(0.5, 0.5, getWidth() - 2, getHeight() - 2, 8, 8));
                g2.setColor(accent);
                g2.fillRoundRect(0, 2, 4, getHeight() - 4, 4, 4);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        card.setOpaque(false);
        card.setPreferredSize(new Dimension(0, 80));
        card.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 10));

        // 名称 + 稀有度徽章
        JPanel row1 = new JPanel(new BorderLayout());
        row1.setOpaque(false);

        JLabel name = new JLabel(unlocked ? a.getName() : "???");
        name.setFont(theme.displayFont(Font.BOLD, 12f));
        name.setForeground(unlocked ? theme.contextFg() : Color.GRAY);
        row1.add(name, BorderLayout.WEST);

        JLabel badge = new JLabel(a.getRarity().getDisplayName(), SwingConstants.CENTER);
        badge.setFont(theme.displayFont(Font.BOLD, 8f));
        badge.setForeground(Color.WHITE);
        badge.setOpaque(true);
        badge.setBackground(unlocked ? accent : Color.DARK_GRAY);
        badge.setBorder(BorderFactory.createEmptyBorder(1, 6, 1, 6));
        row1.add(badge, BorderLayout.EAST);
        card.add(row1, BorderLayout.NORTH);

        // 描述
        JLabel desc = new JLabel(unlocked ? a.getDescription() : "尚未解锁");
        desc.setFont(theme.displayFont(Font.PLAIN, 10f));
        desc.setForeground(unlocked ? theme.contextFg().brighter() : Color.DARK_GRAY);
        card.add(desc, BorderLayout.CENTER);

        // 底部
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row3.setOpaque(false);
        if (unlocked && a.getUnlockedTime() > 0) {
            JLabel date = new JLabel(sdf.format(new Date(a.getUnlockedTime())));
            date.setFont(theme.displayFont(Font.PLAIN, 9f));
            date.setForeground(Color.GRAY);
            row3.add(date);
        }
        card.add(row3, BorderLayout.SOUTH);

        return card;
    }
}
