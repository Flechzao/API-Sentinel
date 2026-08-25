package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.repository.ApiRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Horizontal filter bar with toggle buttons for API status filtering.
 * Shows counts per category and triggers table filter updates.
 */
public class FilterBar extends JPanel {

    private final Map<String, JToggleButton> buttons = new LinkedHashMap<>();
    private final ButtonGroup group = new ButtonGroup();
    private final ApiRepository repository;
    private final BurpTheme theme;
    private final Consumer<ApiStatus> onFilterChanged;
    private Consumer<String> onRiskChanged;

    private static final Color ACTIVE_BG = new Color(55, 90, 127);
    private static final Color ACTIVE_FG = Color.WHITE;
    private static final Color INACTIVE_BG = new Color(220, 222, 225);
    private static final Color INACTIVE_FG = new Color(80, 80, 80);
    private static final Color VULN_COLOR = new Color(200, 40, 40);

    public FilterBar(ApiRepository repository, Consumer<ApiStatus> onFilterChanged, BurpTheme theme) {
        this.repository = repository;
        this.onFilterChanged = onFilterChanged;
        this.theme = theme;

        setLayout(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setBorder(new EmptyBorder(0, 6, 0, 6));
        setOpaque(false);

        JLabel label = new JLabel("筛选:");
        label.setFont(theme.displayFont(Font.BOLD, 12f));
        label.setForeground(new Color(80, 80, 80));
        add(label);

        addFilterButton("全部", null);
        addFilterButton("未测试", ApiStatus.UNTESTED);
        addFilterButton("测试中", ApiStatus.UNDER_TEST);
        addFilterButton("已通过", ApiStatus.PASSED);
        addFilterButton("漏洞", ApiStatus.VULNERABLE);

        // Select "全部" by default
        buttons.get("全部").setSelected(true);
        styleButton(buttons.get("全部"), true);

        // Risk-level filter (separate from status filter, composes with it)
        add(Box.createHorizontalStrut(8));
        JLabel riskLabel = new JLabel("风险:");
        riskLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        riskLabel.setForeground(new Color(80, 80, 80));
        add(riskLabel);
        JComboBox<String> riskCombo = new JComboBox<>(
                new String[]{"全部", "HIGH", "MEDIUM", "LOW", "SAFE", "未分析"});
        riskCombo.setFont(theme.displayFont(Font.PLAIN, 11f));
        riskCombo.addActionListener(e -> {
            if (onRiskChanged != null) {
                String sel = (String) riskCombo.getSelectedItem();
                onRiskChanged.accept("全部".equals(sel) ? null : ("未分析".equals(sel) ? "--" : sel));
            }
        });
        add(riskCombo);

        repository.addChangeListener(() -> javax.swing.SwingUtilities.invokeLater(this::refreshCounts));
        refreshCounts();
    }

    public void setOnRiskChanged(Consumer<String> c) {
        this.onRiskChanged = c;
    }

    private void addFilterButton(String label, ApiStatus status) {
        // RoundedToggleButton (not a plain JToggleButton) — the old version drew
        // a rounded LineBorder over the button's own square content fill, which
        // leaves square corners peeking out from under the rounded stroke.
        JToggleButton btn = new RoundedToggleButton(label, 14);
        btn.setFont(theme.displayFont(Font.PLAIN, 11f));
        btn.setMargin(new Insets(3, 6, 3, 6));
        btn.setFocusPainted(false);
        btn.setFocusable(false);
        btn.setPreferredSize(new Dimension(btn.getPreferredSize().width + 30, 24));
        styleButton(btn, false);

        btn.addActionListener(e -> {
            // Style all buttons
            for (Map.Entry<String, JToggleButton> entry : buttons.entrySet()) {
                styleButton(entry.getValue(), entry.getValue() == btn);
            }
            onFilterChanged.accept(status);
        });

        group.add(btn);
        buttons.put(label, btn);
        add(btn);
    }

    private void styleButton(JToggleButton btn, boolean active) {
        if (active) {
            btn.setBackground(ACTIVE_BG);
            btn.setForeground(ACTIVE_FG);
        } else {
            btn.setBackground(INACTIVE_BG);
            btn.setForeground(INACTIVE_FG);
        }
        btn.repaint();
    }

    public void refreshCounts() {
        if (repository == null) return;

        List<ApiEntry> all = repository.findAll();
        int total = all.size();
        int untested = 0, underTest = 0, passed = 0, vuln = 0;

        for (ApiEntry entry : all) {
            switch (entry.getStatus()) {
                case UNTESTED -> untested++;
                case UNDER_TEST -> underTest++;
                case PASSED -> passed++;
                case VULNERABLE -> vuln++;
            }
        }

        final int ft = total, fu = untested, ftu = underTest, fp = passed, fv = vuln;
        SwingUtilities.invokeLater(() -> {
            updateButtonText("全部", ft);
            updateButtonText("未测试", fu);
            updateButtonText("测试中", ftu);
            updateButtonText("已通过", fp);
            updateButtonText("漏洞", fv);
        });
    }

    private void updateButtonText(String key, int count) {
        JToggleButton btn = buttons.get(key);
        if (btn != null) {
            String newText = key + "(" + count + ")";
            if (!newText.equals(btn.getText())) {
                Dimension size = btn.getPreferredSize();
                btn.setText(newText);
                btn.setPreferredSize(size);
            }
        }
    }

    private void startAutoRefresh() {
        // Removed: now event-driven via repository.addChangeListener
    }

    public void shutdown() {
        // No timer to stop - event-driven now
    }

    /** JToggleButton with an anti-aliased rounded-rect fill instead of the
     *  default L&F's square content area — pairs with RoundedPanel as the
     *  "correct" way to get a rounded card/button instead of a rounded
     *  LineBorder drawn over a square fill (which leaves square corners
     *  peeking out from under the stroke). */
    private static class RoundedToggleButton extends JToggleButton {
        private final int radius;

        RoundedToggleButton(String text, int radius) {
            super(text);
            this.radius = radius;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            // Defensive re-assert — Burp's theme engine walks the whole tab
            // tree once at load and mutates rendering properties on what it
            // finds (confirmed for JLabel's html.disable — observed during theme walk).
            // If it ever flips contentAreaFilled back on for this button,
            // cheaply put it back before painting so the square fill this
            // class exists to avoid doesn't reappear underneath the rounded one.
            if (isContentAreaFilled()) setContentAreaFilled(false);

            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(getBackground());
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);
            } finally {
                g2.dispose();
            }
            super.paintComponent(g);
        }
    }
}
