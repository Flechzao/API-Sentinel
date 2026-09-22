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
    /** Maps fixed keys → display I18n keys, so language toggle can find buttons. */
    private final Map<String, String> buttonKeys = new LinkedHashMap<>();
    private final ButtonGroup group = new ButtonGroup();
    private final ApiRepository repository;
    private final BurpTheme theme;
    private final Consumer<ApiStatus> onFilterChanged;
    private Consumer<String> onRiskChanged;
    private Runnable onBambda;
    private JLabel filterLabel;
    private JLabel riskLabel;
    private JComboBox<String> riskCombo;

    public void setOnBambda(Runnable r) { this.onBambda = r; }

    public FilterBar(ApiRepository repository, Consumer<ApiStatus> onFilterChanged, BurpTheme theme) {
        this.repository = repository;
        this.onFilterChanged = onFilterChanged;
        this.theme = theme;

        setLayout(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setBorder(new EmptyBorder(0, 6, 0, 6));
        setOpaque(false);

        JLabel label = new JLabel(I18n.get("filter_label"));
        this.filterLabel = label;
        label.setFont(theme.displayFont(Font.BOLD, 12f));
        label.setForeground(theme.mutedText());
        add(label);

        addFilterButton("filter_all", I18n.get("filter_all"), null);
        addFilterButton("filter_untested", I18n.get("filter_untested"), ApiStatus.UNTESTED);
        addFilterButton("filter_testing", I18n.get("filter_testing"), ApiStatus.UNDER_TEST);
        addFilterButton("filter_passed", I18n.get("filter_passed"), ApiStatus.PASSED);
        addFilterButton("filter_vuln", I18n.get("filter_vuln"), ApiStatus.VULNERABLE);

        // Select "全部" by default
        buttons.get("filter_all").setSelected(true);
        styleButton(buttons.get("filter_all"), true);

        // Bambda button (between status filter and risk filter)
        add(Box.createHorizontalStrut(8));
        JButton bambdaBtn = new JButton("Bambda");
        bambdaBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        bambdaBtn.setMargin(new java.awt.Insets(1, 6, 1, 6));
        bambdaBtn.setToolTipText(I18n.get("bambda_copy"));
        bambdaBtn.addActionListener(e -> { if (onBambda != null) onBambda.run(); });
        add(bambdaBtn);

        // Risk-level filter (separate from status filter, composes with it)
        add(Box.createHorizontalStrut(8));
        JLabel riskLabel = new JLabel(I18n.get("filter_risk"));
        this.riskLabel = riskLabel;
        riskLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        riskLabel.setForeground(theme.mutedText());
        add(riskLabel);
        JComboBox<String> riskCombo = new JComboBox<>(
                new String[]{I18n.get("filter_all"), "HIGH", "MEDIUM", "LOW", "SAFE", I18n.get("filter_unanalyzed")});
        this.riskCombo = riskCombo;
        riskCombo.setFont(theme.displayFont(Font.PLAIN, 11f));
        riskCombo.addActionListener(e -> {
            if (onRiskChanged != null) {
                String sel = (String) riskCombo.getSelectedItem();
                onRiskChanged.accept("filter_all".equals(sel) ? null : ("filter_unanalyzed".equals(sel) ? "--" : sel));
            }
        });
        add(riskCombo);

        repository.addChangeListener(() -> javax.swing.SwingUtilities.invokeLater(this::refreshCounts));
        refreshCounts();

        // Auto-refresh on language toggle
        I18n.addLangListener(lang -> javax.swing.SwingUtilities.invokeLater(this::refreshI18n));
    }

    private void refreshI18n() {
        if (filterLabel != null) filterLabel.setText(I18n.get("filter_label"));
        if (riskLabel != null) riskLabel.setText(I18n.get("filter_risk"));
        if (riskCombo != null) {
            // Suppress action listener during rebuild — removeAllItems/addItem
            // triggers the listener, which would change the table filter and
            // cause the empty state to flash on (data "disappears" temporarily).
            java.awt.event.ActionListener[] listeners = riskCombo.getActionListeners();
            for (java.awt.event.ActionListener l : listeners) riskCombo.removeActionListener(l);
            String sel = (String) riskCombo.getSelectedItem();
            riskCombo.removeAllItems();
            riskCombo.addItem(I18n.get("filter_all"));
            riskCombo.addItem("HIGH");
            riskCombo.addItem("MEDIUM");
            riskCombo.addItem("LOW");
            riskCombo.addItem("SAFE");
            riskCombo.addItem(I18n.get("filter_unanalyzed"));
            if (sel != null) riskCombo.setSelectedItem(sel);
            for (java.awt.event.ActionListener l : listeners) riskCombo.addActionListener(l);
        }
        refreshCounts();
    }

    public void setOnRiskChanged(Consumer<String> c) {
        this.onRiskChanged = c;
    }

    private void addFilterButton(String label, ApiStatus status) {
        addFilterButton(label, label, status);
    }
    private void addFilterButton(String fixedKey, String label, ApiStatus status) {
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
        buttons.put(fixedKey, btn);
        buttonKeys.put(fixedKey, label);
        add(btn);
    }

    private void styleButton(JToggleButton btn, boolean active) {
        if (active) {
            btn.setBackground(theme.accentBg());
            btn.setForeground(theme.accentFg());
        } else {
            btn.setBackground(theme.chipBg());
            btn.setForeground(theme.chipFg());
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
            updateButtonText("filter_all", ft);
            updateButtonText("filter_untested", fu);
            updateButtonText("filter_testing", ftu);
            updateButtonText("filter_passed", fp);
            updateButtonText("filter_vuln", fv);
        });
    }

    private void updateButtonText(String key, int count) {
        JToggleButton btn = buttons.get(key);
        if (btn != null) {
            String displayText = I18n.get(key);
            String newText = displayText + "(" + count + ")";
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
