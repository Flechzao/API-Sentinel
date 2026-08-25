package com.flechazo.apisentinel.ui;

import javax.swing.*;
import java.awt.*;

/**
 * A JProgressBar that paints a rounded track + rounded fill instead of the
 * default L&F's square, flat-colored bar — used for Pipeline/Agent progress
 * so it matches the rest of the app's rounded-card visual language instead
 * of looking like the one un-styled native control left in the UI.
 *
 * Only the determinate paint path is customized; indeterminate mode (used
 * briefly by the "simple analysis" flow) falls back to the platform L&F,
 * since a custom indeterminate animation isn't worth the added complexity
 * for a rarely-seen transient state.
 */
public class RoundedProgressBar extends JProgressBar {

    private Color fillColor;

    public RoundedProgressBar(int min, int max) {
        super(min, max);
        setOpaque(false);
        setBorderPainted(false);
    }

    public void setFillColor(Color color) { this.fillColor = color; }

    @Override
    protected void paintComponent(Graphics g) {
        if (isIndeterminate()) {
            super.paintComponent(g);
            return;
        }

        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth();
            int h = getHeight();
            int arc = h;

            g2.setColor(getBackground());
            g2.fillRoundRect(0, 0, w, h, arc, arc);

            int range = getMaximum() - getMinimum();
            double pct = range > 0 ? (getValue() - getMinimum()) / (double) range : 0;
            int fillWidth = (int) Math.round(w * Math.max(0, Math.min(1, pct)));
            if (fillWidth > 0) {
                g2.setColor(fillColor != null ? fillColor : getForeground());
                g2.fillRoundRect(0, 0, fillWidth, h, arc, arc);
            }

            if (isStringPainted()) {
                String s = getString();
                if (s != null && !s.isEmpty()) {
                    g2.setFont(getFont());
                    FontMetrics fm = g2.getFontMetrics();
                    int tx = (w - fm.stringWidth(s)) / 2;
                    int ty = (h - fm.getHeight()) / 2 + fm.getAscent();
                    g2.setColor(getForeground());
                    g2.drawString(s, tx, ty);
                }
            }
        } finally {
            g2.dispose();
        }
    }
}
