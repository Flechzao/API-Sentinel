package com.flechazo.apisentinel.ui;

import javax.swing.*;
import java.awt.*;

/**
 * A JPanel that paints its background as an anti-aliased rounded rectangle
 * instead of a hard-edged rect with a rounded LineBorder drawn over a square
 * fill (which leaves square corners peeking out from under the border
 * stroke). Used for chat bubbles so they read as soft cards, matching
 * Burp's own native AI chat, instead of boxy panels.
 */
public class RoundedPanel extends JPanel {

    private int cornerRadius = 14;
    private Color borderColor;

    public RoundedPanel() {
        this(new BorderLayout());
    }

    public RoundedPanel(LayoutManager layout) {
        super(layout);
        setOpaque(false);
    }

    public void setCornerRadius(int radius) { this.cornerRadius = radius; }

    /** Optional thin outline drawn just inside the rounded fill, for subtle
     *  definition against backgrounds close in color to the card itself. */
    public void setBorderColor(Color color) { this.borderColor = color; }

    @Override
    protected void paintComponent(Graphics g) {
        // Defensive re-assert: Burp's applyThemeToComponent walks the whole
        // tab tree once at load and is known to mutate rendering-related
        // properties on components it finds (confirmed for JLabel's
        // html.disable — observed during the tab-tree theme walk). If it ever also flips opaque
        // back to true on this panel, cheaply put it back before painting.
        if (isOpaque()) setOpaque(false);

        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getBackground());
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), cornerRadius, cornerRadius);
            if (borderColor != null) {
                g2.setColor(borderColor);
                g2.setStroke(new BasicStroke(1f));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, cornerRadius, cornerRadius);
            }
        } finally {
            g2.dispose();
        }
        // Deliberately no super.paintComponent(g) call — this panel only ever
        // holds child components (painted separately via paintChildren, not
        // paintComponent), and calling super here would repaint a square
        // background on top of the rounded fill above if something ever
        // forces setOpaque(true) on this component (e.g. Burp's theme engine,
        // which we've already seen mutate JLabel HTML-rendering properties
        // broadly when it walks the tab's component tree — see the html.disable note above).
    }
}
