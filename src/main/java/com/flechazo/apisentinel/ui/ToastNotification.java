package com.flechazo.apisentinel.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A floating toast notification window that auto-dismisses after a specified duration.
 * Used for alerting users about high-risk vulnerabilities discovered by AI analysis.
 */
public class ToastNotification extends JWindow {

    private float opacity = 1.0f;
    private Timer fadeTimer;
    private Timer dismissTimer;

    public enum ToastType {
        DANGER(new Color(180, 30, 30), Color.WHITE),
        WARNING(new Color(200, 140, 0), Color.WHITE),
        SUCCESS(new Color(40, 140, 50), Color.WHITE),
        INFO(new Color(40, 100, 180), Color.WHITE);

        final Color background;
        final Color foreground;

        ToastType(Color bg, Color fg) {
            this.background = bg;
            this.foreground = fg;
        }
    }

    /**
     * Show a toast notification.
     *
     * @param parent      parent component for positioning (can be null)
     * @param message     the notification message
     * @param type        the toast type (DANGER, WARNING, SUCCESS, INFO)
     * @param durationMs  how long to show before fading (milliseconds)
     */
    // P3-5: changed from plain int to AtomicInteger for thread safety.
    private static final java.util.concurrent.atomic.AtomicInteger activeToastCount =
            new java.util.concurrent.atomic.AtomicInteger(0);

    public static void show(Component parent, String message, ToastType type, int durationMs) {
        SwingUtilities.invokeLater(() -> {
            ToastNotification toast = new ToastNotification(parent, message, type, durationMs);
            toast.setVisible(true);
        });
    }

    /**
     * Convenience method for high-risk vulnerability alerts.
     */
    public static void showVulnAlert(Component parent, String apiPath) {
        show(parent, "发现高危漏洞: " + apiPath, ToastType.DANGER, 5000);
    }

    private ToastNotification(Component parent, String message, ToastType type, int durationMs) {
        // Real per-pixel window transparency, needed because this JWindow
        // floats over arbitrary desktop/app content (unlike the chat bubbles,
        // there's no solid-colored container behind it for a rounded panel's
        // corners to blend into) — without this, RoundedPanel's corners would
        // show square white/gray artifacts from the window's own background.
        try {
            setBackground(new Color(0, 0, 0, 0));
        } catch (Exception ignored) {
            // Per-pixel translucency unsupported on this platform/L&F — the
            // toast still works, just with square corners.
        }

        // Content panel — RoundedPanel instead of a square JPanel with a
        // rounded LineBorder drawn over it (which leaves square corners
        // peeking out from under the stroke).
        RoundedPanel content = new RoundedPanel(new BorderLayout(8, 4));
        content.setCornerRadius(12);
        content.setBackground(type.background);
        content.setBorder(new EmptyBorder(10, 16, 10, 16));

        // Icon — vector badge (white disc + type-colored glyph) instead of an
        // emoji char, so it renders identically across platforms/fonts and
        // sits crisply on the toast's saturated background.
        JLabel iconLabel = new JLabel(getIcon(type));
        content.add(iconLabel, BorderLayout.WEST);

        // Message — a line-wrapping JTextArea instead of an <html> JLabel.
        // Burp's theme sets html.disable on JLabels, which made the <html>
        // wrapper render as raw literal tags in the popup. A wrapping text
        // area needs no HTML to break lines at ~280px.
        JTextArea msgArea = new JTextArea(message);
        msgArea.setEditable(false);
        msgArea.setLineWrap(true);
        msgArea.setWrapStyleWord(true);
        msgArea.setOpaque(false);
        msgArea.setBorder(null);
        msgArea.setForeground(type.foreground);
        msgArea.setFont(new Font("SansSerif", Font.BOLD, 13));
        msgArea.setSize(280, Integer.MAX_VALUE);
        Dimension msgPref = msgArea.getPreferredSize();
        msgArea.setPreferredSize(new Dimension(280, Math.max(msgPref.height, 16)));
        content.add(msgArea, BorderLayout.CENTER);

        // Close button — small circular hover highlight instead of bare text
        // with no interaction feedback.
        boolean[] hover = {false};
        JLabel closeBtn = new JLabel("×") {
            @Override
            protected void paintComponent(Graphics g) {
                if (hover[0]) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(new Color(255, 255, 255, 50));
                    g2.fillOval(1, 1, getWidth() - 2, getHeight() - 2);
                    g2.dispose();
                }
                super.paintComponent(g);
            }
        };
        closeBtn.setPreferredSize(new Dimension(20, 20));
        closeBtn.setHorizontalAlignment(SwingConstants.CENTER);
        closeBtn.setForeground(new Color(255, 255, 255, 200));
        closeBtn.setFont(new Font("SansSerif", Font.BOLD, 15));
        closeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        closeBtn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) { dismiss(); }
            @Override public void mouseEntered(java.awt.event.MouseEvent e) { hover[0] = true; closeBtn.repaint(); }
            @Override public void mouseExited(java.awt.event.MouseEvent e) { hover[0] = false; closeBtn.repaint(); }
        });
        content.add(closeBtn, BorderLayout.EAST);

        setContentPane(content);
        pack();

        // Position: top-right corner of the parent or screen
        positionToast(parent);

        // Auto-dismiss after duration
        dismissTimer = new Timer(durationMs, e -> startFadeOut());
        dismissTimer.setRepeats(false);
        dismissTimer.start();
    }

    private void positionToast(Component parent) {
        int toastIndex = activeToastCount.getAndIncrement();
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        int x, y;

        if (parent != null && parent.isShowing()) {
            Point loc = parent.getLocationOnScreen();
            Dimension parentSize = parent.getSize();
            x = loc.x + parentSize.width - getWidth() - 20;
            y = loc.y + 10 + toastIndex * (getHeight() + 8);
        } else {
            x = screenSize.width - getWidth() - 30;
            y = 30 + toastIndex * (getHeight() + 8);
        }

        // Ensure on-screen
        x = Math.max(10, Math.min(x, screenSize.width - getWidth() - 10));
        y = Math.max(10, Math.min(y, screenSize.height - getHeight() - 10));

        setLocation(x, y);
    }

    private void startFadeOut() {
        fadeTimer = new Timer(50, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                opacity -= 0.1f;
                if (opacity <= 0) {
                    dismiss();
                } else {
                    try {
                        ToastNotification.this.setOpacity(Math.max(0, opacity));
                    } catch (Exception ignored) {
                        // setOpacity not supported on all platforms
                        dismiss();
                    }
                }
            }
        });
        fadeTimer.setRepeats(true);
        fadeTimer.start();
    }

    private void dismiss() {
        if (fadeTimer != null) fadeTimer.stop();
        if (dismissTimer != null) dismissTimer.stop();
        activeToastCount.set(Math.max(0, activeToastCount.get() - 1));
        setVisible(false);
        dispose();
    }

    private javax.swing.Icon getIcon(ToastType type) {
        // White badge fill, glyph tinted with the toast's own accent color so
        // it reads as an inset mark on the saturated background.
        IconFactory.Kind kind = switch (type) {
            case DANGER -> IconFactory.Kind.FAIL;
            case WARNING -> IconFactory.Kind.WARN;
            case SUCCESS -> IconFactory.Kind.OK;
            case INFO -> IconFactory.Kind.INFO;
        };
        return IconFactory.badge(kind, 18, Color.WHITE, type.background);
    }

    /**
     * Flash the tab caption by appending a warning marker for a duration.
     *
     * @param tabbedPane the JTabbedPane containing the tab
     * @param tabTitle   the original tab title
     * @param durationMs how long to flash (milliseconds)
     */
    private static final java.util.Set<String> flashingTabs = ConcurrentHashMap.newKeySet();

    public static void flashTabCaption(JTabbedPane tabbedPane, String tabTitle, int durationMs) {
        if (tabbedPane == null) return;
        if (!flashingTabs.add(tabTitle)) return;

        SwingUtilities.invokeLater(() -> {
            // Find tab index
            int idx = -1;
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                if (tabTitle.equals(tabbedPane.getTitleAt(i))) {
                    idx = i;
                    break;
                }
            }
            if (idx < 0) return;

            final int tabIndex = idx;
            final String original = tabbedPane.getTitleAt(tabIndex);

            // Start flashing
            Timer flashTimer = new Timer(500, null);
            final boolean[] on = {false};
            flashTimer.addActionListener(e -> {
                on[0] = !on[0];
                tabbedPane.setTitleAt(tabIndex, on[0] ? original + " ⚠" : original);
            });
            flashTimer.setRepeats(true);
            flashTimer.start();

            // Stop flashing after duration
            Timer stopTimer = new Timer(durationMs, e -> {
                flashTimer.stop();
                tabbedPane.setTitleAt(tabIndex, original);
                flashingTabs.remove(tabTitle);
            });
            stopTimer.setRepeats(false);
            stopTimer.start();
        });
    }

    /** P3-5: test-only reset. */
    public static void resetForTest() {
        activeToastCount.set(0);
    }
}
