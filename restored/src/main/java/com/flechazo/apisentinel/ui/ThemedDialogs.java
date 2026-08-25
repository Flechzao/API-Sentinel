package com.flechazo.apisentinel.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;

/**
 * Themed replacements for the JOptionPane calls scattered across presenters
 * and panels — the native panes render with the Metal look and stock fonts,
 * standing out against every Burp-themed surface in this plugin. Behavior
 * notes:
 *  - blocking, like JOptionPane (all call sites are EDT action handlers);
 *  - ESC always selects the non-affirmative option;
 *  - the affirmative option is the default button, matching what users
 *    already expect from JOptionPane.
 */
public final class ThemedDialogs {

    private static volatile BurpTheme theme;

    private ThemedDialogs() {}

    /** Called once at extension init; before that (or in headless tests)
     *  dialogs fall back to a dark palette (Burp's dominant theme). */
    public static void init(BurpTheme t) {
        theme = t;
    }

    /** 取消/确定 confirmation — true when accepted. */
    public static boolean confirm(Component parent, String message, String title) {
        return show(parent, title, message, Type.WARN, new String[]{"取消", "确定"}) == 1;
    }

    /** 否/是 confirmation — true on "是". */
    public static boolean confirmYesNo(Component parent, String message, String title) {
        return show(parent, title, message, Type.WARN, new String[]{"否", "是"}) == 1;
    }

    public static void info(Component parent, String message, String title) {
        show(parent, title, message, Type.INFO, new String[]{"确定"});
    }

    public static void warn(Component parent, String message, String title) {
        show(parent, title, message, Type.WARN, new String[]{"确定"});
    }

    public static void error(Component parent, String message, String title) {
        show(parent, title, message, Type.ERROR, new String[]{"确定"});
    }

    private enum Type { INFO, WARN, ERROR }

    /** @return index of the clicked button (ESC / window-close → index 0,
     *          the non-affirmative option in every two-button case). */
    private static int show(Component parent, String title, String message,
                            Type type, String[] options) {
        Window owner = parent instanceof Window w
                ? w : (parent != null ? SwingUtilities.getWindowAncestor(parent) : null);

        BurpTheme t = theme;
        Color stripBg;
        Color stripFg;
        Color textFg;
        if (t != null) {
            stripBg = type == Type.INFO ? t.dialogCardBg() : t.warningStripBg();
            stripFg = type == Type.INFO ? t.mutedText()
                    : type == Type.WARN ? t.warningStripFg() : t.errorColor();
            textFg = t.aiTextColor();
        } else {
            stripBg = type == Type.INFO ? new Color(42, 46, 56) : new Color(68, 44, 42);
            stripFg = type == Type.INFO ? new Color(150, 153, 162) : new Color(255, 145, 135);
            textFg = new Color(210, 210, 210);
        }

        JDialog dialog = new JDialog(owner, title, Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(0, 0));
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setResizable(false);

        int[] result = {0};

        JPanel strip = new JPanel(new BorderLayout(10, 0));
        strip.setBackground(stripBg);
        strip.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        JLabel icon = new JLabel(switch (type) {
            case INFO -> "ⓘ"; case WARN -> "⚠"; case ERROR -> "✕"; });
        icon.setFont(new Font("SansSerif", Font.BOLD, 16));
        icon.setForeground(stripFg);
        strip.add(icon, BorderLayout.WEST);

        JTextArea msg = new JTextArea(message);
        msg.setEditable(false);
        msg.setLineWrap(true);
        msg.setWrapStyleWord(true);
        msg.setOpaque(false);
        msg.setColumns(44);
        msg.setFont(t != null ? t.displayFont(Font.PLAIN, 12f) : new Font("SansSerif", Font.PLAIN, 12));
        msg.setForeground(textFg);
        msg.setBorder(null);
        strip.add(msg, BorderLayout.CENTER);
        dialog.add(strip, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.setBorder(BorderFactory.createEmptyBorder(10, 16, 12, 16));
        buttons.setOpaque(false);
        for (int i = 0; i < options.length; i++) {
            JButton b = new JButton(options[i]);
            b.setFont(t != null ? t.displayFont(Font.BOLD, 12f) : new Font("SansSerif", Font.BOLD, 12));
            final int idx = i;
            b.addActionListener(e -> {
                result[0] = idx;
                dialog.dispose();
            });
            if (i == options.length - 1) {
                dialog.getRootPane().setDefaultButton(b);
            }
            buttons.add(b);
        }
        dialog.add(buttons, BorderLayout.SOUTH);

        dialog.getRootPane().registerKeyboardAction(e -> {
            result[0] = 0;
            dialog.dispose();
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);

        dialog.pack();
        dialog.setLocationRelativeTo(owner != null ? owner : parent);
        if (t != null) t.apply(dialog);
        // Re-assert colors after the L&F pass.
        strip.setBackground(stripBg);
        icon.setForeground(stripFg);
        msg.setForeground(textFg);
        dialog.setVisible(true); // modal block until a button is clicked
        return result[0];
    }
}
