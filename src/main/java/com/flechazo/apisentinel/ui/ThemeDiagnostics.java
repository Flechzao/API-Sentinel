package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.config.AppPaths;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * One-shot theme forensics: dumps everything we can learn about Burp's
 * ACTUAL colors on this machine to a file, so the extension's hard-coded
 * palette can be calibrated against evidence instead of guesses.
 *
 * <p>Three evidence layers:
 * <ol>
 *   <li><b>Detached probe</b> — what applyThemeToComponent does to fresh
 *       components (what the failed sampling attempt relied on);</li>
 *   <li><b>UIManager defaults</b> — every Color the installed LookAndFeel
 *       defines (reveals Burp's LAF class + its real palette keys);</li>
 *   <li><b>Live suite-tree samples</b> — colors of REAL, on-screen Burp
 *       components (the ground truth for what "Burp native" looks like).</li>
 * </ol>
 *
 * <p>Output: {@code ~/.api-sentinel/theme-dump.txt} (overwritable). Run once
 * in dark theme and once in light theme.
 */
public final class ThemeDiagnostics {

    private ThemeDiagnostics() {}

    /** Builds the report, writes it, returns the file path. EDT-safe. */
    public static Path dump(MontoyaApi api) throws Exception {
        StringBuilder sb = new StringBuilder(16 * 1024);
        sb.append("=== API Sentinel theme diagnostics ===\n");
        sb.append("time: ").append(LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append('\n');
        sb.append("burp theme: ").append(api.userInterface().currentTheme()).append('\n');
        sb.append("lookAndFeel: ").append(UIManager.getLookAndFeel() == null ? "?"
                : UIManager.getLookAndFeel().getClass().getName()).append('\n');
        Font df = api.userInterface().currentDisplayFont();
        Font ef = api.userInterface().currentEditorFont();
        sb.append("display font: ").append(fontDesc(df)).append('\n');
        sb.append("editor  font: ").append(fontDesc(ef)).append('\n');

        sb.append("\n--- 1. detached probe (applyThemeToComponent on fresh components) ---\n");
        try {
            var ui = api.userInterface();
            JPanel panel = new JPanel();
            ui.applyThemeToComponent(panel);
            sb.append("JPanel    bg=").append(hex(panel.getBackground())).append('\n');

            JLabel label = new JLabel("x");
            ui.applyThemeToComponent(label);
            sb.append("JLabel    fg=").append(hex(label.getForeground()))
                    .append("  bg=").append(hex(label.getBackground())).append('\n');

            JTextField field = new JTextField();
            ui.applyThemeToComponent(field);
            sb.append("JTextField bg=").append(hex(field.getBackground()))
                    .append("  fg=").append(hex(field.getForeground()))
                    .append("  caret=").append(hex(field.getCaretColor()))
                    .append("  border=").append(borderDesc(field.getBorder())).append('\n');

            JButton button = new JButton("x");
            ui.applyThemeToComponent(button);
            sb.append("JButton   bg=").append(hex(button.getBackground()))
                    .append("  fg=").append(hex(button.getForeground()))
                    .append("  border=").append(borderDesc(button.getBorder())).append('\n');

            JTable table = new JTable(1, 1);
            ui.applyThemeToComponent(table);
            sb.append("JTable    bg=").append(hex(table.getBackground()))
                    .append("  fg=").append(hex(table.getForeground()))
                    .append("  grid=").append(hex(table.getGridColor()))
                    .append("  selBg=").append(hex(table.getSelectionBackground())).append('\n');
        } catch (Throwable t) {
            sb.append("probe failed: ").append(t).append('\n');
        }

        sb.append("\n--- 2. UIManager LookAndFeel color defaults ---\n");
        try {
            Map<String, String> colors = new TreeMap<>();
            for (Map.Entry<Object, Object> e : UIManager.getLookAndFeelDefaults().entrySet()) {
                if (e.getValue() instanceof Color c) {
                    colors.put(String.valueOf(e.getKey()), hex(c));
                }
            }
            colors.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            sb.append('(').append(colors.size()).append(" color keys)\n");
        } catch (Throwable t) {
            sb.append("defaults failed: ").append(t).append('\n');
        }

        sb.append("\n--- 3. live suite-tree samples (real on-screen Burp components) ---\n");
        try {
            Frame suite = api.userInterface().swingUtils().suiteFrame();
            if (suite == null) {
                sb.append("suiteFrame() returned null\n");
            } else {
                int visited = 0, recorded = 0;
                Deque<Object[]> queue = new ArrayDeque<>(); // [component, depth]
                queue.add(new Object[]{suite, 0});
                List<String> lines = new ArrayList<>();
                while (!queue.isEmpty() && visited < 6000 && recorded < 90) {
                    Object[] cur = queue.poll();
                    Component c = (Component) cur[0];
                    int depth = (Integer) cur[1];
                    visited++;
                    String line = sampleLine(c, depth);
                    if (line != null) {
                        lines.add(line);
                        recorded++;
                    }
                    if (c instanceof Container cc && depth < 10) {
                        for (Component child : cc.getComponents()) {
                            queue.add(new Object[]{child, depth + 1});
                        }
                    }
                }
                lines.forEach(l -> sb.append(l).append('\n'));
                sb.append("(visited ").append(visited).append(" components, recorded ")
                        .append(recorded).append(")\n");
            }
        } catch (Throwable t) {
            sb.append("suite walk failed: ").append(t).append('\n');
        }

        Path out = AppPaths.resolve("theme-dump.txt");
        Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
        return out;
    }

    /** One line per component that carries its own colors or identity. */
    private static String sampleLine(Component c, int depth) {
        Color bg = c.getBackground();
        Color fg = c.getForeground();
        String name = c.getClass().getSimpleName();
        String text = null;
        if (c instanceof JLabel l) text = l.getText();
        else if (c instanceof AbstractButton b) text = b.getText();
        else if (c instanceof java.awt.Choice ch && ch.getItemCount() > 0) text = ch.getItem(0);
        if (text != null) {
            text = text.replaceAll("\\s+", " ").trim();
            if (text.length() > 24) text = text.substring(0, 24) + "…";
        }
        // Skip pure containers with inherited (null) colors and no identity —
        // noise. Keep everything that either paints its own bg or is a labeled
        // control (its fg is what Burp chose for text).
        boolean interesting = bg != null || text != null && !text.isEmpty();
        if (!interesting) return null;
        return String.format("d%-2d %-22s bg=%s fg=%s%s", depth, name,
                hex(bg), hex(fg), text != null && !text.isEmpty() ? "  \"" + text + "\"" : "");
    }

    private static String hex(Color c) {
        if (c == null) return "null(inherited)";
        return String.format("#%02x%02x%02x%s", c.getRed(), c.getGreen(), c.getBlue(),
                c.getAlpha() < 255 ? " a=" + c.getAlpha() : "");
    }

    private static String borderDesc(Border b) {
        if (b == null) return "null";
        if (b instanceof LineBorder lb) return "line " + hex(lb.getLineColor());
        if (b instanceof CompoundBorder cb) {
            return "compound[" + borderDesc(cb.getOutsideBorder()) + " | "
                    + borderDesc(cb.getInsideBorder()) + "]";
        }
        return b.getClass().getSimpleName();
    }

    private static String fontDesc(Font f) {
        if (f == null) return "null";
        return f.getFamily() + " / " + f.getName() + " / size " + f.getSize()
                + (f.isBold() ? " bold" : "") + (f.isItalic() ? " italic" : "");
    }
}
