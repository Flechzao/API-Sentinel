package com.flechazo.apisentinel.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class MarkdownRenderer {

    private final BurpTheme theme;

    public MarkdownRenderer(BurpTheme theme) {
        this.theme = theme;
    }

    public void render(String markdown, JTextPane pane) {
        StyledDocument doc = pane.getStyledDocument();
        try { doc.remove(0, doc.getLength()); } catch (BadLocationException ignored) {}

        List<Block> blocks = parseBlocks(markdown);
        for (Block block : blocks) {
            renderBlock(block, doc, pane);
        }
    }

    public JPanel renderToPanel(String markdown) {
        List<Block> blocks = parseBlocks(markdown);
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setOpaque(false);

        for (Block block : blocks) {
            if (block.type == BlockType.CODE_BLOCK) {
                panel.add(createCodeBlockComponent(block.content));
                panel.add(Box.createVerticalStrut(4));
            } else if (block.type == BlockType.TABLE) {
                JComponent tableComp = createTableComponent(block.content);
                tableComp.setAlignmentX(Component.LEFT_ALIGNMENT);
                panel.add(tableComp);
                panel.add(Box.createVerticalStrut(4));
            } else {
                JTextPane pane = new JTextPane();
                pane.setEditable(false);
                pane.setOpaque(false);
                pane.setBorder(null);
                pane.setAlignmentX(Component.LEFT_ALIGNMENT);
                renderBlock(block, pane.getStyledDocument(), pane);
                pane.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
                panel.add(pane);
            }
        }
        return panel;
    }

    // ── Block-level parsing ──

    private enum BlockType {
        HEADING_1, HEADING_2, HEADING_3,
        CODE_BLOCK, UNORDERED_LIST, ORDERED_LIST,
        TABLE, PARAGRAPH
    }

    private record Block(BlockType type, String content) {}

    private List<Block> parseBlocks(String markdown) {
        List<Block> blocks = new ArrayList<>();
        String[] lines = markdown.split("\n", -1);
        boolean inCode = false;
        StringBuilder codeBuilder = new StringBuilder();
        StringBuilder paraBuilder = new StringBuilder();
        StringBuilder tableBuilder = new StringBuilder();

        for (String line : lines) {
            if (line.startsWith("```")) {
                if (!inCode) {
                    flushParagraph(paraBuilder, blocks);
                    flushTable(tableBuilder, blocks);
                    inCode = true;
                    codeBuilder.setLength(0);
                } else {
                    blocks.add(new Block(BlockType.CODE_BLOCK, codeBuilder.toString()));
                    codeBuilder.setLength(0);
                    inCode = false;
                }
                continue;
            }
            if (inCode) {
                if (codeBuilder.length() > 0) codeBuilder.append("\n");
                codeBuilder.append(line);
                continue;
            }
            // Table detection: lines starting with |
            if (line.trim().startsWith("|") && line.trim().endsWith("|")) {
                flushParagraph(paraBuilder, blocks);
                if (tableBuilder.length() > 0) tableBuilder.append("\n");
                tableBuilder.append(line);
                continue;
            } else {
                flushTable(tableBuilder, blocks);
            }
            if (line.startsWith("### ")) {
                flushParagraph(paraBuilder, blocks);
                blocks.add(new Block(BlockType.HEADING_3, line.substring(4)));
            } else if (line.startsWith("## ")) {
                flushParagraph(paraBuilder, blocks);
                blocks.add(new Block(BlockType.HEADING_2, line.substring(3)));
            } else if (line.startsWith("# ")) {
                flushParagraph(paraBuilder, blocks);
                blocks.add(new Block(BlockType.HEADING_1, line.substring(2)));
            } else if (line.matches("^[-*] .+")) {
                flushParagraph(paraBuilder, blocks);
                blocks.add(new Block(BlockType.UNORDERED_LIST, line.substring(2)));
            } else if (line.matches("^\\d+\\. .+")) {
                flushParagraph(paraBuilder, blocks);
                int dotIdx = line.indexOf(". ");
                blocks.add(new Block(BlockType.ORDERED_LIST, line.substring(dotIdx + 2)));
            } else if (line.isBlank()) {
                flushParagraph(paraBuilder, blocks);
            } else {
                if (paraBuilder.length() > 0) paraBuilder.append(" ");
                paraBuilder.append(line);
            }
        }
        if (inCode) {
            blocks.add(new Block(BlockType.CODE_BLOCK, codeBuilder.toString()));
        }
        flushTable(tableBuilder, blocks);
        flushParagraph(paraBuilder, blocks);
        return blocks;
    }

    private void flushTable(StringBuilder builder, List<Block> blocks) {
        if (builder.length() > 0) {
            blocks.add(new Block(BlockType.TABLE, builder.toString()));
            builder.setLength(0);
        }
    }

    private void flushParagraph(StringBuilder builder, List<Block> blocks) {
        if (builder.length() > 0) {
            blocks.add(new Block(BlockType.PARAGRAPH, builder.toString()));
            builder.setLength(0);
        }
    }

    // ── Block rendering ──

    private void renderBlock(Block block, StyledDocument doc, JTextPane pane) {
        try {
            switch (block.type) {
                case HEADING_1 -> renderHeading(doc, block.content, 18f);
                case HEADING_2 -> renderHeading(doc, block.content, 16f);
                case HEADING_3 -> renderHeading(doc, block.content, 14f);
                case UNORDERED_LIST -> renderListItem(doc, "  • ", block.content);
                case ORDERED_LIST -> renderListItem(doc, "  ", block.content);
                case CODE_BLOCK -> renderCodeBlock(doc, pane, block.content);
                case TABLE -> renderTableInline(doc, pane, block.content);
                case PARAGRAPH -> renderParagraph(doc, block.content);
            }
        } catch (BadLocationException ignored) {}
    }

    private void renderHeading(StyledDocument doc, String text, float size) throws BadLocationException {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(attrs, theme.displayFont().getFamily());
        StyleConstants.setFontSize(attrs, (int) size);
        StyleConstants.setBold(attrs, true);
        StyleConstants.setForeground(attrs, theme.headingColor());
        if (doc.getLength() > 0) doc.insertString(doc.getLength(), "\n", attrs);
        renderInline(doc, text, attrs);
        doc.insertString(doc.getLength(), "\n", attrs);
    }

    private void renderParagraph(StyledDocument doc, String text) throws BadLocationException {
        SimpleAttributeSet attrs = baseAttrs();
        if (doc.getLength() > 0) doc.insertString(doc.getLength(), "\n", attrs);
        renderInline(doc, text, attrs);
        doc.insertString(doc.getLength(), "\n", attrs);
    }

    private void renderListItem(StyledDocument doc, String prefix, String text) throws BadLocationException {
        SimpleAttributeSet attrs = baseAttrs();
        doc.insertString(doc.getLength(), prefix, attrs);
        renderInline(doc, text, attrs);
        doc.insertString(doc.getLength(), "\n", attrs);
    }

    private void renderCodeBlock(StyledDocument doc, JTextPane pane, String code) throws BadLocationException {
        JComponent codeComp = createCodeBlockComponent(code);
        SimpleAttributeSet compAttrs = new SimpleAttributeSet();
        StyleConstants.setComponent(compAttrs, codeComp);
        if (doc.getLength() > 0) doc.insertString(doc.getLength(), "\n", baseAttrs());
        doc.insertString(doc.getLength(), " ", compAttrs);
        doc.insertString(doc.getLength(), "\n", baseAttrs());
    }

    // ── Inline parsing ──

    private void renderInline(StyledDocument doc, String text, SimpleAttributeSet baseAttrs) throws BadLocationException {
        int pos = 0;
        int len = text.length();

        while (pos < len) {
            if (pos + 1 < len && text.charAt(pos) == '*' && text.charAt(pos + 1) == '*') {
                int end = text.indexOf("**", pos + 2);
                if (end > 0) {
                    SimpleAttributeSet bold = new SimpleAttributeSet(baseAttrs);
                    StyleConstants.setBold(bold, true);
                    doc.insertString(doc.getLength(), text.substring(pos + 2, end), bold);
                    pos = end + 2;
                    continue;
                }
            }
            if (text.charAt(pos) == '*' && (pos == 0 || text.charAt(pos - 1) != '*') &&
                    (pos + 1 < len && text.charAt(pos + 1) != '*')) {
                int end = text.indexOf('*', pos + 1);
                if (end > 0 && (end + 1 >= len || text.charAt(end + 1) != '*')) {
                    SimpleAttributeSet italic = new SimpleAttributeSet(baseAttrs);
                    StyleConstants.setItalic(italic, true);
                    doc.insertString(doc.getLength(), text.substring(pos + 1, end), italic);
                    pos = end + 1;
                    continue;
                }
            }
            if (text.charAt(pos) == '`') {
                int end = text.indexOf('`', pos + 1);
                if (end > 0) {
                    SimpleAttributeSet code = new SimpleAttributeSet();
                    StyleConstants.setFontFamily(code, theme.editorFont().getFamily());
                    StyleConstants.setFontSize(code, 12);
                    StyleConstants.setForeground(code, theme.aiTextColor());
                    StyleConstants.setBackground(code, theme.inlineCodeBg());
                    doc.insertString(doc.getLength(), text.substring(pos + 1, end), code);
                    pos = end + 1;
                    continue;
                }
            }
            int next = len;
            for (int i = pos + 1; i < len; i++) {
                char c = text.charAt(i);
                if (c == '*' || c == '`') { next = i; break; }
            }
            doc.insertString(doc.getLength(), text.substring(pos, next), baseAttrs);
            pos = next;
        }
    }

    // ── Table rendering ──

    private String[][] parseTable(String tableText) {
        String[] lines = tableText.split("\n");
        List<String[]> rows = new ArrayList<>();
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("|")) trimmed = trimmed.substring(1);
            if (trimmed.endsWith("|")) trimmed = trimmed.substring(0, trimmed.length() - 1);
            String[] cells = Arrays.stream(trimmed.split("\\|"))
                    .map(String::trim).toArray(String[]::new);
            // Skip separator rows like |---|---|---|
            if (cells.length > 0 && Arrays.stream(cells).allMatch(c -> c.matches("^:?-+:?$"))) continue;
            rows.add(cells);
        }
        return rows.toArray(new String[0][]);
    }

    private JComponent createTableComponent(String tableText) {
        String[][] rows = parseTable(tableText);
        if (rows.length == 0) {
            JLabel fallback = new JLabel(tableText);
            fallback.setFont(theme.editorFont(12f));
            return fallback;
        }

        String[] headers = rows[0];
        String[][] data = rows.length > 1 ? Arrays.copyOfRange(rows, 1, rows.length) : new String[0][];

        // Normalize column count
        int cols = headers.length;
        for (int i = 0; i < data.length; i++) {
            if (data[i].length < cols) {
                data[i] = Arrays.copyOf(data[i], cols);
                for (int j = data[i].length; j < cols; j++) {
                    if (data[i][j] == null) data[i][j] = "";
                }
            }
        }

        DefaultTableModel model = new DefaultTableModel(data, headers) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        JTable table = new JTable(model);
        table.setFont(theme.displayFont(Font.PLAIN, 12f));
        table.setForeground(theme.aiTextColor());
        table.setBackground(theme.chatBg());
        table.setGridColor(theme.separator());
        table.setShowGrid(true);
        table.setRowHeight(28);
        table.setIntercellSpacing(new Dimension(8, 4));
        table.setFocusable(false);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        // Header style
        JTableHeader header = table.getTableHeader();
        header.setFont(theme.displayFont(Font.BOLD, 12f));
        header.setForeground(theme.headingColor());
        header.setBackground(theme.headerBg());
        header.setReorderingAllowed(false);
        header.setResizingAllowed(true);

        // Cell renderer with word wrap visual
        DefaultTableCellRenderer cellRenderer = new DefaultTableCellRenderer();
        cellRenderer.setVerticalAlignment(SwingConstants.TOP);
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(cellRenderer);
        }

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(theme.chatBg());
        wrapper.setBorder(BorderFactory.createLineBorder(theme.separator(), 1, true));
        wrapper.add(header, BorderLayout.NORTH);
        wrapper.add(table, BorderLayout.CENTER);

        int height = header.getPreferredSize().height + (data.length * 28) + 4;
        wrapper.setPreferredSize(new Dimension(450, Math.min(height, 400)));
        wrapper.setMaximumSize(new Dimension(Integer.MAX_VALUE, Math.min(height, 400)));
        return wrapper;
    }

    private void renderTableInline(StyledDocument doc, JTextPane pane, String tableText) throws BadLocationException {
        JComponent tableComp = createTableComponent(tableText);
        SimpleAttributeSet compAttrs = new SimpleAttributeSet();
        StyleConstants.setComponent(compAttrs, tableComp);
        if (doc.getLength() > 0) doc.insertString(doc.getLength(), "\n", baseAttrs());
        doc.insertString(doc.getLength(), " ", compAttrs);
        doc.insertString(doc.getLength(), "\n", baseAttrs());
    }

    // ── Helpers ──

    private SimpleAttributeSet baseAttrs() {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(attrs, theme.displayFont().getFamily());
        StyleConstants.setFontSize(attrs, 13);
        StyleConstants.setForeground(attrs, theme.aiTextColor());
        return attrs;
    }

    private JComponent createCodeBlockComponent(String code) {
        JTextArea area = new JTextArea(code);
        area.setEditable(false);
        area.setFont(theme.editorFont(12f));
        area.setBackground(theme.codeBlockBg());
        area.setForeground(theme.aiTextColor());
        area.setCaretColor(theme.aiTextColor());
        area.setBorder(new EmptyBorder(6, 8, 6, 8));
        area.setLineWrap(false);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(theme.codeBlockBorder(), 1, true),
                BorderFactory.createEmptyBorder(0, 0, 0, 0)));
        wrapper.add(area, BorderLayout.CENTER);
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);

        int lineCount = Math.max(1, code.split("\n", -1).length);
        int height = Math.min(lineCount * 18 + 16, 300);
        wrapper.setPreferredSize(new Dimension(450, height));
        wrapper.setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
        return wrapper;
    }
}
