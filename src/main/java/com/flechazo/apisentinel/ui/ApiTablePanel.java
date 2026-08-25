package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.model.ApiStatus;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;
import java.util.function.IntConsumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.flechazo.apisentinel.model.ApiEntryTableModel.*;

/**
 * 接口表格面板——展示已捕获 API 列表，支持选中/编辑/右键操作/分析中状态高亮。
 */
public class ApiTablePanel extends JPanel {

    // Fonts derive from Burp's theme (display/editor) instead of raw AWT
    // names — keeps family/weight consistent with everything Burp renders.
    private final Font MONOSPACED_BOLD_11;
    private final Font MONOSPACED_PLAIN_12;
    private final Font SANS_BOLD_11;
    private final Font SANS_ITALIC_11;
    private final Font SANS_PLAIN_11;
    private final Font SANS_PLAIN_12;

    private final JTable table;
    private final ApiEntryTableModel tableModel;
    private final TableRowSorter<ApiEntryTableModel> rowSorter;
    private final JLabel rowCountLabel;
    private final BurpTheme theme;

    private IntConsumer onAnalyzeRow;
    private IntConsumer onAiChat;
    private Consumer<int[]> onDeleteRows;
    private Consumer<int[]> onMarkSafe;
    private Consumer<int[]> onViewTraffic;
    private IntConsumer onViewFindings;
    private IntConsumer onViewPassive;
    private Consumer<int[]> onSendToOrganizer;

    public ApiTablePanel(ApiEntryTableModel tableModel, BurpTheme theme) {
        this.tableModel = tableModel;
        this.theme = theme;
        this.MONOSPACED_BOLD_11 = theme.editorFont().deriveFont(Font.BOLD, 11f);
        this.MONOSPACED_PLAIN_12 = theme.editorFont(12f);
        this.SANS_BOLD_11 = theme.displayFont(Font.BOLD, 11f);
        this.SANS_ITALIC_11 = theme.displayFont(Font.ITALIC, 11f);
        this.SANS_PLAIN_11 = theme.displayFont(Font.PLAIN, 11f);
        this.SANS_PLAIN_12 = theme.displayFont(Font.PLAIN, 12f);
        setLayout(new BorderLayout());

        table = new JTable(tableModel) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                if (!isRowSelected(row)) {
                    // Whole-row accent tint while a Pipeline/Agent run is in
                    // flight — the old ⚙ text prefix in the state column
                    // alone was easy to miss.
                    int m = convertRowIndexToModel(row);
                    ApiEntry e = m >= 0 ? tableModel.getEntryAt(m) : null;
                    boolean analyzing = e != null && tableModel.isAnalyzing(e.getApiPath());
                    if (analyzing) {
                        c.setBackground(theme.accentSoft());
                    } else {
                        Color base = getBackground();
                        c.setBackground(row % 2 == 0 ? base : slightlyDarker(base));
                    }
                }
                return c;
            }
        };
        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(false);
        table.setRowHeight(26);
        table.setShowHorizontalLines(true);
        table.setShowVerticalLines(false);
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setAutoCreateRowSorter(false);
        rowSorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(rowSorter);
        table.setFont(SANS_PLAIN_12);

        TableColumnModel cm = table.getColumnModel();

        // --- Col 0: 方法 ---
        setupCol(cm, COL_METHOD, 60, 80, 100, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setHorizontalAlignment(CENTER);
                setFont(MONOSPACED_BOLD_11);
                if (!s && v != null) {
                    String m = v.toString();
                    if (m.contains("GET")) setForeground(theme.methodGet());
                    else if (m.contains("POST")) setForeground(theme.methodPost());
                    else if (m.contains("DELETE")) setForeground(theme.methodDelete());
                    else if (m.contains("PUT")) setForeground(theme.methodPut());
                    else setForeground(t.getForeground());
                }
                return this;
            }
        });

        // --- Col 1: 接口路径 ---
        setupCol(cm, COL_PATH, 200, 320, -1, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setFont(MONOSPACED_PLAIN_12);
                return this;
            }
        });

        // --- Col 2: 域名 ---
        setupCol(cm, COL_DOMAIN, 80, 140, 220, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setFont(SANS_ITALIC_11);
                if (!s) setForeground(theme.mutedText());
                return this;
            }
        });

        // --- Col 3: 响应码 ---
        setupCol(cm, COL_STATUS_CODE, 42, 55, 65, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setHorizontalAlignment(CENTER);
                setFont(SANS_BOLD_11);
                if (!s && v != null) {
                    String code = v.toString();
                    if ("--".equals(code)) setForeground(theme.mutedText());
                    else if (code.startsWith("2")) setForeground(theme.riskSafe());
                    else if (code.startsWith("3")) setForeground(theme.redirectColor());
                    else if (code.startsWith("4")) setForeground(theme.riskMedium());
                    else if (code.startsWith("5")) setForeground(theme.riskHigh());
                    else setForeground(t.getForeground());
                }
                return this;
            }
        });

        // --- Col 4: 风险 ---
        setupCol(cm, COL_RISK, 50, 68, 80, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setHorizontalAlignment(CENTER);
                setFont(SANS_BOLD_11);
                if (!s && v != null) {
                    String risk = v.toString();
                    // Geometric markers (▲◆●✓), not colored emoji — emoji render
                    // at inconsistent sizes/baselines across OS fonts and clash
                    // with the 状态 column's own geometric glyphs (○◐●✖), which
                    // is exactly the "two icon languages in one table" mismatch.
                    switch (risk) {
                        case "HIGH"   -> { setForeground(theme.riskHigh()); setText("▲ HIGH"); }
                        case "MEDIUM" -> { setForeground(theme.riskMedium()); setText("◆ MED"); }
                        case "LOW"    -> { setForeground(theme.riskLow()); setText("● LOW"); }
                        case "SAFE"   -> { setForeground(theme.riskSafe()); setText("✓ SAFE"); }
                        default       -> { setForeground(theme.mutedText()); setText("--"); }
                    }
                }
                return this;
            }
        });
        // Risk column: combo-box editor for manual override
        JComboBox<String> riskCombo = new JComboBox<>(new String[]{"自动", "HIGH", "MEDIUM", "LOW", "SAFE"});
        riskCombo.setFont(SANS_PLAIN_11);
        riskCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                           boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                setFont(SANS_PLAIN_11);
                setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
                String risk = value != null ? value.toString() : "";
                setText(switch (risk) {
                    case "HIGH" -> "▲ HIGH";
                    case "MEDIUM" -> "◆ MEDIUM";
                    case "LOW" -> "● LOW";
                    case "SAFE" -> "✓ SAFE";
                    default -> "○ 自动";
                });
                if (!isSelected) {
                    setForeground(switch (risk) {
                        case "HIGH" -> theme.riskHigh();
                        case "MEDIUM" -> theme.riskMedium();
                        case "LOW" -> theme.riskLow();
                        case "SAFE" -> theme.riskSafe();
                        default -> theme.mutedText();
                    });
                }
                return this;
            }
        });
        cm.getColumn(COL_RISK).setCellEditor(new DefaultCellEditor(riskCombo));

        // --- Col 5: 发现 ---
        // Multi-line wrapping cell (same approach as 备注/COL_NOTE below) since
        // getDisplayFindings() now returns one vuln type per line instead of
        // a comma-joined, truncated single line.
        setupCol(cm, COL_FINDINGS, 45, 110, 220, null);
        cm.getColumn(COL_FINDINGS).setCellRenderer(new TableCellRenderer() {
            private final JTextArea area = new JTextArea();
            {
                area.setLineWrap(true);
                area.setWrapStyleWord(true);
                area.setFont(SANS_PLAIN_11);
                area.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
            }
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean isSelected, boolean hasFocus, int row, int col) {
                String val = v != null ? v.toString() : "";
                area.setText(val);
                area.setBackground(isSelected ? t.getSelectionBackground() : t.getBackground());
                if (isSelected) {
                    area.setForeground(t.getSelectionForeground());
                } else if ("--".equals(val)) {
                    area.setForeground(theme.mutedText());
                } else if (val.startsWith("0/0") || "0".equals(val)) {
                    area.setForeground(theme.riskSafe());
                } else {
                    area.setForeground(theme.riskHigh());
                }
                int colWidth = t.getColumnModel().getColumn(col).getWidth();
                area.setSize(colWidth, Short.MAX_VALUE);
                int prefHeight = Math.max(26, area.getPreferredSize().height + 4);
                if (t.getRowHeight(row) < prefHeight) {
                    t.setRowHeight(row, prefHeight);
                }

                int modelRow = t.convertRowIndexToModel(row);
                ApiEntry entryForTip = tableModel.getEntryAt(modelRow);
                String tip = entryForTip != null ? entryForTip.getDisplayFindingsTooltip() : null;
                area.setToolTipText(tip != null ? tip : "确认/疑似");
                return area;
            }
        });

        // --- Col 6: 被动（本地零成本检测摘要）---
        // Single-line label renderer on purpose: this column must NEVER stretch
        // row height (the disease this refactor cures) — details live in
        // PassiveFindingsDialog, opened by double-click / right-click.
        setupCol(cm, COL_PASSIVE, 70, 130, 220, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setFont(SANS_PLAIN_11);
                String val = v != null ? v.toString() : "--";
                if (!s) {
                    int modelRow = t.convertRowIndexToModel(r);
                    ApiEntry e = tableModel.getEntryAt(modelRow);
                    setToolTipText(e != null ? e.getDisplayPassiveTooltip() : null);
                    String maxRisk = e != null ? e.getMaxPassiveRisk() : "";
                    setForeground(switch (maxRisk) {
                        case "HIGH" -> theme.riskHigh();
                        case "MEDIUM" -> theme.riskMedium();
                        case "LOW" -> theme.riskLow();
                        default -> "--".equals(val) ? theme.mutedText() : t.getForeground();
                    });
                }
                return this;
            }
        });

        // --- Col 7: 状态 ---
        setupCol(cm, COL_STATE, 60, 80, 100, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setHorizontalAlignment(CENTER);
                setFont(SANS_BOLD_11);
                String status = v != null ? v.toString() : "";
                // The model prefixes "⚙ " while an analysis is in flight —
                // render that as a dedicated, unmissable state instead of
                // letting it fall through as raw prefixed text.
                boolean analyzing = status.startsWith("⚙ ");
                if (analyzing) status = status.substring(2).trim();
                if (!s) {
                    if (analyzing) {
                        setForeground(theme.accentBg());
                    } else {
                        switch (status) {
                            case "未测试"      -> setForeground(theme.mutedText());
                            case "接口测试中"   -> setForeground(theme.statusPending());
                            case "测试通过，安全" -> setForeground(theme.statusOk());
                            case "存在漏洞"     -> setForeground(theme.statusError());
                            default            -> setForeground(t.getForeground());
                        }
                    }
                }
                if (analyzing) {
                    setText("⚙ 分析中…");
                } else {
                    setText(switch (status) {
                        case "未测试"         -> "○ 未测试";
                        case "接口测试中"      -> "◐ 测试中";
                        case "待评估"          -> "◈ 待评估";
                        case "测试通过，安全"   -> "● 已通过";
                        case "存在漏洞"        -> "✖ 漏洞";
                        default              -> status;
                    });
                }
                return this;
            }
        });
        // State column: combo-box editor for free switching
        JComboBox<String> stateCombo = new JComboBox<>();
        for (ApiStatus s : ApiStatus.values()) stateCombo.addItem(s.getDisplayName());
        stateCombo.setFont(SANS_PLAIN_11);
        stateCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                           boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                setFont(SANS_PLAIN_11);
                setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
                String status = value != null ? value.toString() : "";
                setText(switch (status) {
                    case "未测试" -> "○ 未测试";
                    case "接口测试中" -> "◐ 测试中";
                    case "待评估" -> "◈ 待评估";
                    case "测试通过，安全" -> "● 已通过";
                    case "存在漏洞" -> "✖ 漏洞";
                    default -> status;
                });
                if (!isSelected) {
                    setForeground(switch (status) {
                        case "未测试" -> theme.mutedText();
                        case "接口测试中" -> theme.statusPending();
                        case "测试通过，安全" -> theme.statusOk();
                        case "存在漏洞" -> theme.statusError();
                        default -> theme.headerFg();
                    });
                }
                return this;
            }
        });
        cm.getColumn(COL_STATE).setCellEditor(new DefaultCellEditor(stateCombo));

        // --- Col 7: 流量 ---
        setupCol(cm, COL_TRAFFIC, 30, 38, 45, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setHorizontalAlignment(CENTER);
                setFont(SANS_PLAIN_11);
                if (!s && v != null) {
                    setForeground("✓".equals(v.toString()) ? theme.riskSafe() : theme.mutedText());
                }
                setToolTipText("是否已捕获真实流量");
                return this;
            }
        });

        // --- Col 8: 备注 (multi-line wrap) ---
        setupCol(cm, COL_NOTE, 80, 180, -1, null);
        cm.getColumn(COL_NOTE).setCellRenderer(new TableCellRenderer() {
            private final JTextArea area = new JTextArea();
            {
                area.setLineWrap(true);
                area.setWrapStyleWord(true);
                area.setFont(table.getFont());
                area.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
            }
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean isSelected, boolean hasFocus, int row, int col) {
                area.setText(v != null ? v.toString() : "");
                area.setBackground(isSelected ? t.getSelectionBackground() : t.getBackground());
                area.setForeground(isSelected ? t.getSelectionForeground() : t.getForeground());
                int colWidth = t.getColumnModel().getColumn(col).getWidth();
                area.setSize(colWidth, Short.MAX_VALUE);
                int prefHeight = Math.max(26, area.getPreferredSize().height + 4);
                if (t.getRowHeight(row) < prefHeight) {
                    t.setRowHeight(row, prefHeight);
                }
                return area;
            }
        });
        // Note column editor: use a JTextField with the table's font (default
        // editor uses a different font, causing visible font change on click).
        JTextField noteEditorField = new JTextField();
        noteEditorField.setFont(table.getFont());
        noteEditorField.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));
        cm.getColumn(COL_NOTE).setCellEditor(new DefaultCellEditor(noteEditorField));

        // --- Col 10: 操作 ▶ ---
        var actionCol = cm.getColumn(COL_ACTION);
        actionCol.setMinWidth(32);
        actionCol.setPreferredWidth(40);
        actionCol.setMaxWidth(50);
        actionCol.setCellRenderer(new ButtonColumnRenderer(SANS_BOLD_11));
        actionCol.setCellEditor(new ButtonColumnEditor());

        // ====================================================================
        // Right-click context menu + double-click to view findings detail
        // ====================================================================
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { handlePopup(e); }
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() != 2) return;
                int viewCol = table.columnAtPoint(e.getPoint());
                int modelCol = viewCol >= 0 ? table.convertColumnIndexToModel(viewCol) : -1;
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                if (modelCol == COL_PASSIVE) {
                    if (onViewPassive != null) onViewPassive.accept(table.convertRowIndexToModel(viewRow));
                    return;
                }
                if (onViewFindings == null) return;
                if (modelCol != COL_FINDINGS && modelCol != COL_RISK) return;
                onViewFindings.accept(table.convertRowIndexToModel(viewRow));
            }
            private void handlePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int rowAtPoint = table.rowAtPoint(e.getPoint());
                if (rowAtPoint >= 0 && !table.isRowSelected(rowAtPoint)) {
                    table.setRowSelectionInterval(rowAtPoint, rowAtPoint);
                }
                if (table.getSelectedRowCount() > 0) {
                    buildPopupMenu().show(table, e.getX(), e.getY());
                }
            }
        });

        // ====================================================================
        // Keyboard shortcuts
        // ====================================================================
        InputMap im = table.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = table.getActionMap();

        // Delete / Backspace → delete selected rows
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteRows");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "deleteRows");
        am.put("deleteRows", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                if (onDeleteRows != null && table.getSelectedRowCount() > 0) {
                    onDeleteRows.accept(getSelectedRows());
                }
            }
        });

        // Enter → analyze selected row
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "analyzeRow");
        am.put("analyzeRow", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                if (onAnalyzeRow != null && table.getSelectedRowCount() == 1) {
                    onAnalyzeRow.accept(getSelectedRows()[0]);
                }
            }
        });

        // Ctrl/Cmd+C → copy API paths
        int metaKey = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, metaKey), "copyPaths");
        am.put("copyPaths", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { copySelectedPaths(); }
        });

        // Ctrl/Cmd+A → select all
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, metaKey), "selectAll");
        am.put("selectAll", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { table.selectAll(); }
        });

        // ====================================================================
        // Bottom: row count label
        // ====================================================================
        rowCountLabel = new JLabel(" ");
        rowCountLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        rowCountLabel.setForeground(new Color(120, 120, 120));
        rowCountLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));

        // Update count when data or filter changes
        tableModel.addTableModelListener(e -> updateRowCount());
        rowSorter.addRowSorterListener(e -> updateRowCount());
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateRowCount();
        });

        add(new JScrollPane(table), BorderLayout.CENTER);
        add(rowCountLabel, BorderLayout.SOUTH);

        updateRowCount();
    }

    // ====================================================================
    // Right-click context menu builder (native style)
    // ====================================================================
    private JPopupMenu buildPopupMenu() {
        JPopupMenu menu = new JPopupMenu();
        int[] selected = getSelectedRows();
        int count = selected.length;
        String suffix = count > 1 ? "  (" + count + ")" : "";

        JMenuItem selectAllItem = new JMenuItem("全选可见行  (" + table.getRowCount() + ")");
        selectAllItem.addActionListener(e -> table.selectAll());
        menu.add(selectAllItem);
        menu.addSeparator();

        JMenuItem analyzeItem = new JMenuItem("AI 分析" + suffix);
        analyzeItem.addActionListener(e -> {
            if (onAnalyzeRow != null) {
                for (int row : selected) onAnalyzeRow.accept(row);
            }
        });
        menu.add(analyzeItem);

        JMenuItem aiChatItem = new JMenuItem("AI 对话分析");
        aiChatItem.setEnabled(count == 1);
        aiChatItem.addActionListener(e -> {
            if (onAiChat != null && count == 1) onAiChat.accept(selected[0]);
        });
        menu.add(aiChatItem);

        JMenuItem trafficItem = new JMenuItem("查看历史流量");
        trafficItem.addActionListener(e -> {
            if (onViewTraffic != null) onViewTraffic.accept(selected);
        });
        menu.add(trafficItem);

        JMenuItem findingsItem = new JMenuItem("查看发现详情");
        findingsItem.setEnabled(count == 1);
        findingsItem.addActionListener(e -> {
            if (onViewFindings != null && count == 1) onViewFindings.accept(selected[0]);
        });
        menu.add(findingsItem);

        JMenuItem passiveItem = new JMenuItem("查看被动检测详情");
        passiveItem.setEnabled(count == 1);
        passiveItem.addActionListener(e -> {
            if (onViewPassive != null && count == 1) onViewPassive.accept(selected[0]);
        });
        menu.add(passiveItem);

        JMenuItem organizerItem = new JMenuItem("发送到 Organizer" + suffix);
        organizerItem.addActionListener(e -> {
            if (onSendToOrganizer != null) onSendToOrganizer.accept(selected);
        });
        menu.add(organizerItem);

        menu.addSeparator();

        JMenuItem copyItem = new JMenuItem("复制 API 路径" + suffix);
        int metaMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        copyItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, metaMask));
        copyItem.addActionListener(e -> copySelectedPaths());
        menu.add(copyItem);

        JMenuItem safeItem = new JMenuItem("标记为安全" + suffix);
        safeItem.addActionListener(e -> {
            if (onMarkSafe != null) onMarkSafe.accept(selected);
        });
        menu.add(safeItem);

        menu.addSeparator();

        JMenuItem deleteItem = new JMenuItem("删除" + suffix);
        deleteItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0));
        deleteItem.addActionListener(e -> {
            if (onDeleteRows != null) onDeleteRows.accept(selected);
        });
        menu.add(deleteItem);

        return menu;
    }

    // ====================================================================
    // Copy selected API paths to clipboard
    // ====================================================================
    private void copySelectedPaths() {
        int[] rows = getSelectedRows();
        if (rows.length == 0) return;
        String paths = IntStream.of(rows)
                .mapToObj(tableModel::getEntryAt)
                .filter(java.util.Objects::nonNull)
                .map(entry -> {
                    String method = entry.getHttpMethod();
                    String path = entry.getApiPath();
                    return (method != null && !method.isEmpty()) ? method + " " + path : path;
                })
                .collect(Collectors.joining("\n"));
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(paths), null);
    }

    // ====================================================================
    // Row count indicator
    // ====================================================================
    private void updateRowCount() {
        int totalModel = tableModel.getRowCount();
        int visibleView = table.getRowCount(); // after RowFilter
        int selectedCount = table.getSelectedRowCount();

        StringBuilder sb = new StringBuilder();
        if (visibleView < totalModel) {
            sb.append(String.format("显示 %d / %d 条", visibleView, totalModel));
        } else {
            sb.append(String.format("共 %d 条", totalModel));
        }
        if (selectedCount > 0) {
            sb.append(String.format("  |  已选 %d 条", selectedCount));
        }
        rowCountLabel.setText(sb.toString());
    }

    /** Helper: set min/pref/max width + optional renderer for a column. */
    private void setupCol(TableColumnModel cm, int idx, int min, int pref, int max,
                           DefaultTableCellRenderer renderer) {
        var col = cm.getColumn(idx);
        col.setMinWidth(min);
        col.setPreferredWidth(pref);
        if (max > 0) col.setMaxWidth(max);
        if (renderer != null) col.setCellRenderer(renderer);
    }

    private static Color slightlyDarker(Color base) {
        float[] hsb = Color.RGBtoHSB(base.getRed(), base.getGreen(), base.getBlue(), null);
        if (hsb[2] < 0.5f) {
            hsb[2] = Math.min(1.0f, hsb[2] + 0.03f);
        } else {
            hsb[2] = Math.max(0.0f, hsb[2] - 0.03f);
        }
        return Color.getHSBColor(hsb[0], hsb[1], hsb[2]);
    }

    // === Callback setters ===
    public void setOnAnalyzeRow(IntConsumer callback) { this.onAnalyzeRow = callback; }
    public void setOnAiChat(IntConsumer callback) { this.onAiChat = callback; }
    public void setOnDeleteRows(Consumer<int[]> callback) { this.onDeleteRows = callback; }
    public void setOnMarkSafe(Consumer<int[]> callback) { this.onMarkSafe = callback; }
    public void setOnViewTraffic(Consumer<int[]> callback) { this.onViewTraffic = callback; }
    public void setOnViewFindings(IntConsumer callback) { this.onViewFindings = callback; }
    public void setOnViewPassive(IntConsumer callback) { this.onViewPassive = callback; }
    public void setOnSendToOrganizer(Consumer<int[]> callback) { this.onSendToOrganizer = callback; }

    public JTable getTable() { return table; }

    public ApiEntryTableModel getTableModel() { return tableModel; }

    public int[] getSelectedRows() {
        int[] viewRows = table.getSelectedRows();
        int[] modelRows = new int[viewRows.length];
        for (int i = 0; i < viewRows.length; i++) {
            modelRows[i] = table.convertRowIndexToModel(viewRows[i]);
        }
        return modelRows;
    }

    public void selectAndScrollTo(int modelRow) {
        if (modelRow >= 0 && modelRow < tableModel.getRowCount()) {
            try {
                int viewRow = table.convertRowIndexToView(modelRow);
                if (viewRow >= 0) {
                    table.setRowSelectionInterval(viewRow, viewRow);
                    table.scrollRectToVisible(table.getCellRect(viewRow, 0, true));
                }
            } catch (IndexOutOfBoundsException ignored) {}
        }
    }

    public void setSearchFilter(String text) {
        if (text == null || text.isEmpty()) {
            rowSorter.setRowFilter(null);
        } else {
            // Search method (0), path (1), domain (2), note (8)
            rowSorter.setRowFilter(RowFilter.regexFilter(
                    "(?i)" + Pattern.quote(text), COL_METHOD, COL_PATH, COL_DOMAIN, COL_NOTE));
        }
    }

    public void clearSelection() { table.clearSelection(); }

    // --- Button column renderer ---
    private static class ButtonColumnRenderer extends JButton implements TableCellRenderer {
        ButtonColumnRenderer(Font font) {
            setOpaque(true);
            setFont(font);
        }
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            setText(value != null ? value.toString() : "▶");
            setBackground(isSelected ? table.getSelectionBackground() : UIManager.getColor("Button.background"));
            return this;
        }
    }

    // --- Button column editor ---
    private class ButtonColumnEditor extends AbstractCellEditor implements TableCellEditor, ActionListener {
        private final JButton button;
        private int editingRow;

        ButtonColumnEditor() {
            button = new JButton("▶");
            button.setFont(SANS_BOLD_11);
            button.addActionListener(this);
        }
        @Override
        public Component getTableCellEditorComponent(JTable table, Object value,
                                                     boolean isSelected, int row, int column) {
            editingRow = table.convertRowIndexToModel(row);
            button.setText(value != null ? value.toString() : "▶");
            return button;
        }
        @Override public Object getCellEditorValue() { return "▶"; }
        @Override
        public void actionPerformed(ActionEvent e) {
            fireEditingStopped();
            if (onAnalyzeRow != null) onAnalyzeRow.accept(editingRow);
        }
    }
}
