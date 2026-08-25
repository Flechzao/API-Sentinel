package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.UrlUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Dialog that shows all Proxy History items matching a given API entry.
 * Uses Burp Suite's native HttpRequestEditor / HttpResponseEditor for
 * authentic request/response display.
 */
public class HistoryTrafficDialog extends JDialog {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final MontoyaApi api;
    private final BurpTheme theme;
    private final DefaultTableModel listModel;
    private final JTable listTable;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JLabel statusLabel;

    /** Cached matched history items (parallel to table rows). */
    private final List<ProxyHttpRequestResponse> matchedItems = new ArrayList<>();

    /** Callback to push extracted Cookie into AuthConfigPanel: (slot, cookie) → void. */
    private BiConsumer<String, String> onExtractSession;

    public HistoryTrafficDialog(Window owner, MontoyaApi api, ApiEntry entry) {
        super(owner, "历史流量 — " + entry.getHttpMethod() + " " + entry.getApiPath(),
                ModalityType.MODELESS);
        this.api = api;
        this.theme = new BurpTheme(api);
        setSize(1000, 620);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout(0, 0));
        theme.apply(this);

        // ── Top info bar ──────────────────────────────────
        JPanel infoBar = new JPanel(new BorderLayout(8, 0));
        infoBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        JLabel pathLabel = new JLabel(entry.getHttpMethod() + "  " + entry.getApiPath());
        pathLabel.setFont(theme.editorFont(13f).deriveFont(Font.BOLD));
        infoBar.add(pathLabel, BorderLayout.WEST);
        statusLabel = new JLabel("扫描中...");
        statusLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        statusLabel.setForeground(theme.mutedText());
        infoBar.add(statusLabel, BorderLayout.EAST);
        add(infoBar, BorderLayout.NORTH);

        // ── Request list table ────────────────────────────
        listModel = new DefaultTableModel(
                new String[]{"#", "Method", "URL", "Status", "Length", "Time"}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        listTable = new JTable(listModel);
        listTable.setRowHeight(22);
        listTable.setFont(theme.displayFont(Font.PLAIN, 11f));
        listTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        listTable.setShowVerticalLines(false);

        TableColumnModel cm = listTable.getColumnModel();
        cm.getColumn(0).setPreferredWidth(40);   // #
        cm.getColumn(0).setMaxWidth(50);
        cm.getColumn(1).setPreferredWidth(60);   // Method
        cm.getColumn(1).setMaxWidth(80);
        cm.getColumn(2).setPreferredWidth(400);  // URL
        cm.getColumn(3).setPreferredWidth(55);   // Status
        cm.getColumn(3).setMaxWidth(65);
        cm.getColumn(4).setPreferredWidth(70);   // Length
        cm.getColumn(4).setMaxWidth(90);
        cm.getColumn(5).setPreferredWidth(70);   // Time
        cm.getColumn(5).setMaxWidth(80);

        // Method color renderer
        cm.getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setFont(theme.displayFont(Font.BOLD, 11f));
                setHorizontalAlignment(CENTER);
                if (!s && v != null) {
                    setForeground(switch (v.toString()) {
                        case "GET" -> theme.methodGet();
                        case "POST" -> theme.methodPost();
                        case "DELETE" -> theme.methodDelete();
                        case "PUT", "PATCH" -> theme.methodPut();
                        default -> t.getForeground();
                    });
                }
                return this;
            }
        });

        // Status code color renderer
        cm.getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setFont(theme.displayFont(Font.BOLD, 11f));
                setHorizontalAlignment(CENTER);
                if (!s && v != null) {
                    String code = v.toString();
                    if (code.startsWith("2")) setForeground(theme.riskSafe());
                    else if (code.startsWith("3")) setForeground(theme.redirectColor());
                    else if (code.startsWith("4")) setForeground(theme.riskMedium());
                    else if (code.startsWith("5")) setForeground(theme.riskHigh());
                    else setForeground(t.getForeground());
                }
                return this;
            }
        });

        // URL monospaced
        cm.getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setFont(theme.editorFont(12f));
                return this;
            }
        });

        JScrollPane listScroll = new JScrollPane(listTable);
        listScroll.setPreferredSize(new Dimension(0, 180));

        // ── Burp native request/response editors ──────────
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        reqPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBorder(BorderFactory.createTitledBorder("Response"));
        respPanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        editorSplit.setResizeWeight(0.5);
        editorSplit.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean init = false;
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                if (!init && editorSplit.getWidth() > 0) {
                    init = true;
                    editorSplit.setDividerLocation(0.5);
                }
            }
        });

        // ── Main split: list (top) | editors (bottom) ────
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, listScroll, editorSplit);
        mainSplit.setDividerLocation(200);
        mainSplit.setResizeWeight(0.3);
        add(mainSplit, BorderLayout.CENTER);

        // ── Selection listener: show request/response ─────
        listTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = listTable.getSelectedRow();
            if (row >= 0 && row < matchedItems.size()) {
                showItem(matchedItems.get(row));
            }
        });

        // ── Right-click context menu on traffic list ──────
        listTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { showPopup(e); }
            @Override public void mouseReleased(MouseEvent e) { showPopup(e); }
            private void showPopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = listTable.rowAtPoint(e.getPoint());
                if (row >= 0) listTable.setRowSelectionInterval(row, row);
                JPopupMenu popup = buildTrafficPopup();
                if (popup != null) popup.show(listTable, e.getX(), e.getY());
            }
        });

        // ── Bottom button bar ─────────────────────────────
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton sendToRepeater = new JButton("→ Repeater");
        sendToRepeater.setFont(theme.displayFont(Font.PLAIN, 11f));
        sendToRepeater.setToolTipText("将选中请求发送到 Burp Repeater");
        sendToRepeater.addActionListener(e -> sendSelectedToRepeater());
        bottomBar.add(sendToRepeater);

        JButton closeBtn = new JButton("关闭");
        closeBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        closeBtn.addActionListener(e -> dispose());
        bottomBar.add(closeBtn);
        add(bottomBar, BorderLayout.SOUTH);

        // ── Apply Burp theme ──────────────────────────────
        try { api.userInterface().applyThemeToComponent(this); } catch (Exception ignored) {}

        // ── Start scanning in background ──────────────────
        scanHistoryForEntry(entry);
    }

    /** Set callback for extracting session cookies from traffic. */
    public void setOnExtractSession(BiConsumer<String, String> callback) {
        this.onExtractSession = callback;
    }

    private JPopupMenu buildTrafficPopup() {
        int row = listTable.getSelectedRow();
        if (row < 0 || row >= matchedItems.size()) return null;

        JPopupMenu menu = new JPopupMenu();

        JMenuItem repeaterItem = new JMenuItem("发送到 Repeater");
        repeaterItem.addActionListener(e -> sendSelectedToRepeater());
        menu.add(repeaterItem);

        menu.addSeparator();

        JMenuItem extractA = new JMenuItem("提取为会话 A");
        extractA.addActionListener(e -> extractSessionFromRow(row, "A"));
        menu.add(extractA);

        JMenuItem extractB = new JMenuItem("提取为会话 B");
        extractB.addActionListener(e -> extractSessionFromRow(row, "B"));
        menu.add(extractB);

        return menu;
    }

    private void extractSessionFromRow(int row, String slot) {
        if (row < 0 || row >= matchedItems.size()) return;
        ProxyHttpRequestResponse item = matchedItems.get(row);
        String cookie = extractCookieFromItem(item);
        if (cookie == null || cookie.isBlank()) {
            statusLabel.setText("该请求没有 Cookie");
            statusLabel.setForeground(theme.statusPending());
            return;
        }
        if (onExtractSession != null) {
            onExtractSession.accept(slot, cookie);
        }
        statusLabel.setText("已提取到会话 " + slot);
        statusLabel.setForeground(theme.statusOk());
    }

    private String extractCookieFromItem(ProxyHttpRequestResponse item) {
        if (item == null || item.finalRequest() == null) return null;
        for (var header : item.finalRequest().headers()) {
            if ("cookie".equalsIgnoreCase(header.name())) {
                return header.value();
            }
        }
        return null;
    }

    /**
     * Scan proxy history in a background thread and populate the table.
     */
    private void scanHistoryForEntry(ApiEntry entry) {
        com.flechazo.apisentinel.util.SharedTaskPool.submitInteractive(() -> {
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                List<Object[]> rows = new ArrayList<>();
                List<ProxyHttpRequestResponse> matched = new ArrayList<>();
                int seq = 0;

                for (ProxyHttpRequestResponse item : history) {
                    try {
                        String url = item.finalRequest().url();
                        String urlPath = UrlUtils.extractPath(url);
                        if (UrlUtils.isStaticResource(urlPath)) continue;

                        if (UrlUtils.pathsLikelyMatch(entry.getApiPath(), urlPath)) {
                            String method = item.finalRequest().method();
                            if ("OPTIONS".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method)) continue;
                            seq++;
                            int statusCode = item.response() != null ? item.response().statusCode() : 0;
                            int length = item.response() != null ? item.response().body().length() : 0;

                            // Try to get timestamp
                            String timeStr = "";
                            try {
                                // Use annotation time or current time as fallback
                                timeStr = TIME_FMT.format(Instant.now());
                            } catch (Exception ignored) {}

                            rows.add(new Object[]{
                                    seq,
                                    method,
                                    url,
                                    statusCode > 0 ? String.valueOf(statusCode) : "--",
                                    formatLength(length),
                                    timeStr
                            });
                            matched.add(item);
                        }
                    } catch (Exception ignored) {}
                }

                final int total = seq;
                SwingUtilities.invokeLater(() -> {
                    matchedItems.clear();
                    matchedItems.addAll(matched);
                    listModel.setRowCount(0);
                    for (Object[] row : rows) {
                        listModel.addRow(row);
                    }
                    statusLabel.setText(String.format("共 %d 条匹配记录（History 总计 %d 条）",
                            total, history.size()));
                    statusLabel.setForeground(total > 0 ? theme.statusOk() : theme.statusPending());

                    // Auto-select first row
                    if (total > 0) {
                        listTable.setRowSelectionInterval(0, 0);
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("扫描失败: " + ex.getMessage());
                    statusLabel.setForeground(theme.statusError());
                });
            }
        });
    }

    /**
     * Display the selected history item in Burp's native editors.
     */
    private void showItem(ProxyHttpRequestResponse item) {
        try {
            requestEditor.setRequest(item.finalRequest());
        } catch (Exception e) {
            try {
                requestEditor.setRequest(HttpRequest.httpRequest(item.finalRequest().toString()));
            } catch (Exception ignored) {}
        }

        if (item.response() != null) {
            try {
                responseEditor.setResponse(item.response());
            } catch (Exception e) {
                try {
                    responseEditor.setResponse(HttpResponse.httpResponse(item.response().toString()));
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Send the currently selected request to Burp's native Repeater.
     */
    private void sendSelectedToRepeater() {
        int row = listTable.getSelectedRow();
        if (row < 0 || row >= matchedItems.size()) {
            statusLabel.setText("请先选择一条记录");
            statusLabel.setForeground(theme.statusPending());
            return;
        }
        try {
            ProxyHttpRequestResponse item = matchedItems.get(row);
            HttpRequest request = item.finalRequest();
            String path = "/";
            try { path = request.path(); } catch (Exception ignored) {}
            api.repeater().sendToRepeater(request, "Sentinel: " + path);
            statusLabel.setText("→ 已发送到 Burp Repeater");
            statusLabel.setForeground(theme.redirectColor());
        } catch (Exception ex) {
            statusLabel.setText("发送失败: " + ex.getMessage());
            statusLabel.setForeground(theme.statusError());
        }
    }

    private static String formatLength(int length) {
        if (length < 1024) return length + " B";
        if (length < 1024 * 1024) return String.format("%.1f KB", length / 1024.0);
        return String.format("%.1f MB", length / (1024.0 * 1024));
    }
}
