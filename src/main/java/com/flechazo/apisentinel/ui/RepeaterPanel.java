package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.flechazo.apisentinel.testgen.model.TestCase;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Built-in Repeater panel aligned with Burp Suite's native Repeater layout.
 * Uses Burp's HttpRequestEditor / HttpResponseEditor for full HTTP message display.
 *
 * Layout:
 *   Top:    Payload table (test case list)
 *   Middle: Toolbar — [发送] [→ Repeater] [⇋ Comparer] [Sentinel 分析]  status
 *   Bottom: Horizontal split — Request editor (left) | Response editor (right)
 */
/** 内嵌 Repeater 面板——测试用例表 + payload 实测结果 + Send 重发，支持跨重启持久化。 */
public class RepeaterPanel extends JPanel {

    private final MontoyaApi api;
    private final DefaultTableModel payloadModel;
    private final JTable payloadTable;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JButton sendButton;
    private final JLabel statusLabel;
    private Runnable onAiChatRequested;

    // Payload-list collapse/expand (give Request/Response more vertical room
    // without needing to drag the divider every time).
    private JSplitPane payloadSplit;
    private int expandedListHeight = 150;
    private boolean listCollapsed = false;
    private static final int COLLAPSED_LIST_HEIGHT = 32;

    private final List<TestCase> testCases = new ArrayList<>();
    private final List<com.flechazo.apisentinel.auth.AuthTestRound> authTestRounds = new ArrayList<>();
    private int authTestRowOffset = -1;
    private String currentHost = "";
    private boolean currentUseHttps = true;
    private volatile String baselineResponse = null;
    private boolean addingFollowUp = false;
    private volatile boolean agentResultApplied = false;
    private String currentEntryPath = null;

    // Cache sent requests/responses per test case index for display
    private final Map<Integer, String> sentRequestCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<Integer, String> receivedResponseCache = new java.util.concurrent.ConcurrentHashMap<>();

    // Per-entry cache for test cases and results. Bounded LRU (access order):
    // a long Burp session visits arbitrarily many entries, and the old
    // unbounded map kept every visited entry's state alive forever.
    private static final int MAX_ENTRY_STATE_CACHE = 200;
    private final Map<String, EntryRepeaterState> entryStateCache =
            java.util.Collections.synchronizedMap(
                    new java.util.LinkedHashMap<String, EntryRepeaterState>(64, 0.75f, true) {
                        @Override
                        protected boolean removeEldestEntry(Map.Entry<String, EntryRepeaterState> eldest) {
                            return size() > MAX_ENTRY_STATE_CACHE;
                        }
                    });

    private record EntryRepeaterState(
            List<TestCase> testCases,
            List<String[]> tableRows,
            String host,
            boolean useHttps,
            Map<Integer, String> sentCache,
            Map<Integer, String> receivedCache
    ) {}

    public RepeaterPanel(MontoyaApi api) {
        this.api = api;
        BurpTheme theme = new BurpTheme(api);
        setLayout(new BorderLayout(0, 0));

        // Create Burp-native HTTP editors
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // === TOP: Payload table ===
        payloadModel = new DefaultTableModel(new String[]{"名称", "类别", "目标参数", "Payload", "验证结果", "响应码", "响应大小"}, 0) {
            // Allow editing name/category/target/payload so users can tweak
            // auto-generated cases or add their own; 验证结果/响应码/响应大小 are
            // computed by the verification flow and stay read-only.
            @Override public boolean isCellEditable(int row, int col) { return col < 4; }
        };
        payloadTable = new JTable(payloadModel);
        payloadTable.setRowHeight(22);
        payloadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        payloadTable.getColumnModel().getColumn(0).setPreferredWidth(180);
        payloadTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        payloadTable.getColumnModel().getColumn(2).setPreferredWidth(100);
        payloadTable.getColumnModel().getColumn(3).setPreferredWidth(250);
        payloadTable.getColumnModel().getColumn(4).setPreferredWidth(90);
        payloadTable.getColumnModel().getColumn(5).setPreferredWidth(58);
        payloadTable.getColumnModel().getColumn(6).setPreferredWidth(72);
        payloadTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                setHorizontalAlignment(CENTER);
                if (!s && v != null) {
                    String text = v.toString();
                    if (text.contains("无风险")) setForeground(new Color(120, 120, 120));
                    else if (text.contains("HIGH") || text.contains("已确认")) setForeground(Color.RED);
                    else if (text.contains("MEDIUM")) setForeground(new Color(200, 130, 0));
                    else if (text.contains("异常")) setForeground(new Color(200, 0, 0));
                    else if (text.equals("待验证")) setForeground(new Color(150, 150, 150));
                    else setForeground(getForeground());
                }
                return this;
            }
        });
        payloadTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !addingFollowUp) {
                int row = payloadTable.getSelectedRow();
                if (row >= 0 && authTestRowOffset >= 0 && row >= authTestRowOffset) {
                    int authIdx = row - authTestRowOffset;
                    if (authIdx >= 0 && authIdx < authTestRounds.size()) {
                        loadAuthTestRoundIntoEditors(authTestRounds.get(authIdx));
                    }
                } else if (row >= 0 && row < testCases.size()) {
                    loadTestCaseIntoRequest(row, testCases.get(row));
                } else if (row >= testCases.size()) {
                    loadFollowUpFromCache(row);
                }
            }
        });

        JScrollPane payloadScroll = new JScrollPane(payloadTable);

        // Row-number gutter: DefaultTableModel has no "computed" column, and
        // the table already has scattered addRow() call sites (loadTestCases,
        // follow-up rows, auth-test rows, manual "+ 添加测试用例") — retrofitting
        // a real leading "#" column would mean shifting every hardcoded column
        // index (验证结果 is column 4) at every one of those sites. A JList row
        // header avoids all of that: it just mirrors the table's row count.
        DefaultListModel<Integer> rowHeaderModel = new DefaultListModel<>();
        Runnable syncRowHeaderSize = () -> {
            int rows = payloadModel.getRowCount();
            while (rowHeaderModel.size() < rows) rowHeaderModel.addElement(rowHeaderModel.size() + 1);
            while (rowHeaderModel.size() > rows) rowHeaderModel.removeElementAt(rowHeaderModel.size() - 1);
        };
        syncRowHeaderSize.run();

        JList<Integer> rowHeader = new JList<>(rowHeaderModel);
        rowHeader.setFixedCellWidth(32);
        rowHeader.setFixedCellHeight(payloadTable.getRowHeight());
        rowHeader.setBackground(UIManager.getColor("Panel.background"));

        payloadModel.addTableModelListener(e -> {
            syncRowHeaderSize.run();
            rowHeader.setFixedCellHeight(payloadTable.getRowHeight());
            rowHeader.revalidate();
            rowHeader.repaint();
        });
        rowHeader.setCellRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                    boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                setHorizontalAlignment(CENTER);
                setForeground(new Color(140, 140, 140));
                setBorder(BorderFactory.createEmptyBorder());
                return this;
            }
        });
        // Keep the highlighted row number in sync with the table's own selection.
        payloadTable.getSelectionModel().addListSelectionListener(e -> {
            int sel = payloadTable.getSelectedRow();
            if (sel >= 0 && sel < rowHeaderModel.size()) rowHeader.setSelectedIndex(sel);
            else rowHeader.clearSelection();
        });
        payloadScroll.setRowHeaderView(rowHeader);

        // The row-number gutter had no header cell of its own in the corner
        // above it (JScrollPane leaves UPPER_LEFT_CORNER empty by default
        // even with both a row header and a column header present) — a bare
        // "#" label there makes it read as a real numbered column instead of
        // an unlabeled strip down the left edge.
        JLabel rowHeaderCorner = new JLabel("#", SwingConstants.CENTER);
        rowHeaderCorner.setFont(payloadTable.getTableHeader().getFont());
        rowHeaderCorner.setOpaque(true);
        rowHeaderCorner.setBackground(payloadTable.getTableHeader().getBackground());
        rowHeaderCorner.setForeground(payloadTable.getTableHeader().getForeground());
        rowHeaderCorner.setBorder(UIManager.getBorder("TableHeader.cellBorder"));
        payloadScroll.setCorner(JScrollPane.UPPER_LEFT_CORNER, rowHeaderCorner);

        JPanel payloadListPanel = new JPanel(new BorderLayout());
        JPanel payloadListHeader = new JPanel(new BorderLayout());
        JLabel payloadListTitle = new JLabel(" 测试用例列表");
        payloadListTitle.setFont(theme.displayFont(Font.BOLD, 12f));
        payloadListHeader.add(payloadListTitle, BorderLayout.WEST);
        JButton collapseListBtn = new JButton("▲ 折叠");
        collapseListBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        collapseListBtn.setMargin(new Insets(1, 6, 1, 6));
        collapseListBtn.setFocusPainted(false);
        collapseListBtn.setToolTipText("收起/展开测试用例列表，给 Request/Response 腾出更多空间");
        JPanel payloadListHeaderRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        payloadListHeaderRight.add(collapseListBtn);
        payloadListHeader.add(payloadListHeaderRight, BorderLayout.EAST);
        payloadListHeader.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")));
        payloadListPanel.add(payloadListHeader, BorderLayout.NORTH);
        payloadListPanel.add(payloadScroll, BorderLayout.CENTER);

        // === MIDDLE: Toolbar (like Burp native Repeater top bar) ===
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        toolbar.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, UIManager.getColor("Separator.foreground")));

        sendButton = new JButton("Send");
        sendButton.setFont(theme.displayFont(Font.BOLD, 13f));
        sendButton.setFocusPainted(false);
        sendButton.setPreferredSize(new Dimension(80, 28));
        sendButton.addActionListener(e -> sendRequest());
        toolbar.add(sendButton);

        toolbar.add(Box.createHorizontalStrut(8));

        JButton toBurpRepeater = new JButton("→ Repeater");
        toBurpRepeater.setFont(theme.displayFont(Font.PLAIN, 11f));
        toBurpRepeater.setToolTipText("发送到 Burp 原生 Repeater");
        toBurpRepeater.addActionListener(e -> sendToBurpNativeRepeater());
        toolbar.add(toBurpRepeater);

        JButton toComparer = new JButton("⇋ Comparer");
        toComparer.setFont(theme.displayFont(Font.PLAIN, 11f));
        toComparer.setToolTipText("发送基线 + 当前响应到 Comparer 对比");
        toComparer.addActionListener(e -> sendToComparer());
        toolbar.add(toComparer);

        JButton addCaseBtn = new JButton("+ 添加测试用例");
        addCaseBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        addCaseBtn.setToolTipText("手动添加一个测试用例行（可编辑名称/参数/Payload）");
        addCaseBtn.addActionListener(e -> {
            payloadModel.addRow(new Object[]{"新测试用例", "手动", "", "", "待验证", "", ""});
            int r = payloadModel.getRowCount() - 1;
            payloadTable.setRowSelectionInterval(r, r);
        });
        toolbar.add(addCaseBtn);

        toolbar.add(Box.createHorizontalStrut(8));
        JButton aiChatBtn = new JButton("AI");
        aiChatBtn.setFont(theme.displayFont(Font.BOLD, 11f));
        aiChatBtn.setFocusPainted(false);
        aiChatBtn.setToolTipText("打开 AI 对话分析当前请求");
        aiChatBtn.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        aiChatBtn.addActionListener(e -> { if (onAiChatRequested != null) onAiChatRequested.run(); });
        toolbar.add(aiChatBtn);

        toolbar.add(Box.createHorizontalStrut(16));
        statusLabel = new JLabel(" ");
        statusLabel.setFont(theme.displayFont(Font.ITALIC, 11f));
        toolbar.add(statusLabel);

        // === BOTTOM: Request | Response horizontal split ===
        Component requestComponent = requestEditor.uiComponent();
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestComponent, BorderLayout.CENTER);

        Component responseComponent = responseEditor.uiComponent();
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseComponent, BorderLayout.CENTER);

        JSplitPane httpSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        httpSplit.setResizeWeight(0.5);
        // Delay divider positioning until the component is actually sized
        httpSplit.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean initialized = false;
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                if (!initialized && httpSplit.getWidth() > 0) {
                    initialized = true;
                    httpSplit.setDividerLocation(0.5);
                }
            }
        });

        // === Assemble: payload table (top) | toolbar | editors (bottom) ===
        JPanel bottomPanel = new JPanel(new BorderLayout(0, 0));
        bottomPanel.add(toolbar, BorderLayout.NORTH);
        bottomPanel.add(httpSplit, BorderLayout.CENTER);

        payloadSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, payloadListPanel, bottomPanel);
        payloadSplit.setDividerLocation(expandedListHeight);
        payloadSplit.setResizeWeight(0.2);
        add(payloadSplit, BorderLayout.CENTER);

        collapseListBtn.addActionListener(e -> {
            if (!listCollapsed) {
                expandedListHeight = payloadSplit.getDividerLocation();
                payloadSplit.setDividerLocation(COLLAPSED_LIST_HEIGHT);
                collapseListBtn.setText("▼ 展开");
            } else {
                payloadSplit.setDividerLocation(expandedListHeight);
                collapseListBtn.setText("▲ 折叠");
            }
            listCollapsed = !listCollapsed;
        });

        // Apply Burp LAF to all components
        theme.apply(this);

        // Initial template
        setRequestFromRaw("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com");
    }

    // ======================== Public API ========================

    /** True when the panel currently displays the given entry's state — lets
     *  async producers (e.g. BatchOrchestrator's auto test-case generation)
     *  skip UI writes that would otherwise land on whatever entry the user
     *  switched to in the meantime. */
    public boolean isShowingEntry(String path) {
        return path != null && path.equals(currentEntryPath);
    }

    /** An entry's analysis records were deleted: always drop the cached
     *  Repeater state (otherwise the deleted run's rows resurrect on the next
     *  visit), and if that entry is currently displayed, reset the payload
     *  table too. The caller may refresh with the latest remaining record
     *  via showHistoricalRecord() right afterwards when one exists. */
    public void forgetForPath(String entryPath) {
        if (entryPath == null) return;
        entryStateCache.remove(entryPath);
        if (entryPath.equals(currentEntryPath)) {
            SwingUtilities.invokeLater(this::resetEntryState);
        }
    }

    /**
     * Live-update test cases during Agent execution. Only applies if the
     * Repeater is currently showing the given entry — otherwise silently
     * dropped (the final applyAgentResult at completion handles the full
     * reconciliation regardless).
     */
    public void showLiveTestCases(String entryPath, List<TestCase> allCases) {
        agentResultApplied = false;
        SwingUtilities.invokeLater(() -> {
            if (!isShowingEntry(entryPath)) return;
            doLoadTestCases(allCases);
        });
    }

    /**
     * Live-update a single payload result during Agent execution. Maps the
     * result to an existing test-case row (if index < row count) or appends
     * as a follow-up row. Only applies if Repeater shows the given entry.
     */
    public void showLivePayloadResult(String entryPath, PayloadResult pr, int resultIndex) {
        SwingUtilities.invokeLater(() -> {
            if (!isShowingEntry(entryPath)) return;
            if (agentResultApplied) return;
            int caseCount = testCases.size();
            if (resultIndex < caseCount) {
                doShowPayloadResult(resultIndex, pr.sentRequest(), pr.receivedResponse(),
                        pr.statusCode(), pr.responseTimeMs(), pr.anomalyDetected(), pr.wafVendor(), pr.wafScore());
            } else {
                doAddFollowUpPayloadResult(pr);
            }
            if (!pr.anomalyDetected()) {
                int row = Math.min(resultIndex, payloadModel.getRowCount() - 1);
                if (row >= 0) {
                    String current = String.valueOf(payloadModel.getValueAt(row, 4));
                    if (current.startsWith("✓")) {
                        payloadModel.setValueAt("⏳ 待分析", row, 4);
                    }
                }
            }
        });
    }

    public void loadTestCases(List<TestCase> cases, String host) {
        this.currentHost = host != null ? host : "";
        SwingUtilities.invokeLater(() -> doLoadTestCases(cases));
    }

    /** Clears all per-entry table/cache state. Shared by doLoadTestCases and
     *  applyAgentResult — the latter must reset even when the new entry's
     *  Agent run produced no test cases (e.g. a send_request-only follow-up
     *  verification), otherwise stale rows from whatever entry was
     *  previously shown would linger under the newly-switched-to entry. */
    private void resetEntryState() {
        testCases.clear();
        authTestRounds.clear();
        authTestRowOffset = -1;
        sentRequestCache.clear();
        receivedResponseCache.clear();
        payloadModel.setRowCount(0);
    }

    /** Core of loadTestCases without the invokeLater wrapper, so callers that
     *  need several Repeater updates to land atomically within a single EDT
     *  dispatch (applyAgentResult, PipelineFacade) can call this directly
     *  instead of each queuing its own separate Runnable. Package-private:
     *  callers must already be on the EDT and must have checked
     *  isShowingEntry() themselves right before calling. */
    void doLoadTestCases(List<TestCase> cases) {
        // Save whatever was previously loaded (for currentEntryPath) before replacing it
        saveCurrentState();

        resetEntryState();
        testCases.addAll(cases);
        for (TestCase tc : cases) {
            payloadModel.addRow(new Object[]{tc.name(), tc.category(), tc.targetParam(), tc.payload(), "待验证", "", ""});
        }
        if (!cases.isEmpty()) payloadTable.setRowSelectionInterval(0, 0);

        // Persist this freshly-loaded batch immediately — previously this
        // only happened as a side effect of some *future* showEntry/
        // loadTestCases call's saveCurrentState(), so a newly-generated batch
        // (e.g. right after an Agent analysis finishes) wasn't durably cached
        // until something else happened to trigger a save. Making it durable
        // the moment it's loaded removes that dependency entirely.
        saveCurrentState();
    }

    /**
     * Atomically applies a completed Agent run's results to the Repeater in a
     * single EDT dispatch — switch entry (if needed) + load test cases + back-fill
     * every payload result, all inside one Runnable, instead of AgentFacade
     * queuing N+M separate invokeLater calls (loadTestCases, then one
     * showPayloadResult/addFollowUpPayloadResult per payload) that could be
     * interleaved with unrelated EDT events (another entry's analysis
     * completing, a user click) and land out of order or write into a table
     * that had since been reset out from under them — which is exactly how
     * "later rows never showed up" happened.
     *
     * Deliberately does NOT go through showEntry's cached-state
     * restore path: this method is about to overwrite the table with fresh
     * data anyway, so restoring a stale cached snapshot (asynchronously, via
     * yet another invokeLater) would just re-introduce the same class of race
     * this method exists to avoid.
     *
     * @param onApplied invoked at the end, still on the EDT — use this for any
     *                   follow-up UI action (e.g. switching tabs) that must not
     *                   run on the caller's background thread.
     */
    public void applyAgentResult(String entryPath, String domain, String lastUrl,
                                  List<TestCase> testCases, List<PayloadResult> payloadResults,
                                  Runnable onApplied) {
        agentResultApplied = true;
        SwingUtilities.invokeLater(() -> {
            if (entryPath != null) {
                currentEntryPath = entryPath;
            }
            this.currentHost = domain != null ? domain : "";
            setSchemeFromUrl(lastUrl);
            // Authoritative rebuild. During the run, showLivePayloadResult appended
            // provisional rows carrying "⏳ 待分析"; if we didn't reset for the same
            // entry those stale rows lingered and the final results were appended on
            // top (duplicates + stuck 待分析). Clear and reconstruct from the complete
            // testCases + payloadResults so every row shows its final status.
            resetEntryState();

            if (testCases != null && !testCases.isEmpty()) {
                doLoadTestCases(testCases);
            }
            // Content-based matching (not index) so Agent-mode results — which
            // carry testCase=null and rarely align 1:1 with generated test cases —
            // still update the right row and light up the confirmed-vuln row.
            applyResultsToRows(testCases, payloadResults);
            saveCurrentState();
            if (onApplied != null) onApplied.run();
        });
    }

    /** Human-readable byte size of a response body for the table column. */
    private static String formatSize(String body) {
        if (body == null || body.isEmpty()) return "";
        int bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024));
    }

    /** Apply a set of PayloadResults to the loaded test-case rows using
     *  content-based matching (see findPayloadResultIndex). Results that match a
     *  row update it in place; unmatched results become follow-up rows. Shared by
     *  applyAgentResult / showHistoricalRecord / showEntry so all paths match the
     *  same way instead of fragile index alignment. */
    private void applyResultsToRows(List<TestCase> cases, List<PayloadResult> results) {
        if (results == null || results.isEmpty()) return;
        int caseCount = cases != null ? cases.size() : 0;
        java.util.Set<Integer> matched = new java.util.HashSet<>();
        for (int row = 0; row < caseCount; row++) {
            int idx = findPayloadResultIndex(results, cases.get(row));
            if (idx >= 0 && matched.add(idx)) {
                var pr = results.get(idx);
                doShowPayloadResult(row, pr.sentRequest(), pr.receivedResponse(),
                        pr.statusCode(), pr.responseTimeMs(), pr.anomalyDetected(), pr.wafVendor(), pr.wafScore());
            }
        }
        for (int i = 0; i < results.size(); i++) {
            if (!matched.contains(i)) {
                doAddFollowUpPayloadResult(results.get(i));
            }
        }
    }

    /** Find the PayloadResult that corresponds to a test case, by content.
     *  Pipeline-mode results carry the TestCase reference (exact match); Agent-mode
     *  send_request results have testCase=null, so fall back to matching the test
     *  case's payload against each result's testCase payload or sent request.
     *  Returns -1 when nothing matches. */
    private int findPayloadResultIndex(List<PayloadResult> results, TestCase tc) {
        if (results == null || tc == null) return -1;
        // 1. Reference equality (Pipeline mode sets PayloadResult.testCase).
        for (int i = 0; i < results.size(); i++) {
            if (results.get(i).testCase() == tc) return i;
        }
        String tcPayload = tc.payload();
        if (tcPayload == null || tcPayload.isBlank()) return -1;
        // 2. Payload text match against the result's own test-case payload.
        for (int i = 0; i < results.size(); i++) {
            PayloadResult pr = results.get(i);
            if (pr.testCase() != null && pr.testCase().payload() != null) {
                String p = pr.testCase().payload();
                if (p.equals(tcPayload) || p.contains(tcPayload) || tcPayload.contains(p)) return i;
            }
        }
        // 3. Payload appearing in the raw sent request (covers modified/ad-hoc sends).
        for (int i = 0; i < results.size(); i++) {
            PayloadResult pr = results.get(i);
            if (pr.sentRequest() != null && pr.sentRequest().contains(tcPayload)) return i;
        }
        // 4. Same check on the URL-DECODED request: when the send encoded the
        //    payload ('%27%20OR...' for "' OR..."), rule 3 misses it, leaving
        //    the test-case row without its request/response and dumping the
        //    result as an orphan follow-up row below.
        for (int i = 0; i < results.size(); i++) {
            PayloadResult pr = results.get(i);
            if (pr.sentRequest() != null) {
                try {
                    String decoded = java.net.URLDecoder.decode(
                            pr.sentRequest(), java.nio.charset.StandardCharsets.UTF_8);
                    if (decoded.contains(tcPayload)) return i;
                } catch (IllegalArgumentException ignored) {
                    // stray '%' in an unrelated request part — not decodable, skip
                }
            }
        }
        return -1;
    }

    /**
     * Replaces the current view with a *specific* historical AnalysisRecord's
     * test cases/payload results — unlike showEntry()/applyAgentResult(),
     * this always clears and rebuilds regardless of whether entryPath matches
     * what's already showing. Picking a record from the "历史记录" dropdown is
     * an explicit "show me exactly this past run" request, not a "restore
     * whatever's current for this entry" one — showEntry()'s cache-first
     * behavior, or applyAgentResult()'s skip-reset-if-same-entry behavior,
     * would both incorrectly leave an older/newer record's rows mixed in
     * instead of replacing them.
     */
    public void showHistoricalRecord(String entryPath, String domain, String lastUrl,
                                      List<TestCase> testCases, List<PayloadResult> payloadResults) {
        SwingUtilities.invokeLater(() -> {
            saveCurrentState();
            currentEntryPath = entryPath;
            this.currentHost = domain != null ? domain : "";
            setSchemeFromUrl(lastUrl);
            resetEntryState();
            if (testCases != null && !testCases.isEmpty()) {
                doLoadTestCases(testCases);
            }
            applyResultsToRows(testCases, payloadResults);
            saveCurrentState();
        });
    }

    /** Core of the cache-restore path, shared by showEntry(). No invokeLater —
     *  caller must already be on the EDT. */
    private void restoreCachedState(EntryRepeaterState cached) {
        testCases.clear();
        testCases.addAll(cached.testCases());
        currentHost = cached.host();
        currentUseHttps = cached.useHttps();
        sentRequestCache.clear();
        receivedResponseCache.clear();
        if (cached.sentCache() != null) sentRequestCache.putAll(cached.sentCache());
        if (cached.receivedCache() != null) receivedResponseCache.putAll(cached.receivedCache());
        payloadModel.setRowCount(0);
        for (String[] row : cached.tableRows()) {
            payloadModel.addRow(row);
        }
        if (payloadModel.getRowCount() > 0) payloadTable.setRowSelectionInterval(0, 0);
    }

    /**
     * Single entry point for "the user selected/switched to this entry
     * somewhere" (main table, task queue, history dropdown) — atomically
     * either restores a previously-cached live state for this entry, or
     * builds fresh from the given persisted test cases/payload results, all
     * inside one EDT dispatch.
     *
     * Replaces the old pattern used at all three call sites — call
     * setCurrentEntryPath(path), then separately decide whether to call
     * loadTestCases()/loadPayloadResults() based on its boolean return —
     * which had two bugs: (1) setCurrentEntryPath returned false both for
     * "already showing this entry, nothing to do" and "no cache, must
     * rebuild", so a table selection event that fired again for the entry
     * already on screen (e.g. Swing re-firing selection on
     * fireTableDataChanged after a Pipeline/Agent run persisted its result)
     * would blow away a correct live state and rebuild it from a persisted
     * snapshot; and (2) even when a rebuild was genuinely needed,
     * loadTestCases() only fired when testCases was non-empty, so a
     * send_request-only analysis (no generate_payloads call) had its
     * payloadResults silently dropped entirely, and even when testCases was
     * non-empty, loadTestCases()+loadPayloadResults() were two separate
     * invokeLater dispatches that could race the same way applyAgentResult
     * was built to avoid for the live-completion path.
     *
     * @param onApplied invoked at the end, still on the EDT.
     */
    /** Point the Repeater at the entry an analysis is about to run, starting
     *  from a clean slate. Live test-case/payload updates are gated on
     *  {@link #isShowingEntry} — if the analyzed entry isn't the one on
     *  screen, every live update is silently dropped and all rows appear in a
     *  single batch at the end (the reported "不是实时同步" symptom). Calling
     *  this at run start makes the live updates land in real time. We reset to
     *  a clean slate (rather than loading the previous run's rows) so the prior
     *  run's results don't interleave with the new run's live rows; the
     *  previous run stays retrievable from the history records. */
    public void beginLiveTracking(String entryPath, String domain, String lastUrl) {
        SwingUtilities.invokeLater(() -> {
            saveCurrentState();
            currentEntryPath = entryPath;
            this.currentHost = domain != null ? domain : "";
            setSchemeFromUrl(lastUrl);
            resetEntryState();
            agentResultApplied = false;
        });
    }

    public void showEntry(String entryPath, String domain, String lastUrl,
                           List<TestCase> persistedTestCases, List<PayloadResult> persistedPayloadResults,
                           Runnable onApplied) {
        SwingUtilities.invokeLater(() -> {
            if (entryPath != null && entryPath.equals(currentEntryPath)) {
                if (onApplied != null) onApplied.run();
                return;
            }
            saveCurrentState();
            currentEntryPath = entryPath;
            this.currentHost = domain != null ? domain : "";
            setSchemeFromUrl(lastUrl);

            EntryRepeaterState cached = entryPath != null ? entryStateCache.get(entryPath) : null;
            if (cached != null) {
                restoreCachedState(cached);
            } else {
                resetEntryState();
                if (persistedTestCases != null && !persistedTestCases.isEmpty()) {
                    doLoadTestCases(persistedTestCases);
                }
                applyResultsToRows(persistedTestCases, persistedPayloadResults);
                saveCurrentState();
            }
            if (onApplied != null) onApplied.run();
        });
    }

    private void saveCurrentState() {
        // !testCases.isEmpty() alone missed the "Agent verified via send_request
        // without ever calling generate_payloads" case — those follow-up rows
        // would never get cached, so switching away and back silently dropped
        // them. payloadModel.getRowCount() > 0 also catches that case.
        if (currentEntryPath != null && (!testCases.isEmpty() || payloadModel.getRowCount() > 0)) {
            List<String[]> rows = new ArrayList<>();
            for (int i = 0; i < payloadModel.getRowCount(); i++) {
                String[] row = new String[payloadModel.getColumnCount()];
                for (int j = 0; j < row.length; j++) {
                    Object val = payloadModel.getValueAt(i, j);
                    row[j] = val != null ? val.toString() : "";
                }
                rows.add(row);
            }
            // Snapshot the sent/received caches too, so switching back to this
            // entry restores not just the table rows but the actual traffic
            // behind each row (otherwise selecting a restored row shows the
            // "尚未发送" placeholder because the cache was empty).
            entryStateCache.put(currentEntryPath,
                    new EntryRepeaterState(new ArrayList<>(testCases), rows, currentHost, currentUseHttps,
                            new java.util.HashMap<>(sentRequestCache), new java.util.HashMap<>(receivedResponseCache)));
        }
    }

    public void setCurrentHost(String host) { this.currentHost = host != null ? host : ""; }

    public void setOnAiChatRequested(Runnable callback) { this.onAiChatRequested = callback; }

    public void setSchemeFromUrl(String url) {

        if (url != null) {
            if (url.toLowerCase().startsWith("https://")) currentUseHttps = true;
            else if (url.toLowerCase().startsWith("http://")) currentUseHttps = false;
        }
    }

    public void setRawRequest(String rawRequest, String host) {
        this.currentHost = host != null ? host : "";
        SwingUtilities.invokeLater(() -> setRequestFromRaw(rawRequest, host));
    }

    public void showPayloadResult(int index, String sentRequest, String receivedResponse,
            int statusCode, long elapsed, boolean anomalyDetected, String wafVendor, int wafScore) {
        SwingUtilities.invokeLater(() ->
                doShowPayloadResult(index, sentRequest, receivedResponse, statusCode, elapsed,
                        anomalyDetected, wafVendor, wafScore));
    }

    /** Core of showPayloadResult without the invokeLater wrapper — see doLoadTestCases. */
    void doShowPayloadResult(int index, String sentRequest, String receivedResponse,
            int statusCode, long elapsed, boolean anomalyDetected, String wafVendor, int wafScore) {
        if (index >= 0 && index < payloadModel.getRowCount()) {
            // Suppress the selection listener's row-selection handling — it would
            // otherwise redundantly rebuild the request from the TestCase template
            // right before this method overwrites it with the real sent/received data.
            addingFollowUp = true;
            try {
                payloadTable.setRowSelectionInterval(index, index);
            } finally {
                addingFollowUp = false;
            }
            payloadTable.scrollRectToVisible(payloadTable.getCellRect(index, 0, true));
            boolean isServerError = statusCode >= 500 || statusCode == 0;
            boolean isBlocked = statusCode == 403 || statusCode == 401 || statusCode == 400;
            String result;
            if (wafScore >= PayloadResult.WAF_BLOCKED) {
                // WAF block page — payload never reached the backend: neither a
                // vuln signal nor a "safe" signal.
                result = I18n.get("result_waf_blocked") + (wafVendor != null ? "(" + wafVendor + ")" : "");
            } else if (wafScore >= PayloadResult.WAF_REVIEW) {
                result = I18n.get("result_waf_review");
            } else if (isServerError) {
                result = "⚠ 异常 (" + statusCode + ")";
            } else if (isBlocked) {
                result = "✓ 无风险";
            } else if (anomalyDetected) {
                String originalRisk = index < testCases.size() ? testCases.get(index).riskIfConfirmed() : "MEDIUM";
                result = "⚡ " + originalRisk;
            } else {
                result = "✓ 无风险";
            }
            payloadModel.setValueAt(result, index, 4);
            payloadModel.setValueAt(statusCode > 0 ? String.valueOf(statusCode) : "", index, 5);
            payloadModel.setValueAt(formatSize(receivedResponse), index, 6);

            if (sentRequest != null) sentRequestCache.put(index, sentRequest);
            if (receivedResponse != null) receivedResponseCache.put(index, receivedResponse);
        }
        if (sentRequest != null) setRequestFromRaw(sentRequest, currentHost);
        if (receivedResponse != null && !receivedResponse.isEmpty()) {
            try {
                responseEditor.setResponse(HttpResponse.httpResponse(receivedResponse));
            } catch (Exception e) {
                responseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 " + statusCode + " OK\r\n\r\n" + receivedResponse));
            }
            statusLabel.setText(String.format("验证结果 — %d — %dms", statusCode, elapsed));
            statusLabel.setForeground(statusColor(statusCode));
        } else {
            statusLabel.setText("无响应");
            statusLabel.setForeground(Color.RED);
        }
    }

    /**
     * Appends a follow-up row for a PayloadResult that has no backing
     * TestCase (e.g. a send_request call the Agent made beyond what
     * generate_payloads originally produced) — parses method/path/payload
     * out of the raw request text since there's no TestCase metadata to
     * read them from. Shared by ChatController and AgentFacade so this
     * parsing only lives in one place.
     */
    public void addFollowUpPayloadResult(PayloadResult pr) {
        SwingUtilities.invokeLater(() -> doAddFollowUpPayloadResult(pr));
    }

    /** Core of addFollowUpPayloadResult(PayloadResult) without the invokeLater
     *  wrapper — see doLoadTestCases. */
    private void doAddFollowUpPayloadResult(PayloadResult pr) {
        String method = "GET";
        String path = "/";
        String body = "";
        String rawReq = pr.sentRequest();
        if (rawReq != null && !rawReq.isEmpty()) {
            int firstLineEnd = rawReq.indexOf('\n');
            if (firstLineEnd > 0) {
                String firstLine = rawReq.substring(0, firstLineEnd).trim();
                String[] parts = firstLine.split("\\s+");
                if (parts.length >= 2) { method = parts[0]; path = parts[1]; }
            }
            int bodyStart = rawReq.indexOf("\r\n\r\n");
            if (bodyStart >= 0 && bodyStart + 4 < rawReq.length()) {
                body = rawReq.substring(bodyStart + 4).trim();
            }
        }

        String name = method + " " + path;
        if (name.length() > 80) name = name.substring(0, 77) + "...";

        String targetParam;
        String payload;
        if (!body.isEmpty()) {
            targetParam = "body";
            payload = body.length() > 200 ? body.substring(0, 197) + "..." : body;
        } else {
            int qIdx = path.indexOf('?');
            if (qIdx >= 0 && qIdx + 1 < path.length()) {
                String qs = path.substring(qIdx + 1);
                targetParam = qs.contains("=") ? qs.substring(0, qs.indexOf('=')) : "query";
                payload = qs;
            } else {
                targetParam = "path";
                payload = path;
            }
        }

        doAddFollowUpPayloadResult(name, targetParam, payload,
                pr.sentRequest(), pr.receivedResponse(), pr.statusCode(), pr.responseTimeMs(), pr.anomalyDetected(), pr.wafVendor(), pr.wafScore());
    }


    public void addFollowUpPayloadResult(String name, String targetParam, String payload,
            String sentRequest, String receivedResponse, int statusCode, long elapsed) {
        SwingUtilities.invokeLater(() ->
                doAddFollowUpPayloadResult(name, targetParam, payload, sentRequest, receivedResponse, statusCode, elapsed,
                        false, null, 0));
    }

    /** Core of addFollowUpPayloadResult(String, ...) without the invokeLater
     *  wrapper — see doLoadTestCases.
     *
     *  anomalyDetected added because most of Agent mode's send_request calls
     *  land here (its testCases batch is usually a handful of rows; send_request
     *  is often called many more times, overflowing into follow-up rows) —
     *  this method used to hard-code "✓ 无风险" unconditionally, so even a
     *  payload the AI's final verdict confirmed as a real vulnerability
     *  (see VerdictValidator.markConfirmedPayloads, which sets this flag on
     *  the matching PayloadResult after validation) showed as risk-free. */
    private void doAddFollowUpPayloadResult(String name, String targetParam, String payload,
            String sentRequest, String receivedResponse, int statusCode, long elapsed, boolean anomalyDetected,
            String wafVendor, int wafScore) {
        boolean isServerError = statusCode >= 500 || statusCode == 0;
        boolean isBlocked = statusCode == 403 || statusCode == 401 || statusCode == 400;
        String result;
        if (wafScore >= PayloadResult.WAF_BLOCKED) {
            result = I18n.get("result_waf_blocked") + (wafVendor != null ? "(" + wafVendor + ")" : "");
        } else if (wafScore >= PayloadResult.WAF_REVIEW) {
            result = I18n.get("result_waf_review");
        } else if (isServerError) {
            result = "⚠ 异常 (" + statusCode + ")";
        } else if (isBlocked) {
            result = "✓ 无风险";
        } else if (anomalyDetected) {
            result = "⚡ 已确认";
        } else {
            result = "✓ 无风险";
        }

        int rowIdx = payloadModel.getRowCount();
        addingFollowUp = true;
        try {
            payloadModel.addRow(new Object[]{name, "追问测试", targetParam, payload, result,
                    statusCode > 0 ? String.valueOf(statusCode) : "", formatSize(receivedResponse)});
        } finally {
            addingFollowUp = false;
        }

        if (sentRequest != null) sentRequestCache.put(rowIdx, sentRequest);
        if (receivedResponse != null) receivedResponseCache.put(rowIdx, receivedResponse);

        addingFollowUp = true;
        try {
            payloadTable.setRowSelectionInterval(rowIdx, rowIdx);
        } finally {
            addingFollowUp = false;
        }
        payloadTable.scrollRectToVisible(payloadTable.getCellRect(rowIdx, 0, true));

        if (sentRequest != null) setRequestFromRaw(sentRequest, currentHost);
        if (receivedResponse != null && !receivedResponse.isEmpty()) {
            try {
                responseEditor.setResponse(HttpResponse.httpResponse(receivedResponse));
            } catch (Exception e) {
                responseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 " + statusCode + " OK\r\n\r\n" + receivedResponse));
            }
            statusLabel.setText(String.format("追问测试 — %d — %dms", statusCode, elapsed));
            statusLabel.setForeground(statusColor(statusCode));
        }
    }

    public void showAuthTestRounds(com.flechazo.apisentinel.auth.AuthTestResult result) {
        SwingUtilities.invokeLater(() -> {
            authTestRounds.clear();
            authTestRounds.addAll(result.rounds());
            authTestRowOffset = payloadModel.getRowCount();

            String verdict = result.verdict().name();
            String riskLabel = switch (result.verdict()) {
                case VULNERABLE -> "HIGH";
                case SUSPICIOUS -> "MEDIUM";
                default -> "LOW";
            };
            for (var round : result.rounds()) {
                String name = "越权: " + round.description();
                String detail = String.format("HTTP %d (相似度 %.0f%%)", round.statusCode(), round.similarity() * 100);
                payloadModel.addRow(new Object[]{name, "越权检测", verdict, detail, riskLabel, "", ""});
            }
            if (authTestRowOffset < payloadModel.getRowCount()) {
                payloadTable.setRowSelectionInterval(authTestRowOffset, authTestRowOffset);
                payloadTable.scrollRectToVisible(payloadTable.getCellRect(authTestRowOffset, 0, true));
            }
            statusLabel.setText(String.format("越���检测 — %s (最大相似度 %.0f%%)",
                    verdict, result.maxSimilarity() * 100));
            statusLabel.setForeground(result.verdict() == com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict.VULNERABLE
                    ? new Color(200, 0, 0) : statusColor(200));
        });
    }

    private void loadAuthTestRoundIntoEditors(com.flechazo.apisentinel.auth.AuthTestRound round) {
        String fullReq = round.fullRequest();
        String fullResp = round.fullResponse();
        if (fullReq != null && !fullReq.isEmpty()) {
            setRequestFromRaw(fullReq, currentHost);
        }
        if (fullResp != null && !fullResp.isEmpty()) {
            try {
                responseEditor.setResponse(HttpResponse.httpResponse(fullResp));
            } catch (Exception e) {
                responseEditor.setResponse(HttpResponse.httpResponse(
                        "HTTP/1.1 " + round.statusCode() + " OK\r\n\r\n" + fullResp));
            }
            statusLabel.setText(String.format("越权检测 — %s — HTTP %d (相似度 %.0f%%)",
                    round.description(), round.statusCode(), round.similarity() * 100));
            statusLabel.setForeground(round.similarity() >= 0.85 ? new Color(200, 0, 0)
                    : round.similarity() >= 0.60 ? new Color(200, 150, 0) : new Color(0, 120, 60));
        } else {
            statusLabel.setText("越权检测 — " + round.description() + " (无完整数据)");
            statusLabel.setForeground(Color.GRAY);
        }
    }

    public void loadFromEntry(com.flechazo.apisentinel.model.ApiEntry entry) {
        if (entry == null) return;
        this.currentHost = entry.getDomain() != null ? entry.getDomain() : "";
        String lastUrl = entry.getLastUrl();
        if (lastUrl != null && lastUrl.toLowerCase().startsWith("https://")) currentUseHttps = true;
        else if (lastUrl != null && lastUrl.toLowerCase().startsWith("http://")) currentUseHttps = false;

        SwingUtilities.invokeLater(() -> {
            if (entry.hasTrafficData() && entry.getLastRawRequest() != null && !entry.getLastRawRequest().isEmpty()) {
                setRequestFromRaw(entry.getLastRawRequest(), currentHost);
                this.baselineResponse = entry.getLastRawResponse();
                if (entry.getLastRawResponse() != null && !entry.getLastRawResponse().isEmpty()) {
                    try {
                        responseEditor.setResponse(HttpResponse.httpResponse(entry.getLastRawResponse()));
                        statusLabel.setText(String.format("已加载 — %d", entry.getLastStatusCode()));
                        statusLabel.setForeground(statusColor(entry.getLastStatusCode()));
                    } catch (Exception ignored) {}
                }
            } else {
                String method = entry.getHttpMethod().isEmpty() ? "GET" : entry.getHttpMethod();
                String path = entry.getApiPath().isEmpty() ? "/" : entry.getApiPath();
                String host = currentHost.isEmpty() ? "example.com" : currentHost;
                setRequestFromRaw(method + " " + path + " HTTP/1.1\r\nHost: " + host
                        + "\r\nUser-Agent: API-Sentinel/" + com.flechazo.apisentinel.ApiSentinelExtension.VERSION
                        + "\r\nAccept: */*\r\n\r\n", host);
            }
        });
    }

    // ======================== Private methods ========================

    /** Shown in the Response editor when the selected row has no real
     *  response yet (test case never sent) — without this, switching from a
     *  verified row to an unverified one left the previous row's response
     *  on screen, since the old code only ever updated the editor when a
     *  cached response existed and did nothing otherwise. */
    private static final String NO_RESPONSE_PLACEHOLDER =
            "HTTP/1.1 000 Not Sent\r\n\r\n(该测试用例尚未实际发送，这里没有真实响应——点击上方 Send 按钮发送)";

    private void loadTestCaseIntoRequest(int index, TestCase tc) {
        String cached = sentRequestCache.get(index);
        if (cached != null) {
            String host = !currentHost.isEmpty() ? currentHost : "example.com";
            setRequestFromRaw(cached, host);
            setResponseOrPlaceholder(receivedResponseCache.get(index));
            return;
        }
        setResponseOrPlaceholder(null);
        StringBuilder sb = new StringBuilder();
        String method = tc.method() != null && !tc.method().isEmpty() ? tc.method() : "GET";
        String path = tc.path() != null && !tc.path().isEmpty() ? tc.path() : "/";
        String host = !currentHost.isEmpty() ? currentHost : "example.com";

        sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        if (tc.headers() != null) {
            for (Map.Entry<String, String> h : tc.headers().entrySet())
                sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
        }
        if (tc.headers() == null || !tc.headers().containsKey("User-Agent"))
            sb.append("User-Agent: API-Sentinel/").append(com.flechazo.apisentinel.ApiSentinelExtension.VERSION).append("\r\n");
        if (tc.headers() == null || !tc.headers().containsKey("Accept"))
            sb.append("Accept: */*\r\n");

        String body = tc.body() != null ? tc.body() : "";
        if (!body.isEmpty()) {
            if (tc.headers() == null || !tc.headers().containsKey("Content-Type"))
                sb.append(body.trim().startsWith("{") || body.trim().startsWith("[")
                        ? "Content-Type: application/json\r\n" : "Content-Type: application/x-www-form-urlencoded\r\n");
            sb.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
        }
        sb.append("\r\n");
        if (!body.isEmpty()) sb.append(body);
        setRequestFromRaw(sb.toString(), host);
    }

    private void loadFollowUpFromCache(int row) {
        String cached = sentRequestCache.get(row);
        if (cached != null) {
            String host = !currentHost.isEmpty() ? currentHost : "example.com";
            setRequestFromRaw(cached, host);
        }
        // Follow-up rows are always created with both caches populated
        // together (addFollowUpPayloadResult), so cached==null here should
        // be rare — but resolve explicitly either way rather than silently
        // keeping whatever the previously-selected row left in the editor.
        setResponseOrPlaceholder(receivedResponseCache.get(row));
    }

    /** Resolves the Response editor for the current selection: shows the
     *  given raw response if present, otherwise an explicit placeholder —
     *  never leaves the previously-selected row's response on screen. */
    private void setResponseOrPlaceholder(String cachedResp) {
        try {
            if (cachedResp != null && !cachedResp.isEmpty()) {
                responseEditor.setResponse(HttpResponse.httpResponse(cachedResp));
            } else {
                responseEditor.setResponse(HttpResponse.httpResponse(NO_RESPONSE_PLACEHOLDER));
            }
        } catch (Exception ignored) {}
    }

    private void setRequestFromRaw(String rawRequest, String host) {
        try {
            String h = (host != null && !host.isEmpty()) ? host : currentHost;
            if (h.isEmpty()) h = parseHostFromRequest(rawRequest);
            if (h.isEmpty()) h = "example.com";
            requestEditor.setRequest(HttpRequest.httpRequest(buildHttpService(h), rawRequest));
        } catch (Exception e) {
            try { requestEditor.setRequest(HttpRequest.httpRequest(rawRequest)); } catch (Exception ignored) {}
        }
    }

    private HttpService buildHttpService(String hostWithPort) {
        String hostName = hostWithPort.contains(":") ? hostWithPort.split(":")[0] : hostWithPort;
        boolean useHttps = currentUseHttps;
        int port;
        if (hostWithPort.contains(":")) {
            try { port = Integer.parseInt(hostWithPort.split(":")[1]); }
            catch (NumberFormatException e) { port = useHttps ? 443 : 80; }
            if (port == 443) useHttps = true;
            else if (port == 80) useHttps = false;
            else if (port == 8443) useHttps = true;
        } else {
            port = useHttps ? 443 : 80;
        }
        return HttpService.httpService(hostName, port, useHttps);
    }

    private void sendRequest() {
        HttpRequest httpRequest;
        try { httpRequest = requestEditor.getRequest(); }
        catch (Exception e) { statusLabel.setText("无法解析请求"); statusLabel.setForeground(Color.RED); return; }
        if (httpRequest == null) { statusLabel.setText("请求为空"); statusLabel.setForeground(Color.RED); return; }

        sendButton.setEnabled(false);
        statusLabel.setText("Sending...");
        statusLabel.setForeground(new Color(0xFF, 0x66, 0x00));

        // Entry-switch guard: if the user switches to another entry while this
        // send is in flight, the late response must not be written into the
        // NEW entry's view/cache.
        final String sendEntryPath = currentEntryPath;
        com.flechazo.apisentinel.util.SharedTaskPool.submitInteractive(() -> {
            try {
                String rawStr = httpRequest.toString();
                String host = parseHostFromRequest(rawStr);
                if (host.isEmpty()) host = !currentHost.isEmpty() ? currentHost : "example.com";
                HttpRequest finalReq = HttpRequest.httpRequest(buildHttpService(host), rawStr);

                long start = System.currentTimeMillis();
                HttpRequestResponse result = api.http().sendRequest(finalReq);
                long elapsed = System.currentTimeMillis() - start;

                SwingUtilities.invokeLater(() -> {
                    if (!java.util.Objects.equals(sendEntryPath, currentEntryPath)) {
                        // User switched entries mid-flight: don't clobber the
                        // new entry's view with this stale response.
                        sendButton.setEnabled(true);
                        return;
                    }
                    if (result.response() != null) {
                        responseEditor.setResponse(result.response());
                        int code = result.response().statusCode();
                        statusLabel.setText(String.format("%d — %dms", code, elapsed));
                        statusLabel.setForeground(statusColor(code));

                        int selectedRow = payloadTable.getSelectedRow();
                        if (selectedRow >= 0 && selectedRow < testCases.size()) {
                            boolean isServerError = code >= 500 || code == 0;
                            boolean isBlocked = code == 403 || code == 401 || code == 400;
                            String verifyResult;
                            if (isServerError) {
                                verifyResult = "⚠ 异常 (" + code + ")";
                            } else if (isBlocked) {
                                verifyResult = "✓ 无风险";
                            } else {
                                verifyResult = "✓ 无风险";
                            }
                            payloadModel.setValueAt(verifyResult, selectedRow, 4);
                            payloadModel.setValueAt(String.valueOf(code), selectedRow, 5);
                            payloadModel.setValueAt(formatSize(result.response().toString()), selectedRow, 6);
                            receivedResponseCache.put(selectedRow, result.response().toString());
                        }
                    } else {
                        statusLabel.setText("无响应 — 检查主机/端口/协议");
                        statusLabel.setForeground(Color.RED);
                    }
                    sendButton.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    if (java.util.Objects.equals(sendEntryPath, currentEntryPath)) {
                        statusLabel.setText("错误: " + ex.getMessage());
                        statusLabel.setForeground(Color.RED);
                    }
                    sendButton.setEnabled(true);
                });
            }
        });
    }

    private void sendToBurpNativeRepeater() {
        try {
            HttpRequest request = requestEditor.getRequest();
            if (request == null) { statusLabel.setText("无请求"); statusLabel.setForeground(Color.RED); return; }
            String rawStr = request.toString();
            String host = parseHostFromRequest(rawStr);
            if (host.isEmpty()) host = !currentHost.isEmpty() ? currentHost : "example.com";
            HttpRequest finalReq = HttpRequest.httpRequest(buildHttpService(host), rawStr);
            String path = "/"; try { path = request.path(); } catch (Exception ignored) {}
            api.repeater().sendToRepeater(finalReq, "Sentinel: " + path);
            statusLabel.setText("→ 已发送到 Burp Repeater");
            statusLabel.setForeground(new Color(0, 120, 180));
        } catch (Exception e) {
            statusLabel.setText("发送失败: " + e.getMessage());
            statusLabel.setForeground(Color.RED);
        }
    }

    private void sendToComparer() {
        try {
            HttpResponse cur = responseEditor.getResponse();
            if (cur == null) { statusLabel.setText("当前无响应"); statusLabel.setForeground(Color.RED); return; }
            if (baselineResponse != null && !baselineResponse.isEmpty()) {
                api.comparer().sendToComparer(ByteArray.byteArray(baselineResponse), cur.toByteArray());
                statusLabel.setText("⇋ 已发送 基线+当前 到 Comparer");
            } else {
                api.comparer().sendToComparer(cur.toByteArray());
                statusLabel.setText("⇋ 已发送当前响应到 Comparer（无基线）");
            }
            statusLabel.setForeground(new Color(0, 120, 180));
        } catch (Exception e) {
            statusLabel.setText("Comparer 失败: " + e.getMessage());
            statusLabel.setForeground(Color.RED);
        }
    }

    private String parseHostFromRequest(String raw) {
        if (raw == null) return "";
        for (String line : raw.split("\r?\n")) {
            String t = line.trim();
            if (t.isEmpty()) break;
            if (t.toLowerCase().startsWith("host:")) return t.substring(5).trim();
        }
        return "";
    }

    private Color statusColor(int code) {
        if (code >= 200 && code < 300) return new Color(0, 140, 60);
        if (code >= 400) return Color.RED;
        return Color.ORANGE;
    }
}
