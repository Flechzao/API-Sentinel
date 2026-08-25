package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.model.ApiEntry;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * AI 对话面板——浮动窗口，承载 Agent 步骤视图和对话气泡视图。
 * 含历史会话切换、上下文绑定、输入区、停止分析按钮、沙箱确认卡片。
 */
public class AiChatPanel extends JPanel {

    private final BurpTheme theme;
    private final JPanel chatContainer;
    private final JScrollPane chatScroll;
    private final JTextArea inputArea;
    private final JButton sendButton;
    private final JButton historyMenuButton;
    private final JLabel contextLabel;
    private final JLabel statusDot;
    private final JLabel modelLabel;
    private final JPanel contentCards;
    private final CardLayout contentLayout;
    private final JButton viewToggleBtn;
    private final StepProgressPanel stepProgressPanel;
    private final JPanel inputPanel;
    private final JLabel newMsgIndicator;
    private final JPanel emptyStateWrapper;

    /** Max distinct conversations kept in memory (LRU by access) — previously
     *  unbounded: every ever-visited entry kept its full chat history alive. */
    private static final int MAX_CONVERSATIONS = 50;
    /** Max messages kept per conversation (oldest trimmed first). */
    private static final int MAX_MESSAGES_PER_CONVERSATION = 200;

    private final Map<String, List<ChatMessage>> conversationHistory =
            Collections.synchronizedMap(new LinkedHashMap<String, List<ChatMessage>>(32, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, List<ChatMessage>> eldest) {
                    return size() > MAX_CONVERSATIONS;
                }
            });
    private volatile String currentApiPath = null;
    private volatile ApiEntry currentEntry = null;
    private boolean inStepMode = false;

    private static final java.nio.file.Path CHAT_FILE = com.flechazo.apisentinel.config.AppPaths.chatHistoryFile();
    private final java.util.concurrent.atomic.AtomicBoolean chatDirty = new java.util.concurrent.atomic.AtomicBoolean(false);
    private final java.util.concurrent.ScheduledExecutorService chatFlusher =
            java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "api-sentinel-chat-flush");
                t.setDaemon(true);
                return t;
            });
    private static final com.google.gson.Gson GSON = new com.google.gson.Gson();

    private BiConsumer<String, String> onSendMessage;
    /** Fired by the stop button — cancels ALL active analyses (Pipeline + Agent). */
    private Runnable onCancelAnalysis;
    /** Count of in-flight full analyses (Pipeline/Agent); >0 shows the stop
     *  button. AtomicInteger because batch mode runs up to 2 concurrently and
     *  completions land on background threads. */
    private final java.util.concurrent.atomic.AtomicInteger activeAnalyses =
            new java.util.concurrent.atomic.AtomicInteger(0);
    private JButton stopButton;

    public AiChatPanel(MontoyaApi api) {
        this.theme = new BurpTheme(api);
        loadChatHistory();
        chatFlusher.scheduleAtFixedRate(this::flushChatIfDirty, 15, 15, java.util.concurrent.TimeUnit.SECONDS);

        setLayout(new BorderLayout(0, 4));
        setBorder(new EmptyBorder(4, 4, 4, 4));

        // ── Header bar — the window's own identity strip: status dot +
        //    context + model + actions. Replaces the bare context row that
        //    made the floating window feel like an undecorated utility pane.
        statusDot = new JLabel("●");
        statusDot.setFont(theme.displayFont(Font.BOLD, 11f));
        statusDot.setForeground(theme.statusOk());
        statusDot.setToolTipText("空闲");

        contextLabel = new JLabel("未选择接口");
        contextLabel.setFont(theme.displayFont(Font.BOLD, 12.5f));
        contextLabel.setForeground(theme.headerFg());

        modelLabel = new JLabel();
        modelLabel.setFont(theme.displayFont(Font.PLAIN, 11f));
        modelLabel.setForeground(theme.mutedText());
        modelLabel.setVisible(false);

        // Toggle to switch between the conversation view and the step (tool-call) view.
        viewToggleBtn = headerChip(new JButton("步骤视图"));
        viewToggleBtn.setToolTipText("在「对话」与「步骤(工具调用)」视图之间切换");
        viewToggleBtn.addActionListener(e -> {
            if (inStepMode) switchToChatMode(); else switchToStepMode(false);
        });

        // Stop: visible only while at least one full analysis is running.
        stopButton = headerChip(new JButton("⏹ 停止分析"));
        stopButton.setToolTipText("中断正在运行的 Pipeline/Agent 分析（已收集的部分结果会保留）");
        stopButton.setVisible(false);
        stopButton.addActionListener(e -> {
            if (onCancelAnalysis != null) {
                stopButton.setEnabled(false);
                stopButton.setText("⏹ 正在停止...");
                addSystemPanel("⏹ 已请求中断分析，等待当前步骤结束...");
                onCancelAnalysis.run();
            }
        });

        // Recent conversations live in a dropdown-style popup menu. They used
        // to render as anonymous chips whose labels were the LAST PATH SEGMENT
        // ("search", "fid}", "detail") — indistinguishable from action buttons
        // and frequently unreadable. The menu builds itself on click, so it is
        // always current without refresh bookkeeping.
        historyMenuButton = headerChip(new JButton("历史会话 ▾"));
        historyMenuButton.setToolTipText("切换最近使用过的对话");
        historyMenuButton.addActionListener(e -> showHistoryMenu());

        JPanel headerBar = new JPanel(new BorderLayout(8, 0));
        headerBar.setBackground(theme.headerBg());
        headerBar.setBorder(new EmptyBorder(8, 12, 8, 12));

        JPanel headerLeft = new JPanel();
        headerLeft.setLayout(new BoxLayout(headerLeft, BoxLayout.X_AXIS));
        headerLeft.setOpaque(false);
        headerLeft.add(statusDot);
        headerLeft.add(Box.createHorizontalStrut(6));
        headerLeft.add(contextLabel);

        JPanel headerRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        headerRight.setOpaque(false);
        headerRight.add(modelLabel);
        headerRight.add(historyMenuButton);
        headerRight.add(viewToggleBtn);
        headerRight.add(stopButton);

        headerBar.add(headerLeft, BorderLayout.CENTER);
        headerBar.add(headerRight, BorderLayout.EAST);

        JPanel sep = new JPanel();
        sep.setPreferredSize(new Dimension(0, 1));
        sep.setBackground(theme.separator());

        JPanel headerWrapper = new JPanel(new BorderLayout());
        headerWrapper.setOpaque(false);
        headerWrapper.add(headerBar, BorderLayout.CENTER);
        headerWrapper.add(sep, BorderLayout.SOUTH);
        add(headerWrapper, BorderLayout.NORTH);

        // Chat container (panel-based)
        chatContainer = new JPanel() {
            @Override public Dimension getPreferredSize() {
                int w = getParent() != null ? getParent().getWidth() : super.getPreferredSize().width;
                if (w <= 0) w = super.getPreferredSize().width;
                int h = super.getPreferredSize().height;
                return new Dimension(w, h);
            }
        };
        chatContainer.setLayout(new BoxLayout(chatContainer, BoxLayout.Y_AXIS));
        chatContainer.setBackground(theme.chatBg());
        chatContainer.setBorder(new EmptyBorder(12, 14, 14, 14));

        chatScroll = new JScrollPane(chatContainer);
        chatScroll.setBorder(BorderFactory.createEmptyBorder());
        chatScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        chatScroll.getVerticalScrollBar().setUnitIncrement(16);
        chatScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        chatScroll.getViewport().addChangeListener(e -> {
            chatContainer.revalidate();
        });

        // Step progress panel (for tool-calling mode)
        stepProgressPanel = new StepProgressPanel(theme);

        // CardLayout to switch between chat and step modes
        contentLayout = new CardLayout();
        contentCards = new JPanel(contentLayout);
        contentCards.add(chatScroll, "chat");
        contentCards.add(stepProgressPanel, "steps");
        add(contentCards, BorderLayout.CENTER);

        // Empty state — a bare one-line grey note used to be the entire
        // first-run experience; this card explains the two entry paths.
        emptyStateWrapper = buildEmptyState();
        chatContainer.add(emptyStateWrapper);

        // New-message indicator: shows instead of yanking the viewport when
        // the user has scrolled up to read.
        newMsgIndicator = new JLabel(" ");
        newMsgIndicator.setFont(theme.displayFont(Font.BOLD, 11f));
        newMsgIndicator.setForeground(theme.accentBg());
        newMsgIndicator.setPreferredSize(new Dimension(0, 18));
        newMsgIndicator.setHorizontalAlignment(SwingConstants.RIGHT);
        newMsgIndicator.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        newMsgIndicator.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                forceScrollToBottom();
                hideNewMsgIndicator();
            }
        });

        // Input area: multi-line (paste long payloads), Enter sends,
        // Shift+Enter breaks a line, auto-grows 2..6 rows.
        inputPanel = new JPanel(new BorderLayout(6, 0));
        inputPanel.setBorder(new EmptyBorder(2, 0, 0, 0));

        inputArea = new JTextArea();
        inputArea.setFont(theme.displayFont(Font.PLAIN, 13f));
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        inputArea.setRows(2);
        inputArea.setBorder(new EmptyBorder(6, 8, 6, 8));
        inputArea.setBackground(theme.inputBg());
        inputArea.setForeground(theme.inputFg());
        inputArea.setCaretColor(theme.inputFg());
        inputArea.setToolTipText("输入消息，Enter 发送，Shift+Enter 换行");

        javax.swing.event.DocumentListener rowsListener = new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { updateInputRows(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { updateInputRows(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { updateInputRows(); }
        };
        inputArea.getDocument().addDocumentListener(rowsListener);

        inputArea.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke("ENTER"), "api-sentinel-send");
        inputArea.getActionMap().put("api-sentinel-send", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { sendCurrentInput(); }
        });

        JScrollPane inputScroll = new JScrollPane(inputArea);
        inputScroll.setBorder(BorderFactory.createLineBorder(theme.inputBorder(), BurpTheme.RADIUS_SM, true));
        inputScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);

        sendButton = new JButton("发送");
        sendButton.setFont(theme.displayFont(Font.BOLD, 12f));
        sendButton.setFocusPainted(false);
        // No fixed preferred size: 64x34 clipped the "发送" label under Burp's
        // button insets/font on several themes. Margin + LAF preferred sizing
        // adapts; the wrapper below stretches it to the input's full height.
        sendButton.setMargin(new Insets(4, 18, 4, 18));
        sendButton.setToolTipText("发送 (Enter)");

        JPanel sendWrapper = new JPanel(new BorderLayout());
        sendWrapper.setOpaque(false);
        sendWrapper.add(sendButton, BorderLayout.CENTER);

        inputPanel.add(inputScroll, BorderLayout.CENTER);
        inputPanel.add(sendWrapper, BorderLayout.EAST);

        JPanel southStack = new JPanel(new BorderLayout());
        southStack.setOpaque(false);
        southStack.add(newMsgIndicator, BorderLayout.NORTH);
        southStack.add(inputPanel, BorderLayout.CENTER);
        add(southStack, BorderLayout.SOUTH);

        // Apply Burp LAF
        theme.apply(this);
        chatContainer.setBackground(theme.chatBg());

        // Wire actions
        sendButton.addActionListener(e -> sendCurrentInput());
    }

    private JPanel buildEmptyState() {
        RoundedPanel card = new RoundedPanel(new BorderLayout(0, 6));
        card.setCornerRadius(BurpTheme.RADIUS_LG);
        card.setBackground(theme.aiCardBg());
        card.setBorder(new EmptyBorder(26, 30, 26, 30));
        card.setPreferredSize(new Dimension(440, 220));
        card.setMaximumSize(new Dimension(440, 220));
        card.setAlignmentX(0.5f);

        JPanel col = new JPanel();
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setOpaque(false);

        JLabel title = new JLabel("开始对话");
        title.setFont(theme.displayFont(Font.BOLD, 16f));
        title.setForeground(theme.headingColor());
        title.setAlignmentX(0.5f);
        col.add(title);
        col.add(Box.createVerticalStrut(8));

        JLabel hint1 = new JLabel("① 在左侧接口表格选中一行，即可携带完整流量上下文提问");
        hint1.setFont(theme.displayFont(Font.PLAIN, 12f));
        hint1.setForeground(theme.systemColor());
        hint1.setAlignmentX(0.5f);
        col.add(hint1);

        JLabel hint2 = new JLabel("② 或直接使用快捷指令 / 输入任意安全分析问题");
        hint2.setFont(theme.displayFont(Font.PLAIN, 12f));
        hint2.setForeground(theme.systemColor());
        hint2.setAlignmentX(0.5f);
        col.add(hint2);
        col.add(Box.createVerticalStrut(12));

        JPanel chipsRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
        chipsRow.setOpaque(false);
        chipsRow.setAlignmentX(0.5f);
        for (String[] p : new String[][]{
                {"分析安全风险", "分析这个接口的安全风险"},
                {"漏洞利用", "如何利用这个漏洞"},
                {"绕过方案", "生成绕过方案"}}) {
            chipsRow.add(makeChipButton(p[0], () -> sendPrompt(p[1])));
        }
        col.add(chipsRow);

        card.add(col, BorderLayout.CENTER);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);
        wrapper.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        wrapper.add(Box.createVerticalGlue(), BorderLayout.NORTH);
        wrapper.add(card, BorderLayout.CENTER);
        wrapper.add(Box.createVerticalGlue(), BorderLayout.SOUTH);
        return wrapper;
    }

    private void sendPrompt(String prompt) {
        inputArea.setText(prompt);
        sendCurrentInput();
    }

    private void updateInputRows() {
        int lines = Math.max(1, inputArea.getLineCount());
        int rows = Math.max(2, Math.min(6, lines));
        if (rows != inputArea.getRows()) {
            inputArea.setRows(rows);
            inputPanel.revalidate();
        }
    }

    /** Reflects an in-flight chat request on the send button (disabled,
     *  ellipsis label) — sending used to give zero feedback until the reply
     *  landed. Safe from any thread. */
    public void setBusy(boolean busy) {
        SwingUtilities.invokeLater(() -> {
            sendButton.setEnabled(!busy);
            sendButton.setText(busy ? "…" : "发送");
        });
    }

    /** Chip styling for header buttons — Burp LAF buttons look heavy and
     *  off-palette inside the custom header bar; these stay transparent with
     *  a thin border and hover accent (same visual language as the
     *  empty-state chips). */
    private JButton headerChip(JButton btn) {
        btn.setFont(theme.displayFont(Font.PLAIN, 11f));
        btn.setFocusPainted(false);
        btn.setOpaque(false);
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setForeground(theme.chipFg());
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        java.awt.event.MouseAdapter hover = new java.awt.event.MouseAdapter() {
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                btn.setForeground(theme.accentBg());
                btn.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(theme.accentBg(), 1, true),
                        BorderFactory.createEmptyBorder(3, 10, 3, 10)));
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                btn.setForeground(theme.chipFg());
                btn.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(theme.chipBorder(), 1, true),
                        BorderFactory.createEmptyBorder(3, 10, 3, 10)));
            }
        };
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(theme.chipBorder(), 1, true),
                BorderFactory.createEmptyBorder(3, 10, 3, 10)));
        btn.addMouseListener(hover);
        return btn;
    }

    /** Model badge in the header — wired from the extension alongside
     *  AiAnalysisPanel.setCurrentModel; hidden until known. */
    public void setModelName(String modelName) {
        SwingUtilities.invokeLater(() -> {
            boolean show = modelName != null && !modelName.isBlank();
            modelLabel.setVisible(show);
            if (show) {
                modelLabel.setText("模型: " + modelName);
                modelLabel.setToolTipText("当前 AI Provider 使用的模型");
            }
        });
    }

    /** Flat rounded chip: transparent fill, thin border, hover accent.
     *  Previously these were stock L&F buttons — square, heavy, off-token. */
    private JButton makeChipButton(String label, Runnable onAction) {
        JButton btn = new JButton(label);
        btn.setFont(theme.displayFont(Font.PLAIN, 11f));
        btn.setFocusPainted(false);
        btn.setOpaque(false);
        btn.setContentAreaFilled(false);
        btn.setForeground(theme.chipFg());
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(theme.chipBorder(), 1, true),
                BorderFactory.createEmptyBorder(2, 10, 2, 10)));
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                btn.setForeground(theme.accentBg());
                btn.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(theme.accentBg(), 1, true),
                        BorderFactory.createEmptyBorder(2, 10, 2, 10)));
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                btn.setForeground(theme.chipFg());
                btn.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(theme.chipBorder(), 1, true),
                        BorderFactory.createEmptyBorder(2, 10, 2, 10)));
            }
        });
        btn.addActionListener(e -> onAction.run());
        return btn;
    }

    private void sendCurrentInput() {
        String text = inputArea.getText().trim();
        if (text.isEmpty()) return;
        inputArea.setText("");
        inputArea.setRows(2);
        // A previous analysis may have left the panel in step view; sending a chat
        // message means the user wants the conversation, so reveal it (otherwise
        // they'd type into a hidden chat and think messaging was broken).
        if (inStepMode) switchToChatMode();
        addUserMessage(text);
        if (onSendMessage != null) onSendMessage.accept(text, currentApiPath);
    }

    public void setOnSendMessage(BiConsumer<String, String> handler) {
        this.onSendMessage = handler;
    }

    public void setOnCancelAnalysis(Runnable handler) { this.onCancelAnalysis = handler; }

    /** Package-private theme accessor for ChatInteractionBridge's cards. */
    BurpTheme theme() { return theme; }

    /** Full-analysis lifecycle: +1 on start, -1 on completion/cancel/error.
     *  Drives the stop button's visibility. Safe from any thread. */
    public void setAnalysisActive(boolean starting) {
        // Clamp the decrement at 0: terminal paths that fire BOTH onAgentError
        // and onAgentComplete (max-iterations, repeat-breaker) used to
        // double-decrement, driving the counter negative so later runs never
        // showed the stop button.
        int n = starting
                ? activeAnalyses.incrementAndGet()
                : activeAnalyses.updateAndGet(v -> Math.max(0, v - 1));
        SwingUtilities.invokeLater(() -> {
            boolean running = n > 0;
            stopButton.setVisible(running);
            if (!running) {
                stopButton.setEnabled(true);
                stopButton.setText("⏹ 停止分析");
            }
            // Header status dot doubles as the run indicator.
            statusDot.setForeground(running ? theme.statusPending() : theme.statusOk());
            statusDot.setToolTipText(running ? "分析运行中" : "空闲");
            revalidate();
            repaint();
        });
    }

    /** Append an interactive card (sandbox confirm / ask_user) to the visible
     *  conversation. Flips out of step view first — an analysis switchToStepMode()d
     *  the panel, and a question that needs an answer must not be hidden behind
     *  that card stack. Caller must already be on the EDT. */
    public void addInteractionCard(JComponent card) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> addInteractionCard(card));
            return;
        }
        if (inStepMode) switchToChatMode();
        removeEmptyState();
        chatContainer.add(card);
        chatContainer.revalidate();
        chatContainer.repaint();
        forceScrollToBottom();
    }

    /** Fire a toast anchored to wherever this panel currently lives (docked
     *  tab or detached window) — used when an interactive card lands so a
     *  user staring at another tab knows to come answer it. */
    public void toast(String message, boolean warning) {
        SwingUtilities.invokeLater(() ->
                ToastNotification.show(this, message,
                        warning ? ToastNotification.ToastType.WARNING : ToastNotification.ToastType.INFO,
                        5000));
    }

    public void setContext(ApiEntry entry) {
        if (entry == null) {
            currentApiPath = null;
            currentEntry = null;
            contextLabel.setText("未选择接口");
            contextLabel.setToolTipText(null);
            return;
        }

        String newPath = entry.getApiPath();
        if (newPath.equals(currentApiPath)) return;

        currentApiPath = newPath;
        currentEntry = entry;
        contextLabel.setText(entry.getHttpMethod() + " " + entry.getApiPath());
        contextLabel.setToolTipText(entry.getDomain().isEmpty() ? null
                : entry.getDomain() + entry.getLastUrl());
        setBusy(false);

        clearChatArea();
        addSystemPanel("已切换到 " + entry.getHttpMethod() + " " + entry.getApiPath() + " 上下文");
        renderHistoryFor(newPath);
        if (chatContainer.getComponentCount() == 0) showEmptyState();
    }

    /** Jump straight to another stored conversation (session chip) — used to
     *  require re-selecting the table row, and the global conversation
     *  (where cascade notes land) had no entry point at all. */
    public void switchConversation(String key) {
        if (key == null || key.equals(currentApiPath)) return;
        currentApiPath = key;
        currentEntry = null;
        contextLabel.setText(sessionDisplayName(key));
        contextLabel.setToolTipText("__global__".equals(key) ? "全局会话" : key);
        setBusy(false);

        // After an analysis the panel sits in STEP mode; switching a
        // conversation only swaps the (hidden) chat pane, so the click looked
        // like a no-op. Reveal the conversation view.
        switchToChatMode();

        clearChatArea();
        addSystemPanel("已切换到会话: " + sessionDisplayName(key));
        renderHistoryFor(key);
        if (chatContainer.getComponentCount() == 0) showEmptyState();
    }

    /** Settle any still-running step cards — called when an analysis ends so
     *  the step counter converges to N/N instead of sticking (e.g. "34/44"). */
    public void finishSteps() {
        stepProgressPanel.finishAllSteps();
    }

    private void renderHistoryFor(String key) {
        List<ChatMessage> history = conversationHistory.get(key);
        if (history == null || history.isEmpty()) return;
        // Snapshot under the list lock — trim/append may run concurrently.
        List<ChatMessage> snapshot;
        synchronized (history) { snapshot = new ArrayList<>(history); }
        for (ChatMessage msg : snapshot) {
            switch (msg.role()) {
                case "user" -> addUserPanel(msg.content());
                case "assistant" -> addAiPanel(msg.content());
                case "system" -> addSystemPanel(msg.content());
            }
        }
    }

    /** Conversation-switcher menu, built on demand so it is always current.
     *  The global conversation (where cascade notes land) is always offered
     *  first, then the most recently accessed endpoint conversations. Labels
     *  are FULL paths (left-truncated when long) with the full key as
     *  tooltip — the old chips showed only the last path segment truncated,
     *  producing garbage like "search" / "fid}" / "detail". */
    private void showHistoryMenu() {
        JPopupMenu menu = new JPopupMenu();
        if (!"__global__".equals(currentApiPath)) {
            menu.add(historyMenuItem("__global__", "全局会话（通用提问 / 级联通知）"));
        }
        List<String> keys;
        synchronized (conversationHistory) {
            keys = new ArrayList<>(conversationHistory.keySet());
        }
        int added = 0;
        for (int i = keys.size() - 1; i >= 0 && added < 8; i--) {
            String key = keys.get(i);
            if (key.equals(currentApiPath) || "__global__".equals(key)) continue;
            List<ChatMessage> h = conversationHistory.get(key);
            if (h == null || h.isEmpty()) continue;
            menu.add(historyMenuItem(key, sessionDisplayName(key)));
            added++;
        }
        if (menu.getComponentCount() == 0) {
            JMenuItem empty = new JMenuItem("（暂无历史会话）");
            empty.setEnabled(false);
            menu.add(empty);
        }
        menu.show(historyMenuButton, 0, historyMenuButton.getHeight());
    }

    private JMenuItem historyMenuItem(String key, String display) {
        JMenuItem item = new JMenuItem(display);
        item.setToolTipText(key);
        item.addActionListener(e -> switchConversation(key));
        return item;
    }

    private static String sessionDisplayName(String key) {
        if ("__global__".equals(key)) return "全局会话";
        return key.length() > 30 ? "…" + key.substring(key.length() - 29) : key;
    }

    public void addUserMessage(String text) {
        SwingUtilities.invokeLater(() -> addUserPanel(text));
        storeMessage("user", text);
    }

    public void addAiMessage(String text) {
        SwingUtilities.invokeLater(() -> addAiPanel(text));
        storeMessage("assistant", text);
    }

    public void showThinking() {
        setBusy(true);
        SwingUtilities.invokeLater(() -> addSystemPanel("思考中..."));
    }

    public void appendProgressNote(String text) {
        SwingUtilities.invokeLater(() -> addSystemPanel(text));
    }

    public void addAiMessageAsync(String text) {
        SwingUtilities.invokeLater(() -> {
            addAiPanel(text);
            storeMessage("assistant", text);
        });
    }

    /** Append to a conversation, trimming the oldest messages beyond the cap. */
    private void appendToHistory(String key, ChatMessage msg) {
        List<ChatMessage> list = conversationHistory.computeIfAbsent(key,
                k -> Collections.synchronizedList(new ArrayList<>()));
        synchronized (list) {
            list.add(msg);
            while (list.size() > MAX_MESSAGES_PER_CONVERSATION) {
                list.remove(0);
            }
        }
    }

    public void addAiMessageForPath(String apiPath, String text) {
        SwingUtilities.invokeLater(() -> {
            String key = apiPath != null ? apiPath : "__global__";
            appendToHistory(key, new ChatMessage("assistant", text));
            if (key.equals(currentApiPath)) addAiPanel(text);
        });
    }

    public void appendProgressNoteForPath(String apiPath, String text) {
        SwingUtilities.invokeLater(() -> {
            String key = apiPath != null ? apiPath : "__global__";
            appendToHistory(key, new ChatMessage("system", text));
            if (key.equals(currentApiPath)) addSystemPanel(text);
        });
    }

    /** A cross-endpoint event note (cascade hunting triggers, breaker trips):
     *  ALWAYS rendered in the current conversation — the user may be viewing
     *  any endpoint when a cascade fires on another — and persisted to the
     *  global conversation so it survives context switches. */
    public void addGlobalNote(String text) {
        SwingUtilities.invokeLater(() -> {
            addSystemPanel(text);
            appendToHistory("__global__", new ChatMessage("system", text));
        });
    }

    public void clearHistoryForPath(String apiPath) {
        String key = apiPath != null ? apiPath : "__global__";
        conversationHistory.remove(key);
        // Flag the removal so the debounced flusher persists it — otherwise a
        // deleted conversation resurrects on the next launch.
        chatDirty.set(true);
        if (key.equals(currentApiPath)) {
            clearChatArea();
            addSystemPanel("已清除历史对话，开始新的分析...");
            if (chatContainer.getComponentCount() == 0) showEmptyState();
        }
    }

    public void setContextAsync(ApiEntry entry) {
        SwingUtilities.invokeLater(() -> setContext(entry));
    }

    public void replaceLastAiMessage(String text) {
        setBusy(false);
        SwingUtilities.invokeLater(() -> {
            // Remove the last "thinking" system panel if present
            int count = chatContainer.getComponentCount();
            if (count > 0) {
                Component last = chatContainer.getComponent(count - 1);
                if (last instanceof ChatMessagePanel) {
                    chatContainer.remove(count - 1);
                }
            }
            addAiPanel(text);
            storeMessage("assistant", text);
        });
    }

    public void replaceToolProgressWithReply(String text) {
        setBusy(false);
        SwingUtilities.invokeLater(() -> {
            // Remove all panels added after the user's last message (tool progress + "正在执行工具调用...")
            int userIdx = -1;
            for (int i = chatContainer.getComponentCount() - 1; i >= 0; i--) {
                Component c = chatContainer.getComponent(i);
                if (c instanceof ChatMessagePanel) {
                    // Check if it's a user card by background color
                    if (isUserPanel(c)) {
                        userIdx = i;
                        break;
                    }
                }
            }
            if (userIdx >= 0) {
                while (chatContainer.getComponentCount() > userIdx + 1) {
                    chatContainer.remove(chatContainer.getComponentCount() - 1);
                }
            }
            addAiPanel(text);
            storeMessage("assistant", text);
        });
    }

    private boolean isUserPanel(Component c) {
        if (!(c instanceof JPanel panel)) return false;
        for (Component child : panel.getComponents()) {
            if (child instanceof JPanel outer) {
                for (Component gc : outer.getComponents()) {
                    if (gc instanceof JPanel card) {
                        Color bg = card.getBackground();
                        if (bg != null && bg.equals(theme.userCardBg())) return true;
                    }
                }
            }
        }
        return false;
    }

    public List<ChatMessage> getCurrentHistory() {
        if (currentApiPath == null) return List.of();
        List<ChatMessage> history = conversationHistory.get(currentApiPath);
        if (history == null) return List.of();
        synchronized (history) { return new ArrayList<>(history); }
    }

    public ApiEntry getCurrentEntry() { return currentEntry; }

    /** Conversation key currently bound (endpoint path or "__global__");
     *  null when no context was ever set — showChatWindow uses this to adopt
     *  the table selection on first open. */
    public String getCurrentApiPath() { return currentApiPath; }

    // --- Private panel rendering ---

    private void clearChatArea() {
        chatContainer.removeAll();
        chatContainer.revalidate();
        chatContainer.repaint();
    }

    private void addUserPanel(String text) {
        addPanelSmart(ChatMessagePanel.userMessage(text, theme));
    }

    private void addAiPanel(String text) {
        addPanelSmart(ChatMessagePanel.aiMessage(text, theme));
    }

    private void addSystemPanel(String text) {
        addPanelSmart(ChatMessagePanel.noteMessage(text, theme,
                ChatMessagePanel.classifyNoteColor(text, theme)));
    }

    /** Auto-scroll only when the viewport is already near the bottom — a
     *  blanket scrollToBottom used to yank the view away while the user was
     *  reading earlier messages; now a "↓ 新消息" hint appears instead. */
    private void addPanelSmart(ChatMessagePanel panel) {
        boolean auto = isNearBottom();
        removeEmptyState();
        chatContainer.add(panel);
        chatContainer.revalidate();
        chatContainer.repaint();
        if (auto) {
            forceScrollToBottom();
            hideNewMsgIndicator();
        } else {
            showNewMsgIndicator();
        }
    }

    private boolean isNearBottom() {
        JScrollBar b = chatScroll.getVerticalScrollBar();
        return b.getMaximum() - b.getValue() - b.getVisibleAmount() < 48;
    }

    private void forceScrollToBottom() {
        SwingUtilities.invokeLater(() -> {
            chatContainer.revalidate();
            JScrollBar vbar = chatScroll.getVerticalScrollBar();
            vbar.setValue(vbar.getMaximum());
        });
    }

    private void showNewMsgIndicator() {
        newMsgIndicator.setText("↓ 有新消息，点击回到底部");
    }

    private void hideNewMsgIndicator() {
        newMsgIndicator.setText(" ");
    }

    private void showEmptyState() {
        if (!chatContainer.isAncestorOf(emptyStateWrapper)) {
            chatContainer.add(emptyStateWrapper);
            chatContainer.revalidate();
            chatContainer.repaint();
        }
    }

    private void removeEmptyState() {
        if (chatContainer.isAncestorOf(emptyStateWrapper)) {
            chatContainer.remove(emptyStateWrapper);
        }
    }

    private void storeMessage(String role, String content) {
        String key = currentApiPath != null ? currentApiPath : "__global__";
        appendToHistory(key, new ChatMessage(role, content));
        chatDirty.set(true);
    }

    @SuppressWarnings("unchecked")
    private void loadChatHistory() {
        try {
            if (!java.nio.file.Files.exists(CHAT_FILE)) return;
            String json = java.nio.file.Files.readString(CHAT_FILE);
            var obj = GSON.fromJson(json, com.google.gson.JsonObject.class);
            if (obj == null) return;
            for (var e : obj.entrySet()) {
                String path = e.getKey();
                var arr = e.getValue().getAsJsonArray();
                java.util.List<ChatMessage> msgs = Collections.synchronizedList(new ArrayList<>());
                for (var el : arr) {
                    var m = el.getAsJsonObject();
                    msgs.add(new ChatMessage(
                            m.has("role") ? m.get("role").getAsString() : "system",
                            m.has("content") ? m.get("content").getAsString() : ""));
                }
                // Keep only the most recent messages within the cap.
                while (msgs.size() > MAX_MESSAGES_PER_CONVERSATION) msgs.remove(0);
                if (!msgs.isEmpty()) conversationHistory.put(path, msgs);
            }
        } catch (Exception ignored) {}
    }

    private void flushChatIfDirty() {
        if (chatDirty.compareAndSet(true, false)) saveChatHistory();
    }

    private void saveChatHistory() {
        try {
            java.nio.file.Path dir = CHAT_FILE.getParent();
            if (dir != null) java.nio.file.Files.createDirectories(dir);
            com.google.gson.JsonObject root = new com.google.gson.JsonObject();
            // synchronizedMap + synchronized list: both iterations need
            // explicit locking (LRU map is access-ordered and gets mutated
            // by reads; lists get appended/trimmed from other threads).
            synchronized (conversationHistory) {
                for (var e : conversationHistory.entrySet()) {
                    com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
                    List<ChatMessage> list = e.getValue();
                    synchronized (list) {
                        for (ChatMessage m : list) {
                            com.google.gson.JsonObject mo = new com.google.gson.JsonObject();
                            mo.addProperty("role", m.role());
                            mo.addProperty("content", m.content());
                            arr.add(mo);
                        }
                    }
                    root.add(e.getKey(), arr);
                }
            }
            java.nio.file.Files.writeString(CHAT_FILE, GSON.toJson(root));
        } catch (Exception ignored) {}
    }

    public record ChatMessage(String role, String content) {}

    public void shutdown() {
        // Stop any still-running per-message animation timers (e.g. "思考中..."
        // spinner) so they don't keep UI components / the old ClassLoader alive.
        if (chatContainer != null) {
            for (java.awt.Component c : chatContainer.getComponents()) {
                Object t = (c instanceof JComponent jc) ? jc.getClientProperty("anim-timer") : null;
                if (t instanceof Timer timer) timer.stop();
            }
        }
        if (stepProgressPanel != null) stepProgressPanel.dispose();
        flushChatIfDirty();
        chatFlusher.shutdownNow();
        try {
            chatFlusher.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    // ======================== Step Mode Methods ========================

    /** Switch to the step view, clearing any previous steps. Used when a NEW
     *  analysis starts (fresh step list). */
    public void switchToStepMode() {
        switchToStepMode(true);
    }

    /** @param clearSteps true to wipe existing steps (new analysis starting);
     *  false to just reveal the current steps (user toggling the view). */
    public void switchToStepMode(boolean clearSteps) {
        SwingUtilities.invokeLater(() -> {
            inStepMode = true;
            if (clearSteps) stepProgressPanel.clear();
            contentLayout.show(contentCards, "steps");
            viewToggleBtn.setText("对话视图");
        });
    }

    public void switchToChatMode() {
        SwingUtilities.invokeLater(() -> {
            inStepMode = false;
            contentLayout.show(contentCards, "chat");
            viewToggleBtn.setText("步骤视图");
        });
    }

    public boolean isInStepMode() { return inStepMode; }

    public void addStep(String name, StepProgressPanel.StepType type, String summary) {
        stepProgressPanel.addStep(name, type, summary);
    }

    public void completeCurrentStep(String detail) {
        stepProgressPanel.completeCurrentStep(detail);
    }

    public void completeCurrentStep(String detail, String rawRequest, String rawResponse) {
        stepProgressPanel.completeCurrentStep(detail, rawRequest, rawResponse);
    }

    public void completeCurrentStep() {
        stepProgressPanel.completeCurrentStep();
    }

    public void showFinalResponse(String markdown) {
        setBusy(false);
        stepProgressPanel.addCompletedStep("Response", StepProgressPanel.StepType.RESPONSE, markdown);
        storeMessage("assistant", markdown);
    }
}
