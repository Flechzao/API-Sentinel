package com.flechazo.apisentinel.ui;

import burp.api.montoya.ui.settings.SettingsPanel;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;

import javax.swing.*;
import java.awt.*;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

public class AiSettingsPanel extends JPanel implements SettingsPanel {

    private static final int DEFAULT_CONTEXT_WINDOW_TOKENS = 150_000;
    private static final int MIN_CONTEXT_WINDOW_TOKENS = 8_000;

    private final JTextField endpointField;
    private final JPasswordField apiKeyField;
    private final JTextField modelField;
    private final JTextField fastModelField;
    private final JTextField contextWindowField;
    private final JComboBox<String> providerCombo;
    private final JLabel statusLabel;
    private final JButton testButton;
    private final JButton saveButton;

    private LlmProviderFactory providerFactory;
    private Consumer<String> onProviderChanged;
    private IntConsumer onContextWindowChanged;
    private final BurpTheme theme;

    public AiSettingsPanel(LlmProviderFactory providerFactory, Consumer<String> onProviderChanged,
                            IntConsumer onContextWindowChanged, BurpTheme theme) {
        this.providerFactory = providerFactory;
        this.onProviderChanged = onProviderChanged;
        this.onContextWindowChanged = onContextWindowChanged;
        this.theme = theme;

        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        // Title
        JLabel title = new JLabel("AI Provider 配置");
        // 14, not 16 — matches SensitiveRulesPanel/CodeRepoPanel/AuthConfigPanel's
        // titles; the extra 2pt made this tab's heading visibly jump in size
        // when switching between settings sub-tabs.
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(title, gbc);
        row++;

        gbc.gridwidth = 1;

        // Provider selector
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel("服务商:"), gbc);
        providerCombo = new JComboBox<>(new String[]{"ollama", "claude", "openai", "custom"});
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(providerCombo, gbc);
        row++;

        // Endpoint
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel("接口地址:"), gbc);
        endpointField = new JTextField("http://localhost:11434", 40);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(endpointField, gbc);
        row++;

        // API Key
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel("API 密钥:"), gbc);
        apiKeyField = new JPasswordField(40);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(apiKeyField, gbc);
        row++;

        // Model
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel("模型:"), gbc);
        modelField = new JTextField("llama3", 30);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(modelField, gbc);
        row++;

        // Fast/cheap model for Stage-1 traffic triage (multi-model tiering).
        // Reuses the same provider/endpoint/key as the main model — only the
        // model name differs. Leave empty to disable tiering (use main model).
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel("轻量模型(初筛):"), gbc);
        fastModelField = new JTextField("", 30);
        fastModelField.setToolTipText(
                "可选。用于 Pipeline 第 1 阶段流量初筛的便宜/快速模型（同一 endpoint 与 key，仅模型名不同），"
                + "例如 Claude Haiku / GPT-4o-mini。深挖（payload 生成、最终研判）仍用上方主模型。"
                + "留空 = 不分层，全程用主模型。");
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(fastModelField, gbc);
        row++;

        // Context window (tokens) — sizes the Agent loop's compaction budget.
        // Not auto-detected: cloud models (Claude/GPT) can take a much larger
        // value; local Ollama models vary widely by what you pulled/quantized.
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel("上下文窗口(tokens):"), gbc);
        contextWindowField = new JTextField(String.valueOf(DEFAULT_CONTEXT_WINDOW_TOKENS), 30);
        contextWindowField.setToolTipText(
                "Agent/对话模式的上下文压缩预算。按你所选模型的真实上下文窗口填——"
                + "Claude/GPT 等云端模型可以填大一些，本地 Ollama 模型请按实际拉取的模型规格填，"
                + "不会自动检测。最小 " + MIN_CONTEXT_WINDOW_TOKENS + "。");
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(contextWindowField, gbc);
        row++;

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        testButton = new JButton("测试连接");
        testButton.addActionListener(e -> testConnection());
        saveButton = new JButton("保存配置");
        saveButton.addActionListener(e -> saveConfig());
        buttonPanel.add(testButton);
        buttonPanel.add(saveButton);

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(buttonPanel, gbc);
        row++;

        // Status
        statusLabel = new JLabel(" ");
        statusLabel.setFont(theme.displayFont(Font.ITALIC, 12f));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(statusLabel, gbc);
        row++;

        // Spacer
        gbc.gridy = row; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        add(new JLabel(), gbc);

        // Provider change handler
        providerCombo.addActionListener(e -> {
            String selected = (String) providerCombo.getSelectedItem();
            switch (selected) {
                case "ollama" -> {
                    endpointField.setText("http://localhost:11434");
                    modelField.setText("llama3");
                }
                case "claude" -> {
                    endpointField.setText("https://api.anthropic.com");
                    modelField.setText("claude-sonnet-4-20250514");
                }
                case "openai" -> {
                    endpointField.setText("https://api.openai.com/v1/chat/completions");
                    modelField.setText("gpt-4o");
                }
            }
        });
    }

    public void setConfig(String provider, String endpoint, String apiKey, String model) {
        setConfig(provider, endpoint, apiKey, model, "");
    }

    public void setConfig(String provider, String endpoint, String apiKey, String model, String fastModel) {
        providerCombo.setSelectedItem(provider);
        endpointField.setText(endpoint);
        apiKeyField.setText(apiKey);
        modelField.setText(model);
        fastModelField.setText(fastModel != null ? fastModel : "");
    }

    public void setContextWindowTokens(int tokens) {
        contextWindowField.setText(String.valueOf(Math.max(MIN_CONTEXT_WINDOW_TOKENS, tokens)));
    }

    public int getContextWindowTokens() {
        try {
            return Math.max(MIN_CONTEXT_WINDOW_TOKENS, Integer.parseInt(contextWindowField.getText().trim()));
        } catch (NumberFormatException e) {
            return DEFAULT_CONTEXT_WINDOW_TOKENS;
        }
    }

    private void testConnection() {
        testButton.setEnabled(false);
        testButton.setText("测试中...");
        statusLabel.setText("正在测试连接...");
        statusLabel.setForeground(theme.statusPending());

        String providerId = (String) providerCombo.getSelectedItem();
        LlmProvider provider = providerFactory.get(providerId != null ? providerId : "ollama");
        if (provider == null) {
            statusLabel.setText("未知 Provider: " + providerId);
            statusLabel.setForeground(theme.statusError());
            resetTestButton();
            return;
        }

        provider.configure(endpointField.getText(),
                new String(apiKeyField.getPassword()),
                modelField.getText());

        var future = provider.testConnection();

        javax.swing.Timer timeout = new javax.swing.Timer(15000, e -> {
            future.cancel(true);
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("连接超时 (15s) ✗");
                statusLabel.setForeground(theme.statusError());
                resetTestButton();
            });
        });
        timeout.setRepeats(false);
        timeout.start();

        future.thenAccept(ok -> {
            timeout.stop();
            SwingUtilities.invokeLater(() -> {
                if (ok) {
                    statusLabel.setText("连接成功 ✓");
                    statusLabel.setForeground(theme.statusOk());
                    testButton.setForeground(theme.statusOk());
                } else {
                    statusLabel.setText("连接失败 ✗");
                    statusLabel.setForeground(theme.statusError());
                    testButton.setForeground(theme.statusError());
                }
                resetTestButton();
            });
        }).exceptionally(ex -> {
            timeout.stop();
            SwingUtilities.invokeLater(() -> {
                String msg = ex.getCause() != null ? ex.getCause().getMessage() : ex.getMessage();
                statusLabel.setText("连接异常: " + (msg != null ? msg : "未知错误"));
                statusLabel.setForeground(theme.statusError());
                testButton.setForeground(theme.statusError());
                resetTestButton();
            });
            return null;
        });
    }

    private void resetTestButton() {
        testButton.setText(I18n.get("test_conn"));
        testButton.setEnabled(true);
        javax.swing.Timer resetColor = new javax.swing.Timer(2000, e -> testButton.setForeground(null));
        resetColor.setRepeats(false);
        resetColor.start();
    }

    private static final java.nio.file.Path AI_CONFIG_FILE = com.flechazo.apisentinel.config.AppPaths.aiConfigFile();

    private void saveConfig() {
        String providerId = (String) providerCombo.getSelectedItem();
        LlmProvider provider = providerFactory.get(providerId != null ? providerId : "ollama");
        if (provider != null) {
            provider.configure(endpointField.getText(),
                    new String(apiKeyField.getPassword()),
                    modelField.getText());
        }
        if (onProviderChanged != null) {
            onProviderChanged.accept(providerId);
        }
        if (onContextWindowChanged != null) {
            onContextWindowChanged.accept(getContextWindowTokens());
        }

        // Persist to disk
        try {
            java.nio.file.Path dir = AI_CONFIG_FILE.getParent();
            if (dir != null) java.nio.file.Files.createDirectories(dir);
            com.google.gson.JsonObject obj = new com.google.gson.JsonObject();
            obj.addProperty("provider", providerId);
            obj.addProperty("endpoint", endpointField.getText());
            obj.addProperty("apiKey", new String(apiKeyField.getPassword()));
            obj.addProperty("model", modelField.getText());
            obj.addProperty("fastModel", fastModelField.getText().trim());
            java.nio.file.Files.writeString(AI_CONFIG_FILE,
                    new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(obj));
        } catch (Exception e) {
            System.err.println("[API-Sentinel] AI config save failed: " + e.getMessage());
        }

        statusLabel.setText("已保存");
        statusLabel.setForeground(theme.statusOk());
    }

    public String getSelectedProvider() {
        return (String) providerCombo.getSelectedItem();
    }

    public String getEndpoint() {
        return endpointField.getText();
    }

    public String getApiKey() {
        return new String(apiKeyField.getPassword());
    }

    public String getModel() {
        return modelField.getText();
    }

    /** Cheaper model for Stage-1 triage; empty string means tiering disabled. */
    public String getFastModel() {
        String s = fastModelField.getText();
        return s == null ? "" : s.trim();
    }

    // ── SettingsPanel interface ──

    @Override
    public JComponent uiComponent() {
        return this;
    }

    @Override
    public Set<String> keywords() {
        return Set.of("api-sentinel", "ai", "llm", "openai", "claude", "ollama", "provider", "model", "context", "tokens");
    }
}
