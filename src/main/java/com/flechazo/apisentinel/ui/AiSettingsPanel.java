package com.flechazo.apisentinel.ui;

import burp.api.montoya.ui.settings.SettingsPanel;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.provider.LlmRequest;

import javax.swing.*;
import java.awt.*;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

public class AiSettingsPanel extends JPanel implements SettingsPanel {

    private static final int DEFAULT_CONTEXT_WINDOW_TOKENS = 150_000;
    private static final int MIN_CONTEXT_WINDOW_TOKENS = 8_000;
    private static final int DEFAULT_DAILY_BUDGET_TOKENS = 500_000;
    private static final int MIN_DAILY_BUDGET_TOKENS = 10_000;
    private static final int DEFAULT_PER_REQUEST_MAX_TOKENS = 50_000;
    private static final int MIN_PER_REQUEST_MAX_TOKENS = 1_000;

    private final JTextField endpointField;
    private final JPasswordField apiKeyField;
    private final JTextField modelField;
    private final JTextField fastModelField;
    private final JTextField contextWindowField;
    private final JTextField dailyBudgetField;
    private final JTextField perRequestMaxField;
    private final JComboBox<String> providerCombo;
    private final JLabel statusLabel;
    private final JButton testButton;
    private final JButton saveButton;
    private JButton toolMgmtBtn;

    private BudgetConfigCallback budgetConfigCallback;

    public interface BudgetConfigCallback {
        void onBudgetConfigChanged(int dailyBudgetTokens, int perRequestMaxTokens);
    }

    private final JCheckBox includeRawCredentialsCheck;
    private JCheckBox funFeaturesCheck;
    private JCheckBox modelTieringCheck;

    public interface ModelTieringCallback { void onModelTieringChanged(boolean enabled); }
    private ModelTieringCallback modelTieringCallback;
    public void setModelTieringCallback(ModelTieringCallback cb) { this.modelTieringCallback = cb; }
    public void setModelTieringEnabled(boolean enabled) {
        if (modelTieringCheck != null) modelTieringCheck.setSelected(enabled);
    }
    
    private JCheckBox unlimitedBudgetCheck;
    private boolean disclosureAcceptedThisSession = false;
    private boolean includeRawCredentialsPersisted = false;
    private IncludeRawCredentialsCallback includeRawCredentialsCallback;

    public interface IncludeRawCredentialsCallback {
        void onIncludeRawCredentialsChanged(boolean include);
    }

    public void setIncludeRawCredentialsCallback(IncludeRawCredentialsCallback cb) {
        this.includeRawCredentialsCallback = cb;
    }

    public void setIncludeRawCredentialsPersisted(boolean persisted) {
        this.includeRawCredentialsPersisted = persisted;
    }

    private LlmProviderFactory providerFactory;
    private Consumer<String> onProviderChanged;
    private IntConsumer onContextWindowChanged;
    private ToolConfigCallback onToolConfigChanged;
    private final BurpTheme theme;

    @FunctionalInterface
    public interface ToolConfigCallback {
        void onChange(java.util.Set<String> disabledTools, java.util.Set<String> toolsRequiringAuth);
        default java.util.Set<String> getDisabledTools() { return java.util.Set.of(); }
        default java.util.Set<String> getAuthTools() { return java.util.Set.of(); }
    }

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

        JLabel title = new JLabel(I18n.get("ai_settings_provider_config_title"));
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(title, gbc);
        row++;

        gbc.gridwidth = 1;

        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_provider")), gbc);
        providerCombo = new JComboBox<>(new String[]{"ollama", "claude", "openai", "deepseek", "custom"});
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(providerCombo, gbc);
        row++;

        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_endpoint")), gbc);
        endpointField = new JTextField("http://localhost:11434", 40);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(endpointField, gbc);
        row++;

        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_api_key")), gbc);
        apiKeyField = new JPasswordField(40);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(apiKeyField, gbc);
        row++;

        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_model")), gbc);
        modelField = new JTextField("llama3", 30);
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(modelField, gbc);
        row++;

        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_fast_model")), gbc);
        fastModelField = new JTextField("DeepSeek-V4-Flash-Vision-Exp", 30);
        fastModelField.setToolTipText(I18n.get("ai_settings_fast_model_tooltip"));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(fastModelField, gbc);
        row++;

        modelTieringCheck = new JCheckBox(I18n.get("ai_settings_model_tiering"));
        modelTieringCheck.setToolTipText(I18n.get("ai_settings_model_tiering_tooltip"));
        modelTieringCheck.setSelected(false);
        modelTieringCheck.addActionListener(e -> {
            if (modelTieringCallback != null) modelTieringCallback.onModelTieringChanged(modelTieringCheck.isSelected());
        });
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3; gbc.weightx = 1.0;
        add(modelTieringCheck, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_context_window")), gbc);
        contextWindowField = new JTextField(String.valueOf(DEFAULT_CONTEXT_WINDOW_TOKENS), 30);
        contextWindowField.setToolTipText(String.format(I18n.get("ai_settings_context_window_tooltip"), MIN_CONTEXT_WINDOW_TOKENS));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(contextWindowField, gbc);
        row++;

        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_daily_budget")), gbc);
        dailyBudgetField = new JTextField(String.valueOf(DEFAULT_DAILY_BUDGET_TOKENS), 30);
        dailyBudgetField.setToolTipText(String.format(I18n.get("ai_settings_daily_budget_tooltip"), MIN_DAILY_BUDGET_TOKENS));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(dailyBudgetField, gbc);
        row++;

        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_per_request_max")), gbc);
        perRequestMaxField = new JTextField(String.valueOf(DEFAULT_PER_REQUEST_MAX_TOKENS), 30);
        perRequestMaxField.setToolTipText(String.format(I18n.get("ai_settings_per_request_max_tooltip"), MIN_PER_REQUEST_MAX_TOKENS));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(perRequestMaxField, gbc);
        row++;

        unlimitedBudgetCheck = new JCheckBox(I18n.get("ai_settings_unlimited_budget"));
        unlimitedBudgetCheck.setFont(theme.displayFont(Font.PLAIN, 12f));
        unlimitedBudgetCheck.setToolTipText(I18n.get("ai_settings_unlimited_budget_tooltip"));
        unlimitedBudgetCheck.addActionListener(e -> {
            boolean unlimited = unlimitedBudgetCheck.isSelected();
            dailyBudgetField.setEnabled(!unlimited);
            perRequestMaxField.setEnabled(!unlimited);
        });
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(unlimitedBudgetCheck, gbc);
        row++;

        includeRawCredentialsCheck = new JCheckBox(
                "LLM 发送前脱敏凭证 (仅合规/不信任 LLM 提供商时开启)");
        includeRawCredentialsCheck.setToolTipText(I18n.get("ai_settings_redact_credentials_tooltip"));
        includeRawCredentialsCheck.setSelected(false);
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3; gbc.weightx = 1.0;
        add(includeRawCredentialsCheck, gbc);
        gbc.gridwidth = 1;
        row++;

        // Fun features toggle
        funFeaturesCheck = new JCheckBox("启用成就系统");
        funFeaturesCheck.setToolTipText("发现漏洞时解锁成就、显示粒子特效。统计/成就/图鉴在设置中查看。");
        funFeaturesCheck.setSelected(true);
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3; gbc.weightx = 1.0;
        add(funFeaturesCheck, gbc);
        gbc.gridwidth = 1;
        row++;

        includeRawCredentialsCheck.addActionListener(e -> {
            if (includeRawCredentialsCheck.isSelected()
                    && !disclosureAcceptedThisSession
                    && !includeRawCredentialsPersisted) {
                int choice = javax.swing.JOptionPane.showConfirmDialog(
                        this,
                        I18n.get("ai_settings_redact_disclosure_title") + "\n\n"
                        + I18n.get("ai_settings_redact_disclosure_msg"),
                        I18n.get("ai_settings_redact_disclosure_title"),
                        javax.swing.JOptionPane.YES_NO_OPTION,
                        javax.swing.JOptionPane.WARNING_MESSAGE);
                if (choice == javax.swing.JOptionPane.YES_OPTION) {
                    disclosureAcceptedThisSession = true;
                    if (includeRawCredentialsCallback != null) {
                        includeRawCredentialsCallback.onIncludeRawCredentialsChanged(true);
                    }
                } else {
                    includeRawCredentialsCheck.setSelected(false);
                }
            } else if (!includeRawCredentialsCheck.isSelected()) {
                if (includeRawCredentialsCallback != null) {
                    includeRawCredentialsCallback.onIncludeRawCredentialsChanged(false);
                }
            }
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        testButton = new JButton(I18n.get("ai_settings_test_connection"));
        testButton.addActionListener(e -> testConnection());
        saveButton = new JButton(I18n.get("ai_settings_save_config"));
        saveButton.addActionListener(e -> saveConfig());
        toolMgmtBtn = new JButton(I18n.get("ai_settings_tool_management"));
        toolMgmtBtn.setFont(theme.displayFont(Font.BOLD, 12f));
        toolMgmtBtn.setToolTipText(I18n.get("ai_settings_tool_management_tooltip"));
        toolMgmtBtn.addActionListener(e -> {
            try {
                java.util.Set<String> disabled = onToolConfigChanged != null
                        ? onToolConfigChanged.getDisabledTools() : java.util.Set.of();
                java.util.Set<String> auth = onToolConfigChanged != null
                        ? onToolConfigChanged.getAuthTools() : java.util.Set.of();
                Window ancestor = SwingUtilities.getWindowAncestor(this);
                Frame owner = ancestor instanceof Frame ? (Frame) ancestor : null;
                ToolManagementDialog.showDialog(owner, theme, disabled, auth,
                        (d, a) -> {
                            if (onToolConfigChanged != null) {
                                onToolConfigChanged.onChange(d, a);
                            }
                        });
            } catch (Exception ex) {
                ThemedDialogs.error(this,
                        I18n.get("ai_settings_tool_mgmt_open_failed") + ex.getMessage(), I18n.get("ai_settings_error_title"));
            }
        });
        buttonPanel.add(testButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(toolMgmtBtn);

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(buttonPanel, gbc);
        row++;

        statusLabel = new JLabel(" ");
        statusLabel.setFont(theme.displayFont(Font.ITALIC, 12f));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(statusLabel, gbc);
        row++;

        gbc.gridy = row; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        add(new JLabel(), gbc);

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
                case "deepseek" -> {
                    endpointField.setText("https://api.deepseek.com/v1/chat/completions");
                    modelField.setText("deepseek-chat");
                }
            }
        });

        I18n.addLangListener(lang -> javax.swing.SwingUtilities.invokeLater(() -> {
            if (statusLabel != null) statusLabel.setText(I18n.get("ai_settings_saved"));
            if (testButton != null) testButton.setText(I18n.get("ai_settings_test_connection"));
            if (saveButton != null) saveButton.setText(I18n.get("ai_settings_save_config"));
            if (toolMgmtBtn != null) {
                toolMgmtBtn.setText(I18n.get("ai_settings_tool_management"));
                toolMgmtBtn.setToolTipText(I18n.get("ai_settings_tool_management_tooltip"));
            }
            if (modelTieringCheck != null) {
                modelTieringCheck.setText(I18n.get("ai_settings_model_tiering"));
                modelTieringCheck.setToolTipText(I18n.get("ai_settings_model_tiering_tooltip"));
            }
            if (includeRawCredentialsCheck != null) {
                includeRawCredentialsCheck.setText(I18n.get("ai_settings_redact_credentials"));
                includeRawCredentialsCheck.setToolTipText(I18n.get("ai_settings_redact_credentials_tooltip"));
            }
            if (unlimitedBudgetCheck != null) {
                unlimitedBudgetCheck.setText(I18n.get("ai_settings_unlimited_budget"));
                unlimitedBudgetCheck.setToolTipText(I18n.get("ai_settings_unlimited_budget_tooltip"));
            }
        }));
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

    public void setDailyBudgetTokens(int tokens) {
        dailyBudgetField.setText(String.valueOf(Math.max(MIN_DAILY_BUDGET_TOKENS, tokens)));
    }

    public void setUnlimitedBudget(boolean unlimited) {
        unlimitedBudgetCheck.setSelected(unlimited);
        dailyBudgetField.setEnabled(!unlimited);
        perRequestMaxField.setEnabled(!unlimited);
    }

    public int getDailyBudgetTokens() {
        try {
            return Math.max(MIN_DAILY_BUDGET_TOKENS, Integer.parseInt(dailyBudgetField.getText().trim()));
        } catch (NumberFormatException e) {
            return DEFAULT_DAILY_BUDGET_TOKENS;
        }
    }

    public void setPerRequestMaxTokens(int tokens) {
        perRequestMaxField.setText(String.valueOf(Math.max(MIN_PER_REQUEST_MAX_TOKENS, tokens)));
    }

    public int getPerRequestMaxTokens() {
        try {
            return Math.max(MIN_PER_REQUEST_MAX_TOKENS, Integer.parseInt(perRequestMaxField.getText().trim()));
        } catch (NumberFormatException e) {
            return DEFAULT_PER_REQUEST_MAX_TOKENS;
        }
    }

    public void setOnBudgetConfigChanged(BudgetConfigCallback callback) {
        this.budgetConfigCallback = callback;
    }

    private void testConnection() {
        testButton.setEnabled(false);
        testButton.setText(I18n.get("ai_settings_testing"));
        statusLabel.setText(I18n.get("ai_settings_testing_connection"));
        statusLabel.setForeground(theme.statusPending());

        String providerId = (String) providerCombo.getSelectedItem();
        LlmProvider provider = providerFactory.get(providerId != null ? providerId : "ollama");
        if (provider == null) {
            statusLabel.setText(I18n.get("ai_settings_unknown_provider") + providerId);
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
                statusLabel.setText(I18n.get("ai_settings_conn_timeout"));
                statusLabel.setForeground(theme.statusError());
                resetTestButton();
            });
        });
        timeout.setRepeats(false);
        timeout.start();

        future.thenAccept(ok -> {
            timeout.stop();
            if (ok) {
                String fm = fastModelField.getText();
                if (fm != null && !fm.isBlank()) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("主模型连接成功，正在测试轻量模型 (" + fm + ")...");
                    });
                    LlmRequest fastTestReq = new LlmRequest("You are a test.", "Reply 'ok'.", 10)
                            .withModelOverride(fm);
                    var fastFuture = provider.complete(fastTestReq).thenApply(r -> r.isSuccess());
                    javax.swing.Timer fastTimeout = new javax.swing.Timer(15000, e2 -> {
                        fastFuture.cancel(true);
                        SwingUtilities.invokeLater(() -> {
                            statusLabel.setText("主模型连接成功，但轻量模型测试超时 (" + fm + ")");
                            statusLabel.setForeground(theme.statusPending());
                            resetTestButton();
                        });
                    });
                    fastTimeout.setRepeats(false);
                    fastTimeout.start();
                    fastFuture.thenAccept(fastOk -> {
                        fastTimeout.stop();
                        SwingUtilities.invokeLater(() -> {
                            if (fastOk) {
                                statusLabel.setText(I18n.get("ai_settings_conn_success") + " (主模型 + 轻量模型均正常)");
                                statusLabel.setForeground(theme.statusOk());
                                testButton.setForeground(theme.statusOk());
                            } else {
                                statusLabel.setText("主模型连接成功，但轻量模型 (" + fm + ") 不可用 — Pipeline 将自动回退到主模型");
                                statusLabel.setForeground(theme.statusPending());
                                testButton.setForeground(theme.statusPending());
                            }
                            resetTestButton();
                        });
                    }).exceptionally(ex -> {
                        fastTimeout.stop();
                        SwingUtilities.invokeLater(() -> {
                            statusLabel.setText("主模型连接成功，但轻量模型 (" + fm + ") 测试异常 — Pipeline 将自动回退到主模型");
                            statusLabel.setForeground(theme.statusPending());
                            resetTestButton();
                        });
                        return null;
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText(I18n.get("ai_settings_conn_success"));
                        statusLabel.setForeground(theme.statusOk());
                        testButton.setForeground(theme.statusOk());
                        resetTestButton();
                    });
                }
            } else {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText(I18n.get("ai_settings_conn_failed"));
                    statusLabel.setForeground(theme.statusError());
                    testButton.setForeground(theme.statusError());
                    resetTestButton();
                });
            }
        }).exceptionally(ex -> {
            timeout.stop();
            SwingUtilities.invokeLater(() -> {
                String msg = ex.getCause() != null ? ex.getCause().getMessage() : ex.getMessage();
                statusLabel.setText(I18n.get("ai_settings_conn_error") + (msg != null ? msg : I18n.get("ai_settings_unknown_error")));
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

        try {
            java.nio.file.Path dir = AI_CONFIG_FILE.getParent();
            if (dir != null) java.nio.file.Files.createDirectories(dir);
            com.google.gson.JsonObject obj = new com.google.gson.JsonObject();
            obj.addProperty("provider", providerId);
            obj.addProperty("endpoint", endpointField.getText());
            obj.addProperty("apiKey", new String(apiKeyField.getPassword()));
            obj.addProperty("model", modelField.getText());
            obj.addProperty("fastModel", fastModelField.getText().trim());
            int dailyBudget = unlimitedBudgetCheck.isSelected() ? Integer.MAX_VALUE : getDailyBudgetTokens();
            int perRequestMax = unlimitedBudgetCheck.isSelected() ? Integer.MAX_VALUE : getPerRequestMaxTokens();
            obj.addProperty("dailyBudgetTokens", dailyBudget);
            obj.addProperty("perRequestMaxTokens", perRequestMax);
            obj.addProperty("unlimitedBudget", unlimitedBudgetCheck.isSelected());
            java.nio.file.Files.writeString(AI_CONFIG_FILE,
                    new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(obj));
            if (budgetConfigCallback != null) {
                budgetConfigCallback.onBudgetConfigChanged(dailyBudget, perRequestMax);
            }
        } catch (Exception e) {
            System.err.println("[API-Sentinel] AI config save failed: " + e.getMessage());
        }

        statusLabel.setText(I18n.get("ai_settings_saved"));
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

    public String getFastModel() {
        String s = fastModelField.getText();
        return s == null ? "" : s.trim();
    }

    public boolean isIncludeRawCredentials() { return includeRawCredentialsCheck.isSelected(); }

    public void setIncludeRawCredentials(boolean include) {
        includeRawCredentialsCheck.setSelected(include);
    }

    public void setOnToolConfigChanged(ToolConfigCallback callback) {
        this.onToolConfigChanged = callback;
    }

    @Override
    public JComponent uiComponent() {
        return this;
    }

    @Override
    public Set<String> keywords() {
        return Set.of("api-sentinel", "ai", "llm", "openai", "claude", "ollama", "provider", "model",
                "context", "tokens");
    }

    // === Fun features ===
    public void setFunFeaturesEnabled(boolean enabled) {
        if (funFeaturesCheck != null) funFeaturesCheck.setSelected(enabled);
    }

    public boolean isFunFeaturesEnabled() {
        return funFeaturesCheck != null && funFeaturesCheck.isSelected();
    }

    public void setOnFunFeaturesChanged(Runnable callback) {
        if (funFeaturesCheck != null) {
            funFeaturesCheck.addActionListener(e -> callback.run());
        }
    }
}
