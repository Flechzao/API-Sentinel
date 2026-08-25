package com.flechazo.apisentinel.ai.provider;

import java.util.List;

public record LlmRequest(
    String systemPrompt,
    String userPrompt,
    double temperature,
    int maxTokens,
    String responseFormat,
    List<ChatMessage> messages,
    List<ToolDefinition> tools,
    String modelOverride,
    Integer thinkingBudgetTokens
) {
    public LlmRequest(String systemPrompt, String userPrompt) {
        this(systemPrompt, userPrompt, 0.1, 4096, "json", null, null, null, null);
    }

    public LlmRequest(String systemPrompt, String userPrompt, int maxTokens) {
        this(systemPrompt, userPrompt, 0.1, maxTokens, "json", null, null, null, null);
    }

    public LlmRequest(String systemPrompt, String userPrompt, double temperature, int maxTokens, String responseFormat) {
        this(systemPrompt, userPrompt, temperature, maxTokens, responseFormat, null, null, null, null);
    }

    public LlmRequest(List<ChatMessage> messages, List<ToolDefinition> tools, double temperature, int maxTokens) {
        this(null, null, temperature, maxTokens, null, messages, tools, null, null);
    }

    public boolean isMultiTurn() {
        return messages != null && !messages.isEmpty();
    }

    public boolean hasTools() {
        return tools != null && !tools.isEmpty();
    }

    /** Return a copy of this request that asks the provider to use a specific
     *  model instead of its configured default — used for multi-model tiering
     *  (e.g. a cheap model for Stage-1 traffic triage). Null override keeps the
     *  provider's default model. */
    public LlmRequest withModelOverride(String model) {
        return new LlmRequest(systemPrompt, userPrompt, temperature, maxTokens,
                responseFormat, messages, tools, model, thinkingBudgetTokens);
    }

    /** Return a copy of this request with extended thinking requested at the
     *  given budget. Providers that don't support thinking (see
     *  {@link LlmProvider#supportsExtendedThinking()}) ignore this field. */
    public LlmRequest withThinking(int budgetTokens) {
        return new LlmRequest(systemPrompt, userPrompt, temperature, maxTokens,
                responseFormat, messages, tools, modelOverride, budgetTokens);
    }
}
