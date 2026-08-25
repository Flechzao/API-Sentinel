package com.flechazo.apisentinel.ai.provider;

import java.util.List;

public record LlmResponse(
    String content,
    int promptTokens,
    int completionTokens,
    long latencyMs,
    String model,
    FinishReason finishReason,
    String errorMessage,
    List<ToolCall> toolCalls,
    String thinkingText,
    String rawThinkingBlocksJson
) {
    public enum FinishReason {
        COMPLETE, MAX_TOKENS, ERROR, RATE_LIMITED, TOOL_USE
    }

    public LlmResponse(String content, int promptTokens, int completionTokens,
                       long latencyMs, String model, FinishReason finishReason, String errorMessage) {
        this(content, promptTokens, completionTokens, latencyMs, model, finishReason, errorMessage, null, null, null);
    }

    public LlmResponse(String content, int promptTokens, int completionTokens,
                       long latencyMs, String model, FinishReason finishReason, String errorMessage,
                       List<ToolCall> toolCalls) {
        this(content, promptTokens, completionTokens, latencyMs, model, finishReason, errorMessage, toolCalls, null, null);
    }

    public boolean isSuccess() {
        return finishReason == FinishReason.COMPLETE || finishReason == FinishReason.MAX_TOKENS
               || finishReason == FinishReason.TOOL_USE;
    }

    public int totalTokens() {
        return promptTokens + completionTokens;
    }

    public boolean hasToolCalls() {
        return toolCalls != null && !toolCalls.isEmpty();
    }

    public static LlmResponse error(String message) {
        return new LlmResponse("", 0, 0, 0, "", FinishReason.ERROR, message, null);
    }
}
