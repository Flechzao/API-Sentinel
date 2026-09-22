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
    String rawThinkingBlocksJson,
    /** Tokens written to the provider's prompt cache on this call (Anthropic:
     *  {@code usage.cache_creation_input_tokens}; OpenAI:
     *  {@code usage.prompt_tokens_details.cached_tokens} for <i>misses</i> —
     *  OpenAI only reports reads, so this stays 0 on OpenAI responses).
     *  Billed at the write rate. Zero when caching was not requested or
     *  the provider didn't return the field. */
    int cacheCreationInputTokens,
    /** Tokens served from the provider's prompt cache (Anthropic:
     *  {@code usage.cache_read_input_tokens}; OpenAI:
     *  {@code usage.prompt_tokens_details.cached_tokens}).
     *  Billed at the read rate (~10% of input on Anthropic, ~50% on OpenAI).
     *  Zero when nothing was cached yet or caching was not requested. */
    int cacheReadInputTokens
) {
    public enum FinishReason {
        COMPLETE, MAX_TOKENS, ERROR, RATE_LIMITED, TOOL_USE
    }

    public LlmResponse(String content, int promptTokens, int completionTokens,
                       long latencyMs, String model, FinishReason finishReason, String errorMessage) {
        this(content, promptTokens, completionTokens, latencyMs, model, finishReason, errorMessage, null, null, null, 0, 0);
    }

    public LlmResponse(String content, int promptTokens, int completionTokens,
                       long latencyMs, String model, FinishReason finishReason, String errorMessage,
                       List<ToolCall> toolCalls) {
        this(content, promptTokens, completionTokens, latencyMs, model, finishReason, errorMessage, toolCalls, null, null, 0, 0);
    }

    public LlmResponse(String content, int promptTokens, int completionTokens,
                       long latencyMs, String model, FinishReason finishReason, String errorMessage,
                       List<ToolCall> toolCalls, String thinkingText, String rawThinkingBlocksJson) {
        this(content, promptTokens, completionTokens, latencyMs, model, finishReason, errorMessage,
                toolCalls, thinkingText, rawThinkingBlocksJson, 0, 0);
    }

    public boolean isSuccess() {
        return finishReason == FinishReason.COMPLETE || finishReason == FinishReason.MAX_TOKENS
               || finishReason == FinishReason.TOOL_USE;
    }

    /** Total input-side tokens reported by the provider. Note: for Anthropic,
     *  {@code input_tokens} already excludes cache reads (those live in
     *  {@link #cacheReadInputTokens}), so the <i>billable</i> input footprint
     *  is {@code promptTokens + cacheCreationInputTokens + cacheReadInputTokens * readRate}.
     *  Use {@link #billableInputTokens()} for cost math. */
    public int totalTokens() {
        return promptTokens + completionTokens;
    }

    /** Sum of every token category the provider reported for this call —
     *  the number that actually hits the invoice. For providers that don't
     *  separate cache fields, this equals {@link #totalTokens()}. */
    public int billableInputTokens() {
        return promptTokens + cacheCreationInputTokens + cacheReadInputTokens;
    }

    public boolean hasToolCalls() {
        return toolCalls != null && !toolCalls.isEmpty();
    }

    public static LlmResponse error(String message) {
        return new LlmResponse("", 0, 0, 0, "", FinishReason.ERROR, message, null);
    }
}
