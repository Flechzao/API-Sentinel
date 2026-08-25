package com.flechazo.apisentinel.ai.provider;

import java.util.concurrent.CompletableFuture;

/**
 * LLM Provider 统一接口——定义消息对话、工具调用、Token 估算、扩展思考、连接测试等能力。
 * 实现类：{@link ClaudeProvider}、{@link OpenAiProvider}、{@link OllamaProvider}。
 */
public interface LlmProvider {

    String getId();

    String getDisplayName();

    CompletableFuture<Boolean> testConnection();

    CompletableFuture<LlmResponse> complete(LlmRequest request);

    int estimateTokens(String text);

    boolean isAvailable();

    void configure(String endpoint, String apiKey, String model);

    default boolean supportsToolCalling() {
        return false;
    }

    /** True when this provider can perform extended/interleaved thinking
     *  (Anthropic's "thinking" request block). Providers that don't support
     *  it simply ignore {@link LlmRequest#thinkingBudgetTokens()}. */
    default boolean supportsExtendedThinking() {
        return false;
    }
}
