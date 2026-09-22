package com.flechazo.apisentinel.ai.provider;

import java.util.concurrent.ExecutorService;

/**
 * DeepSeek LLM Provider — uses OpenAI-compatible API format.
 *
 * <p>DeepSeek's API is fully compatible with OpenAI's chat completions format,
 * including vision support for models like DeepSeek-V4-Flash-Vision-Exp.
 * This provider wraps {@link OpenAiProvider} with DeepSeek-specific defaults.
 *
 * <p>Supported features:
 * <ul>
 *   <li>Text chat completions (deepseek-chat, deepseek-reasoner)</li>
 *   <li>Vision/multimodal (DeepSeek-V4-Flash-Vision-Exp)</li>
 *   <li>Function calling / tool use</li>
 *   <li>JSON response format</li>
 * </ul>
 *
 * <p>Default endpoint: {@code https://api.deepseek.com/v1/chat/completions}
 */
public class DeepSeekProvider implements LlmProvider {

    private final OpenAiProvider delegate;

    public DeepSeekProvider() {
        this.delegate = new OpenAiProvider();
        // Set DeepSeek defaults
        delegate.configure("https://api.deepseek.com/v1/chat/completions", "", "deepseek-chat");
    }

    @Override
    public String getId() { return "deepseek"; }

    @Override
    public String getDisplayName() { return "DeepSeek"; }

    @Override
    public boolean supportsToolCalling() { return true; }

    /** DeepSeek vision models support multimodal content. */
    public boolean supportsVision() { return true; }

    @Override
    public void configure(String endpoint, String apiKey, String model) {
        delegate.configure(endpoint, apiKey, model);
    }

    @Override
    public java.util.concurrent.CompletableFuture<Boolean> testConnection() {
        return delegate.testConnection();
    }

    @Override
    public java.util.concurrent.CompletableFuture<LlmResponse> complete(LlmRequest request) {
        return delegate.complete(request);
    }

    @Override
    public int estimateTokens(String text) {
        return delegate.estimateTokens(text);
    }

    @Override
    public boolean isAvailable() {
        return delegate.isAvailable();
    }

    public void setExecutor(ExecutorService executor) {
        delegate.setExecutor(executor);
    }
}
