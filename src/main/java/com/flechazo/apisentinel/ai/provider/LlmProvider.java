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

    /** P0-7: shared CJK-aware token estimate. Each provider's
     *  {@link #estimateTokens(String)} overrides this with its own
     *  heuristic, but the default gives callers a reasonable baseline
     *  when they don't have a specific provider in hand (e.g. the
     *  agent's compaction budget math).
     *
     *  <p>Why this lives here: the pre-P0-7 {@code length/3.5} estimate
     *  under-counted CJK text by 1.7–2.5× (Chinese characters are
     *  typically 1 token each, not ~0.28 as {@code length/3.5} gives).
     *  Combined with the 150K compaction threshold, a Chinese-language
     *  analysis would blow past the model's context window, fail with
     *  400, and lose the entire run's progress. Centralising the CJK
     *  penalty here keeps the three provider implementations honest and
     *  gives a single place to tune when new scripts need to be
     *  accounted for. */
    static int estimateTokensDefault(String text) {
        if (text == null || text.isEmpty()) return 0;
        long cjk = 0;
        long other = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            // Basic CJK ranges: Han (CJK Unified + Ext-A), Hangul, Kana,
            // CJK punctuation/fullwidth. Covers zh/ja/ko — the scripts
            // actually observed in the field per the §3.2 F4 audit.
            if ((c >= 0x4E00 && c <= 0x9FFF)       // CJK Unified Ideographs
                    || (c >= 0x3400 && c <= 0x4DBF) // CJK Unified Ext-A
                    || (c >= 0xAC00 && c <= 0xD7A3) // Hangul Syllables
                    || (c >= 0x3040 && c <= 0x30FF) // Hiragana + Katakana
                    || (c >= 0xFF00 && c <= 0xFFEF) // Fullwidth Forms
                    || (c >= 0x3000 && c <= 0x303F)) { // CJK Symbols/Punctuation
                cjk++;
            } else {
                other++;
            }
        }
        // Surrogate pairs (emoji, CJK Ext-B+): count as 1 token per code
        // point, not per UTF-16 unit. String.length() double-counts
        // surrogates; codePointCount gives the right number.
        long surrogates = 0;
        for (int i = 0; i < text.length(); i++) {
            if (Character.isHighSurrogate(text.charAt(i))) surrogates++;
        }
        // Each surrogate pair contributes 2 to `other` via length() but
        // is one code point / ~1 token. Adjust by subtracting the extra
        // count once per pair.
        long otherCodePoints = other - surrogates;
        double nonCjkTokens = otherCodePoints / 3.5;
        return (int) Math.ceil(cjk + nonCjkTokens);
    }

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

    /**
     * Release any resources held by this provider (HTTP client threads,
     * connection pools, etc.). Called on extension unload. Default is a
     * no-op — providers with internal resources should override.
     */
    default void close() {
        // No-op by default
    }
}
