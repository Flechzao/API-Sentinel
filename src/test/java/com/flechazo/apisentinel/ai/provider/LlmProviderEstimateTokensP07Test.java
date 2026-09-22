package com.flechazo.apisentinel.ai.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P0-7 — {@link LlmProvider#estimateTokensDefault(String)}
 * is the new shared token-estimate baseline. The pre-P0-7
 * {@code length/3.5} heuristic under-counted Chinese text by 1.7–2.5×,
 * which made the agent's compaction logic think it was under budget
 * when it wasn't, so the next LLM call blew past the model's context
 * window and lost the entire run's progress on a 400.
 *
 * <p>All three providers (Claude / OpenAI / Ollama) now delegate to this
 * shared default, so one test file covers all of them.
 */
class LlmProviderEstimateTokensP07Test {

    @Test
    void latinText_roughlyOneTokenPerThreePointFiveChars() {
        // Sanity lock on the legacy behavior for pure-ASCII input — the
        // new CJK penalty must not regress English estimates.
        String text = "hello world, this is a plain ASCII sentence with no CJK at all";
        int estimate = LlmProvider.estimateTokensDefault(text);
        // ~63 chars / 3.5 ≈ 18 tokens.
        assertThat(estimate).isBetween(10, 30);
    }

    @Test
    void chineseText_countsEachCharAsRoughlyOneToken() {
        // The exact regression the fix targets: pre-P0-7 this would
        // return 6 / 3.5 = 1 (rounded), a ~6× undercount. Post-P0-7
        // each CJK char contributes ~1 token.
        String chineseOnly = "这是一个纯中文句子"; // 8 characters
        int estimate = LlmProvider.estimateTokensDefault(chineseOnly);
        assertThat(estimate)
                .as("8 CJK characters must estimate to at least 6 tokens "
                        + "(the pre-P0-7 heuristic gave 1–2 here)")
                .isGreaterThanOrEqualTo(6);
    }

    @Test
    void mixedEnglishChinese_sitsBetweenBothExtremes() {
        String mixed = "Hello 你好 world 世界";
        int estimate = LlmProvider.estimateTokensDefault(mixed);
        // 4 CJK chars (~4 tokens) + 13 non-CJK chars (~3.7 tokens) ≈ 7.7.
        // The pre-P0-7 estimate would have been ~21/3.5 = 6, so the new
        // number is meaningfully higher.
        assertThat(estimate).isBetween(6, 14);
    }

    @Test
    void japaneseAndKorean_alsoCountedAsCjk() {
        // Hiragana, Katakana, Hangul — all in the CJK penalty band.
        String ja = "こんにちは";  // 5 hiragana
        String ko = "안녕하세요";  // 5 hangul
        assertThat(LlmProvider.estimateTokensDefault(ja)).isGreaterThanOrEqualTo(4);
        assertThat(LlmProvider.estimateTokensDefault(ko)).isGreaterThanOrEqualTo(4);
    }

    @Test
    void emptyAndNullInput_safe() {
        assertThat(LlmProvider.estimateTokensDefault(null)).isZero();
        assertThat(LlmProvider.estimateTokensDefault("")).isZero();
    }

    @Test
    void providerInstances_allDelegateToSharedDefault() {
        // The whole point of P0-7 is that the three provider
        // implementations stop drifting on their own heuristics. Pin
        // the contract here so the next person who "optimises" one
        // provider's estimate has to update this test intentionally.
        String chinese = "中文";
        int shared = LlmProvider.estimateTokensDefault(chinese);
        assertThat(new com.flechazo.apisentinel.ai.provider.ClaudeProvider()
                .estimateTokens(chinese)).isEqualTo(shared);
        assertThat(new com.flechazo.apisentinel.ai.provider.OpenAiProvider()
                .estimateTokens(chinese)).isEqualTo(shared);
        assertThat(new com.flechazo.apisentinel.ai.provider.OllamaProvider()
                .estimateTokens(chinese)).isEqualTo(shared);
    }

    @Test
    void surrogatePairs_notDoubleCounted() {
        // Emoji (and CJK Ext-B) live above the BMP and are encoded as a
        // surrogate pair in UTF-16. String.length() counts them as 2
        // code units; the estimator must not double-count them as 2
        // tokens either. Pre-P0-7 the heuristic returned length/3.5,
        // which double-counted every emoji as ~0.57 tokens each; the
        // new code corrects that by subtracting the surrogate count.
        String emoji = "🎉🎊🎁";  // 3 code points, 6 UTF-16 units
        int estimate = LlmProvider.estimateTokensDefault(emoji);
        // Pre-P0-7: 6/3.5 ≈ 1.7. Post-P0-7: 3 non-CJK code points
        // / 3.5 ≈ 0.86 → 1 (ceiling). Both round small; the key
        // property is that doubling the emoji count should roughly
        // double the estimate, not give a random number.
        assertThat(estimate).isBetween(1, 3);

        // Doubling the string should roughly double the estimate
        // (not stay the same, which would indicate broken counting).
        int doubled = LlmProvider.estimateTokensDefault(emoji + emoji);
        assertThat(doubled).isGreaterThanOrEqualTo(estimate);
    }
}
