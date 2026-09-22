package com.flechazo.apisentinel.ai.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for OpenAI prompt-caching accounting.
 *
 * <p>OpenAI's automatic prompt caching reports cached tokens as a
 * <b>subset</b> of {@code prompt_tokens} (unlike Anthropic, which reports
 * them as separate fields). To keep
 * {@link LlmResponse#billableInputTokens()} provider-agnostic (a simple
 * sum), the provider splits {@code prompt_tokens} into the non-cached
 * portion (kept in {@code promptTokens}) and the cached portion (carried
 * by {@code cacheReadInputTokens}). The sum is unchanged — only the
 * decomposition differs — and billable math stays correct without a
 * provider-aware branch.
 *
 * <p>If the splitting logic ever regresses, billable input for OpenAI
 * responses would double-count the cached portion and the daily budget
 * would drain roughly 2× faster than it should.
 */
class OpenAiProviderCachingTest {

    private OpenAiProvider provider = new OpenAiProvider();

    private LlmResponse parse(String body) throws Exception {
        var method = OpenAiProvider.class.getDeclaredMethod("parseResponse", String.class, long.class);
        method.setAccessible(true);
        return (LlmResponse) method.invoke(provider, body, 42L);
    }

    @Test
    void splitsCachedTokensOutOfPromptTokens() throws Exception {
        String apiResponse = """
                {
                  "id": "chatcmpl-abc",
                  "object": "chat.completion",
                  "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "hi"},
                    "finish_reason": "stop"
                  }],
                  "usage": {
                    "prompt_tokens": 5000,
                    "completion_tokens": 200,
                    "total_tokens": 5200,
                    "prompt_tokens_details": {
                      "cached_tokens": 4200,
                      "audio_tokens": 0
                    }
                  }
                }
                """;
        LlmResponse resp = parse(apiResponse);

        // 5000 prompt_tokens - 4200 cached = 800 non-cached.
        assertThat(resp.promptTokens()).isEqualTo(800);
        assertThat(resp.cacheReadInputTokens()).isEqualTo(4200);
        assertThat(resp.cacheCreationInputTokens()).isZero();
        assertThat(resp.completionTokens()).isEqualTo(200);
        // billable = 800 + 4200 + 0 = 5000 — exactly the raw prompt_tokens
        // the invoice is based on. No double-count.
        assertThat(resp.billableInputTokens()).isEqualTo(5000);
    }

    @Test
    void noCachedTokensFieldKeepsLegacyBehavior() throws Exception {
        // Models or endpoints that don't return prompt_tokens_details:
        // prompt_tokens stays raw, cache read is zero, billable input
        // still equals prompt_tokens.
        String apiResponse = """
                {
                  "id": "chatcmpl-xyz",
                  "object": "chat.completion",
                  "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop"
                  }],
                  "usage": {
                    "prompt_tokens": 1234,
                    "completion_tokens": 56,
                    "total_tokens": 1290
                  }
                }
                """;
        LlmResponse resp = parse(apiResponse);

        assertThat(resp.promptTokens()).isEqualTo(1234);
        assertThat(resp.cacheReadInputTokens()).isZero();
        assertThat(resp.billableInputTokens()).isEqualTo(1234);
    }

    @Test
    void malformedPromptTokensDetailsIsIgnoredGracefully() throws Exception {
        // prompt_tokens_details present but not an object (e.g. an API
        // change or proxy rewriting the payload). Must not NPE; just
        // skip the split.
        String apiResponse = """
                {
                  "id": "chatcmpl-def",
                  "object": "chat.completion",
                  "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": ""},
                    "finish_reason": "stop"
                  }],
                  "usage": {
                    "prompt_tokens": 300,
                    "completion_tokens": 10,
                    "total_tokens": 310,
                    "prompt_tokens_details": "unexpected-string"
                  }
                }
                """;
        LlmResponse resp = parse(apiResponse);

        assertThat(resp.promptTokens()).isEqualTo(300);
        assertThat(resp.cacheReadInputTokens()).isZero();
        assertThat(resp.billableInputTokens()).isEqualTo(300);
    }

    @Test
    void cachedTokensNeverExceedPromptTokens() throws Exception {
        // Defensive: if a buggy proxy reports cached_tokens > prompt_tokens,
        // promptTokens must clamp to zero, not go negative (a negative
        // promptTokens would under-count billable input and silently
        // drain the budget's accuracy).
        String apiResponse = """
                {
                  "id": "chatcmpl-ovr",
                  "object": "chat.completion",
                  "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": ""},
                    "finish_reason": "stop"
                  }],
                  "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 5,
                    "total_tokens": 105,
                    "prompt_tokens_details": {
                      "cached_tokens": 9999
                    }
                  }
                }
                """;
        LlmResponse resp = parse(apiResponse);

        assertThat(resp.promptTokens()).isZero();
        assertThat(resp.cacheReadInputTokens()).isEqualTo(9999);
        assertThat(resp.billableInputTokens()).isEqualTo(9999);
    }
}
