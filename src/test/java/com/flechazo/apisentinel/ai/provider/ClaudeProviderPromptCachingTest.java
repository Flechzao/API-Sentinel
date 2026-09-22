package com.flechazo.apisentinel.ai.provider;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for Claude prompt-caching (P1-7).
 *
 * <p>Anthropic's caching is keyed by an exact byte-level match of everything
 * <b>up to and including</b> the element carrying a
 * {@code cache_control: {"type": "ephemeral"}} marker. We place three
 * markers — last tool, first system content block (the stable main
 * prompt), and the last message — and the tests below pin each one.
 *
 * <p>Why these tests matter: a regression that drops even one marker
 * silently kills the cache hit rate. Without the assertions, the wire
 * payload would still be well-formed JSON and the LLM would still
 * respond, but the invoice would quietly go back to full input price
 * on every turn.
 */
class ClaudeProviderPromptCachingTest {

    private ClaudeProvider provider = new ClaudeProvider();

    private static ToolDefinition td(String name) {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        return new ToolDefinition(name, "desc-" + name, schema);
    }

    private LlmRequest multiTurn(List<ChatMessage> messages, List<ToolDefinition> tools) {
        return new LlmRequest(
                null,           // systemPrompt (empty — test drives it via ChatMessage.system)
                null,           // userPrompt
                0.3,            // temperature
                16384,          // maxTokens
                null,           // responseFormat
                messages,
                tools,
                null,           // modelOverride
                null            // thinkingBudget
        );
    }

    /** Tool cache: when tools are present on a multi-turn request, the LAST
     *  tool definition must carry cache_control. The rest must not — marking
     *  every tool would cost a cache write per-tool rather than one for the
     *  whole catalog. */
    @Test
    void multiTurnWithToolsMarksCacheControlOnLastTool() {
        List<ChatMessage> messages = List.of(
                ChatMessage.system("MAIN"),
                ChatMessage.user("hi")
        );
        List<ToolDefinition> tools = List.of(td("a"), td("b"), td("c"));

        JsonObject body = provider.buildRequestBody(multiTurn(messages, tools), null);

        JsonArray toolsArray = body.getAsJsonArray("tools");
        assertThat(toolsArray.size()).isEqualTo(3);

        // Only the last tool carries the marker.
        assertThat(toolsArray.get(0).getAsJsonObject().has("cache_control")).isFalse();
        assertThat(toolsArray.get(1).getAsJsonObject().has("cache_control")).isFalse();
        JsonObject lastTool = toolsArray.get(2).getAsJsonObject();
        assertThat(lastTool.has("cache_control")).isTrue();
        assertThat(lastTool.getAsJsonObject("cache_control").get("type").getAsString())
                .isEqualTo("ephemeral");
    }

    /** System cache: the merged system prompt must be converted from a plain
     *  string into the content-block array form, with cache_control on the
     *  FIRST block (the stable main prompt). Subsequent blocks (dynamic
     *  injections) must NOT carry a marker — otherwise the cache key changes
     *  every time an injection differs and the hit rate drops to zero. */
    @Test
    void multiTurnSystemIsConvertedToBlockArrayWithCacheOnFirstBlock() {
        String main = "MAIN_SYSTEM_PROMPT_5K_TOKENS";
        String refl = "REFLECTION_FAILURE_LESSON";
        String find = "FINDINGS_SUMMARY";

        List<ChatMessage> messages = List.of(
                ChatMessage.system(main),
                ChatMessage.user("initial"),
                ChatMessage.system(refl),
                ChatMessage.system(find)
        );

        JsonObject body = provider.buildRequestBody(multiTurn(messages, null), null);

        // system is no longer a plain string.
        assertThat(body.get("system").isJsonPrimitive()).isFalse();
        JsonArray blocks = body.getAsJsonArray("system");
        assertThat(blocks.size()).isEqualTo(3);

        // Block 0 = main prompt, must carry cache_control.
        JsonObject block0 = blocks.get(0).getAsJsonObject();
        assertThat(block0.get("type").getAsString()).isEqualTo("text");
        assertThat(block0.get("text").getAsString()).isEqualTo(main);
        assertThat(block0.has("cache_control")).isTrue();
        assertThat(block0.getAsJsonObject("cache_control").get("type").getAsString())
                .isEqualTo("ephemeral");

        // Blocks 1+ = dynamic injections, no marker.
        JsonObject block1 = blocks.get(1).getAsJsonObject();
        assertThat(block1.get("text").getAsString()).isEqualTo(refl);
        assertThat(block1.has("cache_control")).isFalse();
        JsonObject block2 = blocks.get(2).getAsJsonObject();
        assertThat(block2.get("text").getAsString()).isEqualTo(find);
        assertThat(block2.has("cache_control")).isFalse();
    }

    /** Message cache: the LAST message (regardless of role) must carry
     *  cache_control so the conversation history accumulates in cache. */
    @Test
    void multiTurnMarksCacheControlOnLastMessage() {
        List<ChatMessage> messages = List.of(
                ChatMessage.system("MAIN"),
                ChatMessage.user("turn 1"),
                ChatMessage.assistant("reply 1"),
                ChatMessage.user("turn 2")
        );

        JsonObject body = provider.buildRequestBody(multiTurn(messages, null), null);

        JsonArray msgs = body.getAsJsonArray("messages");
        // The system message was merged into the system array, not messages.
        assertThat(msgs.size()).isEqualTo(3);
        for (int i = 0; i < msgs.size() - 1; i++) {
            assertThat(msgs.get(i).getAsJsonObject().has("cache_control")).isFalse();
        }
        JsonObject last = msgs.get(msgs.size() - 1).getAsJsonObject();
        assertThat(last.has("cache_control")).isTrue();
        assertThat(last.getAsJsonObject("cache_control").get("type").getAsString())
                .isEqualTo("ephemeral");
    }

    /** Single-turn must NOT carry any cache markers — caching is only
     *  profitable when the same prefix is sent on multiple turns. Marking
     *  a one-shot request would pay a write cost and never recoup. */
    @Test
    void singleTurnSkipsAllCacheMarkers() {
        LlmRequest req = new LlmRequest("SINGLE_TURN_PROMPT", "hello", 0.3, 4096, null);

        JsonObject body = provider.buildRequestBody(req, null);

        // system stays a plain string (no block-array conversion).
        assertThat(body.get("system").isJsonPrimitive()).isTrue();
        assertThat(body.get("system").getAsString()).isEqualTo("SINGLE_TURN_PROMPT");
        // messages is just one user turn, no marker.
        JsonArray msgs = body.getAsJsonArray("messages");
        for (int i = 0; i < msgs.size(); i++) {
            assertThat(msgs.get(i).getAsJsonObject().has("cache_control")).isFalse();
        }
    }

    /** JSON-format instruction must append cleanly whether the system is
     *  still a string (single-turn) or already a content-block array
     *  (multi-turn). A regression here would silently drop the JSON hint
     *  or corrupt the cache marker. */
    @Test
    void jsonFormatInstructionSurvivesSystemConversion() {
        List<ChatMessage> messages = List.of(
                ChatMessage.system("MAIN_PROMPT"),
                ChatMessage.user("give me JSON")
        );
        LlmRequest req = new LlmRequest(null, null, 0.3, 4096, "json", messages, null, null, null);

        JsonObject body = provider.buildRequestBody(req, null);

        JsonArray blocks = body.getAsJsonArray("system");
        assertThat(blocks).isNotNull();
        // The merged system got split into two blocks by the P0-1 separator
        // ("\n\n"): block 0 = the stable main prompt (the cached portion),
        // block 1 = the JSON instruction (dynamic, so NOT cached — that way
        // tweaking the hint doesn't invalidate the main-prompt cache).
        assertThat(blocks.size()).isEqualTo(2);

        String text0 = blocks.get(0).getAsJsonObject().get("text").getAsString();
        String text1 = blocks.get(1).getAsJsonObject().get("text").getAsString();
        assertThat(text0).isEqualTo("MAIN_PROMPT");
        assertThat(text1).contains("JSON").contains("IMPORTANT");
        // The cache marker is on block 0 (the stable portion). Block 1 has
        // no marker — this is intentional: if the JSON hint text ever
        // changes, the main prompt's cache key is undisturbed.
        assertThat(blocks.get(0).getAsJsonObject().has("cache_control")).isTrue();
        assertThat(blocks.get(1).getAsJsonObject().has("cache_control")).isFalse();
    }

    /** parseResponse must surface Anthropic's cache usage fields on the
     *  LlmResponse so the budget manager can bill them correctly. */
    @Test
    void parseResponseSurfacesCacheUsageFields() throws Exception {
        String apiResponse = """
                {
                  "id": "msg_01X",
                  "type": "message",
                  "role": "assistant",
                  "content": [{"type":"text","text":"hello"}],
                  "stop_reason": "end_turn",
                  "usage": {
                    "input_tokens": 1000,
                    "output_tokens": 500,
                    "cache_creation_input_tokens": 5200,
                    "cache_read_input_tokens": 0
                  }
                }
                """;
        var method = ClaudeProvider.class.getDeclaredMethod("parseResponse", String.class, long.class);
        method.setAccessible(true);
        LlmResponse resp = (LlmResponse) method.invoke(provider, apiResponse, 123L);

        assertThat(resp.promptTokens()).isEqualTo(1000);
        assertThat(resp.completionTokens()).isEqualTo(500);
        assertThat(resp.cacheCreationInputTokens()).isEqualTo(5200);
        assertThat(resp.cacheReadInputTokens()).isEqualTo(0);
        // billable input = 1000 + 5200 + 0 = 6200
        assertThat(resp.billableInputTokens()).isEqualTo(6200);
    }

    /** Regression: the legacy LlmResponse constructors (callers that don't
     *  know about caching) must still produce a well-formed response with
     *  zero cache fields. Otherwise every existing provider would NPE. */
    @Test
    void legacyLlmResponseConstructorsDefaultCacheFieldsToZero() {
        LlmResponse legacy = new LlmResponse("ok", 100, 50, 10L, "m",
                LlmResponse.FinishReason.COMPLETE, null);
        assertThat(legacy.cacheCreationInputTokens()).isZero();
        assertThat(legacy.cacheReadInputTokens()).isZero();
        assertThat(legacy.billableInputTokens()).isEqualTo(100);
    }
}
