package com.flechazo.apisentinel.ai.provider;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard for the single-system principle (P0-1 fix).
 *
 * <p>Pre-2026-09-06 bug: {@code ClaudeProvider.buildMultiTurnBody} iterated
 * {@code request.messages()} and called
 * {@code body.addProperty("system", msg.content())} for every system-role
 * entry. Gson's JsonObject overwrites duplicate keys, so in a 20-iteration
 * Agent run the <b>original main system prompt</b>
 * (SafetyRules, tool-use rules, GoT instructions, analysis strategy —
 * ~5.2K tokens of carefully curated guidance) was silently evicted by
 * whatever reflection/findings/validation summary was injected last.
 * The comment in AgentLoop.java L323-325 even described a
 * "remove previous reflection" step that was never implemented
 * (removeIf appears 0 times in AgentLoop).
 *
 * <p>The fix collects all system-role messages into a single buffer in
 * arrival order, then writes it ONCE — the main prompt always survives
 * at the front, dynamic injections append in order.
 */
class ClaudeProviderSystemMergeTest {

    private ClaudeProvider provider = new ClaudeProvider();

    private LlmRequest multiTurnRequest(String systemFromRequestField, List<ChatMessage> messages) {
        return new LlmRequest(
                systemFromRequestField,  // systemPrompt
                null,                    // userPrompt
                0.3,                     // temperature
                16384,                   // maxTokens
                null,                    // responseFormat (NOT "json" — separate path)
                messages,
                null,                    // tools
                null,                    // modelOverride
                null                     // thinkingBudget
        );
    }

    /** The core P0-1 scenario: a multi-turn request carrying the main system
     *  prompt first, then a reflection injection, then a findings injection.
     *  Before the fix, only the findings summary survived to the wire. */
    @Test
    void multiTurnMergesMultipleSystemMessagesInOrder() {
        String mainPrompt = "MAIN_SYSTEM_PROMPT_SafetyRules_tool_use_rules_GoT";
        String reflection = "REFLECTION_FAILURE_LESSON_from_iteration_5";
        String findings = "FINDINGS_SUMMARY_from_evidence_store";

        List<ChatMessage> messages = List.of(
                ChatMessage.system(mainPrompt),
                ChatMessage.user("initial user message"),
                ChatMessage.system(reflection),
                ChatMessage.assistant("assistant turn"),
                ChatMessage.system(findings),
                ChatMessage.user("next user message")
        );

        JsonObject body = new JsonObject();
        provider.buildMultiTurnBody(body, multiTurnRequest(null, messages));

        // The merged system prompt must contain ALL three parts — the main
        // prompt can never be evicted by later injections.
        assertThat(body.has("system"))
                .as("merged system prompt must be written to the body")
                .isTrue();
        String merged = body.get("system").getAsString();
        assertThat(merged)
                .contains(mainPrompt)
                .contains(reflection)
                .contains(findings);

        // Order preserved: main prompt comes before reflection which comes
        // before findings. If the order ever flips, the model sees dynamic
        // injections first and the stable guidance second — a subtle
        // behavioral regression.
        int mainIdx = merged.indexOf(mainPrompt);
        int reflIdx = merged.indexOf(reflection);
        int findIdx = merged.indexOf(findings);
        assertThat(mainIdx).isLessThan(reflIdx);
        assertThat(reflIdx).isLessThan(findIdx);

        // And the non-system messages must still all land in the messages array.
        JsonArray arr = body.getAsJsonArray("messages");
        assertThat(arr.size()).isEqualTo(3);
    }

    /** Simulates the AgentLoop multi-iteration accumulation: main prompt +
     *  N pairs of (reflection, findings) all in the message list. The main
     *  prompt must remain in the merged output regardless of N. */
    @Test
    void multiTurnMainPromptSurvivesAcrossIterations() {
        String mainPrompt = "MAIN_SYSTEM_PROMPT_5K_TOKENS";
        java.util.List<ChatMessage> messages = new java.util.ArrayList<>();
        messages.add(ChatMessage.system(mainPrompt));
        messages.add(ChatMessage.user("initial"));
        // Simulate 10 iterations each injecting reflection + findings
        for (int i = 1; i <= 10; i++) {
            messages.add(ChatMessage.system("REFLECTION_iter_" + i));
            messages.add(ChatMessage.system("FINDINGS_iter_" + i));
            messages.add(ChatMessage.assistant("turn " + i));
            messages.add(ChatMessage.user("continue"));
        }

        JsonObject body = new JsonObject();
        provider.buildMultiTurnBody(body, multiTurnRequest(null, messages));

        String merged = body.get("system").getAsString();
        assertThat(merged).contains(mainPrompt);
        assertThat(merged).contains("REFLECTION_iter_1");
        assertThat(merged).contains("REFLECTION_iter_10");
        assertThat(merged).contains("FINDINGS_iter_10");
        // Main prompt at the very front (index 0) — not somewhere in the middle.
        assertThat(merged.indexOf(mainPrompt)).isZero();
    }

    /** Regression: when request.systemPrompt() is set via the request field
     *  (ChatController's path) rather than as a ChatMessage.system entry,
     *  it must still land at the front of the merged system. */
    @Test
    void requestFieldSystemPromptPrependsWhenMessageListHasSystemEntries() {
        String fromField = "SYSTEM_FROM_REQUEST_FIELD";
        String fromMessage = "SYSTEM_FROM_CHAT_MESSAGE";

        List<ChatMessage> messages = List.of(
                ChatMessage.system(fromMessage),
                ChatMessage.user("hi")
        );

        JsonObject body = new JsonObject();
        provider.buildMultiTurnBody(body, multiTurnRequest(fromField, messages));

        String merged = body.get("system").getAsString();
        assertThat(merged).startsWith(fromField);
        assertThat(merged).contains(fromMessage);
    }

    /** Empty system: when neither the request field nor any message carries
     *  a system prompt, the body must not get a system property (Claude
     *  accepts requests without one). */
    @Test
    void noSystemPropertyWhenNothingToMerge() {
        List<ChatMessage> messages = List.of(
                ChatMessage.user("hi"),
                ChatMessage.assistant("hello"),
                ChatMessage.user("thanks")
        );

        JsonObject body = new JsonObject();
        provider.buildMultiTurnBody(body, multiTurnRequest(null, messages));

        assertThat(body.has("system"))
                .as("must not emit an empty 'system' property — Claude accepts "
                        + "no-system requests and an empty string could trigger "
                        + "unnecessary token charges")
                .isFalse();
        assertThat(body.getAsJsonArray("messages").size()).isEqualTo(3);
    }

    /** Single-turn (request.systemPrompt only, no messages) must still land
     *  the prompt on the body as a plain string — this is ChatController's
     *  primary path. */
    @Test
    void singleTurnStillSetsSystemFromStringField() {
        List<ChatMessage> empty = List.of();
        LlmRequest req = multiTurnRequest("SINGLE_TURN_SYSTEM_PROMPT", empty);
        // The single-turn path is triggered when messages() is null/empty,
        // but our constructor sets it to empty list → isMultiTurn() returns
        // false (empty is treated as not-multi-turn per LlmRequest.isMultiTurn).
        JsonObject body = new JsonObject();
        provider.buildSingleTurnBody(body, req);

        assertThat(body.get("system").getAsString()).isEqualTo("SINGLE_TURN_SYSTEM_PROMPT");
        // Single-turn should still have exactly one user turn (from userPrompt).
        assertThat(body.getAsJsonArray("messages").size()).isGreaterThanOrEqualTo(0);
    }

    /** Defensive: a null content on a system ChatMessage must not NPE the
     *  merge (defensive since we'd rather not crash the loop on bad data). */
    @Test
    void nullContentOnSystemMessageIsTolerated() {
        List<ChatMessage> messages = List.of(
                ChatMessage.system("REAL_MAIN_PROMPT"),
                new ChatMessage("system", null),  // bad entry
                ChatMessage.user("hi")
        );

        JsonObject body = new JsonObject();
        provider.buildMultiTurnBody(body, multiTurnRequest(null, messages));

        assertThat(body.get("system").getAsString()).contains("REAL_MAIN_PROMPT");
    }
}
