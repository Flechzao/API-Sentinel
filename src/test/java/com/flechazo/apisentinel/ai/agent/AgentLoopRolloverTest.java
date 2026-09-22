package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.ConfidenceLevel;
import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.FindingCategory;
import com.flechazo.apisentinel.ai.pipeline.AnalysisConfig;
import com.flechazo.apisentinel.ai.provider.ChatMessage;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ① Context-window rollover. Verifies the handoff: when the conversation
 *  approaches the window, history is cleared down to [system prompt, initial
 *  task, thread_hint], the durable FindingEvidenceStore state is summarised
 *  into the thread_hint, and the window id advances — so the new window can
 *  recover via read_analysis_notes instead of losing early findings to lossy
 *  compaction. Default-off; the cap bounds runaway window growth.
 */
class AgentLoopRolloverTest {

    @AfterEach
    void clearProp() {
        System.clearProperty("apisentinel.rollover.enabled");
    }

    /** Minimal provider — only estimateTokens matters for the rollover
     *  threshold (text length / 4, matching the production estimate). */
    private static LlmProvider provider() {
        return new LlmProvider() {
            @Override public String getId() { return "fake"; }
            @Override public String getDisplayName() { return "Fake"; }
            @Override public CompletableFuture<Boolean> testConnection() {
                return CompletableFuture.completedFuture(true);
            }
            @Override public CompletableFuture<LlmResponse> complete(LlmRequest request) {
                return CompletableFuture.failedFuture(new IllegalStateException("unexpected"));
            }
            @Override public int estimateTokens(String text) {
                return text == null ? 0 : text.length() / 4;
            }
            @Override public boolean isAvailable() { return true; }
            @Override public void configure(String endpoint, String apiKey, String model) {}
        };
    }

    /** contextWindowTokens=400 → rollover triggers at 80% = 320 tokens
     *  ⇒ ~1280 chars of content. */
    private static AnalysisConfig smallConfig() {
        return new AnalysisConfig(true, 10, true, false,
                "", "A", "", "B", 400, true,
                false, false, false, false, 0, false, false);
    }

    private static AgentLoop loopWithRollover() {
        System.setProperty("apisentinel.rollover.enabled", "true");
        return new AgentLoop(provider(), null, null, smallConfig(), List.of(),
                new LeveledLogger(null), null);
    }

    private static List<ChatMessage> bigConversation() {
        List<ChatMessage> msgs = new ArrayList<>();
        msgs.add(ChatMessage.system("system prompt — static"));
        msgs.add(ChatMessage.user("initial task: test /api/test"));
        // ~5000 chars ⇒ 1250 tokens, well over the 320 trigger.
        msgs.add(ChatMessage.assistant("x".repeat(5000)));
        return msgs;
    }

    private static FindingEvidenceStore storeWithState() {
        FindingEvidenceStore s = new FindingEvidenceStore(new LeveledLogger(null));
        s.addManualFinding(FindingCategory.SQL_INJECTION.name(), "id",
                "' OR 1=1-- returned all rows", ConfidenceLevel.CONFIRMED.name());
        s.appendProgress("tested /api/login; id param looks injectable", 0);
        return s;
    }

    @Test
    void rollover_clearsHistory_injectsThreadHint_advancesWindow() {
        AgentLoop loop = loopWithRollover();
        List<ChatMessage> messages = bigConversation();
        FindingEvidenceStore store = storeWithState();
        List<Integer> tracker = new ArrayList<>(List.of(2, 3)); // stale indices

        boolean rolled = loop.rolloverIfNeeded(messages, store, tracker);

        assertThat(rolled).as("rollover should fire (est over 80%)").isTrue();
        // History cleared down to: system prompt + initial task + thread_hint.
        assertThat(messages).hasSize(3);
        assertThat(messages.get(0).role()).isEqualTo("system");
        assertThat(messages.get(0).content()).isEqualTo("system prompt — static");
        assertThat(messages.get(1).role()).isEqualTo("user");
        assertThat(messages.get(1).content()).isEqualTo("initial task: test /api/test");
        assertThat(messages.get(2).role()).isEqualTo("system");
        assertThat(messages.get(2).content()).contains("<thread_hint>")
                .contains("已确认 1")
                .contains("read_analysis_notes")
                .contains("tested /api/login");  // most recent progress inlined
        // Window advanced + store tagged for the new window.
        assertThat(store.getCurrentWindowId()).isEqualTo(1);
        // Stale dynamic-injection indices from the cleared history are gone.
        assertThat(tracker).isEmpty();
    }

    @Test
    void rollover_disabledByDefault_returnsFalse_andLeavesHistory() {
        // No system property set → rollover off (the safe default).
        AgentLoop loop = new AgentLoop(provider(), null, null, smallConfig(), List.of(),
                new LeveledLogger(null), null);
        List<ChatMessage> messages = bigConversation();
        FindingEvidenceStore store = storeWithState();
        List<Integer> tracker = new ArrayList<>(List.of(2));

        boolean rolled = loop.rolloverIfNeeded(messages, store, tracker);

        assertThat(rolled).isFalse();
        assertThat(messages).hasSize(3);          // untouched
        assertThat(messages.get(2).content()).isEqualTo("x".repeat(5000));
        assertThat(store.getCurrentWindowId()).isZero();
        assertThat(tracker).containsExactly(2);   // untouched
    }

    @Test
    void rollover_respectsMaxWindowsCapsRunawayGrowth() {
        AgentLoop loop = loopWithRollover();
        FindingEvidenceStore store = storeWithState();
        List<Integer> tracker = new ArrayList<>();

        // MAX_ROLLOVER_WINDOWS = 3: the first three rollovers succeed (each
        // refills the conversation to overflow first), the fourth must fall
        // back to compaction instead of opening another window.
        for (int i = 0; i < 3; i++) {
            List<ChatMessage> messages = bigConversation();
            assertThat(loop.rolloverIfNeeded(messages, store, tracker))
                    .as("rollover %d should fire", i + 1).isTrue();
        }
        assertThat(store.getCurrentWindowId()).isEqualTo(3);

        // Fourth window: cap reached → no rollover, history untouched.
        List<ChatMessage> messages = bigConversation();
        assertThat(loop.rolloverIfNeeded(messages, store, tracker))
                .as("cap reached must not roll over again").isFalse();
        assertThat(messages).hasSize(3);          // untouched (still big)
        assertThat(store.getCurrentWindowId()).isEqualTo(3);
    }
}
