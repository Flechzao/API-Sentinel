package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.pipeline.PipelineConfig;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.provider.ChatMessage;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.ai.provider.ToolCall;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end tests of the AgentLoop's control-loop mechanics, driven by a
 * scripted fake LLM provider against a REAL AgentLoop + real tool registry:
 * the repeated-batch circuit breaker, stale thinking-block stripping, the
 * submit_report same-batch short-circuit, and the post-execution verified
 * count that submit_report's verify gate reads.
 *
 * <p>Tools that would need Burp or a code repo (send_request, grep_repo, ...)
 * degrade to clean error results with null dependencies — that is exactly the
 * behavior these mechanics tests rely on (a failed send must NOT count as a
 * verified payload).
 */
class AgentLoopMechanicsTest {

    // ------------------------------------------------------------------
    // Fakes
    // ------------------------------------------------------------------

    /** Returns scripted responses in order, recording every request it sees.
     *  Exhausting the script fails the future loudly instead of letting the
     *  loop wander into unscripted territory.
     *
     *  <p>IMPORTANT: {@code LlmRequest.messages()} is the loop's LIVE list —
     *  it keeps mutating after the call. Message assertions must use
     *  {@link #messagesOf(int)}, which returns a snapshot taken AT call time. */
    static class FakeLlmProvider implements LlmProvider {
        final Deque<LlmResponse> scripted = new ArrayDeque<>();
        final List<LlmRequest> requests = new CopyOnWriteArrayList<>();
        final List<List<ChatMessage>> messageSnapshots = new CopyOnWriteArrayList<>();

        void script(LlmResponse... responses) {
            scripted.addAll(Arrays.asList(responses));
        }

        List<ChatMessage> messagesOf(int callIndex) {
            return messageSnapshots.get(callIndex);
        }

        @Override public String getId() { return "fake"; }
        @Override public String getDisplayName() { return "Fake"; }
        @Override public CompletableFuture<Boolean> testConnection() {
            return CompletableFuture.completedFuture(true);
        }
        @Override public CompletableFuture<LlmResponse> complete(LlmRequest request) {
            requests.add(request);
            // Non-multi-turn requests (tools' internal one-shot LLM calls,
            // e.g. TestCaseService) carry messages == null.
            messageSnapshots.add(request.messages() != null
                    ? List.copyOf(request.messages()) : List.of());
            LlmResponse next = scripted.poll();
            if (next == null) {
                return CompletableFuture.failedFuture(
                        new IllegalStateException("FakeLlmProvider script exhausted — "
                                + "the loop made more LLM calls than expected"));
            }
            return CompletableFuture.completedFuture(next);
        }
        @Override public int estimateTokens(String text) {
            return text == null ? 0 : text.length() / 4;
        }
        @Override public boolean isAvailable() { return true; }
        @Override public void configure(String endpoint, String apiKey, String model) {}
    }

    static class RecordingCallback implements AgentLoop.AgentCallback {
        /** Tool names in result-processing order (paired with the result). */
        final List<String> toolResultTools = new CopyOnWriteArrayList<>();
        final List<String> toolResultBodies = new CopyOnWriteArrayList<>();
        final List<String> errors = new CopyOnWriteArrayList<>();

        @Override public void onAgentThinking(String thought) {}
        @Override public void onToolCall(String toolName, String args) {}
        @Override public void onToolResult(String toolName, String result) {
            toolResultTools.add(toolName);
            toolResultBodies.add(result);
        }
        @Override public void onAgentComplete(PipelineResult result) {}
        @Override public void onAgentError(String error) { errors.add(error); }
        @Override public void onIterationComplete(int iteration, int maxIterations) {}
    }

    // ------------------------------------------------------------------
    // Builders
    // ------------------------------------------------------------------

    private static LlmResponse toolCalls(String thinkingBlocksJson, ToolCall... calls) {
        return new LlmResponse("", 10, 10, 0, "fake",
                LlmResponse.FinishReason.TOOL_USE, null, List.of(calls), null, thinkingBlocksJson);
    }

    private static ToolCall call(String name, String argsJson) {
        return new ToolCall("call-" + name, name, argsJson);
    }

    private static String safeVerdict() {
        return "{\"overall_risk\":\"SAFE\",\"summary\":\"未发现漏洞\","
                + "\"confirmed_vulns\":[],\"suspected_vulns\":[],\"recommendations\":\"\"}";
    }

    private static String suspectedVerdict() {
        return "{\"overall_risk\":\"MEDIUM\",\"summary\":\"疑似注入\","
                + "\"confirmed_vulns\":[],\"recommendations\":\"\","
                + "\"suspected_vulns\":[{\"type\":\"SQL注入\",\"title\":\"疑似SQL注入\","
                + "\"reason\":\"参数拼接\",\"confidence\":\"MEDIUM\"}]}";
    }

    private static ApiEntry entry() {
        ApiEntry e = new ApiEntry("GET", "/api/test");
        e.setDomain("test.example.com");
        e.setLastUrl("http://test.example.com/api/test");
        // A captured request lets send_request pass its own preExecute gate
        // (it returns a rejection-as-warning when there is no traffic at all).
        e.setLastRawRequest("GET /api/test HTTP/1.1\r\nHost: test.example.com\r\n\r\n");
        e.setLastStatusCode(200);
        return e;
    }

    private static PipelineConfig config() {
        return new PipelineConfig(true, 10, true, false,
                "", "A", "", "B", 150_000, true,
                false, false, false, false, 0, false, false);
    }

    private static AgentLoop loop(FakeLlmProvider provider) {
        return new AgentLoop(provider, null, null, config(), List.of(),
                new LeveledLogger(null), null);
    }

    // ------------------------------------------------------------------
    // Repeated-batch circuit breaker
    // ------------------------------------------------------------------

    @Test
    void repeatedIdenticalBatchTripsBreakerWellBeforeMaxIterations() throws Exception {
        FakeLlmProvider provider = new FakeLlmProvider();
        // 6 identical calls scripted; the breaker must stop the loop at the
        // 5th, long before MAX_ITERATIONS (50).
        for (int i = 0; i < 6; i++) {
            provider.script(toolCalls(null, call("heuristic_scan", "{}")));
        }

        AgentLoop agentLoop = loop(provider);
        RecordingCallback cb = new RecordingCallback();
        try {
            PipelineResult result = agentLoop.execute(entry(), cb).get(60, TimeUnit.SECONDS);

            assertThat(result.verdict()).isNotNull();
            assertThat(result.verdict().summary()).startsWith("[重复熔断]");
            // Turns 1-4 executed, turn 5 tripped HALT_AT — exactly 5 LLM calls,
            // the 6th scripted response stays unused.
            assertThat(provider.requests).hasSize(5);
            assertThat(cb.errors).anyMatch(e -> e.contains("相同的工具调用"));
        } finally {
            agentLoop.shutdown();
        }
    }

    @Test
    void repeatedBatchInjectsReflectionBeforeHalting() throws Exception {
        FakeLlmProvider provider = new FakeLlmProvider();
        for (int i = 0; i < 6; i++) {
            provider.script(toolCalls(null, call("heuristic_scan", "{}")));
        }

        AgentLoop agentLoop = loop(provider);
        try {
            agentLoop.execute(entry(), new RecordingCallback()).get(60, TimeUnit.SECONDS);

            // The 5th request (index 4) must carry the injected reflection —
            // a user message about identical calls, appended after the tool
            // results (message order must stay valid for the API).
            List<ChatMessage> msgs = provider.messagesOf(4);
            assertThat(msgs).anyMatch(m -> "user".equals(m.role())
                    && m.content() != null
                    && m.content().contains("完全相同的工具调用批次"));
            // The reflection sits AFTER the last tool result, never between an
            // assistant tool_use message and its tool results.
            int lastToolResult = -1, reflectionIdx = -1;
            for (int i = 0; i < msgs.size(); i++) {
                if ("tool".equals(msgs.get(i).role())) lastToolResult = i;
                if ("user".equals(msgs.get(i).role())
                        && msgs.get(i).content() != null
                        && msgs.get(i).content().contains("完全相同的工具调用批次")) {
                    reflectionIdx = i;
                }
            }
            assertThat(reflectionIdx).isGreaterThan(lastToolResult);
        } finally {
            agentLoop.shutdown();
        }
    }

    // ------------------------------------------------------------------
    // Stale thinking-block stripping
    // ------------------------------------------------------------------

    @Test
    void olderThinkingBlocksAreStrippedLatestIsKept() throws Exception {
        String thinking1 = "[{\"type\":\"thinking\",\"thinking\":\"t1\",\"signature\":\"s1\"}]";
        String thinking2 = "[{\"type\":\"thinking\",\"thinking\":\"t2\",\"signature\":\"s2\"}]";

        FakeLlmProvider provider = new FakeLlmProvider();
        provider.script(
                toolCalls(thinking1, call("heuristic_scan", "{}")),
                toolCalls(thinking2, call("grep_repo", "{\"pattern\":\"password\"}")),
                toolCalls(null, call("submit_report", safeVerdict()))
        );

        AgentLoop agentLoop = loop(provider);
        try {
            PipelineResult result = agentLoop.execute(entry(), new RecordingCallback())
                    .get(60, TimeUnit.SECONDS);
            assertThat(result.verdict()).isNotNull();

            // The third LLM call carries the full history. By then turn-1's
            // thinking is stale (only the turn right after production must
            // echo it) and must be gone, while turn-2's — the latest
            // assistant message — must still ride along.
            List<ChatMessage> assistants = provider.messagesOf(2).stream()
                    .filter(m -> "assistant".equals(m.role()))
                    .toList();
            assertThat(assistants).hasSize(2); // stripped, not dropped
            assertThat(assistants.get(0).rawThinkingBlocksJson()).isNull();
            assertThat(assistants.get(0).hasToolCalls()).isTrue(); // structure intact
            assertThat(assistants.get(1).rawThinkingBlocksJson()).isEqualTo(thinking2);
        } finally {
            agentLoop.shutdown();
        }
    }

    // ------------------------------------------------------------------
    // submit_report same-batch short-circuit
    // ------------------------------------------------------------------

    @Test
    void acceptedSubmitSkipsRestOfItsBatch() throws Exception {
        FakeLlmProvider provider = new FakeLlmProvider();
        provider.script(
                toolCalls(null, call("heuristic_scan", "{}")),
                toolCalls(null,
                        call("submit_report", safeVerdict()),
                        call("grep_repo", "{\"pattern\":\"secret\"}"))
        );

        AgentLoop agentLoop = loop(provider);
        RecordingCallback cb = new RecordingCallback();
        try {
            PipelineResult result = agentLoop.execute(entry(), cb).get(60, TimeUnit.SECONDS);

            assertThat(result.verdict()).isNotNull();
            assertThat(result.verdict().overallRisk()).isEqualTo("SAFE");
            // grep_repo was in the accepted submit's batch and must NOT have
            // been executed or processed.
            assertThat(cb.toolResultTools).containsExactly("heuristic_scan", "submit_report");
            // The loop ended right after the accepted submit — no further turn.
            assertThat(provider.requests).hasSize(2);
        } finally {
            agentLoop.shutdown();
        }
    }

    @Test
    void rejectedSubmitStillRunsRestOfItsBatch() throws Exception {
        FakeLlmProvider provider = new FakeLlmProvider();
        provider.script(
                // submit_report first WITHOUT heuristic_scan done — gate 1
                // rejects it; the batch's remaining call must still run.
                toolCalls(null,
                        call("submit_report", safeVerdict()),
                        call("heuristic_scan", "{}")),
                toolCalls(null, call("submit_report", safeVerdict()))
        );

        AgentLoop agentLoop = loop(provider);
        RecordingCallback cb = new RecordingCallback();
        try {
            PipelineResult result = agentLoop.execute(entry(), cb).get(60, TimeUnit.SECONDS);

            assertThat(result.verdict()).isNotNull();
            assertThat(cb.toolResultTools)
                    .containsExactly("submit_report", "heuristic_scan", "submit_report");
            // The first submit's result is the gate-1 rejection text.
            assertThat(cb.toolResultBodies.get(0)).contains("heuristic_scan first");
        } finally {
            agentLoop.shutdown();
        }
    }

    // ------------------------------------------------------------------
    // Verified count = real request results, not optimistic call count
    // ------------------------------------------------------------------

    @Test
    void failedSendsDoNotCountAsVerifiedForSubmitGate() throws Exception {
        FakeLlmProvider provider = new FakeLlmProvider();
        provider.script(
                // turn 1: heuristic_scan (gate-1 prereq for submit_report)
                toolCalls(null, call("heuristic_scan", "{}")),
                // turn 2: generate_payloads ...
                toolCalls(null, call("generate_payloads", "{}")),
                // ... whose INTERNAL TestCaseService LLM call yields 2 cases:
                new LlmResponse(
                        "{\"reasoning\":\"r\",\"test_cases\":["
                                + "{\"name\":\"sqli-1\",\"category\":\"SQL注入\","
                                + "\"target_param\":\"id\",\"payload\":\"' OR 1=1--\","
                                + "\"method\":\"GET\",\"path\":\"/api/test\",\"headers\":{},"
                                + "\"body\":\"\",\"description\":\"d1\","
                                + "\"expected_if_vulnerable\":\"e1\",\"risk_if_confirmed\":\"HIGH\"},"
                                + "{\"name\":\"sqli-2\",\"category\":\"SQL注入\","
                                + "\"target_param\":\"id\",\"payload\":\"1 AND 1=2\","
                                + "\"method\":\"GET\",\"path\":\"/api/test\",\"headers\":{},"
                                + "\"body\":\"\",\"description\":\"d2\","
                                + "\"expected_if_vulnerable\":\"e2\",\"risk_if_confirmed\":\"HIGH\"}]}",
                        10, 10, 0, "fake", LlmResponse.FinishReason.COMPLETE, null),
                // turns 3+4: two sends that FAIL (no Burp API in tests) and
                // therefore produce zero PayloadResults — with the old
                // optimistic count they would still register as 2 verified.
                toolCalls(null, call("send_request",
                        "{\"method\":\"GET\",\"path\":\"/api/test\",\"body\":\"p1\"}")),
                toolCalls(null, call("send_request",
                        "{\"method\":\"GET\",\"path\":\"/api/test\",\"body\":\"p2\"}")),
                // turn 5: submit WITH a finding — gate 2 must REJECT it
                // (generated 2, verified 0), unlike under the old optimistic
                // count where the 2 failed sends registered as "2 verified"
                // and this same report sailed through. The script ends here:
                // gate 2 keeps rejecting until payloads are really verified,
                // so the next call exhausts the script and the loop winds down
                // through its controlled error-fallback path.
                toolCalls(null, call("submit_report", suspectedVerdict()))
        );

        AgentLoop agentLoop = loop(provider);
        RecordingCallback cb = new RecordingCallback();
        try {
            PipelineResult result = agentLoop.execute(entry(), cb).get(60, TimeUnit.SECONDS);

            // The gate-2 rejection text proves the recount semantics: the two
            // FAILED sends did not count as verified.
            int rejectedSubmitIdx = cb.toolResultTools.indexOf("submit_report");
            assertThat(rejectedSubmitIdx).isGreaterThanOrEqualTo(0);
            assertThat(cb.toolResultBodies.get(rejectedSubmitIdx))
                    .contains("generated 2 test payload")
                    .contains("only verified 0");

            // The suspected verdict was never accepted — the final verdict is
            // the evidence-so-far fallback (risk LOW), not the MEDIUM report.
            // Under the old optimistic count the first submit would have been
            // accepted and the risk would be MEDIUM.
            assertThat(result.verdict()).isNotNull();
            assertThat(result.verdict().overallRisk()).isEqualTo("LOW");
            assertThat(result.verdict().suspectedVulns()).isEmpty();

            // Both sends ran and both failed cleanly (no Burp API in tests).
            assertThat(cb.toolResultBodies).anyMatch(r -> r.contains("Burp API not available"));
        } finally {
            agentLoop.shutdown();
        }
    }
}
