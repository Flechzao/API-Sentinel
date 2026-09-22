package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.tool.AgentTool;
import com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry;
import com.flechazo.apisentinel.ai.pipeline.AnalysisConfig;
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

    private static AnalysisConfig config() {
        return new AnalysisConfig(true, 10, true, false,
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
            // P2-2: Gate 2 now binds to finding count, not generate_payloads.
            // 1 finding claimed, 2 generated, 0 verified → required = min(max(2,1),5) = 2,
            // so the rejection demands "at least 2" verifications and reports
            // "only 0 payload(s) were verified".
            assertThat(cb.toolResultBodies.get(rejectedSubmitIdx))
                    .contains("only 0 payload(s) were verified")
                    .contains("at least 2");

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

    /** P2-2 B1 wiring: when the agent never calls submit_report (script
     *  exhausts → future fails → fallback), buildFallbackResult reconstructs
     *  a verdict from thinking text. inferRiskFromEvidence sees "sql注入" and
     *  returns HIGH, but confirmed is empty. Pre-B1 the report would be
     *  HIGH-with-empty-confirmed (violating the "HIGH requires a surviving
     *  confirmed" invariant). B1 routes the reconstruction through
     *  VerdictValidator.validate, whose Phase 5 downgrades HIGH→MEDIUM.
     *  This test pins the WIRING (that buildFallbackResult actually calls
     *  validate), not just the validate contract — the contract alone
     *  (tested in VerdictValidatorP08Test) wouldn't catch a regression that
     *  removes the validate call from the fallback path. */
    @Test
    void fallbackReconstruction_highRiskFromThinkingText_downgradedByValidate() throws Exception {
        FakeLlmProvider provider = new FakeLlmProvider();
        provider.script(
                // turn 1: heuristic_scan (Gate 1 satisfied)
                toolCalls(null, call("heuristic_scan", "{}")),
                // turn 2: pure thinking text carrying a HIGH keyword — adds
                // "sql注入" to stageDescriptions, no submit_report call.
                new LlmResponse("分析发现 sql注入 疑似线索，尚未验证",
                        10, 10, 0, "fake", LlmResponse.FinishReason.COMPLETE,
                        null, List.of(), null, null)
                // turn 3: script exhausted → FakeLlmProvider fails the future
                // → AgentLoop catch(Throwable) → buildFallbackResult.
        );
        AgentLoop agentLoop = loop(provider);
        RecordingCallback cb = new RecordingCallback();
        try {
            PipelineResult result = agentLoop.execute(entry(), cb).get(60, TimeUnit.SECONDS);

            // B1 wiring: the reconstructed HIGH is downgraded — overall_risk
            // is NOT HIGH (Phase 5: HIGH + no surviving confirmed → MEDIUM).
            assertThat(result.verdict()).isNotNull();
            assertThat(result.verdict().overallRisk())
                    .as("fallback HIGH-with-no-confirmed must be downgraded by B1")
                    .isNotEqualTo("HIGH");
            // The salvage note (B1 labels the reconstruction as unverified).
            assertThat(result.verdict().summary()).contains("未完成验证");
        } finally {
            agentLoop.shutdown();
        }
    }

    /** P2-3: Agent tool results sent to the LLM must be wrapped in the
     *  per-run nonce fence — pre-P2-3 they entered the conversation as raw
     *  text, so an attacker response body (send_request), DOM dump
     *  (browser_render) or grep hit (grep_repo) could carry prompt injection
     *  with no demarcation. A1 fixed Pipeline's FinalVerdictPrompt but left
     *  the Agent loop's tool results unfenced; this pins the wiring. */
    @Test
    void toolResultsSentToLlmAreFencedWithNonce() throws Exception {
        FakeLlmProvider provider = new FakeLlmProvider();
        provider.script(
                // turn 0: heuristic_scan tool call (satisfies Gate 1)
                toolCalls(null, call("heuristic_scan", "{}")),
                // turn 1: submit a SAFE verdict so the loop ends cleanly
                toolCalls(null, call("submit_report", safeVerdict()))
        );
        AgentLoop agentLoop = loop(provider);
        RecordingCallback cb = new RecordingCallback();
        try {
            agentLoop.execute(entry(), cb).get(60, TimeUnit.SECONDS);

            // System prompt (call 0) carries the fence instruction.
            List<ChatMessage> call0 = provider.messagesOf(0);
            assertThat(call0.get(0).content()).contains("安全围栏");
            assertThat(call0.get(0).content()).contains("UNTRUSTED[");

            // The tool result bound for the LLM (call 1's messages) is
            // fenced: a tool-result message carries the nonce-bearing marker.
            List<ChatMessage> call1 = provider.messagesOf(1);
            String fencedToolResult = call1.stream()
                    .map(ChatMessage::content)
                    .filter(c -> c != null && c.contains("UNTRUSTED["))
                    .filter(c -> c.contains("START ===") && c.contains("END ==="))
                    .findFirst().orElse(null);
            assertThat(fencedToolResult)
                    .as("tool result sent to the LLM must carry the nonce fence markers")
                    .isNotNull();

            // The UI callback got the RAW (unfenced) result — only the
            // LLM-bound message is wrapped, the UI shows clean output.
            assertThat(cb.toolResultBodies)
                    .as("UI callback must receive the raw tool result, not the fence-wrapped one")
                    .allSatisfy(b -> assertThat(b).doesNotContain("UNTRUSTED["));
        } finally {
            agentLoop.shutdown();
        }
    }

    /** P2-2 concurrency invariant: stateful/HTTP/LLM tools mutate shared
     *  state (the payloadResults pool, session state) and must NEVER
     *  parallelise within a batch — otherwise the shared
     *  SendRequestTool.payloadResults + citedExecutionIndex O(1) lookups
     *  would race. Only read-only tools parallelise. Pins this so a future
     *  "let's parallelise send_request" change can't silently reintroduce
     *  the race. */
    @Test
    void statefulToolsAreNotParallelizable_pinsConcurrencySafety() {
        // Registry with stubs whose isReadOnly() reflects each tool's real
        // classification — drives the metadata-based parallel decision in
        // AgentLoop.canParallelize (no longer a hardcoded name set).
        AgentToolRegistry reg = readOnlyStubRegistry(
                "send_request", "chain_hunter", "submit_report",
                "verify_boolean_blind", "verify_timing_blind",
                "test_auth_bypass", "active_probe", "generate_payloads",
                "analyze_traffic", "waf_bypass_retry",
                "read_file", "grep_repo");

        // Stateful / HTTP / LLM tools must NOT parallelise.
        for (String tool : new String[]{"send_request", "chain_hunter",
                "submit_report", "verify_boolean_blind", "verify_timing_blind",
                "test_auth_bypass", "active_probe", "generate_payloads",
                "analyze_traffic", "waf_bypass_retry"}) {
            assertThat(AgentLoop.canParallelize(java.util.List.of(
                    new ToolCall("c1", tool, "{}")), reg))
                    .as("stateful tool %s must not parallelise", tool)
                    .isFalse();
        }
        // Read-only tools ARE parallelisable.
        assertThat(AgentLoop.canParallelize(java.util.List.of(
                new ToolCall("c1", "read_file", "{}"),
                new ToolCall("c2", "grep_repo", "{}")), reg)).isTrue();
        // A mix (one read + one stateful) must NOT parallelise.
        assertThat(AgentLoop.canParallelize(java.util.List.of(
                new ToolCall("c1", "read_file", "{}"),
                new ToolCall("c2", "send_request", "{}")), reg)).isFalse();
    }

    /** Builds a registry of stub tools whose {@link AgentTool#isReadOnly()}
     *  returns true for the known read-only tool names and false otherwise,
     *  mirroring the real tool implementations. ToolContext is null —
     *  canParallelize only resolves the tool and reads its metadata. */
    private static AgentToolRegistry readOnlyStubRegistry(String... names) {
        java.util.Set<String> readOnly = java.util.Set.of(
                "read_file", "grep_repo", "search_source_code", "search_traffic",
                "find_definition", "find_callers", "fingerprint_components",
                "heuristic_scan", "list_sessions", "map_sibling_endpoints");
        AgentToolRegistry reg = new AgentToolRegistry(null);
        for (String n : names) {
            boolean ro = readOnly.contains(n);
            reg.register(new AgentTool() {
                @Override public String name() { return n; }
                @Override public String description() { return "stub"; }
                @Override public com.google.gson.JsonObject inputSchema() { return new com.google.gson.JsonObject(); }
                @Override public String execute(String argumentsJson) { return "{}"; }
                @Override public boolean isReadOnly() { return ro; }
            });
        }
        return reg;
    }
}
