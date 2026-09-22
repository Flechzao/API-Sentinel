package com.flechazo.apisentinel.ai.agent.tool;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P2-2 regression guard for {@link SubmitReportTool}'s Gate 2 (verification
 * coverage). Pre-P2-2 the gate bound to the tool name {@code generate_payloads}
 * ({@code generatedPayloadCount > 0}), so an LLM that skipped
 * generate_payloads and hand-wrote payloads straight to {@code send_request}
 * had {@code generated=0} → {@code required=0} → the guard
 * {@code generated > 0 && verified < required} was false → the gate silently
 * skipped. The fix binds to behaviour: report N findings → must verify
 * {@code min(N, 5)} via real-request tools, regardless of whether
 * generate_payloads was ever called.
 */
class SubmitReportToolP2Test {

    /** 3 confirmed findings, only 1 verified, generate_payloads NEVER called.
     * Pre-P2-2 this passed Gate 2 (generated=0 → skipped). Must now reject. */
    @Test
    void gate2_bypassingGeneratePayloads_withUnverifiedFindings_isRejected() {
        SubmitReportTool tool = new SubmitReportTool();
        ToolContext ctx = new ToolContext(null, null, null, null, null, null, null);
        ctx.sessionState().recordToolCall("heuristic_scan"); // satisfy Gate 1
        ctx.sessionState().recordToolCall("send_request");   // satisfy Gate 4's real-request gate
        ctx.sessionState().setGeneratedPayloadCount(0);      // generate_payloads NOT called
        ctx.sessionState().setVerifiedPayloadCount(1);        // only 1 verified

        String verdict = "{\"overall_risk\":\"HIGH\",\"summary\":\"x\","
                + "\"confirmed_vulns\":[{},{},{}]}"; // 3 findings

        String rejection = tool.preExecute(verdict, ctx);
        assertThat(rejection).isNotNull();
        assertThat(rejection).contains("Report rejected");
        // Driven by finding count (3), not by generatedPayloadCount (0).
        assertThat(rejection).contains("3");
    }

    /** Same shape but verifying all 3 → Gate 2 passes (returns null = allow). */
    @Test
    void gate2_bypassingGeneratePayloads_withAllFindingsVerified_passes() {
        SubmitReportTool tool = new SubmitReportTool();
        ToolContext ctx = new ToolContext(null, null, null, null, null, null, null);
        ctx.sessionState().recordToolCall("heuristic_scan");
        ctx.sessionState().recordToolCall("send_request");
        ctx.sessionState().recordToolCall("test_auth_bypass"); // satisfy Gate 3 coverage (auth)
        ctx.sessionState().setGeneratedPayloadCount(0);
        ctx.sessionState().setVerifiedPayloadCount(3);

        String verdict = "{\"overall_risk\":\"HIGH\",\"summary\":\"x\","
                + "\"confirmed_vulns\":[{},{},{}]}";

        // Gate 2 satisfied; Gate 4 satisfied (send_request called). No code repos
        // so Gate 1b skipped. Gate 3 coverage fully satisfied (no logger call).
        // preExecute returns null to allow.
        assertThat(tool.preExecute(verdict, ctx)).isNull();
    }

    /** Pre-P2-2 honest path still works: generate_payloads=3, verified=3. */
    @Test
    void gate2_generatePayloadsPath_withAllVerified_passes() {
        SubmitReportTool tool = new SubmitReportTool();
        ToolContext ctx = new ToolContext(null, null, null, null, null, null, null);
        ctx.sessionState().recordToolCall("heuristic_scan");
        ctx.sessionState().recordToolCall("send_request");
        ctx.sessionState().recordToolCall("test_auth_bypass");
        ctx.sessionState().setGeneratedPayloadCount(3);
        ctx.sessionState().setVerifiedPayloadCount(3);

        String verdict = "{\"overall_risk\":\"HIGH\",\"summary\":\"x\","
                + "\"confirmed_vulns\":[{},{},{}]}";

        assertThat(tool.preExecute(verdict, ctx)).isNull();
    }

    /** Cap at 5: 8 findings require only 5 verifications. */
    @Test
    void gate2_requiredCappedAt5_whenManyFindings() {
        SubmitReportTool tool = new SubmitReportTool();
        ToolContext ctx = new ToolContext(null, null, null, null, null, null, null);
        ctx.sessionState().recordToolCall("heuristic_scan");
        ctx.sessionState().recordToolCall("send_request");
        ctx.sessionState().setGeneratedPayloadCount(0);
        ctx.sessionState().setVerifiedPayloadCount(4); // < 5 → reject

        StringBuilder v = new StringBuilder("{\"overall_risk\":\"HIGH\",\"summary\":\"x\",\"confirmed_vulns\":[");
        for (int i = 0; i < 8; i++) v.append("{},");
        v.setLength(v.length() - 1);
        v.append("]}");

        String rejection = tool.preExecute(v.toString(), ctx);
        assertThat(rejection).isNotNull();
        assertThat(rejection).contains("at least 5"); // min(8,5)=5
    }

    /** P2-2 补充:Gate 1b — 配置了代码仓库却没跑 audit_codebase → 拒绝。 */
    @Test
    void gate1b_codeReposConfiguredWithoutAuditCodebase_rejected() {
        SubmitReportTool tool = new SubmitReportTool();
        // Non-empty codeRepos triggers Gate 1b.
        ToolContext ctx = new ToolContext(null, null, null, null,
                java.util.List.of(new com.flechazo.apisentinel.config.CodeRepo()),
                null, null);
        ctx.sessionState().recordToolCall("heuristic_scan"); // satisfy Gate 1
        // audit_codebase NOT called → Gate 1b must reject before Gate 2/3.
        String verdict = "{\"overall_risk\":\"SAFE\",\"summary\":\"x\","
                + "\"confirmed_vulns\":[],\"suspected_vulns\":[]}";
        String rejection = tool.preExecute(verdict, ctx);
        assertThat(rejection).isNotNull();
        assertThat(rejection).contains("audit_codebase");
    }

    /** P2-2 补充:Gate 1b — 跑过 audit_codebase 后放行。 */
    @Test
    void gate1b_codeReposConfiguredWithAuditCodebase_passes() {
        SubmitReportTool tool = new SubmitReportTool();
        ToolContext ctx = new ToolContext(null, null, null, null,
                java.util.List.of(new com.flechazo.apisentinel.config.CodeRepo()),
                null, null);
        ctx.sessionState().recordToolCall("heuristic_scan");
        ctx.sessionState().recordToolCall("audit_codebase");
        ctx.sessionState().recordToolCall("send_request");
        ctx.sessionState().recordToolCall("test_auth_bypass");
        // Empty SAFE verdict → no Gate 2 requirement, Gate 4 satisfied.
        String verdict = "{\"overall_risk\":\"SAFE\",\"summary\":\"x\","
                + "\"confirmed_vulns\":[],\"suspected_vulns\":[]}";
        assertThat(tool.preExecute(verdict, ctx)).isNull();
    }
}
