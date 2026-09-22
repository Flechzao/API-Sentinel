package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.testgen.model.TestCase;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Adversarial tests for the P0-8 hardening of {@link VerdictValidator}.
 *
 * <p>Each of the five bypasses documented in §3.1.2 of the audit gets
 * two tests:
 *
 * <ol>
 *   <li><b>Attacker view</b>: a malicious LLM / prompt-injection
 *       payload tries the bypass that worked pre-P0-8; the validator
 *       must now reject (demote to suspected).</li>
 *   <li><b>Defender view</b>: a genuine positive that the pre-P0-8
 *       validator correctly accepted; it must still be accepted after
 *       the hardening — otherwise the fix is collateral damage.</li>
 * </ol>
 *
 * <p>These tests are what makes P0-8 durable. Without them, the next
 * person who "optimises" {@link VerdictValidator#isAuthClass} or
 * {@link VerdictValidator#findPayloadResult} can silently re-introduce
 * a bypass and CI won't catch it.
 */
class VerdictValidatorP08Test {

    // ============== #1: isAuthClass wide match ==============

    @Test
    void bypass1_accessSubstring_noLongerMislabelsAccessLogInjection() {
        // "Access Log Injection" is an informational log-echo issue, not
        // an access-control bug. Pre-P0-8 isAuthClass returned true
        // because "access" is a substring, routing the finding through
        // the permissive auth gate. Post-P0-8 it must return false.
        assertThat(VerdictValidator.isAuthClass("Access Log Injection")).isFalse();
        assertThat(VerdictValidator.isAuthClass("Back Channel Leak")).isFalse();
        assertThat(VerdictValidator.isAuthClass("Cache-Control 缺失")).isFalse();
        assertThat(VerdictValidator.isAuthClass("Broken Authentication")).isFalse();
    }

    @Test
    void bypass1_realAuthClassesStillRecognised() {
        assertThat(VerdictValidator.isAuthClass("IDOR")).isTrue();
        assertThat(VerdictValidator.isAuthClass("越权访问")).isTrue();
        assertThat(VerdictValidator.isAuthClass("水平越权")).isTrue();
        assertThat(VerdictValidator.isAuthClass("垂直越权")).isTrue();
        assertThat(VerdictValidator.isAuthClass("未授权访问")).isTrue();
        assertThat(VerdictValidator.isAuthClass("Broken Access Control")).isTrue();
        assertThat(VerdictValidator.isAuthClass("Access Control 错误")).isTrue();
        assertThat(VerdictValidator.isAuthClass("Privilege Escalation")).isTrue();
        assertThat(VerdictValidator.isAuthClass("Auth Bypass")).isTrue();
        assertThat(VerdictValidator.isAuthClass("unauthorized access")).isTrue();
    }

    // ============== #2: auth cross-check two-session gate ==============

    @Test
    void bypass2_authConfirm_singleSessionTaggedRequest_demoted() {
        // Adversary cites a confirm with only one session-tagged request
        // — no cross-session evidence. P0-8 must demote.
        PayloadResult aliceReq = new PayloadResult(null,
                "GET /api/orders/1 HTTP/1.1\r\nCookie: alice\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{\"user\":\"alice\",\"order\":1}",
                200, 50, false, 0L, 0, null, 0, "alice", false);

        ConfirmedVuln fakeIdor = new ConfirmedVuln("IDOR", "越权读取他人订单",
                "返回 alice 数据", "", "alice 数据", "", "我用 alice 账号读到数据", "", 0);

        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(fakeIdor),
                List.of(), "summary", "", 100,
                List.of(aliceReq), false);

        assertThat(v.confirmedVulns()).isEmpty();
        assertThat(v.suspectedVulns()).hasSize(1);
        assertThat(v.rejectionReasons().toString()).contains("auth");
    }

    @Test
    void bypass2_authConfirm_twoDifferentSessions_survives() {
        // Defender: alice's request AND bob's request on the same path,
        // both session-tagged, both non-WAF-blocked — this IS a real
        // IDOR proof. Must survive.
        PayloadResult aliceReq = new PayloadResult(null,
                "GET /api/orders/1 HTTP/1.1\r\nCookie: alice\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{\"user\":\"alice\",\"data\":\"alice-data\"}",
                200, 50, false, 0L, 0, null, 0, "alice", false);
        PayloadResult bobReq = new PayloadResult(null,
                "GET /api/orders/1 HTTP/1.1\r\nCookie: bob\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{\"user\":\"alice\",\"data\":\"alice-data\"}",
                200, 50, false, 0L, 1, null, 0, "bob", false);

        // The response snippet the LLM cites must be a verbatim substring
        // of ONE of the captured response bodies (P0-8 #4). We pick the
        // "alice-data" token which both bodies contain.
        ConfirmedVuln realIdor = new ConfirmedVuln("IDOR", "水平越权读取 alice 订单",
                "bob 请求返回 alice 数据", "", "alice-data",
                "", "bob 读 /orders/1 返回 alice 数据", "", 1);

        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(realIdor),
                List.of(), "summary", "", 100,
                List.of(aliceReq, bobReq), false);

        assertThat(v.confirmedVulns()).hasSize(1);
    }

    @Test
    void bypass2_legacyUntaggedRequests_stillAccepted() {
        // Backward compatibility: pre-P0-8 callers don't tag sessions.
        // When no result carries authSession, the old "any real request"
        // behaviour is preserved with a note — not a hard reject.
        PayloadResult oldReq = new PayloadResult(null,
                "GET /api/x HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{}",
                200, 50, false);

        ConfirmedVuln legacyAuth = new ConfirmedVuln("IDOR", "legacy-confirm",
                "evidence", "", "resp", "", "proof", "", -1);

        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(legacyAuth),
                List.of(), "s", "r", 100, List.of(oldReq), false);

        assertThat(v.confirmedVulns()).hasSize(1);
        assertThat(v.rejectionReasons().toString())
                .as("legacy path should surface a note about missing session tagging")
                .contains("authSession");
    }

    // ============== #3: findPayloadResult substring-too-loose ==============

    @Test
    void bypass3_shortCitedPayload_refusedInAgentMode() {
        // Adversary: LLM cites payload "1" (or "'" or "a") — matches
        // everything by substring. P0-8 must refuse so the confirm is
        // demoted to suspected.
        PayloadResult sentReq = new PayloadResult(null,
                "GET /api/orders?id=1 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{\"id\":1}",
                200, 50, false);
        ConfirmedVuln fake = new ConfirmedVuln("SQLI", "fake", "evidence",
                "1", "resp", "", "", "", -1);

        PayloadResult match = VerdictValidator.findPayloadResult(List.of(sentReq),
                "1", -1, null);
        assertThat(match).isNull();

        // And the downstream validate() demotes.
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(fake),
                List.of(), "s", "r", 100, List.of(sentReq), false);
        assertThat(v.confirmedVulns()).isEmpty();
    }

    @Test
    void bypass3_realisticPayloadLength_stillMatches() {
        // Defender: a realistic SQLi payload ("' OR 1=1", 8 chars) is
        // above the floor and matches the sent request — must still be
        // accepted.
        PayloadResult sentReq = new PayloadResult(null,
                "GET /api?id=' OR 1=1 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 500\r\n\r\n", 500, 50, false);
        ConfirmedVuln real = new ConfirmedVuln("SQLI", "SQL 注入", "报错",
                "' OR 1=1", "500 error", "", "", "", -1);

        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(real),
                List.of(), "s", "r", 100, List.of(sentReq), false);
        assertThat(v.confirmedVulns()).hasSize(1);
    }

    @Test
    void bypass3_pipelineModeIgnoresLengthFloor() {
        // Pipeline mode (testCase.payload() present) is trusted — the
        // verifier authored the payload, not the LLM — so the length
        // floor doesn't apply. A short testCase.payload() match must
        // still be accepted.
        TestCase tc = new TestCase("t", "SQLi", "id", "1", "GET", "/api",
                Map.of(), "", "", "", "HIGH");
        PayloadResult pr = new PayloadResult(tc, "GET /api?id=1 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n", 200, 50, true);
        ConfirmedVuln cv = new ConfirmedVuln("SQLI", "SQL 注入", "evidence",
                "1", "resp", "", "", "", -1);

        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(cv),
                List.of(), "s", "r", 100, List.of(pr), true);
        assertThat(v.confirmedVulns()).hasSize(1);
    }

    // ============== #4: fabricated evidence / response snippet ==============

    @Test
    void bypass4_hallucinatedResponseSnippet_demotedInMultiResultBatch() {
        // Adversary: the LLM cites a response snippet that doesn't
        // appear in ANY of the captured responses — pure hallucination.
        // With multiple results in the batch, P0-8 must demote.
        TestCase tc1 = new TestCase("t", "SQLi", "id", "' OR 1=1", "GET", "/api",
                Map.of(), "", "", "", "HIGH");
        PayloadResult pr1 = new PayloadResult(tc1,
                "GET /api?id=' OR 1=1 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}",
                200, 50, false);
        TestCase tc2 = new TestCase("t2", "SQLi", "id", "' OR 2=2", "GET", "/api",
                Map.of(), "", "", "", "HIGH");
        PayloadResult pr2 = new PayloadResult(tc2,
                "GET /api?id=' OR 2=2 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}",
                200, 50, false);

        ConfirmedVuln fake = new ConfirmedVuln("SQLI", "SQL 注入", "evidence",
                "' OR 1=1",
                "admin password hash: 5f4dcc3b5aa765d61d8327deb882cf99",
                "", "", "", -1);

        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(fake),
                List.of(), "s", "r", 100, List.of(pr1, pr2), false);
        assertThat(v.confirmedVulns()).isEmpty();
        assertThat(v.suspectedVulns()).hasSize(1);
        assertThat(v.rejectionReasons().toString()).contains("evidence");
    }

    @Test
    void bypass4_realResponseSnippetAnchor_survives() {
        // Defender: the cited response snippet IS a substring of a
        // real captured body — must survive.
        TestCase tc = new TestCase("t", "SQLI", "id", "' OR 1=1", "GET", "/api",
                Map.of(), "", "", "", "HIGH");
        PayloadResult pr = new PayloadResult(tc,
                "GET /api?id=' OR 1=1 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 500 Internal Server Error\r\n\r\n"
                        + "You have an error in your SQL syntax near '' OR 1=1'",
                500, 50, true);
        ConfirmedVuln real = new ConfirmedVuln("SQLI", "SQL 注入",
                "database error echoed payload",
                "' OR 1=1",
                "You have an error in your SQL syntax near '' OR 1=1'",
                "", "", "", -1);

        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(real),
                List.of(), "s", "r", 100, List.of(pr), true);
        assertThat(v.confirmedVulns()).hasSize(1);
    }

    // ============== #5: markConfirmedPayloads no longer rewrites anomalyDetected ==============

    @Test
    void bypass5_markConfirmed_doesNotRewriteAnomalyDetected() {
        // Adversary pre-P0-8: a hallucinated confirm that slipped past
        // validate() could force its row green by rewriting
        // anomalyDetected=true on a clean result. Post-P0-8, the
        // original observation is preserved; only claimedByVerdict is
        // set.
        //
        // Payload is deliberately ≥ MIN_CITED_PAYLOAD_LENGTH (4 chars)
        // so the Agent-mode substring fallback in findPayloadResult
        // actually fires — shorter payloads would be refused and the
        // row wouldn't be marked, masking the regression this test is
        // meant to pin.
        PayloadResult clean = new PayloadResult(null,
                "GET /api?id=p1xx HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{}",
                200, 50, false);
        FinalVerdict verdict = new FinalVerdict("HIGH",
                List.of(new ConfirmedVuln("SQLI", "fake", "evidence", "p1xx",
                        "resp", "", "", "", -1)),
                List.of(), "s", "r", 100);

        List<PayloadResult> marked = VerdictValidator.markConfirmedPayloads(verdict,
                List.of(clean));

        assertThat(marked.get(0).anomalyDetected())
                .as("the original observation must be preserved intact")
                .isFalse();
        assertThat(marked.get(0).claimedByVerdict())
                .as("the post-validation marker lives on the dedicated flag")
                .isTrue();
    }

    @Test
    void bypass5_showsAsVerified_combinesBothSignals() {
        // Defender: the UI helper must light up for both genuinely
        // observed anomalies and post-validation confirmed matches —
        // otherwise either true source would render without a green
        // check.
        PayloadResult observed = new PayloadResult(null, "r", "b", 200, 50,
                /* anomalyDetected */ true, 0L, -1, null, 0, null, false);
        PayloadResult claimed = new PayloadResult(null, "r", "b", 200, 50,
                /* anomalyDetected */ false, 0L, -1, null, 0, null,
                /* claimedByVerdict */ true);
        PayloadResult neither = new PayloadResult(null, "r", "b", 200, 50,
                false, 0L, -1, null, 0, null, false);

        assertThat(observed.showsAsVerified()).isTrue();
        assertThat(claimed.showsAsVerified()).isTrue();
        assertThat(neither.showsAsVerified()).isFalse();
    }

    // ============== Index-binding fast path (the P0-8 centerpiece) ==============

    @Test
    void indexBound_confirmResolvesInO1_andRejectsMissingIndex() {
        // When the LLM binds its confirm to a citedExecutionIndex, the
        // validator resolves it in O(1) without any substring ambiguity.
        // A non-existent index is a hard reject — the LLM cited a send
        // that never happened.
        PayloadResult real = new PayloadResult(null, "r", "b", 200, 50,
                true, 0L, /* executionIndex */ 7, null, 0, null, false);

        ConfirmedVuln bound = new ConfirmedVuln("SQLI", "real", "evidence",
                "", "resp", "", "", "", /* citedExecutionIndex */ 7);
        ConfirmedVuln hallucinated = new ConfirmedVuln("SQLI", "fake", "evidence",
                "", "resp", "", "", "", /* citedExecutionIndex */ 999);

        FinalVerdict v1 = VerdictValidator.validate("HIGH", List.of(bound),
                List.of(), "s", "r", 100, List.of(real), true);
        assertThat(v1.confirmedVulns()).hasSize(1);

        FinalVerdict v2 = VerdictValidator.validate("HIGH", List.of(hallucinated),
                List.of(), "s", "r", 100, List.of(real), true);
        assertThat(v2.confirmedVulns()).isEmpty();
        assertThat(v2.suspectedVulns()).hasSize(1);
    }

    // ============== P2-2: Phase 5 invariant relied on by fallback ==============

    /**
     * AgentLoop.buildFallbackResult's null branch (agent never called
     * submit_report — budget exhausted / exception / max iterations)
     * reconstructs a verdict from thinking text via inferRiskFromEvidence,
     * which can return HIGH from a keyword like "sql注入" while confirmed is
     * empty. P2-2 routes that reconstruction through validate, which MUST
     * downgrade HIGH→MEDIUM/LOW when no confirmed survives — the "HIGH
     * requires a surviving confirmed" invariant. This test pins that
     * contract; if anyone weakens Phase 5, the fallback path silently
     * re-introduces HIGH-with-empty-confirmed reports.
     */
    @Test
    void phase5_highRiskWithNoSurvivingConfirmed_isDowngraded() {
        // Reconstructed shape: HIGH risk, no confirmed, a suspected inferred
        // from text (no payload binding, no real evidence chain).
        SuspectedVuln suspected = new SuspectedVuln("SQL注入", "SQL注入漏洞",
                "agent 思考文本提到 sql注入", "", "HIGH");
        FinalVerdict reconstructed = new FinalVerdict("HIGH", List.of(),
                List.of(suspected), "[未完成验证] 思考文本含 sql注入", "", 0);

        FinalVerdict validated = VerdictValidator.validate(reconstructed,
                List.of(), false, null);

        assertThat(validated.overallRisk()).isIn("LOW", "MEDIUM");
        assertThat(validated.overallRisk()).isNotEqualTo("HIGH");
        // The salvage note must survive into the final summary so the user
        // sees the report is an unverified reconstruction.
        assertThat(validated.summary()).contains("未完成验证");
        // And the downgrade reason is recorded for audit traceability.
        assertThat(validated.rejectionReasons().stream().anyMatch(r -> r.contains("降级")))
                .isTrue();
    }

    @Test
    void phase5_highRiskWithNoConfirmedNoSuspected_downgradedToLow() {
        // Nothing survived at all → LOW, not HIGH.
        FinalVerdict reconstructed = new FinalVerdict("HIGH", List.of(),
                List.of(), "思考文本含 rce 关键词", "", 0);
        FinalVerdict validated = VerdictValidator.validate(reconstructed,
                List.of(), false, null);
        assertThat(validated.overallRisk()).isEqualTo("LOW");
    }
}
