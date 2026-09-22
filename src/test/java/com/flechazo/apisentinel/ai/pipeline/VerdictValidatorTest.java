package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.testgen.model.TestCase;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VerdictValidatorTest {

    private static PayloadResult pipelineResult(String payload, boolean anomaly) {
        TestCase tc = new TestCase("test", "SQLi", "id", payload, "GET", "/api",
                Map.of(), "", "desc", "error", "HIGH");
        return new PayloadResult(tc, "GET /api?id=" + payload + " HTTP/1.1\r\n\r\n",
                "HTTP/1.1 500 Internal Server Error\r\n\r\n", 500, 100, anomaly);
    }

    private static PayloadResult agentResult(String sentRequest) {
        return new PayloadResult(null, sentRequest, "HTTP/1.1 200 OK\r\n\r\n", 200, 50, false);
    }

    private static ConfirmedVuln confirmedVuln(String payload) {
        return new ConfirmedVuln("SQLI", "SQL 注入", "报错回显", payload, "syntax error", "curl ...");
    }

    private static ConfirmedVuln confirmedVuln(String type, String title, String evidence, String payload) {
        return new ConfirmedVuln(type, title, evidence, payload, "resp snippet", "curl ...");
    }

    private static SuspectedVuln suspectedVuln(String type, String title, String reason) {
        return new SuspectedVuln(type, title, reason, "curl ...");
    }

    /** Agent-mode PayloadResult tagged with a session + execution index. */
    private static PayloadResult sessionResult(int idx, String path, String session, String respBody) {
        return new PayloadResult(null,
                "POST " + path + " HTTP/1.1\r\n\r\nbody",
                "HTTP/1.1 200\r\nContent-Type: application/json\r\n\r\n" + respBody,
                200, 50, false, 0L, idx, null, 0, session, false);
    }

    // ===== IDOR (auth-class) two-session confirmation must survive =====

    @Test
    void idor_twoSession_codeEvidence_survivesAsConfirmed() {
        // Regression: a genuine IDOR proven by two sessions on the SAME
        // gateway endpoint was false-demoted to suspected because (a) its
        // "response" snippet wasn't a verbatim slice of a captured body and
        // (b) the response-substring gate applied to auth-class. Auth-class is
        // now anchored by the two-session cross-check, not a response substring.
        String path = "/api/v1/v3/api/";
        PayloadResult sessA = sessionResult(0, path, "session_A", "{\"peerAccountId\":\"111111111111\"}");
        PayloadResult sessB = sessionResult(1, path, "session_B", "{\"peerAccountId\":\"111111111111\"}");
        ConfirmedVuln idor = new ConfirmedVuln(
                "越权访问/IDOR（水平越权）", "缺少资源归属校验",
                "代码证据：Controller→Service.getDetail 无 uid 校验（非响应子串）",
                "requestBody={\"innerPeeringId\":\"peering_test_001\"}",
                "会话B读到会话A的 accountId（人类描述，非逐字响应）",
                "curl ...",
                "会话B读到会话A的资源，匿名访问 401", "", 1);
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(idor), List.of(),
                "summary", "rec", 0, List.of(sessA, sessB), false);
        assertEquals(1, v.confirmedVulns().size(),
                "IDOR should survive as confirmed; suspected=" + v.suspectedVulns());
        assertEquals("HIGH", v.overallRisk());
    }

    @Test
    void markConfirmedPayloads_marksBothIdorSessionPackets() {
        // The two-session evidence pair must both render as 已确认 (not just the
        // cited one), so the test-case list doesn't show "无风险" on a proven IDOR.
        String path = "/api/v1/v3/api/";
        PayloadResult sessA = sessionResult(0, path, "session_A", "{\"x\":1}");
        PayloadResult sessB = sessionResult(1, path, "session_B", "{\"x\":1}");
        ConfirmedVuln idor = new ConfirmedVuln(
                "越权访问/IDOR", "缺少归属校验", "代码证据", "payload",
                "resp", "curl ...", "身份证据", "", 1);
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(idor), List.of(),
                "s", "r", 0, List.of(sessA, sessB), false);
        assertEquals(1, v.confirmedVulns().size());

        List<PayloadResult> marked = VerdictValidator.markConfirmedPayloads(v, List.of(sessA, sessB));
        assertTrue(marked.get(0).showsAsVerified(), "owner-session packet should be marked confirmed");
        assertTrue(marked.get(1).showsAsVerified(), "attacker-session packet should be marked confirmed");
    }

    @Test
    void idor_misCitedIndex_fallsBackToPairSearch() {
        // A slightly-wrong cited_execution_index must not hard-fail the auth
        // cross-check when the two-session evidence still exists in the batch.
        String path = "/api/v1/v3/api/";
        PayloadResult sessA = sessionResult(0, path, "session_A", "{\"x\":1}");
        PayloadResult sessB = sessionResult(1, path, "session_B", "{\"x\":1}");
        ConfirmedVuln idor = new ConfirmedVuln(
                "越权访问/IDOR", "缺少归属校验", "代码证据", "payload",
                "resp", "curl ...", "会话B读到会话A数据，匿名 401", "", 99 /* nonexistent index */);
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(idor), List.of(),
                "summary", "rec", 0, List.of(sessA, sessB), false);
        assertEquals(1, v.confirmedVulns().size(),
                "mis-cited index should fall back to pair search; suspected=" + v.suspectedVulns());
    }

    // ===== Phase 2: informational-only blacklist backstop =====

    @Test
    void informationalConfirmed_noChainEvidence_removedAndNotedInSummary() {
        // "缺失安全头" is informational-only; even though the payload was
        // genuinely sent (passes payload-sent gate), it must still be demoted
        // out of confirmed because the finding TYPE is a hardening nit, not a vuln.
        ConfirmedVuln info = confirmedVuln("缺失安全头", "缺少CSP", "响应无CSP头", "n/a");
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(info),
                List.of(), "summary", "", 100,
                List.of(agentResult("GET /api HTTP/1.1\r\n\r\n")), false);

        assertTrue(v.confirmedVulns().isEmpty(), "informational confirmed should be removed");
        assertTrue(v.suspectedVulns().isEmpty(), "informational should not linger in suspected either");
        assertTrue(v.summary().contains("信息级") || v.summary().contains("加固"),
                "summary should note the removal, got: " + v.summary());
    }

    @Test
    void informationalConfirmed_withChainEvidence_survives() {
        // CORS-without-credentials is normally informational, but if the
        // evidence shows credentials were actually exfiltrated (a real chain),
        // it's a genuine finding and must survive the blacklist.
        ConfirmedVuln cors = confirmedVuln("CORS通配符", "CORS凭证外带",
                "Access-Control-Allow-Origin: * 带凭证请求外带了用户PII个人信息",
                "Origin: https://evil.com");
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(cors),
                List.of(), "summary", "", 100,
                List.of(agentResult("GET /api HTTP/1.1\r\nOrigin: https://evil.com\r\n\r\n")), false);

        assertEquals(1, v.confirmedVulns().size(), "chained CORS finding should survive");
    }

    @Test
    void informationalSuspected_removed() {
        SuspectedVuln info = suspectedVuln("版本信息泄露", "Server版本暴露",
                "Server: nginx/1.18.0，无对应可利用CVE");
        FinalVerdict v = VerdictValidator.validate("LOW", List.of(), List.of(info),
                "summary", "", 100, List.of(), false);

        assertTrue(v.suspectedVulns().isEmpty(), "informational suspected should be removed");
        assertTrue(v.summary().contains("加固") || v.summary().contains("信息级"));
    }

    // ===== P2-2: rule 7 internal-IP programmatic backstop =====

    @Test
    void internalIpLeak_noChain_removed() {
        // Pre-P2-2 this sailed past the backstop — no "内网ip" keyword
        // existed in INFORMATIONAL_TYPE_KEYWORDS, so an LLM typing the
        // finding as "内网IP泄露" produced a confirmed (the IP verbatim
        // appears in the response, so evidenceTiesToRealResponse passes).
        // Now rule 7 has a programmatic backstop and removes it.
        SuspectedVuln ip = suspectedVuln("内网IP泄露", "错误页泄露内网地址",
                "响应错误页出现 10.0.0.5 内网地址，无利用链");
        FinalVerdict v = VerdictValidator.validate("LOW", List.of(), List.of(ip),
                "summary", "", 100, List.of(), false);
        assertTrue(v.suspectedVulns().isEmpty(),
                "internal-IP leak without a chain should be removed by rule 7 backstop");
    }

    @Test
    void internalIpLeak_partOfSsrfChain_survives() {
        // Rule 7 carve-out: an internal IP that came back as part of an SSRF
        // data-return chain is NOT informational. The chain keyword
        // (内网数据/metadata) in the reason exempts it.
        SuspectedVuln ip = suspectedVuln("内网IP泄露", "SSRF 返回内网数据",
                "SSRF 链路访问 169.254.169.254 返回内网数据 metadata");
        FinalVerdict v = VerdictValidator.validate("MEDIUM", List.of(), List.of(ip),
                "summary", "", 100, List.of(), false);
        assertEquals(1, v.suspectedVulns().size(),
                "internal-IP finding with a real SSRF data-return chain must survive");
    }

    @Test
    void nonInformationalConfirmed_unaffectedByBlacklist() {
        // A real SQLi (type "SQL注入") with chain evidence (行数据) is neither
        // informational nor demoted — must pass through untouched.
        ConfirmedVuln sqli = confirmedVuln("SQL注入", "联合查询注入",
                "返回了users表行数据 dump", "' UNION SELECT 1,2,3-- -");
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(sqli),
                List.of(), "summary", "", 100,
                List.of(agentResult("GET /api?id=' UNION SELECT 1,2,3-- - HTTP/1.1\r\n\r\n")), false);

        assertEquals(1, v.confirmedVulns().size());
        assertEquals("HIGH", v.overallRisk());
    }

    @Test
    void confirmed_withMatchingPayloadAndAnomaly_survives() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR 1=1")),
                List.of(), "summary", "fix it", 100,
                List.of(pipelineResult("' OR 1=1", true)), true);

        assertEquals(1, v.confirmedVulns().size());
        assertTrue(v.suspectedVulns().isEmpty());
        assertEquals("HIGH", v.overallRisk());
    }

    @Test
    void blindSqliConfirmed_citingFalseConditionPayload_matchesVerifierDetail() {
        // Regression (2026-08 demo run, GET /api/products/detail): the LLM
        // confirmed a boolean blind SQLi citing the FALSE half of the pair
        // ("1 AND 1=2" — the decisive side of the divergence). The verifier's
        // PayloadResult used to carry only a length-diff detail plus the
        // TRUE-condition request, so the citation matched NOTHING and the
        // programmatic confirmation was demoted to suspected. The verifiers
        // now embed both full payload texts in the detail (which lands in
        // testCase().payload()) — both modes must accept it.
        TestCase tc = new TestCase("布尔盲注-id", "盲注验证", "id",
                "响应长度差异 47 字节 (75.8%): true 62 vs false 15 [technique: basic]"
                        + " [payload: 1 AND 1=1 / 1 AND 1=2]",
                "GET", "/api/products/detail", Map.of(), "", "程序化盲注验证（布尔/时序）",
                "程序化确认注入", "HIGH");
        PayloadResult blindResult = new PayloadResult(tc,
                "GET /api/products/detail?id=1+AND+1%3D1 HTTP/1.1\r\nHost: t\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{\"found\":true}", 200, 80, true);

        ConfirmedVuln blindSqli = confirmedVuln("SQL注入", "布尔盲注",
                "true/false 响应差异 75.8%", "1 AND 1=2");

        FinalVerdict pipelineMode = VerdictValidator.validate("HIGH", List.of(blindSqli),
                List.of(), "summary", "", 100, List.of(blindResult), true);
        assertEquals(1, pipelineMode.confirmedVulns().size(),
                "Pipeline mode (requireAnomaly=true) must accept the programmatic confirmation");

        FinalVerdict agentMode = VerdictValidator.validate("HIGH", List.of(blindSqli),
                List.of(), "summary", "", 100, List.of(blindResult), false);
        assertEquals(1, agentMode.confirmedVulns().size(),
                "Agent mode (requireAnomaly=false) must accept the programmatic confirmation");
    }

    @Test
    void confirmed_withNoMatchingPayload_demotedToSuspected() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR 1=1")),
                List.of(), "summary", "", 100, List.of(), true);

        assertTrue(v.confirmedVulns().isEmpty());
        assertEquals(1, v.suspectedVulns().size());
        assertEquals("SQLI", v.suspectedVulns().get(0).type());
    }

    @Test
    void confirmed_matchedButNoAnomaly_requireTrue_demoted() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR 1=1")),
                List.of(), "summary", "", 100,
                List.of(pipelineResult("' OR 1=1", false)), true);

        assertTrue(v.confirmedVulns().isEmpty());
        assertEquals(1, v.suspectedVulns().size());
    }

    @Test
    void confirmed_matchedButNoAnomaly_requireFalse_survives() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR 1=1")),
                List.of(), "summary", "", 100,
                List.of(pipelineResult("' OR 1=1", false)), false);

        assertEquals(1, v.confirmedVulns().size());
        assertTrue(v.suspectedVulns().isEmpty());
    }

    @Test
    void overallRiskHigh_noSurvivingConfirmed_downgradedToMedium() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR 1=1")),
                List.of(new SuspectedVuln("XSS", "反射型XSS", "疑似", "curl ...")),
                "summary", "", 100, List.of(), true);

        assertEquals("MEDIUM", v.overallRisk());
        assertTrue(v.summary().contains("校验"));
    }

    @Test
    void overallRiskHigh_noSuspectedEither_downgradedToLow() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(),
                List.of(), "summary", "", 100, List.of(), true);

        assertEquals("LOW", v.overallRisk());
    }

    @Test
    void overallRiskHigh_withSurvivingConfirmed_preserved() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR 1=1")),
                List.of(), "summary", "", 100,
                List.of(pipelineResult("' OR 1=1", true)), true);

        assertEquals("HIGH", v.overallRisk());
        assertFalse(v.summary().contains("校验"));
    }

    @Test
    void agentMode_payloadFoundInSentRequest_matches() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("1' OR '1'='1")),
                List.of(), "summary", "", 100,
                List.of(agentResult("GET /api/orders/1' OR '1'='1 HTTP/1.1\r\n\r\n")), false);

        assertEquals(1, v.confirmedVulns().size());
    }

    // Regression: LLM cites the payload in human-readable form, but the raw
    // HTTP request has it percent-encoded — a literal-only substring check
    // would wrongly demote a genuinely-verified finding.
    @Test
    void agentMode_urlEncodedPayloadInSentRequest_stillMatches() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR '1'='1")),
                List.of(), "summary", "", 100,
                List.of(agentResult("GET /api/users/search?name=%27%20OR%20%271%27%3D%271 HTTP/1.1\r\n\r\n")),
                false);

        assertEquals(1, v.confirmedVulns().size());
    }

    @Test
    void agentMode_payloadNeverSent_demoted() {
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(confirmedVuln("' OR 1=1")),
                List.of(), "summary", "", 100,
                List.of(agentResult("GET /api/orders/1 HTTP/1.1\r\n\r\n")), false);

        assertTrue(v.confirmedVulns().isEmpty());
        assertEquals(1, v.suspectedVulns().size());
    }

    @Test
    void emptyPayloadResults_allConfirmedDemoted() {
        FinalVerdict v = VerdictValidator.validate("MEDIUM",
                List.of(confirmedVuln("a"), confirmedVuln("b")),
                List.of(), "summary", "", 100, List.of(), false);

        assertTrue(v.confirmedVulns().isEmpty());
        assertEquals(2, v.suspectedVulns().size());
    }

    @Test
    void noConfirmedVulns_passesThroughUnchanged() {
        SuspectedVuln sv = new SuspectedVuln("IDOR", "越权", "疑似原因", "curl ...");
        FinalVerdict v = VerdictValidator.validate("LOW", List.of(), List.of(sv),
                "summary", "recs", 42, List.of(), false);

        assertEquals("LOW", v.overallRisk());
        assertEquals(1, v.suspectedVulns().size());
        assertEquals("summary", v.summary());
        assertEquals(42, v.totalTokensUsed());
    }

    @Test
    void convenienceOverload_defaultsToLenientMode() {
        FinalVerdict original = new FinalVerdict("HIGH", List.of(confirmedVuln("x")),
                List.of(), "s", "r", 10);
        FinalVerdict v = VerdictValidator.validate(original,
                List.of(pipelineResult("x", false)));

        // requireAnomaly defaults to false in the 2-arg overload -> survives
        assertEquals(1, v.confirmedVulns().size());
    }

    // ===== WAF-blocked payload cross-validation =====

    private static PayloadResult wafResult(String payload, boolean anomaly, String vendor, int score) {
        TestCase tc = new TestCase("test", "SQLi", "id", payload, "GET", "/api",
                Map.of(), "", "desc", "error", "HIGH");
        return new PayloadResult(tc, "GET /api?id=" + payload + " HTTP/1.1\r\n\r\n",
                "HTTP/1.1 403 Forbidden\r\n\r\n<html>blocked</html>", 403, 100, anomaly,
                0L, 0, vendor, score);
    }

    @Test
    void wafBlockedConfirmed_demotedToSuspected_evenWithAnomaly() {
        // The payload's "anomaly" was triggered by the WAF block page itself —
        // the request never reached the backend, so it cannot back a confirmed.
        FinalVerdict v = VerdictValidator.validate("HIGH",
                List.of(confirmedVuln("' OR 1=1")), List.of(), "summary", "", 100,
                List.of(wafResult("' OR 1=1", true, "cloudflare", 85)), true);

        assertTrue(v.confirmedVulns().isEmpty(), "WAF-blocked confirmed must be demoted");
        assertEquals(1, v.suspectedVulns().size());
        assertTrue(v.suspectedVulns().get(0).reason().contains("WAF"),
                "demotion reason should mention WAF: " + v.suspectedVulns().get(0).reason());
        // HIGH with no surviving confirmed demotes to MEDIUM (suspected exists)
        assertEquals("MEDIUM", v.overallRisk());
    }

    @Test
    void wafPassedConfirmed_survives() {
        // Score below the review band: the response genuinely came from the
        // backend, so the confirmed stands.
        FinalVerdict v = VerdictValidator.validate("HIGH",
                List.of(confirmedVuln("' OR 1=1")), List.of(), "summary", "", 100,
                List.of(wafResult("' OR 1=1", true, null, 10)), true);

        assertEquals(1, v.confirmedVulns().size());
        assertEquals("HIGH", v.overallRisk());
    }

    @Test
    void markConfirmedPayloads_wafBlocked_notForceMarked() {
        FinalVerdict verdict = new FinalVerdict("HIGH", List.of(confirmedVuln("p1")),
                List.of(), "s", "r", 10);
        List<PayloadResult> marked = VerdictValidator.markConfirmedPayloads(verdict,
                List.of(wafResult("p1", false, "cloudflare", 85)));

        assertFalse(marked.get(0).anomalyDetected(),
                "WAF-suspected response must not be painted as anomaly");
    }

    @Test
    void markConfirmedPayloads_cleanResult_forceMarked() {
        // P0-8 #5: the pre-P0-8 behaviour was to rewrite anomalyDetected
        // to true, which destroyed the original observation. The new
        // behaviour keeps anomalyDetected untouched and flips the
        // dedicated claimedByVerdict flag instead — the UI's green check
        // now renders on showsAsVerified() (anomaly || claimed), while
        // audit / export layers can tell the two apart.
        FinalVerdict verdict = new FinalVerdict("HIGH", List.of(confirmedVuln("p1")),
                List.of(), "s", "r", 10);
        List<PayloadResult> marked = VerdictValidator.markConfirmedPayloads(verdict,
                List.of(pipelineResult("p1", false)));

        assertFalse(marked.get(0).anomalyDetected(),
                "P0-8: anomalyDetected must NOT be rewritten — the original observation is preserved");
        assertTrue(marked.get(0).claimedByVerdict(),
                "P0-8: claimedByVerdict is set when the result matches a surviving confirmed");
        assertTrue(marked.get(0).showsAsVerified(),
                "UI-facing helper: green-check condition still holds (anomaly || claimed)");
    }

    // ===== Phase 4: identity audit =====

    private static ConfirmedVuln authConfirmed(String payload, String identityProof) {
        return new ConfirmedVuln("越权访问", "水平越权-" + payload, "替换ID返回他人数据",
                payload, "200 + 他人数据", "curl ...", identityProof, "");
    }

    private static com.flechazo.apisentinel.auth.AuthTestResult authResult(
            com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict verdict) {
        return new com.flechazo.apisentinel.auth.AuthTestResult(
                verdict, "IDOR/水平越权", List.of("cookie"), "会话A", "会话B",
                verdict == com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict.VULNERABLE ? 0.9 : 0.1,
                "evidence", List.of());
    }

    @Test
    void authConfirmed_noIdentityProof_demoted() {
        FinalVerdict v = VerdictValidator.validate("HIGH",
                List.of(authConfirmed("p1", "")), List.of(), "s", "r", 100,
                List.of(pipelineResult("p1", true)), true);

        assertTrue(v.confirmedVulns().isEmpty(), "auth confirm without identity proof must be demoted");
        assertEquals(1, v.suspectedVulns().size());
        assertTrue(v.suspectedVulns().get(0).reason().contains("identity_not_proven"));
        assertTrue(v.rejectionReasons().stream().anyMatch(r -> r.contains("identity_not_proven")),
                "rejectionReasons should record the identity demotion");
    }

    @Test
    void authConfirmed_withIdentityProof_survives() {
        FinalVerdict v = VerdictValidator.validate("HIGH",
                List.of(authConfirmed("p1", "会话A凭证请求他人资源ID；匿名401；数据属会话B")),
                List.of(), "s", "r", 100,
                List.of(pipelineResult("p1", true)), true);

        assertEquals(1, v.confirmedVulns().size());
    }

    @Test
    void nonAuthConfirmed_noIdentityProof_unaffected() {
        // Non-auth findings are not subject to the identity audit.
        FinalVerdict v = VerdictValidator.validate("HIGH",
                List.of(confirmedVuln("p1")), List.of(), "s", "r", 100,
                List.of(pipelineResult("p1", true)), true);

        assertEquals(1, v.confirmedVulns().size());
    }

    @Test
    void authTestSafe_conflictSoftFlagged() {
        FinalVerdict v = VerdictValidator.validate("HIGH",
                List.of(authConfirmed("p1", "完整身份证据: 会话A/匿名401/他人数据")),
                List.of(), "s", "r", 100,
                List.of(pipelineResult("p1", true)), true,
                authResult(com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict.SAFE));

        // Soft conflict: confirm survives but gets flagged for human review.
        assertEquals(1, v.confirmedVulns().size());
        assertTrue(v.rejectionReasons().stream().anyMatch(r -> r.contains("软冲突")),
                "SAFE conflict should be flagged: " + v.rejectionReasons());
    }

    @Test
    void authTestVulnerable_noAuthConfirmed_missedFindingNote() {
        FinalVerdict v = VerdictValidator.validate("MEDIUM",
                List.of(confirmedVuln("p1")), List.of(), "s", "r", 100,
                List.of(pipelineResult("p1", true)), true,
                authResult(com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict.VULNERABLE));

        assertTrue(v.rejectionReasons().stream().anyMatch(r -> r.contains("漏报提醒")),
                "programmatic VULNERABLE without auth confirm should be flagged: " + v.rejectionReasons());
    }

    @Test
    void payloadNotSent_rejectionReasonRecorded() {
        FinalVerdict v = VerdictValidator.validate("HIGH",
                List.of(confirmedVuln("never-sent")), List.of(), "s", "r", 100,
                List.of(), false);

        assertTrue(v.confirmedVulns().isEmpty());
        assertTrue(v.rejectionReasons().stream().anyMatch(r ->
                        r.contains("confirmed 降级") && r.contains("未在实际发送的请求中找到")),
                "demotion reasons should be structured: " + v.rejectionReasons());
    }

    @Test
    void isAuthClass_variants() {
        assertTrue(VerdictValidator.isAuthClass("越权访问"));
        assertTrue(VerdictValidator.isAuthClass("未授权访问"));
        assertTrue(VerdictValidator.isAuthClass("IDOR"));
        assertTrue(VerdictValidator.isAuthClass("Broken Access Control"));
        assertFalse(VerdictValidator.isAuthClass("SQL注入"));
        assertFalse(VerdictValidator.isAuthClass(null));
    }

    // ===== Auth-class payload gate (regression: invoices IDOR case) =====
    // An IDOR confirm's "payload" is a forged identity cookie and a successful
    // attack returns a NORMAL 200 — there is no anomaly to detect and the LLM
    // often leaves payloadUsed blank. The old "payload text match" gate demoted
    // such genuinely-verified confirms to suspected. Auth-class must instead be
    // gated on "at least one real request sent" + the identity audit.

    @Test
    void authConfirmed_blankPayloadUsed_agentMode_survivesWithIdentityProof() {
        ConfirmedVuln idor = new ConfirmedVuln("水平越权", "伪造会话凭证越权读取他人数据",
                "伪造 SESSION_USER=1 返回 200 他人发票；匿名 403；反向验证证明属主校验被伪造身份绕穿",
                "", "200 + 他人数据", "curl ...",
                "用会话A凭证访问他人资源ID返回其数据；匿名访问403；返回数据确属会话B", "");
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(idor), List.of(), "s", "r", 100,
                List.of(agentResult("GET /api/invoices/2001 HTTP/1.1\r\nCookie: SESSION_USER=1\r\n\r\n")),
                false);
        assertEquals(1, v.confirmedVulns().size(),
                "auth confirm with blank payloadUsed must survive in agent mode when a real "
                + "request was sent and identity evidence is present");
    }

    @Test
    void authConfirmed_blankPayloadUsed_noRequestSent_demoted() {
        // No request actually sent — even an auth-class confirm must not stand.
        ConfirmedVuln idor = new ConfirmedVuln("水平越权", "伪造会话凭证越权", "推测可越权",
                "", "无", "curl ...", "身份证据完整", "");
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(idor), List.of(), "s", "r", 100,
                List.of(), false);
        assertTrue(v.confirmedVulns().isEmpty(),
                "auth confirm with zero sent requests must be demoted");
        assertEquals(1, v.suspectedVulns().size());
    }

    @Test
    void authConfirmed_blankPayloadUsed_andIdentityProofBlank_demotedByIdentityAudit() {
        // Request sent (passes the new payload gate) but no identity evidence —
        // the identity audit must still demote it.
        ConfirmedVuln idor = new ConfirmedVuln("水平越权", "伪造会话凭证越权", "返回他人数据",
                "", "200", "curl ...", "", "");
        FinalVerdict v = VerdictValidator.validate("HIGH", List.of(idor), List.of(), "s", "r", 100,
                List.of(agentResult("GET /api/invoices/2001 HTTP/1.1\r\n\r\n")), false);
        assertTrue(v.confirmedVulns().isEmpty(),
                "auth confirm without identity proof must still be demoted by the identity audit");
        assertTrue(v.suspectedVulns().get(0).reason().contains("identity_not_proven"));
    }
}
