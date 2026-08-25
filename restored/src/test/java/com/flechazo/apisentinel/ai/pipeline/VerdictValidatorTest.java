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
        FinalVerdict verdict = new FinalVerdict("HIGH", List.of(confirmedVuln("p1")),
                List.of(), "s", "r", 10);
        List<PayloadResult> marked = VerdictValidator.markConfirmedPayloads(verdict,
                List.of(pipelineResult("p1", false)));

        assertTrue(marked.get(0).anomalyDetected());
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
        assertTrue(v.rejectionReasons().stream().anyMatch(r -> r.contains("payload 校验失败")),
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
