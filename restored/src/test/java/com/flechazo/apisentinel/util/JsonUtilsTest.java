package com.flechazo.apisentinel.util;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.pipeline.*;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;
import com.flechazo.apisentinel.testgen.model.TestCase;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonUtilsTest {

    @Test
    void roundTrip_basicFields() {
        ApiEntry entry = new ApiEntry("GET", "/api/v1/users");
        entry.updateStatus(ApiStatus.VULNERABLE, VulnType.UNAUTHORIZED, "未授权访问");
        entry.setNote("test note");
        entry.setDomain("example.com");
        entry.setLastSeenTimestamp(1000L);

        String json = JsonUtils.toJson(List.of(entry));
        List<ApiEntry> restored = JsonUtils.fromJson(json);

        assertEquals(1, restored.size());
        ApiEntry r = restored.get(0);
        assertEquals("GET", r.getHttpMethod());
        assertEquals("/api/v1/users", r.getApiPath());
        assertEquals(ApiStatus.VULNERABLE, r.getStatus());
        assertEquals(VulnType.UNAUTHORIZED, r.getVulnType());
        assertEquals("未授权访问", r.getResult());
        assertEquals("test note", r.getNote());
        assertEquals("example.com", r.getDomain());
        assertEquals(1000L, r.getLastSeenTimestamp());
    }

    @Test
    void roundTrip_trafficFields() {
        ApiEntry entry = new ApiEntry("POST", "/api/login");
        entry.setLastRawRequest("POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin&pass=123");
        entry.setLastRawResponse("HTTP/1.1 200 OK\r\n\r\n{\"token\":\"abc\"}");
        entry.setLastUrl("https://example.com/api/login");
        entry.setLastStatusCode(200);

        String json = JsonUtils.toJson(List.of(entry));
        List<ApiEntry> restored = JsonUtils.fromJson(json);

        ApiEntry r = restored.get(0);
        assertEquals("POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin&pass=123", r.getLastRawRequest());
        assertEquals("HTTP/1.1 200 OK\r\n\r\n{\"token\":\"abc\"}", r.getLastRawResponse());
        assertEquals("https://example.com/api/login", r.getLastUrl());
        assertEquals(200, r.getLastStatusCode());
    }

    @Test
    void roundTrip_analysisHistory() {
        ApiEntry entry = new ApiEntry("GET", "/api/data");

        VulnFinding finding = new VulnFinding("SQLi", "HIGH", 0.85, "SQL注入",
                "发现SQL注入", "id=1' OR 1=1", "/api/data?id=", "参数化查询");
        AnalysisResult result = new AnalysisResult(
                List.of(finding), "存在SQL注入风险", AnalysisResult.RiskLevel.HIGH,
                500, 1200L, "gpt-4", null);
        AnalysisRecord record = new AnalysisRecord("TRAFFIC_ONLY", result);

        entry.addAnalysisRecord(record);

        String json = JsonUtils.toJson(List.of(entry));
        List<ApiEntry> restored = JsonUtils.fromJson(json);

        ApiEntry r = restored.get(0);
        assertEquals(1, r.getAnalysisHistory().size());
        AnalysisRecord rr = r.getAnalysisHistory().get(0);
        assertEquals("TRAFFIC_ONLY", rr.mode());
        assertNotNull(rr.result());
        assertEquals(AnalysisResult.RiskLevel.HIGH, rr.result().overallRisk());
        assertEquals(1, rr.result().findings().size());
        assertEquals("SQLi", rr.result().findings().get(0).type());
        assertEquals(0.85, rr.result().findings().get(0).confidence(), 0.001);
    }

    @Test
    void roundTrip_analysisRecordWithTestCases() {
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        AnalysisResult result = AnalysisResult.failed(null);
        AnalysisRecord record = new AnalysisRecord("TRAFFIC_ONLY", result);

        TestCase tc = new TestCase("SQLi Test", "SQLi", "id", "1' OR 1=1",
                "GET", "/api/test?id=1' OR 1=1", Map.of("X-Custom", "val"),
                "", "测试SQL注入", "返回全部数据", "HIGH");
        record = record.withTestCases(List.of(tc));
        entry.addAnalysisRecord(record);

        String json = JsonUtils.toJson(List.of(entry));
        List<ApiEntry> restored = JsonUtils.fromJson(json);

        AnalysisRecord rr = restored.get(0).getAnalysisHistory().get(0);
        assertEquals(1, rr.testCases().size());
        TestCase rtc = rr.testCases().get(0);
        assertEquals("SQLi Test", rtc.name());
        assertEquals("id", rtc.targetParam());
        assertEquals("val", rtc.headers().get("X-Custom"));
    }

    @Test
    void roundTrip_pipelineResult() {
        ApiEntry entry = new ApiEntry("GET", "/api/vuln");
        AnalysisResult trafficResult = new AnalysisResult(List.of(), "安全",
                AnalysisResult.RiskLevel.LOW, 100, 500L, "ollama", null);

        ConfirmedVuln cv = new ConfirmedVuln("XSS", "反射XSS", "<script>alert(1)</script>",
                "<img onerror=alert(1)>", "200 OK with script", "dalfox url ...");
        SuspectedVuln sv = new SuspectedVuln("IDOR", "疑似越权", "资源ID可枚举", "curl ...");
        FinalVerdict verdict = new FinalVerdict("HIGH", List.of(cv), List.of(sv),
                "发现XSS漏洞", "修复建议", 1000);
        PipelineResult pr = new PipelineResult(trafficResult, "源码内容", List.of(), List.of(), verdict, java.util.Map.of());

        AnalysisRecord record = new AnalysisRecord("TRAFFIC_ONLY", trafficResult)
                .withPipelineResult(pr);
        entry.addAnalysisRecord(record);

        String json = JsonUtils.toJson(List.of(entry));
        List<ApiEntry> restored = JsonUtils.fromJson(json);

        AnalysisRecord rr = restored.get(0).getAnalysisHistory().get(0);
        assertTrue(rr.hasPipelineResult());
        FinalVerdict rv = rr.pipelineResult().verdict();
        assertEquals("HIGH", rv.overallRisk());
        assertEquals(1, rv.confirmedVulns().size());
        assertEquals("XSS", rv.confirmedVulns().get(0).type());
        assertEquals(1, rv.suspectedVulns().size());
        assertEquals("IDOR", rv.suspectedVulns().get(0).type());
    }

    @Test
    void roundTrip_verdictPhase4Fields() {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1001");
        AnalysisResult trafficResult = new AnalysisResult(List.of(), "存在越权",
                AnalysisResult.RiskLevel.HIGH, 100, 500L, "claude", null);

        // Phase 4: identityProof + cvss on confirmed; confidence + escalationPath
        // on suspected (regression: these used to be dropped on serialize);
        // rejectionReasons on the verdict itself.
        ConfirmedVuln cv = new ConfirmedVuln("越权访问", "水平越权", "替换ID返回他人数据",
                "/api/users/1002", "200 + 他人订单", "curl ...",
                "会话A凭证请求 /api/users/1002（属会话B）；匿名访问401；返回数据含他人手机号",
                "7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)");
        SuspectedVuln sv = new SuspectedVuln("IDOR", "疑似批量枚举", "ID连续递增", "curl ...",
                "LOW", "结合未授权可批量拖取");
        FinalVerdict verdict = new FinalVerdict("HIGH", List.of(cv), List.of(sv),
                "发现水平越权", "修复建议", 1000,
                List.of("identity_not_proven: '历史遗留' 越权类 confirmed 缺少身份证据，降级为疑似"));
        PipelineResult pr = new PipelineResult(trafficResult, "", List.of(), List.of(), verdict, java.util.Map.of());

        entry.addAnalysisRecord(new AnalysisRecord("PIPELINE", trafficResult).withPipelineResult(pr));

        List<ApiEntry> restored = JsonUtils.fromJson(JsonUtils.toJson(List.of(entry)));
        FinalVerdict rv = restored.get(0).getAnalysisHistory().get(0).pipelineResult().verdict();

        ConfirmedVuln rcv = rv.confirmedVulns().get(0);
        assertTrue(rcv.identityProof().contains("会话A"), rcv.identityProof());
        assertTrue(rcv.cvss().startsWith("7.5"), rcv.cvss());

        SuspectedVuln rsv = rv.suspectedVulns().get(0);
        assertEquals("LOW", rsv.confidence());
        assertEquals("结合未授权可批量拖取", rsv.escalationPath());

        assertEquals(1, rv.rejectionReasons().size());
        assertTrue(rv.rejectionReasons().get(0).contains("identity_not_proven"));
    }

    @Test
    void deserialize_unknownEnumValue_fallsBackToDefault() {
        String json = """
                {"version":"4.0.0","apis":[{
                  "id":"abc","httpMethod":"GET","apiPath":"/test",
                  "status":"FUTURE_STATUS","vulnType":"UNKNOWN_VULN",
                  "result":"","note":"","domain":"","lastSeenTimestamp":0
                }]}""";

        List<ApiEntry> restored = JsonUtils.fromJson(json);
        assertEquals(1, restored.size());
        assertEquals(ApiStatus.UNTESTED, restored.get(0).getStatus());
        assertNull(restored.get(0).getVulnType());
    }

    @Test
    void deserialize_missingTrafficFields_defaultsToEmpty() {
        String json = """
                {"version":"4.0.0","apis":[{
                  "id":"abc","httpMethod":"GET","apiPath":"/test",
                  "status":"UNTESTED","result":"","note":"","domain":"","lastSeenTimestamp":0
                }]}""";

        List<ApiEntry> restored = JsonUtils.fromJson(json);
        ApiEntry r = restored.get(0);
        assertEquals("", r.getLastRawRequest());
        assertEquals("", r.getLastRawResponse());
        assertEquals("", r.getLastUrl());
        assertEquals(0, r.getLastStatusCode());
        assertTrue(r.getAnalysisHistory().isEmpty());
    }

    // ===== Passive findings: round-trip + legacy note migration =====

    @Test
    void passiveFindings_roundTrip() {
        ApiEntry entry = new ApiEntry("GET", "/api/pf");
        entry.addPassiveFindingIfAbsent(new com.flechazo.apisentinel.model.PassiveFinding(
                "pf000001", com.flechazo.apisentinel.model.PassiveFinding.Source.HEURISTIC,
                "MEDIUM", "CORS 配置错误", "Origin反射", "ACAO 反射 evil.example", "限制 Origin 白名单", 123L));
        entry.addPassiveFindingIfAbsent(new com.flechazo.apisentinel.model.PassiveFinding(
                "pf000002", com.flechazo.apisentinel.model.PassiveFinding.Source.SENSITIVE_INFO,
                "INFO", "敏感信息", "Email", "", "", 456L));

        List<ApiEntry> restored = JsonUtils.fromJson(JsonUtils.toJson(List.of(entry)));
        ApiEntry r = restored.get(0);
        assertEquals(2, r.getPassiveFindings().size());
        var first = r.getPassiveFindings().get(0);
        assertEquals("pf000001", first.id());
        assertEquals(com.flechazo.apisentinel.model.PassiveFinding.Source.HEURISTIC, first.source());
        assertEquals("MEDIUM", first.risk());
        assertEquals("Origin反射", first.title());
        assertEquals("ACAO 反射 evil.example", first.evidence());
        assertEquals("限制 Origin 白名单", first.remediation());
        assertEquals(123L, first.detectedAt());
    }

    @Test
    void legacyNote_migratedToFindings_userTextPreserved() {
        // v4.0-style note mixing machine markers with a hand-written line.
        String legacyNote = "[敏感信息] Email, Phone\n用户手写备注第一行\n"
                + "[Heuristic] [MEDIUM] 通配符 Origin 配合凭据共享: ACAO:* 且 ACAC:true\n"
                + "[LOW] 缺少安全头: 缺少 HSTS\n"
                + "[越权] [未授权检测-待确认] 去除认证头后仍返回 2xx (200)\n原始状态码: 200";
        String json = """
                {"version":"4.0.0","apis":[{
                  "id":"abc","httpMethod":"GET","apiPath":"/legacy",
                  "status":"UNTESTED","result":"","note":%s,"domain":"","lastSeenTimestamp":0
                }]}""".formatted(new com.google.gson.Gson().toJson(legacyNote));

        List<ApiEntry> restored = JsonUtils.fromJson(json);
        ApiEntry r = restored.get(0);

        // User note keeps only the hand-written line.
        assertEquals("用户手写备注第一行", r.getNote());
        // 2 sensitive rules + 2 heuristic + 1 unauthorized = 5 findings.
        assertEquals(5, r.getPassiveFindings().size());

        long sensitive = r.getPassiveFindings().stream()
                .filter(f -> f.source() == com.flechazo.apisentinel.model.PassiveFinding.Source.SENSITIVE_INFO)
                .count();
        assertEquals(2, sensitive);
        assertTrue(r.getPassiveFindings().stream()
                .anyMatch(f -> f.title().equals("Email")));

        var heuristic = r.getPassiveFindings().stream()
                .filter(f -> f.source() == com.flechazo.apisentinel.model.PassiveFinding.Source.HEURISTIC)
                .toList();
        assertEquals(2, heuristic.size());
        assertTrue(heuristic.stream().anyMatch(f -> f.title().equals("通配符 Origin 配合凭据共享")
                && f.risk().equals("MEDIUM") && f.evidence().contains("ACAO:*")));
        assertTrue(heuristic.stream().anyMatch(f -> f.title().equals("缺少安全头")
                && f.risk().equals("LOW")));

        var unauth = r.getPassiveFindings().stream()
                .filter(f -> f.source() == com.flechazo.apisentinel.model.PassiveFinding.Source.UNAUTHORIZED)
                .toList();
        assertEquals(1, unauth.size());
        assertEquals("未授权访问探测（待确认）", unauth.get(0).title());
        assertTrue(unauth.get(0).evidence().contains("原始状态码: 200"),
                "越权 evidence should absorb continuation lines: " + unauth.get(0).evidence());
    }

    @Test
    void legacyNote_plainUserNote_untouched() {
        String json = """
                {"version":"4.0.0","apis":[{
                  "id":"abc","httpMethod":"GET","apiPath":"/plain",
                  "status":"UNTESTED","result":"","note":"just a user note","domain":"","lastSeenTimestamp":0
                }]}""";
        ApiEntry r = JsonUtils.fromJson(json).get(0);
        assertEquals("just a user note", r.getNote());
        assertFalse(r.hasPassiveFindings());
    }
}
