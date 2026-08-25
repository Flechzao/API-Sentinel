package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for blind-injection classifiers and parameter mutation (pure parts). */
class BlindVerifierTest {

    // ===== Boolean classification =====

    @Test
    void booleanClassify_statusDiff_confirmed() {
        assertNotNull(BooleanBlindVerifier.classify(200, 500, 500, 500));
    }

    @Test
    void booleanClassify_lengthDiffOver5pct_confirmed() {
        // 840 vs 500 → 40% diff
        assertNotNull(BooleanBlindVerifier.classify(200, 840, 200, 500));
    }

    @Test
    void booleanClassify_smallLengthDiff_notConfirmed() {
        // 510 vs 500 → 2% < 5%
        assertNull(BooleanBlindVerifier.classify(200, 510, 200, 500));
    }

    @Test
    void booleanClassify_identical_notConfirmed() {
        assertNull(BooleanBlindVerifier.classify(200, 500, 200, 500));
    }

    // ===== Timing classification =====

    @Test
    void timingClassify_delayOverThreshold_confirmed() {
        assertNotNull(TimingBlindVerifier.classifyTiming(300, 5200, 200, 5000));
    }

    @Test
    void timingClassify_noDelay_notConfirmed() {
        assertNull(TimingBlindVerifier.classifyTiming(300, 800, 200, 5000));
    }

    @Test
    void timingClassify_5xx_neverConfirmed() {
        assertNull(TimingBlindVerifier.classifyTiming(300, 9000, 500, 5000));
        assertNull(TimingBlindVerifier.classifyTiming(300, 9000, 0, 5000));
    }

    @Test
    void timingSleepPayloads_allDbsPresent() {
        assertEquals(5, TimingBlindVerifier.SLEEP_PAYLOADS.size());
        assertTrue(TimingBlindVerifier.SLEEP_PAYLOADS.get("mysql").contains("SLEEP(5)"));
        assertTrue(TimingBlindVerifier.SLEEP_PAYLOADS.get("postgresql").contains("pg_sleep"));
        assertTrue(TimingBlindVerifier.SLEEP_PAYLOADS.get("mssql").contains("WAITFOR DELAY"));
    }

    // ===== Parameter mutation =====

    private static final String RAW_QUERY =
            "GET /api/users?id=1001&name=bob HTTP/1.1\r\n"
          + "Host: example.com\r\n\r\n";

    private static final String RAW_JSON =
            "POST /api/login HTTP/1.1\r\n"
          + "Host: example.com\r\n"
          + "Content-Type: application/json\r\n\r\n"
          + "{\"username\":\"alice\",\"password\":\"pw\"}";

    @Test
    void mutate_query_appendsPayload() {
        String r = BlindParamMutator.mutate(RAW_QUERY, "id", "query", "1001 AND 1=1");
        assertNotNull(r);
        String target = com.flechazo.apisentinel.util.HttpMessageUtils.requestTarget(r);
        assertTrue(target.contains("AND+1%3D1") || target.contains("AND%201%3D1"), target);
        assertTrue(target.contains("name=bob"), target);
    }

    @Test
    void mutate_bodyJson_escapesProperly() {
        String r = BlindParamMutator.mutate(RAW_JSON, "username", "body_json", "alice' AND '1'='1");
        assertNotNull(r);
        String body = com.flechazo.apisentinel.util.HttpMessageUtils.bodyOf(r);
        assertTrue(body.contains("alice' AND '1'='1"), body);
        // still valid JSON
        assertNotNull(com.flechazo.apisentinel.util.HttpMessageUtils.parseJsonObject(body));
    }

    @Test
    void mutate_cookie_replacesValue() {
        String raw = "GET /x HTTP/1.1\r\nHost: h\r\nCookie: token=abc; a=1\r\n\r\n";
        String r = BlindParamMutator.mutate(raw, "token", "cookie", "forged");
        assertNotNull(r);
        String cookie = com.flechazo.apisentinel.util.HttpMessageUtils.getHeader(r, "Cookie");
        assertTrue(cookie.contains("token=forged"), cookie);
    }

    @Test
    void mutate_unknownLocation_null() {
        assertNull(BlindParamMutator.mutate(RAW_QUERY, "id", "nowhere", "x"));
    }

    // ===== Candidate discovery / location =====

    @Test
    void candidateSqlParams_picksIdLikeParams() {
        ApiEntry entry = new ApiEntry("GET", "/api/users");
        entry.setLastRawRequest("GET /api/users?id=1&color=red&search=x HTTP/1.1\r\nHost: h\r\n\r\n");
        var candidates = BlindParamMutator.candidateSqlParams(entry, 5);
        assertTrue(candidates.contains("id"));
        assertTrue(candidates.contains("search"));
        assertFalse(candidates.contains("color"), "non-SQL params should not be candidates");
    }

    @Test
    void locateParam_queryAndJson() {
        ApiEntry q = new ApiEntry("GET", "/x");
        q.setLastRawRequest(RAW_QUERY);
        assertEquals("query", BlindParamMutator.locateParam(q, "id"));

        ApiEntry j = new ApiEntry("POST", "/api/login");
        j.setLastRawRequest(RAW_JSON);
        assertEquals("body_json", BlindParamMutator.locateParam(j, "username"));
    }
}
