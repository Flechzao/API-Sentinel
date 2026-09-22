package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 载荷库单元测试
 *
 * @since 1.2.0
 */
class PayloadLibraryTest {

    @Test
    void get_existingType_returnsNonEmptyList() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.SQL_INJECTION);

        assertNotNull(payloads);
        assertFalse(payloads.isEmpty(), "SQL_INJECTION 应有 Payload");
    }

    @Test
    void get_nonExistentType_returnsEmptyList() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get("NON_EXISTENT_TYPE");

        assertNotNull(payloads);
        assertTrue(payloads.isEmpty());
    }

    @Test
    void get_returnsUnmodifiableList() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.BOLA);

        assertThrows(UnsupportedOperationException.class, () -> {
            payloads.add(new PayloadLibrary.Payload("test", "test", "test"));
        });
    }

    @Test
    void getAll_returnsAllPayloads() {
        List<PayloadLibrary.Payload> all = PayloadLibrary.getAll();

        assertNotNull(all);
        assertEquals(PayloadLibrary.totalCount(), all.size());
        assertTrue(all.size() >= 150, "应有至少 150 个 Payload，实际: " + all.size());
    }

    @Test
    void getAttackTypes_returnsAllRegisteredTypes() {
        List<String> types = PayloadLibrary.getAttackTypes();

        assertNotNull(types);
        assertFalse(types.isEmpty());
        assertTrue(types.contains(AttackType.BOLA));
        assertTrue(types.contains(AttackType.SQL_INJECTION));
        assertTrue(types.contains(AttackType.XSS));
        assertTrue(types.contains(AttackType.SSRF));
    }

    @Test
    void totalCount_matchesSumOfAllTypes() {
        int total = PayloadLibrary.totalCount();
        int sum = PayloadLibrary.getAttackTypes().stream()
                .mapToInt(type -> PayloadLibrary.get(type).size())
                .sum();

        assertEquals(sum, total);
    }

    @Test
    void search_findsPayloadsByValue() {
        List<PayloadLibrary.Payload> results = PayloadLibrary.search("UNION");

        assertFalse(results.isEmpty());
        assertTrue(results.stream().anyMatch(p -> p.value().contains("UNION")));
    }

    @Test
    void search_caseInsensitive() {
        List<PayloadLibrary.Payload> results1 = PayloadLibrary.search("union");
        List<PayloadLibrary.Payload> results2 = PayloadLibrary.search("UNION");
        List<PayloadLibrary.Payload> results3 = PayloadLibrary.search("Union");

        assertEquals(results1.size(), results2.size());
        assertEquals(results2.size(), results3.size());
    }

    @Test
    void search_findsPayloadsByName() {
        List<PayloadLibrary.Payload> results = PayloadLibrary.search("盲注");

        assertFalse(results.isEmpty());
    }

    @Test
    void search_findsPayloadsByDescription() {
        List<PayloadLibrary.Payload> results = PayloadLibrary.search("绕过");

        assertFalse(results.isEmpty());
    }

    @Test
    void search_nonExistentKeyword_returnsEmpty() {
        List<PayloadLibrary.Payload> results = PayloadLibrary.search("xyzzy_nonexistent_keyword_12345");

        assertTrue(results.isEmpty());
    }

    @Test
    void getStats_containsAllTypes() {
        Map<String, Integer> stats = PayloadLibrary.getStats();

        assertNotNull(stats);
        assertTrue(stats.containsKey(AttackType.BOLA));
        assertTrue(stats.containsKey(AttackType.SQL_INJECTION));
        assertTrue(stats.containsKey("TOTAL"));
    }

    @Test
    void getStats_totalMatchesActualCount() {
        Map<String, Integer> stats = PayloadLibrary.getStats();
        int totalFromStats = stats.get("TOTAL");
        int actualTotal = PayloadLibrary.totalCount();

        assertEquals(actualTotal, totalFromStats);
    }

    @Test
    void getStats_individualCountsMatchListSizes() {
        Map<String, Integer> stats = PayloadLibrary.getStats();

        for (String type : PayloadLibrary.getAttackTypes()) {
            int expectedSize = PayloadLibrary.get(type).size();
            int statsSize = stats.getOrDefault(type, 0);
            assertEquals(expectedSize, statsSize, "类型 " + type + " 计数不匹配");
        }
    }

    @Test
    void render_replacesSingleVariable() {
        String payload = "{{id}}+1";
        String result = PayloadLibrary.render(payload, Map.of("id", "123"));

        assertEquals("123+1", result);
    }

    @Test
    void render_replacesMultipleVariables() {
        String payload = "{{id}}/{{other_id}}";
        String result = PayloadLibrary.render(payload, Map.of("id", "123", "other_id", "456"));

        assertEquals("123/456", result);
    }

    @Test
    void render_leavesUnmatchedVariablesIntact() {
        String payload = "{{id}}/{{unknown}}";
        String result = PayloadLibrary.render(payload, Map.of("id", "123"));

        assertEquals("123/{{unknown}}", result);
    }

    @Test
    void render_nullPayload_returnsNull() {
        String result = PayloadLibrary.render(null, Map.of("id", "123"));

        assertNull(result);
    }

    @Test
    void render_nullParams_returnsOriginal() {
        String payload = "{{id}}+1";
        String result = PayloadLibrary.render(payload, null);

        assertEquals(payload, result);
    }

    @Test
    void render_emptyParams_returnsOriginal() {
        String payload = "{{id}}+1";
        String result = PayloadLibrary.render(payload, Map.of());

        assertEquals(payload, result);
    }

    @Test
    void render_noVariables_returnsOriginal() {
        String payload = "1+1";
        String result = PayloadLibrary.render(payload, Map.of("id", "123"));

        assertEquals("1+1", result);
    }

    @Test
    void bolaPayloads_containsIdManipulation() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.BOLA);

        assertFalse(payloads.isEmpty());
        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("{{id}}")),
                "BOLA Payload 应包含 {{id}} 模板变量");
    }

    @Test
    void sqliPayloads_containsClassicAttacks() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.SQL_INJECTION);

        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("UNION")),
                "SQLi Payload 应包含 UNION 注入");
        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("OR '1'='1")),
                "SQLi Payload 应包含 OR 绕过");
        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("SLEEP")),
                "SQLi Payload 应包含时间盲注");
    }

    @Test
    void xssPayloads_containsScriptTags() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.XSS);

        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("<script>")),
                "XSS Payload 应包含 script 标签");
        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("onerror")),
                "XSS Payload 应包含事件处理器");
    }

    @Test
    void ssrfPayloads_containsInternalAddresses() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.SSRF);

        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("127.0.0.1")),
                "SSRF Payload 应包含本地回环");
        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("169.254.169.254")),
                "SSRF Payload 应包含云元数据地址");
    }

    @Test
    void sstiPayloads_containsTemplateExpressions() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.SSTI);

        assertTrue(payloads.stream().anyMatch(p -> p.value().contains("{{7*7}}")),
                "SSTI Payload 应包含模板表达式");
    }

    @Test
    void payloadRecord_hasAllFields() {
        PayloadLibrary.Payload payload = new PayloadLibrary.Payload("test_value", "test_name", "test_desc");

        assertEquals("test_value", payload.value());
        assertEquals("test_name", payload.name());
        assertEquals("test_desc", payload.description());
    }

    @Test
    void allPayloads_haveNonEmptyFields() {
        for (PayloadLibrary.Payload payload : PayloadLibrary.getAll()) {
            assertNotNull(payload.value(), "Payload value 不应为 null");
            assertNotNull(payload.name(), "Payload name 不应为 null");
            assertNotNull(payload.description(), "Payload description 不应为 null");
            assertFalse(payload.name().isEmpty(), "Payload name 不应为空");
            assertFalse(payload.description().isEmpty(), "Payload description 不应为空");
        }
    }

    @Test
    void bolaPayloads_countIsExpected() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.BOLA);
        assertEquals(14, payloads.size(), "BOLA 应有 14 个 Payload");
    }

    @Test
    void sqliPayloads_countIsExpected() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.SQL_INJECTION);
        assertEquals(24, payloads.size(), "SQL_INJECTION 应有 24 个 Payload");
    }

    @Test
    void xssPayloads_countIsExpected() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.XSS);
        assertEquals(13, payloads.size(), "XSS 应有 13 个 Payload");
    }

    @Test
    void ssrfPayloads_countIsExpected() {
        List<PayloadLibrary.Payload> payloads = PayloadLibrary.get(AttackType.SSRF);
        assertEquals(18, payloads.size(), "SSRF 应有 18 个 Payload");
    }
}
