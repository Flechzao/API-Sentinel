package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.AttackType;
import com.flechazo.apisentinel.detection.PayloadLibrary;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ListAttackTypesTool 单元测试
 *
 * 验证 list_attack_types 工具的查询模式（列表/详情/搜索/过滤）和 JSON 输出契约。
 * 零 LLM 调用、纯本地查询，无需 mock 任何外部依赖。
 *
 * @since 1.1.0
 */
class ListAttackTypesToolTest {

    private final ListAttackTypesTool tool = new ListAttackTypesTool(null);

    private JsonObject exec(String argsJson) {
        return JsonParser.parseString(tool.execute(argsJson)).getAsJsonObject();
    }

    // ==================== 元数据 ====================

    @Test
    void name_isListAttackTypes() {
        assertEquals("list_attack_types", tool.name());
    }

    @Test
    void description_mentionsPayloadsAndIsNonEmpty() {
        String desc = tool.description();
        assertTrue(desc != null && !desc.isBlank());
        assertTrue(desc.toLowerCase().contains("payload") || desc.contains("Payload"));
    }

    @Test
    void inputSchema_isObjectTypeWithProperties() {
        JsonObject schema = tool.inputSchema();
        assertEquals("object", schema.get("type").getAsString());
        JsonObject props = schema.getAsJsonObject("properties");
        assertNotNull(props);
        assertTrue(props.has("attack_type"));
        assertTrue(props.has("severity"));
        assertTrue(props.has("owasp_top10_only"));
        assertTrue(props.has("search"));
        assertTrue(props.has("payload_limit"));
    }

    @Test
    void isReadOnly_usesAgentToolDefault() {
        // 未覆写 isReadOnly()，沿用 AgentTool 默认值 false
        assertFalse(tool.isReadOnly());
    }

    // ==================== 列表模式 ====================

    @Test
    void execute_noArgs_listsAllAttackTypes() {
        JsonObject out = exec("{}");

        assertTrue(out.get("success").getAsBoolean());
        int total = out.get("total").getAsInt();
        assertEquals(AttackType.getAll().size(), total);
        assertEquals(AttackType.getAll().size(), out.getAsJsonArray("attack_types").size());
        assertTrue(out.get("total_payloads").getAsInt() > 0);
    }

    @Test
    void execute_nullArgs_listsAllAttackTypes() {
        // parseArgs(null) 返回空对象 → 列表模式
        JsonObject out = JsonParser.parseString(tool.execute(null)).getAsJsonObject();
        assertTrue(out.get("success").getAsBoolean());
        assertEquals(AttackType.getAll().size(), out.get("total").getAsInt());
    }

    @Test
    void execute_invalidJson_fallsBackToList() {
        // 非法 JSON 不应抛异常，回退为列表模式
        JsonObject out = JsonParser.parseString(tool.execute("not-a-json{}")).getAsJsonObject();
        assertTrue(out.get("success").getAsBoolean());
    }

    @Test
    void execute_list_eachTypeHasRequiredFields() {
        JsonObject out = exec("{}");
        JsonObject first = out.getAsJsonArray("attack_types").get(0).getAsJsonObject();
        assertTrue(first.has("id"));
        assertTrue(first.has("name"));
        assertTrue(first.has("severity"));
        assertTrue(first.has("owasp_mapping"));
        assertTrue(first.has("payload_count"));
    }

    // ==================== OWASP Top 10 过滤 ====================

    @Test
    void execute_owaspTop10Only_returnsOwaspTypes() {
        JsonObject out = exec("{\"owasp_top10_only\": true}");

        assertTrue(out.get("success").getAsBoolean());
        assertEquals(AttackType.getOwaspApiTop10().size(), out.get("total").getAsInt());
        assertEquals("OWASP API Top 10", out.get("filter").getAsString());
    }

    // ==================== 严重性过滤 ====================

    @Test
    void execute_severityFilter_returnsMatchingSeverity() {
        JsonObject out = exec("{\"severity\": \"CRITICAL\"}");

        assertTrue(out.get("success").getAsBoolean());
        assertEquals(AttackType.getBySeverity("CRITICAL").size(), out.get("total").getAsInt());
        // 过滤字段携带原始值（非大写）
        assertEquals("severity=CRITICAL", out.get("filter").getAsString());
    }

    @Test
    void execute_severityFilter_lowercasedInput_stillMatches() {
        // executeList 内部做了 toUpperCase
        JsonObject out = exec("{\"severity\": \"high\"}");
        assertEquals(AttackType.getBySeverity("HIGH").size(), out.get("total").getAsInt());
    }

    // ==================== 详情模式 ====================

    @Test
    void execute_detailForKnownType_returnsPayloads() {
        JsonObject out = exec("{\"attack_type\": \"BOLA\"}");

        assertTrue(out.get("success").getAsBoolean());
        assertEquals("BOLA", out.get("id").getAsString());
        assertTrue(out.has("payloads"));
        assertTrue(out.get("payload_total").getAsInt() > 0);
        assertEquals(PayloadLibrary.get("BOLA").size(), out.get("payload_total").getAsInt());
    }

    @Test
    void execute_detailIncludesPayloadFields() {
        JsonObject out = exec("{\"attack_type\": \"SQL_INJECTION\", \"payload_limit\": 1}");
        JsonObject firstPayload = out.getAsJsonArray("payloads").get(0).getAsJsonObject();
        assertTrue(firstPayload.has("payload"));
        assertTrue(firstPayload.has("name"));
    }

    @Test
    void execute_detailForUnknownType_returnsErrorAndAvailable() {
        JsonObject out = exec("{\"attack_type\": \"DOES_NOT_EXIST\"}");

        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().contains("DOES_NOT_EXIST"));
        assertTrue(out.has("available_types"));
        assertTrue(out.getAsJsonArray("available_types").size() > 0);
    }

    // ==================== 搜索模式 ====================

    @Test
    void execute_search_returnsMatches() {
        JsonObject out = exec("{\"search\": \"sql\"}");

        assertTrue(out.get("success").getAsBoolean());
        assertEquals("sql", out.get("keyword").getAsString());
        assertEquals(PayloadLibrary.search("sql").size(), out.get("total_matches").getAsInt());
        assertTrue(out.has("results"));
    }

    @Test
    void execute_search_noMatches_returnsZero() {
        JsonObject out = exec("{\"search\": \"zzz_no_match_zzz\"}");
        assertEquals(0, out.get("total_matches").getAsInt());
        assertEquals(0, out.getAsJsonArray("results").size());
    }

    // ==================== payload_limit ====================

    @Test
    void execute_payloadLimit_truncatesDetail() {
        JsonObject out = exec("{\"attack_type\": \"SQL_INJECTION\", \"payload_limit\": 2}");

        assertEquals(2, out.getAsJsonArray("payloads").size());
        assertEquals(2, out.get("payload_shown").getAsInt());
        // payload_total 仍反映真实总数
        assertTrue(out.get("payload_total").getAsInt() >= 2);
        // 截断时应给出 hint
        assertTrue(out.has("hint"));
    }

    @Test
    void execute_payloadLimit_truncatesSearch() {
        JsonObject out = exec("{\"search\": \"or\", \"payload_limit\": 1}");
        assertTrue(out.getAsJsonArray("results").size() <= 1);
        assertEquals(1, out.get("shown").getAsInt());
    }

    @Test
    void execute_payloadLimitInvalid_fallsBackToDefault() {
        // 非整数 payload_limit → 默认 10，不应抛异常
        JsonObject out = exec("{\"attack_type\": \"BOLA\", \"payload_limit\": \"abc\"}");
        assertTrue(out.get("success").getAsBoolean());
    }
}
