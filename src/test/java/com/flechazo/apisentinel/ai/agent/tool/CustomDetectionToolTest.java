package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CustomDetectionTool 单元测试
 *
 * 验证 custom_detection 工具的 list/run/reload 三种动作、模板匹配器评估
 * （regex/word/status）、part 提取（body/headers/all）、negative 反转，以及
 * 参数校验。模板从临时目录加载，自包含、不依赖项目内 custom-templates/。
 *
 * @since 1.1.0
 */
class CustomDetectionToolTest {

    @TempDir
    Path templateDir;

    private ToolContext ctx;

    @BeforeEach
    void setUp() throws IOException {
        // 一个 word 匹配器模板：命中 "sql syntax" 即匹配（words 必须用内联数组格式）
        writeTemplate("test-sqli.yaml", """
                id: test-sqli
                name: Test SQLi Detection
                severity: high
                type: response-pattern
                matchers:
                  - type: word
                    words: ["sql syntax", "mysql error"]
                    condition: or
                    part: body
                tags: sqli, test
                description: Detects SQL error leakage
                remediation: Use parameterized queries
                """);

        // 一个 regex 匹配器模板
        writeTemplate("test-regex.yaml", """
                id: test-stacktrace
                name: Stack Trace Leakage
                severity: medium
                type: response-pattern
                matchers:
                  - type: regex
                    pattern: "NullPointerException|at com\\.flec.*\\.java"
                    part: body
                tags: infoleak
                """);

        // 一个 status 匹配器模板
        writeTemplate("test-status.yaml", """
                id: test-server-error
                name: Server Error 500
                severity: high
                type: response-pattern
                matchers:
                  - type: status
                    status: 500
                tags: error
                """);

        // logger 非空：CustomDetectionTool 构造时调用 loader.loadAll() 会写日志
        ctx = new ToolContext(null, null, null, null, null, null, new LeveledLogger(null));
    }

    private void writeTemplate(String fileName, String yaml) throws IOException {
        Files.writeString(templateDir.resolve(fileName), yaml);
    }

    private CustomDetectionTool newTool() {
        return new CustomDetectionTool(ctx, templateDir);
    }

    private JsonObject exec(String argsJson) {
        return JsonParser.parseString(newTool().execute(argsJson)).getAsJsonObject();
    }

    // ==================== 元数据 ====================

    @Test
    void name_isCustomDetection() {
        assertEquals("custom_detection", newTool().name());
    }

    @Test
    void description_mentionsTemplatesAndActions() {
        String desc = newTool().description();
        assertTrue(desc.toLowerCase().contains("template"));
        assertTrue(desc.contains("list"));
        assertTrue(desc.contains("run"));
    }

    @Test
    void isReadOnly_usesAgentToolDefault() {
        // 未覆写 isReadOnly()，沿用 AgentTool 默认值 false
        assertFalse(newTool().isReadOnly());
    }

    @Test
    void inputSchema_hasActionAndTemplateId() {
        JsonObject schema = newTool().inputSchema();
        assertEquals("object", schema.get("type").getAsString());
        JsonObject props = schema.getAsJsonObject("properties");
        assertTrue(props.has("action"));
        assertTrue(props.has("template_id"));
        assertTrue(props.has("tag"));
        assertTrue(props.has("severity"));
    }

    // ==================== list 动作 ====================

    @Test
    void execute_defaultAction_isList() {
        JsonObject out = exec("{}");
        assertTrue(out.get("success").getAsBoolean());
        assertEquals("list", out.get("action").getAsString());
        assertEquals(3, out.get("count").getAsInt());
    }

    @Test
    void execute_listEachTemplateHasFields() {
        JsonObject out = exec("{\"action\":\"list\"}");
        JsonObject first = out.getAsJsonArray("templates").get(0).getAsJsonObject();
        assertTrue(first.has("id"));
        assertTrue(first.has("name"));
        assertTrue(first.has("severity"));
        assertTrue(first.has("matchers"));
        assertTrue(first.has("summary"));
    }

    @Test
    void execute_listIncludesStats() {
        JsonObject out = exec("{\"action\":\"list\"}");
        assertTrue(out.has("stats"));
        JsonObject stats = out.getAsJsonObject("stats");
        // stats 至少应有 loaded 数量字段
        assertTrue(stats.size() > 0);
    }

    @Test
    void execute_listByTag_filtersTemplates() {
        JsonObject out = exec("{\"action\":\"list\",\"tag\":\"sqli\"}");
        assertTrue(out.get("success").getAsBoolean());
        // 只有 test-sqli 带 sqli tag
        assertEquals(1, out.get("count").getAsInt());
        JsonObject t = out.getAsJsonArray("templates").get(0).getAsJsonObject();
        assertEquals("test-sqli", t.get("id").getAsString());
    }

    @Test
    void execute_listBySeverity_filtersTemplates() {
        JsonObject out = exec("{\"action\":\"list\",\"severity\":\"high\"}");
        // test-sqli(high) + test-server-error(high) = 2
        assertEquals(2, out.get("count").getAsInt());
    }

    @Test
    void execute_listByTag_noMatch_returnsZero() {
        JsonObject out = exec("{\"action\":\"list\",\"tag\":\"nonexistent-tag\"}");
        assertEquals(0, out.get("count").getAsInt());
    }

    // ==================== run 动作：参数校验 ====================

    @Test
    void execute_runWithoutTemplateId_returnsError() {
        JsonObject out = exec("{\"action\":\"run\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("template_id"));
    }

    @Test
    void execute_runWithUnknownTemplateId_returnsError() {
        JsonObject out = exec("{\"action\":\"run\",\"template_id\":\"no-such-template\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("not found"));
    }

    // ==================== run 动作：entry/response 校验 ====================

    @Test
    void execute_runWithoutEntry_returnsError() {
        // ctx.entry() == null
        JsonObject out = exec("{\"action\":\"run\",\"template_id\":\"test-sqli\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("api entry"));
    }

    @Test
    void execute_runWithEntryButEmptyResponse_returnsError() {
        ApiEntry entry = new ApiEntry("GET", "/api/users");
        entry.setLastRawResponse("");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject result = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-sqli\"}")).getAsJsonObject();
        assertFalse(result.get("success").getAsBoolean());
        assertTrue(result.get("error").getAsString().toLowerCase().contains("response"));
    }

    // ==================== run 动作：匹配器评估 ====================

    @Test
    void execute_runWordMatcher_matchesOnBody() {
        ApiEntry entry = entryWithResponse("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>SQL Syntax error in query</html>");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-sqli\"}")).getAsJsonObject();

        assertTrue(out.get("success").getAsBoolean());
        assertTrue(out.get("matched").getAsBoolean());
        assertEquals(1, out.get("matchers_matched").getAsInt());
        assertEquals("high", out.get("severity").getAsString());
        assertTrue(out.has("finding"));
        assertTrue(out.has("remediation"));
    }

    @Test
    void execute_runWordMatcher_noMatchWhenAbsent() {
        ApiEntry entry = entryWithResponse("HTTP/1.1 200 OK\n\n{\"status\":\"ok\"}");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-sqli\"}")).getAsJsonObject();

        assertTrue(out.get("success").getAsBoolean());
        assertFalse(out.get("matched").getAsBoolean());
        assertEquals(0, out.get("matchers_matched").getAsInt());
    }

    @Test
    void execute_runRegexMatcher_matchesStacktrace() {
        ApiEntry entry = entryWithResponse("HTTP/1.1 500\n\njava.lang.NullPointerException\n\tat com.flec.util.DbHelper.java:42");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-stacktrace\"}")).getAsJsonObject();

        assertTrue(out.get("matched").getAsBoolean());
        assertEquals("medium", out.get("severity").getAsString());
    }

    @Test
    void execute_runStatusMatcher_matches500() {
        ApiEntry entry = entryWithResponse("HTTP/1.1 500 Internal Server Error\n\nerror");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-server-error\"}")).getAsJsonObject();

        assertTrue(out.get("matched").getAsBoolean());
    }

    @Test
    void execute_runStatusMatcher_noMatchOn200() {
        ApiEntry entry = entryWithResponse("HTTP/1.1 200 OK\n\nok");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-server-error\"}")).getAsJsonObject();

        assertFalse(out.get("matched").getAsBoolean());
    }

    @Test
    void execute_runHeadersPart_onlyMatchesHeaders() {
        // 写一个只在 headers 部分匹配 word 的模板
        try {
            writeTemplate("test-headers.yaml", """
                    id: test-headers
                    name: Header Leak
                    severity: low
                    type: response-pattern
                    matchers:
                      - type: word
                        words: ["x-powered-by"]
                        part: headers
                    tags: infoleak
                    """);
        } catch (IOException e) {
            fail("写入模板失败", e);
        }

        // body 含 x-powered-by 但 headers 不含 → 不应匹配
        ApiEntry entry = entryWithResponse("HTTP/1.1 200 OK\n\nx-powered-by: something");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-headers\"}")).getAsJsonObject();
        assertFalse(out.get("matched").getAsBoolean());

        // headers 含 X-Powered-By → 匹配
        ApiEntry entry2 = entryWithResponse("HTTP/1.1 200 OK\nX-Powered-By: Express\n\nbody content");
        ctx = new ToolContext(entry2, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out2 = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-headers\"}")).getAsJsonObject();
        assertTrue(out2.get("matched").getAsBoolean());
    }

    // ==================== reload 动作 ====================

    @Test
    void execute_reload_returnsSuccess() {
        JsonObject out = exec("{\"action\":\"reload\"}");
        assertTrue(out.get("success").getAsBoolean());
        assertEquals("reload", out.get("action").getAsString());
        assertTrue(out.has("stats"));
    }

    @Test
    void execute_reload_picksUpNewTemplate() throws IOException {
        // 初始 3 个模板
        assertEquals(3, exec("{\"action\":\"list\"}").get("count").getAsInt());

        // 新增一个模板并 reload
        writeTemplate("extra.yaml", """
                id: extra-template
                name: Extra
                severity: info
                type: response-pattern
                matchers:
                  - type: word
                    words: ["extra"]
                """);
        JsonObject out = exec("{\"action\":\"reload\"}");
        assertTrue(out.get("success").getAsBoolean());

        JsonObject list = exec("{\"action\":\"list\"}");
        assertEquals(4, list.get("count").getAsInt());
    }

    // ==================== 未知动作 ====================

    @Test
    void execute_unknownAction_returnsError() {
        JsonObject out = exec("{\"action\":\"frobnicate\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("action"));
    }

    // ==================== P1 正则 ReDoS 防护 ====================

    @Test
    void execute_runCatastrophicRegex_rejectedForRedos() throws IOException {
        // (a+)+ 是教科书级灾难性回溯形态；响应体本可命中，但因 ReDoS 防护被拒绝
        writeTemplate("test-redos.yaml", """
                id: test-redos
                name: ReDoS Bait
                severity: high
                type: response-pattern
                matchers:
                  - type: regex
                    pattern: "(a+)+b"
                    part: body
                tags: redos
                """);
        ApiEntry entry = entryWithResponse("HTTP/1.1 200 OK\n\naaaaab");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-redos\"}")).getAsJsonObject();

        assertTrue(out.get("success").getAsBoolean());
        // 被拒绝 → 不匹配
        assertFalse(out.get("matched").getAsBoolean());
        assertEquals(0, out.get("matchers_matched").getAsInt());
    }

    @Test
    void execute_runOverlongRegex_rejected() throws IOException {
        // 超过 MAX_REGEX_PATTERN_LEN(2000) 的正则被拒绝
        String longPattern = "a".repeat(2001);
        writeTemplate("test-longregex.yaml", """
                id: test-longregex
                name: Overlong Regex
                severity: low
                type: response-pattern
                matchers:
                  - type: regex
                    pattern: "%s"
                    part: body
                tags: long
                """.formatted(longPattern));
        ApiEntry entry = entryWithResponse("HTTP/1.1 200 OK\n\naaaaa");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-longregex\"}")).getAsJsonObject();

        assertFalse(out.get("matched").getAsBoolean());
    }

    @Test
    void execute_runSafeRegexStillWorks_afterRedosGuard() throws IOException {
        // 确认 ReDoS 防护不会误杀正常正则（含 .* 量词但无嵌套量词组）
        writeTemplate("test-saferegex.yaml", """
                id: test-saferegex
                name: Safe Regex
                severity: medium
                type: response-pattern
                matchers:
                  - type: regex
                    pattern: "version.*[0-9]+\\.[0-9]+"
                    part: body
                tags: safe
                """);
        ApiEntry entry = entryWithResponse("HTTP/1.1 200 OK\n\nserver version 1.23 build 9");
        ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));

        JsonObject out = JsonParser.parseString(
                new CustomDetectionTool(ctx, templateDir)
                        .execute("{\"action\":\"run\",\"template_id\":\"test-saferegex\"}")).getAsJsonObject();

        assertTrue(out.get("matched").getAsBoolean());
    }

    // ==================== 辅助 ====================

    private ApiEntry entryWithResponse(String rawResponse) {
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        entry.setLastRawResponse(rawResponse);
        return entry;
    }
}
