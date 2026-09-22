package com.flechazo.apisentinel.ai.agent.tool;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GeneratePocTool 单元测试
 *
 * 验证 generate_poc 工具的参数校验、PoC 生成、文件保存、累积计数与 JSON 输出契约。
 * PoC 生成走纯模板逻辑（PoCGeneratorService），无需 LLM。
 *
 * @since 1.1.0
 */
class GeneratePocToolTest {

    private GeneratePocTool newTool() {
        // logger 为 null 时工具内部有 null 守卫；PoCGeneratorService 接受 null logger
        return new GeneratePocTool(new ToolContext(null, null, null, null, null, null, null));
    }

    private JsonObject exec(GeneratePocTool t, String argsJson) {
        return JsonParser.parseString(t.execute(argsJson)).getAsJsonObject();
    }

    // ==================== 元数据 ====================

    @Test
    void name_isGeneratePoc() {
        assertEquals("generate_poc", newTool().name());
    }

    @Test
    void description_mentionsSupportedVulnTypes() {
        String desc = newTool().description();
        assertTrue(desc.toLowerCase().contains("injection"));
        assertTrue(desc.toLowerCase().contains("bola") || desc.contains("IDOR"));
    }

    @Test
    void isReadOnly_isFalse_canWriteFiles() {
        assertFalse(newTool().isReadOnly());
    }

    @Test
    void inputSchema_requiresVulnTypeEndpointUrl() {
        JsonObject schema = newTool().inputSchema();
        assertEquals("object", schema.get("type").getAsString());
        var required = schema.getAsJsonArray("required");
        // 三个必填字段
        assertEquals(3, required.size());
        assertTrue(required.asList().stream().anyMatch(e -> e.getAsString().equals("vuln_type")));
        assertTrue(required.asList().stream().anyMatch(e -> e.getAsString().equals("endpoint")));
        assertTrue(required.asList().stream().anyMatch(e -> e.getAsString().equals("url")));
    }

    // ==================== 参数校验 ====================

    @Test
    void execute_missingVulnType_returnsError() {
        JsonObject out = exec(newTool(),
                "{\"endpoint\":\"GET /api/users/{id}\",\"url\":\"https://x.test/api/users/1\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertEquals("vuln_type is required", out.get("error").getAsString());
    }

    @Test
    void execute_missingEndpoint_returnsError() {
        JsonObject out = exec(newTool(),
                "{\"vuln_type\":\"SQL Injection\",\"url\":\"https://x.test/api/users/1\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertEquals("endpoint is required", out.get("error").getAsString());
    }

    @Test
    void execute_missingUrl_returnsError() {
        JsonObject out = exec(newTool(),
                "{\"vuln_type\":\"SQL Injection\",\"endpoint\":\"GET /api/users/{id}\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertEquals("url is required", out.get("error").getAsString());
    }

    @Test
    void execute_invalidJson_returnsError() {
        JsonObject out = JsonParser.parseString(newTool().execute("{bad json")).getAsJsonObject();
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("json"));
    }

    // ==================== 生成 ====================

    @Test
    void execute_validInput_generatesPoCWithCurl() {
        GeneratePocTool tool = newTool();
        JsonObject out = exec(tool, """
                {"vuln_type":"SQL Injection","severity":"CRITICAL",
                 "endpoint":"GET /api/users/{id}","url":"https://x.test/api/users/1",
                 "method":"GET","payload":"' OR '1'='1","evidence":"syntax error",
                 "confidence":95}
                """);

        assertTrue(out.get("success").getAsBoolean());
        assertEquals("SQL Injection", out.get("vuln_type").getAsString());
        assertEquals("CRITICAL", out.get("severity").getAsString());
        assertEquals(95, out.get("confidence").getAsInt());
        assertTrue(out.has("curl_command"));
        String curl = out.get("curl_command").getAsString();
        assertTrue(curl.contains("https://x.test/api/users/1"));
    }

    @Test
    void execute_defaultSeverityIsHigh() {
        JsonObject out = exec(newTool(), """
                {"vuln_type":"XSS","endpoint":"GET /search","url":"https://x.test/search"}
                """);
        assertEquals("HIGH", out.get("severity").getAsString());
    }

    @Test
    void execute_defaultConfidenceIs80() {
        JsonObject out = exec(newTool(), """
                {"vuln_type":"XSS","endpoint":"GET /search","url":"https://x.test/search"}
                """);
        assertEquals(80, out.get("confidence").getAsInt());
    }

    @Test
    void execute_generatedPocsAccumulate() {
        GeneratePocTool tool = newTool();
        exec(tool, """
                {"vuln_type":"XSS","endpoint":"GET /a","url":"https://x.test/a"}
                """);
        JsonObject out2 = exec(tool, """
                {"vuln_type":"SSRF","endpoint":"POST /fetch","url":"https://x.test/fetch"}
                """);
        // 第二次生成的 total_generated 应为 2
        assertEquals(2, out2.get("total_generated").getAsInt());
        assertEquals(2, tool.getGeneratedPocs().size());
    }

    @Test
    void execute_bolaGeneratesPoC() {
        JsonObject out = exec(newTool(), """
                {"vuln_type":"BOLA/IDOR","endpoint":"GET /api/orders/{id}",
                 "url":"https://x.test/api/orders/1001","method":"GET"}
                """);
        assertTrue(out.get("success").getAsBoolean());
        assertTrue(out.has("curl_command"));
        assertTrue(out.has("steps"));
    }

    @Test
    void execute_customVulnType_stillGenerates() {
        JsonObject out = exec(newTool(), """
                {"vuln_type":"Custom Business Logic Flaw",
                 "endpoint":"POST /api/transfer","url":"https://x.test/api/transfer"}
                """);
        assertTrue(out.get("success").getAsBoolean());
        assertEquals("Custom Business Logic Flaw", out.get("vuln_type").getAsString());
    }

    // ==================== 文件保存 ====================

    @Test
    void execute_saveToFile_writesMarkdown(@TempDir Path tempDir) throws Exception {
        Path target = tempDir.resolve("poc-sqli-001.md");
        GeneratePocTool tool = newTool();
        JsonObject out = exec(tool, """
                {"vuln_type":"SQL Injection","endpoint":"GET /api/users/{id}",
                 "url":"https://x.test/api/users/1","save_to_file":"%s"}
                """.formatted(target.toString()));

        assertTrue(out.get("success").getAsBoolean());
        assertEquals(target.toAbsolutePath().toString(), out.get("saved_to").getAsString());
        assertEquals("markdown", out.get("format").getAsString());
        // 文件确实被写入且非空
        assertTrue(Files.exists(target));
        String content = Files.readString(target);
        assertFalse(content.isBlank());
        assertTrue(content.contains("SQL Injection"));
    }

    @Test
    void execute_saveToUnwritablePath_reportsSaveError() {
        // 一个无法写入的路径（目录不存在且不可创建的深层路径）
        GeneratePocTool tool = newTool();
        JsonObject out = exec(tool, """
                {"vuln_type":"XSS","endpoint":"GET /a","url":"https://x.test/a",
                 "save_to_file":"/nonexistent-root-dir-xyz/poc.md"}
                """);
        // 生成仍成功，仅保存失败
        assertTrue(out.get("success").getAsBoolean());
        assertTrue(out.has("save_error"));
        assertTrue(out.get("save_error").getAsString().toLowerCase().contains("save"));
    }
}
