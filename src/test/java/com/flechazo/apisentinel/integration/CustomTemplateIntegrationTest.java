package com.flechazo.apisentinel.integration;

import com.flechazo.apisentinel.ai.agent.tool.CustomDetectionTool;
import com.flechazo.apisentinel.ai.agent.tool.ToolContext;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 自定义检测模板端到端集成测试
 *
 * 用项目内置 {@code custom-templates/} 的 3 个真实模板（SQLi / SSRF / 敏感数据），
 * 端到端验证 加载 → 解析 → 索引 → 匹配 全链路：
 * <ul>
 *   <li>模板被 TemplateLoader 正确加载并按 ID 可查</li>
 *   <li>regex + word 多匹配器均生效</li>
 *   <li>body part 提取正确（只扫响应体，不扫头部）</li>
 *   <li>命中/不命中分支正确</li>
 * </ul>
 * 仅在测试工作目录下存在 custom-templates 时运行（gradle test cwd = 项目根），否则跳过。
 *
 * @since 1.1.0
 */
class CustomTemplateIntegrationTest {

    private static final Path TEMPLATE_DIR = Path.of(System.getProperty("user.dir"), "custom-templates");

    private static boolean templatesAvailable() {
        return Files.isDirectory(TEMPLATE_DIR)
                && Files.exists(TEMPLATE_DIR.resolve("sqli-detection.yaml"));
    }

    private ToolContext ctxWithResponse(String rawResponse) {
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        entry.setLastRawResponse(rawResponse);
        return new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));
    }

    private JsonObject run(String templateId, String rawResponse) {
        CustomDetectionTool tool = new CustomDetectionTool(ctxWithResponse(rawResponse), TEMPLATE_DIR);
        return JsonParser.parseString(tool.execute(
                "{\"action\":\"run\",\"template_id\":\"" + templateId + "\"}")).getAsJsonObject();
    }

    @Test
    void sqliTemplate_matchesSqlErrorResponse() {
        // skip if shipped templates not on disk
        org.junit.jupiter.api.Assumptions.assumeTrue(templatesAvailable(),
                "custom-templates 目录不存在，跳过端到端测试");

        String resp = "HTTP/1.1 500 Internal Server Error\r\n"
                + "Content-Type: text/html\r\n\r\n"
                + "<html>You have an error in your SQL syntax near 'OR 1=1'</html>";
        JsonObject out = run("custom-sqli-detection", resp);

        assertTrue(out.get("success").getAsBoolean());
        assertTrue(out.get("matched").getAsBoolean(), "SQL 错误响应应被 sqli 模板命中");
        assertEquals("critical", out.get("severity").getAsString());
        // sqli 模板有 regex + word 两个匹配器，两者都可能命中
        assertTrue(out.get("matchers_matched").getAsInt() >= 1);
        assertTrue(out.has("remediation"));
    }

    @Test
    void sqliTemplate_noMatchOnCleanResponse() {
        org.junit.jupiter.api.Assumptions.assumeTrue(templatesAvailable(),
                "custom-templates 目录不存在，跳过端到端测试");

        String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"id\":1,\"name\":\"alice\"}";
        JsonObject out = run("custom-sqli-detection", resp);
        assertTrue(out.get("success").getAsBoolean());
        assertFalse(out.get("matched").getAsBoolean(), "干净响应不应被命中");
        assertEquals(0, out.get("matchers_matched").getAsInt());
    }

    @Test
    void ssrfTemplate_matchesInternalIpInBody() {
        org.junit.jupiter.api.Assumptions.assumeTrue(templatesAvailable(),
                "custom-templates 目录不存在，跳过端到端测试");

        String resp = "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"data\":\"fetched from 169.254.169.254/latest/meta-data/\"}";
        JsonObject out = run("custom-ssrf-detection", resp);
        assertTrue(out.get("matched").getAsBoolean(), "响应体含内网 IP 应被 ssrf 模板命中");
        assertEquals("high", out.get("severity").getAsString());
    }

    @Test
    void sensitiveDataTemplate_matchesPasswordLeak() {
        org.junit.jupiter.api.Assumptions.assumeTrue(templatesAvailable(),
                "custom-templates 目录不存在，跳过端到端测试");

        String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"user\":\"alice\",\"password\":\"s3cret\",\"api_key\":\"sk-1234\"}";
        JsonObject out = run("custom-sensitive-data", resp);
        assertTrue(out.get("matched").getAsBoolean(), "响应体泄露 password/api_key 应被敏感数据模板命中");
    }

    @Test
    void bodyPart_doesNotMatchHeaderOnlyContent() {
        // 关键词出现在 headers 而非 body，part=body 的匹配器不应命中
        org.junit.jupiter.api.Assumptions.assumeTrue(templatesAvailable(),
                "custom-templates 目录不存在，跳过端到端测试");

        String resp = "HTTP/1.1 200 OK\r\nX-Hint: mysql error\r\n\r\n"
                + "{\"ok\":true}";  // body 不含 mysql error
        JsonObject out = run("custom-sqli-detection", resp);
        assertFalse(out.get("matched").getAsBoolean(), "part=body 不应匹配 header 中的关键词");
    }

    @Test
    void listAction_returnsAllShippedTemplates() {
        org.junit.jupiter.api.Assumptions.assumeTrue(templatesAvailable(),
                "custom-templates 目录不存在，跳过端到端测试");

        CustomDetectionTool tool = new CustomDetectionTool(
                new ToolContext(null, null, null, null, null, null, new LeveledLogger(null)),
                TEMPLATE_DIR);
        JsonObject out = JsonParser.parseString(tool.execute("{\"action\":\"list\"}")).getAsJsonObject();

        assertTrue(out.get("success").getAsBoolean());
        // 项目内置至少 3 个模板
        assertTrue(out.get("count").getAsInt() >= 3);
        // stats 字段存在
        assertTrue(out.has("stats"));
    }

    @Test
    void listBySeverity_filtersCorrectly() {
        org.junit.jupiter.api.Assumptions.assumeTrue(templatesAvailable(),
                "custom-templates 目录不存在，跳过端到端测试");

        CustomDetectionTool tool = new CustomDetectionTool(
                new ToolContext(null, null, null, null, null, null, new LeveledLogger(null)),
                TEMPLATE_DIR);
        JsonObject high = JsonParser.parseString(tool.execute(
                "{\"action\":\"list\",\"severity\":\"high\"}")).getAsJsonObject();
        JsonObject critical = JsonParser.parseString(tool.execute(
                "{\"action\":\"list\",\"severity\":\"critical\"}")).getAsJsonObject();

        // sqli=critical, ssrf=high, sensitive=high
        assertEquals(1, critical.get("count").getAsInt());
        assertEquals(2, high.get("count").getAsInt());
    }
}
