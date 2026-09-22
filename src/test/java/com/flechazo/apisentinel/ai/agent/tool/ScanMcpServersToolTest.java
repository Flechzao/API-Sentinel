package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ScanMcpServersTool 单元测试
 *
 * 验证 scan_mcp_servers 工具的参数校验、scan_current_host 目标派生、
 * isReadOnly 契约，以及对不可达目标的完整 execute→scan→响应构建路径
 * （连接被拒即时返回，不依赖真实 MCP 服务器）。McpSecurityScanner 的
 * 端点探测与风险评估由其自身的测试覆盖。
 *
 * @since 1.1.0
 */
class ScanMcpServersToolTest {

    private ScanMcpServersTool newTool() {
        // logger 非空：execute 在扫描路径会调用 ctx.logger().info
        return new ScanMcpServersTool(
                new ToolContext(null, null, null, null, null, null, new LeveledLogger(null)));
    }

    private JsonObject exec(String argsJson) {
        return JsonParser.parseString(newTool().execute(argsJson)).getAsJsonObject();
    }

    // ==================== 元数据 ====================

    @Test
    void name_isScanMcpServers() {
        assertEquals("scan_mcp_servers", newTool().name());
    }

    @Test
    void description_mentionsAuthAndEndpoints() {
        String desc = newTool().description();
        assertTrue(desc.toLowerCase().contains("mcp"));
        assertTrue(desc.toLowerCase().contains("auth"));
    }

    @Test
    void isReadOnly_isTrue() {
        // 扫描类工具，只读
        assertTrue(newTool().isReadOnly());
    }

    @Test
    void inputSchema_hasTargetUrlAndScanCurrentHost() {
        JsonObject schema = newTool().inputSchema();
        assertEquals("object", schema.get("type").getAsString());
        JsonObject props = schema.getAsJsonObject("properties");
        assertTrue(props.has("target_url"));
        assertTrue(props.has("scan_current_host"));
    }

    // ==================== 参数校验 ====================

    @Test
    void execute_noTargetAndNoScanCurrentHost_returnsError() {
        JsonObject out = exec("{}");
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("target_url"));
    }

    @Test
    void execute_emptyTargetUrl_returnsError() {
        JsonObject out = exec("{\"target_url\":\"\"}");
        assertFalse(out.get("success").getAsBoolean());
    }

    @Test
    void execute_invalidJson_returnsError() {
        JsonObject out = JsonParser.parseString(newTool().execute("{bad")).getAsJsonObject();
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("json"));
    }

    // ==================== scan_current_host 派生 ====================

    @Test
    void execute_scanCurrentHostButNoEntry_returnsError() {
        // ctx.entry() == null → target 无法派生 → 错误（不触发网络）
        ScanMcpServersTool tool = new ScanMcpServersTool(
                new ToolContext(null, null, null, null, null, null, new LeveledLogger(null)));
        JsonObject out = JsonParser.parseString(
                tool.execute("{\"scan_current_host\":true}")).getAsJsonObject();
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("target_url"));
    }

    @Test
    void execute_scanCurrentHostWithEntry_derivesTargetFromDomain() {
        // entry 有 domain → target = https://domain → 扫描 127.0.0.1 端口 1（拒绝）
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        entry.setDomain("127.0.0.1:1");
        ToolContext ctx = new ToolContext(entry, null, null, null, null, null, new LeveledLogger(null));
        ScanMcpServersTool tool = new ScanMcpServersTool(ctx);

        JsonObject out = JsonParser.parseString(
                tool.execute("{\"scan_current_host\":true}")).getAsJsonObject();

        // 派生成功：base_url 应来自 domain（https://127.0.0.1:1）
        assertEquals("https://127.0.0.1:1", out.get("base_url").getAsString());
        assertEquals(0, out.get("endpoints_found").getAsInt());
    }

    // ==================== 显式 target_url 扫描（不可达目标） ====================

    @Test
    @Timeout(30)
    void execute_unreachableTarget_returnsNoEndpointsResult() {
        // 127.0.0.1:1 无监听 → 连接被拒（即时），7 个端点全部失败、0 个 endpoint
        JsonObject out = exec("{\"target_url\":\"http://127.0.0.1:1\"}");

        // 连接失败被记入 errors → success=true（工具约定：有 errors 视为执行完成）
        assertTrue(out.get("success").getAsBoolean());
        assertEquals("http://127.0.0.1:1", out.get("base_url").getAsString());
        assertEquals(0, out.get("endpoints_found").getAsInt());
        assertEquals(0, out.get("critical_risk").getAsInt());
        assertTrue(out.has("message"));
        assertEquals("No MCP endpoints found on target", out.get("message").getAsString());
        assertTrue(out.has("next_step"));
    }

    @Test
    @Timeout(30)
    void execute_targetWithoutScheme_getsHttpsPrefix() {
        // 不带 scheme 的 target → 扫描器补 https://
        JsonObject out = exec("{\"target_url\":\"127.0.0.1:1\"}");
        // https://127.0.0.1:1 连接被拒（可能 TLS 握手失败 → 同样进 errors）
        assertEquals("https://127.0.0.1:1", out.get("base_url").getAsString());
    }
}
