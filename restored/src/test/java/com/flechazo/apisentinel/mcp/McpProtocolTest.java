package com.flechazo.apisentinel.mcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Wire-format tests for the MCP JSON-RPC codec (pure functions). */
class McpProtocolTest {

    @Test
    void parseRequest_valid() {
        JsonObject req = McpProtocol.parseRequest(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        assertNotNull(req);
        assertEquals("tools/list", McpProtocol.methodOf(req));
        assertFalse(McpProtocol.isNotification(req));
    }

    @Test
    void parseRequest_malformed_returnsNull() {
        assertNull(McpProtocol.parseRequest(null));
        assertNull(McpProtocol.parseRequest(""));
        assertNull(McpProtocol.parseRequest("not json"));
        assertNull(McpProtocol.parseRequest("[1,2]"));
    }

    @Test
    void isNotification_noId() {
        JsonObject notif = McpProtocol.parseRequest(
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
        assertTrue(McpProtocol.isNotification(notif));
    }

    @Test
    void buildInitializeResponse_shape() {
        String json = McpProtocol.buildInitializeResponse(
                JsonParser.parseString("1"), "api-sentinel", "1.0");
        JsonObject resp = JsonParser.parseString(json).getAsJsonObject();
        assertEquals("2.0", resp.get("jsonrpc").getAsString());
        assertEquals("1", resp.get("id").getAsString());
        JsonObject result = resp.getAsJsonObject("result");
        assertEquals(McpProtocol.PROTOCOL_VERSION, result.get("protocolVersion").getAsString());
        assertEquals("api-sentinel", result.getAsJsonObject("serverInfo").get("name").getAsString());
        assertTrue(result.getAsJsonObject("capabilities").has("tools"));
    }

    @Test
    void buildToolsListResponse_listsTools() {
        JsonObject schema = McpProtocol.emptyObjectSchema();
        String json = McpProtocol.buildToolsListResponse(
                JsonParser.parseString("2"),
                List.of(new McpProtocol.ToolDef("list_apis", "desc", schema)));
        JsonObject resp = JsonParser.parseString(json).getAsJsonObject();
        JsonArray tools = resp.getAsJsonObject("result").getAsJsonArray("tools");
        assertEquals(1, tools.size());
        assertEquals("list_apis", tools.get(0).getAsJsonObject().get("name").getAsString());
        assertTrue(tools.get(0).getAsJsonObject().has("inputSchema"));
    }

    @Test
    void buildToolResultResponse_contentAndError() {
        String json = McpProtocol.buildToolResultResponse(
                JsonParser.parseString("3"), "hello", false);
        JsonObject resp = JsonParser.parseString(json).getAsJsonObject();
        JsonObject result = resp.getAsJsonObject("result");
        assertEquals("hello", result.getAsJsonArray("content")
                .get(0).getAsJsonObject().get("text").getAsString());
        assertFalse(result.get("isError").getAsBoolean());
    }

    @Test
    void buildErrorResponse_shape() {
        String json = McpProtocol.buildErrorResponse(JsonParser.parseString("4"), -32601, "not found");
        JsonObject resp = JsonParser.parseString(json).getAsJsonObject();
        assertEquals(-32601, resp.getAsJsonObject("error").get("code").getAsInt());
        assertEquals("not found", resp.getAsJsonObject("error").get("message").getAsString());
    }

    @Test
    void stringSchema_buildsRequired() {
        java.util.LinkedHashMap<String, String> props = new java.util.LinkedHashMap<>();
        props.put("path", "API path");
        JsonObject schema = McpProtocol.stringSchema(props, List.of("path"));
        assertEquals("object", schema.get("type").getAsString());
        assertTrue(schema.getAsJsonObject("properties").has("path"));
        assertEquals("path", schema.getAsJsonArray("required").get(0).getAsString());
    }
}
