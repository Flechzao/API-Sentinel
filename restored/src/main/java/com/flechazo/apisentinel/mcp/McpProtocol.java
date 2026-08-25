package com.flechazo.apisentinel.mcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;

/**
 * Minimal MCP (Model Context Protocol) JSON-RPC 2.0 codec for the Streamable
 * HTTP transport. Implements only the subset API-Sentinel needs:
 * initialize / tools/list / tools/call / ping (+ notifications). Kept as pure
 * static functions so the wire format is unit-testable without a socket.
 */
public final class McpProtocol {

    /** MCP protocol version this server speaks. */
    public static final String PROTOCOL_VERSION = "2025-06-18";

    private McpProtocol() {}

    /** A tool definition advertised in tools/list. */
    public record ToolDef(String name, String description, JsonObject inputSchema) {}

    // ======================== parsing ========================

    /** Parse a request body into a JsonObject; null when malformed. */
    public static JsonObject parseRequest(String body) {
        if (body == null || body.isBlank()) return null;
        try {
            JsonElement el = JsonParser.parseString(body);
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        } catch (Exception e) {
            return null;
        }
    }

    public static String methodOf(JsonObject request) {
        return request != null && request.has("method") && request.get("method").isJsonPrimitive()
                ? request.get("method").getAsString() : "";
    }

    /** Notifications carry no id and expect no response. */
    public static boolean isNotification(JsonObject request) {
        return request == null || !request.has("id") || request.get("id").isJsonNull();
    }

    // ======================== responses ========================

    private static JsonObject baseResponse(JsonElement id) {
        JsonObject resp = new JsonObject();
        resp.addProperty("jsonrpc", "2.0");
        if (id != null && !id.isJsonNull()) resp.add("id", id);
        return resp;
    }

    public static String buildInitializeResponse(JsonElement id, String serverName, String version) {
        JsonObject resp = baseResponse(id);
        JsonObject result = new JsonObject();
        result.addProperty("protocolVersion", PROTOCOL_VERSION);
        JsonObject capabilities = new JsonObject();
        JsonObject toolsCap = new JsonObject();
        toolsCap.addProperty("listChanged", false);
        capabilities.add("tools", toolsCap);
        result.add("capabilities", capabilities);
        JsonObject serverInfo = new JsonObject();
        serverInfo.addProperty("name", serverName);
        serverInfo.addProperty("version", version);
        result.add("serverInfo", serverInfo);
        resp.add("result", result);
        return resp.toString();
    }

    public static String buildToolsListResponse(JsonElement id, List<ToolDef> tools) {
        JsonObject resp = baseResponse(id);
        JsonObject result = new JsonObject();
        JsonArray arr = new JsonArray();
        for (ToolDef t : tools) {
            JsonObject tool = new JsonObject();
            tool.addProperty("name", t.name());
            tool.addProperty("description", t.description());
            tool.add("inputSchema", t.inputSchema() != null ? t.inputSchema() : emptyObjectSchema());
            arr.add(tool);
        }
        result.add("tools", arr);
        resp.add("result", result);
        return resp.toString();
    }

    public static String buildToolResultResponse(JsonElement id, String text, boolean isError) {
        JsonObject resp = baseResponse(id);
        JsonObject result = new JsonObject();
        JsonArray content = new JsonArray();
        JsonObject textPart = new JsonObject();
        textPart.addProperty("type", "text");
        textPart.addProperty("text", text == null ? "" : text);
        content.add(textPart);
        result.add("content", content);
        result.addProperty("isError", isError);
        resp.add("result", result);
        return resp.toString();
    }

    public static String buildEmptyResultResponse(JsonElement id) {
        JsonObject resp = baseResponse(id);
        resp.add("result", new JsonObject());
        return resp.toString();
    }

    public static String buildErrorResponse(JsonElement id, int code, String message) {
        JsonObject resp = baseResponse(id);
        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message == null ? "" : message);
        resp.add("error", error);
        return resp.toString();
    }

    // ======================== schema helpers ========================

    public static JsonObject emptyObjectSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", new JsonObject());
        return schema;
    }

    /** Build an object schema from (name → description) pairs, all string type. */
    public static JsonObject stringSchema(java.util.LinkedHashMap<String, String> props,
                                          List<String> required) {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject properties = new JsonObject();
        if (props == null) props = new java.util.LinkedHashMap<>();
        for (var e : props.entrySet()) {
            JsonObject p = new JsonObject();
            p.addProperty("type", "string");
            p.addProperty("description", e.getValue());
            properties.add(e.getKey(), p);
        }
        schema.add("properties", properties);
        if (required != null && !required.isEmpty()) {
            JsonArray req = new JsonArray();
            required.forEach(req::add);
            schema.add("required", req);
        }
        return schema;
    }
}
