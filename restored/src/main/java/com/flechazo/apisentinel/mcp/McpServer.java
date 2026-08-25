package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Lightweight MCP server embedded in the Burp extension, exposing API-Sentinel
 * over the MCP Streamable HTTP transport (single POST endpoint). Implemented on
 * the JDK's built-in {@link HttpServer} — zero extra dependencies, avoiding any
 * shade/classloader risk inside Burp. Only the loopback interface is bound.
 *
 * Listens on 127.0.0.1:&lt;port&gt;/mcp. Claude Code connects with a
 * {@code {"type":"http","url":"http://127.0.0.1:9877/mcp"}} MCP config.
 */
public class McpServer {

    private static final String SERVER_NAME = "api-sentinel";

    private final HttpServer server;
    private final ExecutorService executor;
    private final McpTools tools;
    private final LeveledLogger logger;
    private final int port;

    public McpServer(int port, McpTools tools, String version, LeveledLogger logger) throws IOException {
        this.tools = tools;
        this.logger = logger;
        this.port = port;
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        this.executor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "api-sentinel-mcp");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(executor);
        server.createContext("/mcp", exchange -> handleMcp(exchange, version));
    }

    public void start() {
        server.start();
        if (logger != null) {
            logger.info("[MCP] server listening on http://127.0.0.1:%d/mcp", port);
        }
    }

    public int getPort() {
        return port;
    }

    public void shutdown() {
        try {
            server.stop(0);
        } catch (Exception ignored) {}
        executor.shutdownNow();
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        if (logger != null) logger.info("[MCP] server stopped");
    }

    // ======================== request handling ========================

    private void handleMcp(HttpExchange exchange, String version) {
        try {
            String method = exchange.getRequestMethod();
            if (!"POST".equalsIgnoreCase(method)) {
                // Streamable HTTP clients open an SSE stream with GET; this
                // tools-only server has nothing to push, so decline politely.
                sendJson(exchange, 405,
                        McpProtocol.buildErrorResponse(null, -32600, "Only POST is supported"));
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            JsonObject request = McpProtocol.parseRequest(body);
            if (request == null) {
                sendJson(exchange, 400, McpProtocol.buildErrorResponse(null, -32700, "Parse error"));
                return;
            }

            String rpcMethod = McpProtocol.methodOf(request);
            JsonElement id = request.get("id");
            boolean notification = McpProtocol.isNotification(request);

            if ("initialize".equals(rpcMethod)) {
                sendJson(exchange, 200,
                        McpProtocol.buildInitializeResponse(id, SERVER_NAME, version));
            } else if ("ping".equals(rpcMethod)) {
                sendJson(exchange, 200, McpProtocol.buildEmptyResultResponse(id));
            } else if ("tools/list".equals(rpcMethod)) {
                sendJson(exchange, 200,
                        McpProtocol.buildToolsListResponse(id, tools.listTools()));
            } else if ("tools/call".equals(rpcMethod)) {
                handleToolCall(exchange, request, id);
            } else if (notification) {
                // notifications/initialized etc. — acknowledge with no body.
                sendJson(exchange, 202, "");
            } else {
                sendJson(exchange, 200,
                        McpProtocol.buildErrorResponse(id, -32601, "Method not found: " + rpcMethod));
            }
        } catch (Exception e) {
            if (logger != null) logger.warn("[MCP] handler error: %s", e.getMessage());
            try {
                sendJson(exchange, 500, McpProtocol.buildErrorResponse(null, -32603, "Internal error"));
            } catch (Exception ignored) {}
        } finally {
            exchange.close();
        }
    }

    private void handleToolCall(HttpExchange exchange, JsonObject request, JsonElement id) throws IOException {
        JsonObject params = request.has("params") && request.get("params").isJsonObject()
                ? request.getAsJsonObject("params") : new JsonObject();
        String name = params.has("name") ? params.get("name").getAsString() : "";
        JsonObject args = params.has("arguments") && params.get("arguments").isJsonObject()
                ? params.getAsJsonObject("arguments") : new JsonObject();

        McpTools.ToolResult result = tools.callTool(name, args);
        sendJson(exchange, 200,
                McpProtocol.buildToolResultResponse(id, result.text(), result.isError()));
    }

    private void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json == null ? new byte[0] : json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}
