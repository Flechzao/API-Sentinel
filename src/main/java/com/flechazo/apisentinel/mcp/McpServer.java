package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lightweight MCP (Model Context Protocol) server embedded in the Burp
 * extension, exposing API-Sentinel over the MCP Streamable HTTP transport
 * (single POST endpoint at {@code /mcp}).
 *
 * <p><b>Why a raw {@link ServerSocket} instead of {@code com.sun.net.httpserver}:</b>
 * Burp Suite ships a trimmed JRE built without the {@code jdk.httpserver}
 * module, so {@code com.sun.net.httpserver.HttpServer} raises
 * {@code NoClassDefFoundError} at load time inside Burp (it only works under a
 * full JDK, e.g. unit tests / standalone). {@link ServerSocket} lives in
 * {@code java.base} and is always present, so this transport works in every
 * Burp runtime. We implement just enough HTTP/1.1 to serve JSON-RPC POSTs.
 *
 * <p>Only the loopback interface is bound. Requests must pass: no cross-origin
 * {@code Origin} header (CSRF), exact {@code Host} match (DNS rebinding),
 * {@code Authorization: Bearer <token>}, and {@code Content-Type: application/json}.
 *
 * <p>Clients connect with a {@code {"type":"http","url":"http://127.0.0.1:<port>/mcp"}}
 * MCP config plus the Bearer token printed once to the Burp extension console.
 */
public class McpServer {

    private static final String SERVER_NAME = "api-sentinel";
    private static final int READ_TIMEOUT_MS = 30_000;
    private static final int MAX_BODY_BYTES = 8 * 1024 * 1024; // 8 MiB safety cap

    private final ServerSocket serverSocket;
    private final ExecutorService executor;
    private final McpTools tools;
    private final LeveledLogger logger;
    private final int port;
    private final String version;
    private final String authToken;
    private final boolean requireAuth;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread acceptThread;

    /** Backward-compatible: mint a fresh token and require auth. */
    public McpServer(int port, McpTools tools, String version, LeveledLogger logger) throws IOException {
        this(port, tools, version, logger, mintToken(), true);
    }

    /**
     * @param authToken   the bearer token clients must present (persisted by the caller)
     * @param requireAuth when false, the Authorization check is skipped (loopback +
     *                    Origin/Host guards still apply) — matches Burp's native MCP
     */
    public McpServer(int port, McpTools tools, String version, LeveledLogger logger,
                     String authToken, boolean requireAuth) throws IOException {
        this.tools = tools;
        this.logger = logger;
        this.port = port;
        this.version = version;
        this.authToken = (authToken == null || authToken.isBlank()) ? mintToken() : authToken;
        this.requireAuth = requireAuth;
        this.serverSocket = new ServerSocket();
        this.serverSocket.setReuseAddress(true);
        this.serverSocket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "api-sentinel-mcp");
            t.setDaemon(true);
            return t;
        });
    }

    /** Generate a 256-bit bearer token (64 hex chars). */
    public static String mintToken() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder(64);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Generate a short opaque session id (128-bit, 32 hex chars). */
    private static String mintSessionId() {
        byte[] bytes = new byte[16];
        new java.security.SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder(32);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** The auth token MCP clients must send as {@code Authorization: Bearer <token>}. */
    public String getAuthToken() { return authToken; }

    public int getPort() { return port; }

    public void start() {
        running.set(true);
        acceptThread = new Thread(this::acceptLoop, "api-sentinel-mcp-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        // The listening URL + token are printed once in the extension's
        // startup summary block (below "初始化完成"), so nothing is logged here
        // beyond a debug trace.
        if (logger != null) logger.debug("[MCP] accept loop started on 127.0.0.1:%d", port);
    }

    public void shutdown() {
        running.set(false);
        try {
            serverSocket.close();
        } catch (Exception ignored) {}
        executor.shutdownNow();
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        if (logger != null) logger.debug("[MCP] server stopped");
    }

    // ======================== accept loop ========================

    private void acceptLoop() {
        while (running.get()) {
            final Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                // Closed on shutdown, or transient accept error.
                if (running.get() && logger != null) logger.warn("[MCP] accept error: %s", e.toString());
                break;
            }
            executor.submit(() -> handleConnection(socket));
        }
    }

    private void handleConnection(Socket socket) {
        try (socket) {
            socket.setSoTimeout(READ_TIMEOUT_MS);
            InputStream in = new BufferedInputStream(socket.getInputStream());
            OutputStream out = new BufferedOutputStream(socket.getOutputStream());
            // Serve requests on this connection until the peer closes or asks to.
            while (running.get()) {
                boolean keepAlive = handleRequest(in, out);
                out.flush();
                if (!keepAlive) break;
            }
        } catch (IOException ignored) {
            // Client hung up / read timeout — normal.
        } catch (Throwable t) {
            if (logger != null) logger.warn("[MCP] connection error: %s", t.toString());
        }
    }

    /**
     * Parse and answer one HTTP request. Returns whether the connection may be
     * kept alive for another request. Returns false on EOF.
     */
    private boolean handleRequest(InputStream in, OutputStream out) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null) return false;       // EOF — peer closed
        if (requestLine.isEmpty()) return true;       // stray blank line — ignore

        String[] parts = requestLine.split(" ");
        String method = parts.length > 0 ? parts[0] : "";
        String target = parts.length > 1 ? parts[1] : "";

        Map<String, String> headers = new HashMap<>();
        int contentLength = 0;
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String k = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String v = line.substring(colon + 1).trim();
                headers.put(k, v);
                if (k.equals("content-length")) {
                    try { contentLength = Integer.parseInt(v); } catch (NumberFormatException ignored) {}
                }
            }
        }

        boolean keepAlive = !"close".equalsIgnoreCase(headers.get("connection"));

        if (contentLength < 0 || contentLength > MAX_BODY_BYTES) {
            sendResponse(out, 413, McpProtocol.buildErrorResponse(null, -32600, "Request body too large"), keepAlive);
            return keepAlive;
        }
        String body = contentLength > 0 ? readBody(in, contentLength) : "";

        // ---- Security guards (mirror the loopback + CSRF + auth model) ----
        if (!target.startsWith("/mcp")) {
            sendResponse(out, 404, McpProtocol.buildErrorResponse(null, -32601, "Not found"), keepAlive);
            return keepAlive;
        }
        String origin = headers.get("origin");
        if (origin != null && !origin.isBlank()) {
            sendResponse(out, 403, McpProtocol.buildErrorResponse(null, -32000,
                    "Cross-origin requests are forbidden (CSRF guard)"), keepAlive);
            return keepAlive;
        }
        String host = headers.get("host");
        String expectedHost = "127.0.0.1:" + port;
        String expectedHostAlt = "localhost:" + port;
        if (host == null || (!host.equals(expectedHost) && !host.equals(expectedHostAlt))) {
            sendResponse(out, 403, McpProtocol.buildErrorResponse(null, -32000,
                    "Host header mismatch (DNS rebinding guard). Expected: " + expectedHost), keepAlive);
            return keepAlive;
        }
        if (requireAuth) {
            String auth = headers.get("authorization");
            if (auth == null || !auth.equals("Bearer " + authToken)) {
                sendResponse(out, 401, McpProtocol.buildErrorResponse(null, -32000,
                        "Missing or invalid Authorization header. Expected: Bearer <token>. "
                        + "See the Burp extension console output for the token."), keepAlive);
                return keepAlive;
            }
        }
        String contentType = headers.get("content-type");
        if (contentType == null || !contentType.contains("application/json")) {
            sendResponse(out, 415, McpProtocol.buildErrorResponse(null, -32000,
                    "Content-Type must be application/json"), keepAlive);
            return keepAlive;
        }
        if (!"POST".equalsIgnoreCase(method)) {
            // Streamable HTTP clients may open an SSE stream with GET; this
            // tools-only server has nothing to push, so decline politely.
            sendResponse(out, 405, McpProtocol.buildErrorResponse(null, -32600, "Only POST is supported"), keepAlive);
            return keepAlive;
        }

        // ---- JSON-RPC routing ----
        JsonObject request = McpProtocol.parseRequest(body);
        if (request == null) {
            sendResponse(out, 400, McpProtocol.buildErrorResponse(null, -32700, "Parse error"), keepAlive);
            return keepAlive;
        }
        String rpcMethod = McpProtocol.methodOf(request);
        JsonElement id = request.get("id");
        boolean notification = McpProtocol.isNotification(request);

        // MCP session id: client echoes the id we mint at initialize. Absent =>
        // shared anonymous session (raw curl / older clients still work).
        String sessionId = headers.get("mcp-session-id");

        if ("initialize".equals(rpcMethod)) {
            // Mint a session id when the client didn't bring one, and hand it
            // back via the Mcp-Session-Id response header for subsequent calls.
            String issued = (sessionId != null && !sessionId.isBlank()) ? sessionId : mintSessionId();
            sendResponse(out, 200, McpProtocol.buildInitializeResponse(id, SERVER_NAME, version), keepAlive, issued);
        } else if ("ping".equals(rpcMethod)) {
            sendResponse(out, 200, McpProtocol.buildEmptyResultResponse(id), keepAlive);
        } else if ("tools/list".equals(rpcMethod)) {
            sendResponse(out, 200, McpProtocol.buildToolsListResponse(id, tools.listTools(sessionId)), keepAlive);
        } else if ("tools/call".equals(rpcMethod)) {
            JsonObject params = request.has("params") && request.get("params").isJsonObject()
                    ? request.getAsJsonObject("params") : new JsonObject();
            String name = params.has("name") ? params.get("name").getAsString() : "";
            JsonObject args = params.has("arguments") && params.get("arguments").isJsonObject()
                    ? params.getAsJsonObject("arguments") : new JsonObject();
            McpTools.ToolResult result = tools.callTool(name, args, sessionId);
            sendResponse(out, 200, McpProtocol.buildToolResultResponse(id, result.text(), result.isError()), keepAlive);
        } else if (notification) {
            // notifications/initialized etc. — acknowledge with no body.
            sendResponse(out, 202, "", keepAlive);
        } else {
            sendResponse(out, 200, McpProtocol.buildErrorResponse(id, -32601, "Method not found: " + rpcMethod), keepAlive);
        }
        return keepAlive;
    }

    // ======================== HTTP I/O helpers ========================

    /** Read a single CRLF/LF-terminated line as UTF-8. Returns {@code null} at
     *  EOF (peer closed with no more data), {@code ""} for a blank line. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
        int c = in.read();
        if (c == -1) return null;
        while (c != -1 && c != '\n') {
            if (c != '\r') buf.write(c);
            c = in.read();
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    private static String readBody(InputStream in, int contentLength) throws IOException {
        byte[] body = new byte[contentLength];
        int off = 0;
        while (off < contentLength) {
            int n = in.read(body, off, contentLength - off);
            if (n < 0) break;
            off += n;
        }
        return new String(body, 0, off, StandardCharsets.UTF_8);
    }

    private static void sendResponse(OutputStream out, int status, String jsonBody, boolean keepAlive)
            throws IOException {
        sendResponse(out, status, jsonBody, keepAlive, null);
    }

    private static void sendResponse(OutputStream out, int status, String jsonBody, boolean keepAlive,
                                     String sessionId) throws IOException {
        byte[] payload = jsonBody == null ? new byte[0] : jsonBody.getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + status + " " + reason(status) + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: " + payload.length + "\r\n"
                + (sessionId != null ? "Mcp-Session-Id: " + sessionId + "\r\n" : "")
                + "Connection: " + (keepAlive ? "keep-alive" : "close") + "\r\n"
                + "\r\n";
        out.write(head.getBytes(StandardCharsets.US_ASCII));
        if (payload.length > 0) out.write(payload);
    }

    private static String reason(int status) {
        return switch (status) {
            case 200 -> "OK";
            case 202 -> "Accepted";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 413 -> "Payload Too Large";
            case 415 -> "Unsupported Media Type";
            default -> "Internal Server Error";
        };
    }
}
