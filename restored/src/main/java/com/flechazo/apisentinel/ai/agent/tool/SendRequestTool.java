package com.flechazo.apisentinel.ai.agent.tool;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.detection.WafDetector;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class SendRequestTool implements AgentTool {

    private static final Set<String> AUTH_HEADER_NAMES = Set.of(
            "cookie", "authorization", "x-token", "x-access-token",
            "x-csrf-token", "x-xsrf-token", "x-api-key", "x-auth-token",
            "x-session-id", "token", "session");

    private final ToolContext ctx;
    private final List<PayloadResult> payloadResults =
            java.util.Collections.synchronizedList(new ArrayList<>());

    public SendRequestTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    public List<PayloadResult> getPayloadResults() { return payloadResults; }

    @Override
    public String preExecute(String argumentsJson, ToolContext ctx) {
        // Gate 1 used to REJECT sends when the entry had no captured traffic
        // (returning a "warning" that AgentToolRegistry treats as a hard
        // rejection). That made the entire no-traffic flow — where the system
        // prompt explicitly instructs the agent to construct and send a
        // request — impossible: every send_request bounced, zero payloads ever
        // executed (observed in real runs: N send calls, 0 results). Sending a
        // constructed request without auth headers is a legitimate action
        // (unauthenticated-access testing), so this gate no longer blocks.
        // Gate 2: check if previous payloads were WAF-blocked and bypass hasn't been tried
        if (ctx.pipelineConfig() != null && ctx.pipelineConfig().wafDetectionEnabled()) {
            boolean anyWafBlocked = payloadResults.stream().anyMatch(PayloadResult::isWafBlocked);
            boolean bypassTried = payloadResults.stream()
                    .anyMatch(pr -> pr.sentRequest() != null && pr.sentRequest().contains("waf_bypass"));
            if (anyWafBlocked && !bypassTried) {
                return "{\"warning\": \"Previous payloads were WAF-blocked. Consider calling "
                        + "waf_bypass_retry first to attempt encoding bypass before sending "
                        + "more payloads that will also be blocked.\"}";
            }
        }
        return null; // allow
    }

    @Override
    public void postExecute(String argumentsJson, String result, ToolContext ctx) {
        // Auto-detect signals in the response and suggest follow-up actions
        if (result == null || result.contains("\"error\"")) return;

        try {
            var args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            String method = args.has("method") ? args.get("method").getAsString() : "GET";
            String path = args.has("path") ? args.get("path").getAsString() : "";

            var resp = com.google.gson.JsonParser.parseString(result).getAsJsonObject();
            int statusCode = resp.has("status_code") ? resp.get("status_code").getAsInt() : 0;
            boolean wafDetected = resp.has("waf_detected") && resp.get("waf_detected").getAsBoolean();
            String responseBody = resp.has("response_body") ? resp.get("response_body").getAsString() : "";

            if (!wafDetected && statusCode >= 500) {
                // 5xx is NOT a vuln signal — just note it
                ctx.logger().debug("[send_request] %s %s → 5xx (%d) — not a vuln signal",
                        method, path, statusCode);
            }

            if (wafDetected && !payloadResults.isEmpty()) {
                PayloadResult last = payloadResults.get(payloadResults.size() - 1);
                // Mark the last result as WAF-blocked in-place
                // (PayloadResult is a record, but we track via the list)
                ctx.logger().info("[send_request] WAF detected on %s %s — suggest bypass", method, path);
            }

            // Auto-detect SQL error patterns
            if (statusCode == 500 && responseBody != null && !responseBody.isEmpty()) {
                String lower = responseBody.toLowerCase();
                if (containsSqlError(lower)) {
                    ctx.logger().info("[send_request] SQL error detected in response — suggest blind verification");
                }
            }
        } catch (Exception ignored) {
            // postExecute should never throw — it's advisory only
        }
    }

    private static boolean containsSqlError(String lower) {
        return lower.contains("sql syntax") || lower.contains("mysql") || lower.contains("ora-")
                || lower.contains("postgresql") || lower.contains("sqlite")
                || lower.contains("sqlexception") || lower.contains("jdbc")
                || lower.contains("hibernate") || lower.contains("unclosed quotation")
                || lower.contains("you have an error in your sql");
    }

    @Override
    public String name() { return "send_request"; }

    @Override
    public String description() {
        return "Send a single HTTP request to the target server and observe the response. "
             + "Use this to verify suspected vulnerabilities by crafting specific payloads. "
             + "Original authentication headers are preserved by default. Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject methodProp = new JsonObject();
        methodProp.addProperty("type", "string");
        methodProp.addProperty("description", "HTTP method (GET, POST, PUT, DELETE, etc.)");
        props.add("method", methodProp);

        JsonObject pathProp = new JsonObject();
        pathProp.addProperty("type", "string");
        pathProp.addProperty("description", "URL path with query string (e.g. /api/users?id=1)");
        props.add("path", pathProp);

        JsonObject bodyProp = new JsonObject();
        bodyProp.addProperty("type", "string");
        bodyProp.addProperty("description", "Request body (for POST/PUT). Optional.");
        props.add("body", bodyProp);

        JsonObject headersProp = new JsonObject();
        headersProp.addProperty("type", "string");
        headersProp.addProperty("description", "Additional headers as 'Key: Value' lines separated by \\n. Optional.");
        props.add("headers", headersProp);

        JsonObject authProp = new JsonObject();
        authProp.addProperty("type", "boolean");
        authProp.addProperty("description", "Whether to include original auth headers. Default true.");
        props.add("use_original_auth", authProp);

        JsonObject hostProp = new JsonObject();
        hostProp.addProperty("type", "string");
        hostProp.addProperty("description", "Optional destination host as 'host:port' (e.g. 'localhost:8089'). "
                + "Only needed when this API has no captured traffic of its own (no known host) — "
                + "pick one of the candidate hosts returned in the 'available_hosts' error, or from search_traffic.");
        props.add("host", hostProp);

        JsonObject payloadsProp = new JsonObject();
        payloadsProp.addProperty("type", "array");
        payloadsProp.addProperty("description", "Optional: array of payload variants to send concurrently. "
                + "Each item is a {method, path, body, headers} object. When provided, all variants are sent "
                + "in parallel and results are returned as an array. Use this to batch-test multiple payloads "
                + "at once instead of calling send_request repeatedly.");
        JsonObject payloadItem = new JsonObject();
        payloadItem.addProperty("type", "object");
        JsonObject piProps = new JsonObject();
        piProps.add("body", simpleProp("string", "Request body for this variant"));
        piProps.add("path", simpleProp("string", "Override path for this variant"));
        piProps.add("headers", simpleProp("string", "Additional headers for this variant"));
        payloadItem.add("properties", piProps);
        payloadsProp.add("items", payloadItem);
        props.add("payloads", payloadsProp);

        schema.add("properties", props);

        var required = new com.google.gson.JsonArray();
        required.add("method");
        required.add("path");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (ctx.montoyaApi() == null) {
            return "{\"error\": \"Burp API not available\"}";
        }

        try {
            var args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            String method = args.get("method").getAsString();
            String path = args.get("path").getAsString();
            String body = args.has("body") ? args.get("body").getAsString() : "";
            String extraHeaders = args.has("headers") ? args.get("headers").getAsString() : "";
            boolean useAuth = !args.has("use_original_auth") || args.get("use_original_auth").getAsBoolean();
            String hostOverride = args.has("host") && !args.get("host").getAsString().isBlank()
                    ? args.get("host").getAsString() : null;

            // Batch mode: send multiple payload variants concurrently
            if (args.has("payloads") && args.get("payloads").isJsonArray()) {
                return executeBatch(method, path, body, extraHeaders, useAuth,
                        args.getAsJsonArray("payloads"), hostOverride);
            }

            // Single mode: original behavior
            return sendSingle(method, path, body, extraHeaders, useAuth, hostOverride);
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /** Resolved send destination, or an error explaining why no host is routable. */
    private record Target(HttpService service, String host, int port, boolean useHttps, String error) {}

    /**
     * Resolve where to send the request. Priority: explicit host override →
     * the entry's own domain/lastUrl → bootstrap from recent proxy traffic.
     * Bootstrapping only auto-picks a host when recent history is unambiguous
     * (exactly one distinct host); with several hosts it returns them as
     * available_hosts so the Agent chooses instead of guessing (avoids routing
     * payloads at the wrong target).
     */
    private Target resolveTarget(String hostOverride) {
        String host;
        int port;
        boolean useHttps;
        if (hostOverride != null && !hostOverride.isBlank()) {
            useHttps = hostOverride.startsWith("https");
            host = extractHost(hostOverride, useHttps);
            port = extractPort(hostOverride, useHttps);
        } else {
            var entry = ctx.entry();
            String domain = entry.getDomain() != null ? entry.getDomain() : "";
            useHttps = entry.getLastUrl() != null && entry.getLastUrl().startsWith("https");
            host = extractHost(domain, useHttps);
            port = extractPort(domain, useHttps);
            String lastUrl = entry.getLastUrl();
            if (lastUrl != null && !lastUrl.isBlank()) {
                try {
                    java.net.URI uri = new java.net.URI(lastUrl);
                    if (uri.getHost() != null) host = uri.getHost();
                    if (uri.getPort() > 0) port = uri.getPort();
                    useHttps = "https".equalsIgnoreCase(uri.getScheme());
                } catch (Exception ignored) {}
            }
        }
        // No host yet (entry has no captured traffic): bootstrap from recent history.
        if (host == null || host.isBlank()) {
            List<String> recent = new com.flechazo.apisentinel.active.TrafficSearcher(ctx.montoyaApi())
                    .recentHostPorts(5);
            if (recent.size() == 1) {
                host = extractHost(recent.get(0), false);
                port = extractPort(recent.get(0), false);
            } else if (recent.isEmpty()) {
                return new Target(null, null, 0, false,
                        "{\"error\":\"No routable host: this API has no captured traffic and the proxy "
                        + "history is empty. Browse the target through Burp first, then retry.\"}");
            } else {
                com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
                recent.forEach(arr::add);
                return new Target(null, null, 0, false,
                        "{\"error\":\"No routable host: this API has no captured traffic and multiple "
                        + "recent hosts exist, so I won't guess. Re-call send_request with an explicit "
                        + "'host' param (pick the target app).\",\"available_hosts\":" + arr + "}");
            }
        }
        return new Target(HttpService.httpService(host, port, useHttps), host, port, useHttps, null);
    }

    /** Send a single request and return the result. */
    private String sendSingle(String method, String path, String body,
                               String extraHeaders, boolean useAuth, String hostOverride) {
        Target t = resolveTarget(hostOverride);
        if (t.error() != null) return t.error();
        var entry = ctx.entry();
        String rawReq = buildRawRequest(method, path, body, extraHeaders, useAuth, t.host(), t.port(), t.useHttps(), entry);
        return sendAndRecord(t.service(), rawReq, method, path);
    }

    /** Send multiple payload variants concurrently and return all results. */
    private String executeBatch(String method, String path, String baseBody,
                                 String extraHeaders, boolean useAuth,
                                 com.google.gson.JsonArray variants, String hostOverride) {
        Target t = resolveTarget(hostOverride);
        if (t.error() != null) return t.error();
        var entry = ctx.entry();
        String host = t.host();
        int port = t.port();
        boolean useHttps = t.useHttps();
        HttpService service = t.service();

        // Build a task for each variant
        List<CompletableFuture<String>> futures = new ArrayList<>();
        for (int i = 0; i < variants.size(); i++) {
            var varObj = variants.get(i).getAsJsonObject();
            String varBody = varObj.has("body") ? varObj.get("body").getAsString() : baseBody;
            String varPath = varObj.has("path") ? varObj.get("path").getAsString() : path;
            String varHeaders = varObj.has("headers") ? varObj.get("headers").getAsString() : extraHeaders;
            String varMethod = varObj.has("method") ? varObj.get("method").getAsString() : method;

            String rawReq = buildRawRequest(varMethod, varPath, varBody, varHeaders,
                    useAuth, host, port, useHttps, entry);

            futures.add(CompletableFuture.supplyAsync(() ->
                    sendAndRecord(service, rawReq, varMethod, varPath)));
        }

        // Wait for all to complete
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        // Collect results
        com.google.gson.JsonArray results = new com.google.gson.JsonArray();
        for (int i = 0; i < futures.size(); i++) {
            try {
                results.add(com.google.gson.JsonParser.parseString(futures.get(i).get()));
            } catch (Exception e) {
                com.google.gson.JsonObject err = new com.google.gson.JsonObject();
                err.addProperty("error", e.getMessage());
                results.add(err);
            }
        }
        com.google.gson.JsonObject out = new com.google.gson.JsonObject();
        out.addProperty("batch", true);
        out.addProperty("count", variants.size());
        out.add("results", results);
        return out.toString();
    }

    private static String extractHeaders(HttpRequestResponse result) {
        if (result.response() == null) return "";
        StringBuilder sb = new StringBuilder();
        for (var h : result.response().headers()) {
            if (sb.length() > 0) sb.append("\n");
            sb.append(h.name()).append(": ").append(h.value());
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n...[truncated]";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String extractHost(String domain, boolean useHttps) {
        if (domain.contains(":")) return domain.split(":")[0];
        return domain;
    }

    private static int extractPort(String domain, boolean useHttps) {
        if (domain.contains(":")) {
            try { return Integer.parseInt(domain.split(":")[1]); }
            catch (NumberFormatException e) { return useHttps ? 443 : 80; }
        }
        return useHttps ? 443 : 80;
    }

    private String buildRawRequest(String method, String path, String body,
                                    String extraHeaders, boolean useAuth,
                                    String host, int port, boolean useHttps,
                                    ApiEntry entry) {
        StringBuilder rawReqBuilder = new StringBuilder();
        rawReqBuilder.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        boolean standardPort = (useHttps && port == 443) || (!useHttps && port == 80);
        rawReqBuilder.append("Host: ").append(host);
        if (!standardPort) rawReqBuilder.append(":").append(port);
        rawReqBuilder.append("\r\n");

        if (useAuth && entry.getLastRawRequest() != null) {
            String[] lines = entry.getLastRawRequest().split("\r?\n");
            for (String line : lines) {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    String headerName = line.substring(0, colon).trim().toLowerCase();
                    if (AUTH_HEADER_NAMES.contains(headerName)) {
                        rawReqBuilder.append(line).append("\r\n");
                    }
                }
            }
        }

        if (extraHeaders != null && !extraHeaders.isEmpty()) {
            for (String h : extraHeaders.split("\\\\n|\n")) {
                if (!h.trim().isEmpty()) rawReqBuilder.append(h.trim()).append("\r\n");
            }
        }

        if (body != null && !body.isEmpty()) {
            rawReqBuilder.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
            rawReqBuilder.append("\r\n").append(body);
        } else {
            rawReqBuilder.append("\r\n");
        }
        return rawReqBuilder.toString();
    }

    private static final int MAX_429_RETRIES = 3;
    private static final long[] BACKOFF_MS = {1000, 3000, 8000};

    private String sendAndRecord(HttpService service, String rawReq, String method, String path) {
        HttpRequest httpReq = HttpRequest.httpRequest(service, rawReq);

        HttpRequestResponse result = null;
        long start = System.currentTimeMillis();
        long elapsed = 0;
        int retryCount = 0;

        for (int attempt = 0; attempt <= MAX_429_RETRIES; attempt++) {
            start = System.currentTimeMillis();
            result = ctx.montoyaApi().http().sendRequest(httpReq);
            elapsed = System.currentTimeMillis() - start;
            int code = result.response() != null ? result.response().statusCode() : 0;
            if (code == 429 && attempt < MAX_429_RETRIES) {
                retryCount++;
                long wait = BACKOFF_MS[attempt];
                String retryAfter = result.response() != null
                        ? HttpMessageUtils.getHeader(HttpMessageUtils.buildRawResponse(result.response()), "Retry-After")
                        : null;
                if (retryAfter != null) {
                    try { wait = Math.min(Long.parseLong(retryAfter.trim()) * 1000, 15000); }
                    catch (NumberFormatException ignored) {}
                }
                try { Thread.sleep(wait); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                continue;
            }
            break;
        }

        String sentRaw = HttpMessageUtils.buildRawRequest(result.request());
        String recvRaw = result.response() != null ? HttpMessageUtils.buildRawResponse(result.response()) : "";
        int statusCode = result.response() != null ? result.response().statusCode() : 0;

        WafDetector.WafDetectionResult waf = (ctx.pipelineConfig() != null
                && ctx.pipelineConfig().wafDetectionEnabled())
                ? new WafDetector(ctx.logger()).detect(recvRaw, statusCode, elapsed)
                : new WafDetector.WafDetectionResult(null, 0, "waf detection disabled");

        payloadResults.add(new PayloadResult(null, sentRaw, recvRaw, statusCode, elapsed, false,
                start, -1, waf.vendor(), waf.score()));

        JsonObject out = new JsonObject();
        out.addProperty("status_code", statusCode);
        out.addProperty("response_time_ms", elapsed);
        String responseBody = result.response() != null ? result.response().bodyToString() : "";
        out.addProperty("response_body", truncate(responseBody, 6000));
        out.addProperty("response_length", responseBody.length());
        out.addProperty("response_headers", truncate(extractHeaders(result), 2000));
        if (waf.isSuspected()) {
            out.addProperty("waf_detected", true);
            out.addProperty("waf_vendor", waf.vendor() != null ? waf.vendor() : "unknown");
            out.addProperty("waf_score", waf.score());
            out.addProperty("waf_hint", waf.isBlocked()
                    ? "该响应是 WAF 拦截页（payload 未到达后端），不是漏洞证据。可改用编码变体/不同结构重试；多次失败则在结论中注明 WAF 防护有效。"
                    : "该响应疑似 WAF 或业务拦截页，判断前请谨慎核对响应内容。");
        }
        if (statusCode == 429) {
            out.addProperty("rate_limited", true);
            out.addProperty("rate_limit_hint", "目标返回 429 (已重试 " + retryCount
                    + " 次)。建议: 降低请求频率，等待一段时间再继续测试，或在报告中注明目标有限速保护。");
        }
        return out.toString();
    }

    private static com.google.gson.JsonObject simpleProp(String type, String desc) {
        com.google.gson.JsonObject p = new com.google.gson.JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }
}
