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

    // P3-10: unified to single source of truth
    private static final Set<String> AUTH_HEADER_NAMES = com.flechazo.apisentinel.util.AuthHeaders.AUTH_HEADERS;

    private final ToolContext ctx;
    private final List<PayloadResult> payloadResults =
            java.util.Collections.synchronizedList(new ArrayList<>());

    /** Sequential index assigned to each sent request, so VerdictValidator can
     *  bind a finding to the exact payload via {@code citedExecutionIndex}
     *  (the strong O(1) anti-hallucination path) instead of falling back to
     *  fuzzy text matching. -1 (the old hard-coded value) disabled binding. */
    private final java.util.concurrent.atomic.AtomicInteger execCounter =
            new java.util.concurrent.atomic.AtomicInteger(0);
    /** Session label for the current send_request call (e.g. "alice"/"bob"),
     *  parsed from the optional {@code auth_session} arg and stamped onto
     *  each PayloadResult so the IDOR two-session check can run. Set at the
     *  start of execute(); send_request is non-readonly so calls don't
     *  overlap, and the payloads-array path only reads it. */
    private volatile String currentAuthSession = null;

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

        JsonObject multipartProp = new JsonObject();
        multipartProp.addProperty("type", "boolean");
        multipartProp.addProperty("description", "If true, the 'body' is treated as multipart form fields "
                + "(format: 'field1=value1\\nfield2=value2'). A random boundary is auto-generated and "
                + "Content-Type: multipart/form-data is set. Use this for file upload endpoints. "
                + "To include a file, prefix the value with 'file:' and provide the local path "
                + "(e.g. 'file=@/tmp/test.jsp'). Default false.");
        props.add("multipart", multipartProp);

        JsonObject timeoutProp = new JsonObject();
        timeoutProp.addProperty("type", "integer");
        timeoutProp.addProperty("description", "Request timeout in milliseconds. Default 30000 (30s). "
                + "Max 120000 (120s). Use a shorter timeout for quick probes, longer for slow endpoints.");
        props.add("timeout_ms", timeoutProp);

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

        // Session label for IDOR/authorization testing: stamp the request with
        // which authenticated session it represents (e.g. "alice", "bob") so
        // VerdictValidator's two-session check can bind auth-class findings to
        // concrete cross-session evidence instead of a permissive any-request gate.
        JsonObject authSessionProp = new JsonObject();
        authSessionProp.addProperty("type", "string");
        authSessionProp.addProperty("description",
                "Optional: a label for the authenticated session this request uses "
                        + "(e.g. \"alice\", \"bob\", \"anonymous\"). For IDOR/authz testing, "
                        + "tag each session's request so the validator can require two "
                        + "different sessions hitting the same endpoint. Leave empty for "
                        + "non-auth tests.");
        props.add("auth_session", authSessionProp);

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
            String method = args.has("method") && !args.get("method").isJsonNull()
                    ? args.get("method").getAsString() : null;
            String path = args.has("path") && !args.get("path").isJsonNull()
                    ? args.get("path").getAsString() : null;
            if (method == null || method.isEmpty()) {
                return "{\"error\": \"'method' is required (e.g. GET, POST, PUT, DELETE)\"}";
            }
            if (path == null || path.isEmpty()) {
                return "{\"error\": \"'path' is required (e.g. /api/users?id=1)\"}";
            }
            String body = args.has("body") && !args.get("body").isJsonNull()
                    ? args.get("body").getAsString() : "";
            String extraHeaders = args.has("headers") && !args.get("headers").isJsonNull()
                    ? args.get("headers").getAsString() : "";
            // `useAuth` is deliberately NOT final — enforceScope below
            // may force it to false on cross-domain sends, and the
            // result must flow into both sendSingle and executeBatch.
            // Both call sites capture it by value so there's no
            // effectively-final requirement on this variable.
            boolean useAuth = !args.has("use_original_auth") || args.get("use_original_auth").getAsBoolean();
            boolean multipart = args.has("multipart") && args.get("multipart").getAsBoolean();
            int timeoutMs = args.has("timeout_ms") && !args.get("timeout_ms").isJsonNull()
                    ? Math.min(Math.max(args.get("timeout_ms").getAsInt(), 1000), 120000) : 30000;
            String hostOverride = args.has("host") && !args.get("host").isJsonNull() && !args.get("host").getAsString().isBlank()
                    ? args.get("host").getAsString() : null;
        // Tag this call's requests with the session label the agent chose, so
        // each emitted PayloadResult carries authSession for the IDOR check.
        currentAuthSession = args.has("auth_session") && !args.get("auth_session").isJsonNull()
                ? args.get("auth_session").getAsString() : null;

            // P0-2 scope gate: refuse to route to off-target destinations
            // (IMDS / internal networks / localhost) and strip credentials
            // when the destination differs from the entry's captured
            // domain. Pre-P0-2, `use_original_auth` defaulted to true and
            // `host` was unrestricted, so a sufficiently persuasive LLM
            // could ship the user's live session cookie to
            // http://169.254.169.254 or any arbitrary exfiltration sink
            // with zero UI confirmation.
            ScopeCheck scopeCheck = enforceScope(hostOverride, ctx.entry());
            if (scopeCheck.rejectJson != null) {
                return scopeCheck.rejectJson;
            }
            if (scopeCheck.stripAuth) {
                useAuth = false;
                ctx.logger().warn("[SendRequestTool] cross-domain send to %s (entry domain %s) — "
                                + "use_original_auth forced to false to avoid credential leakage",
                        hostOverride, ctx.entry().getDomain());
            }

            // Batch mode: send multiple payload variants concurrently
            final boolean finalUseAuth = useAuth;
            if (args.has("payloads") && args.get("payloads").isJsonArray()) {
                return executeBatch(method, path, body, extraHeaders, finalUseAuth,
                        args.getAsJsonArray("payloads"), hostOverride, multipart, timeoutMs);
            }

            // Single mode: original behavior
            return sendSingle(method, path, body, extraHeaders, finalUseAuth, hostOverride, multipart, timeoutMs);
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /** P0-2 scope check result. Either the send proceeds (rejectJson=null,
     *  stripAuth=false), the credentials are silently stripped because the
     *  destination is off-domain (rejectJson=null, stripAuth=true), or the
     *  send is hard-rejected with a structured error payload. */
    private record ScopeCheck(String rejectJson, boolean stripAuth) {
        static ScopeCheck ok() { return new ScopeCheck(null, false); }
        static ScopeCheck withStrippedAuth() { return new ScopeCheck(null, true); }
        static ScopeCheck rejected(String reason) {
            return new ScopeCheck("{\"error\": \"send_request blocked by scope policy: "
                    + escapeJson(reason)
                    + ". Pick a destination inside the target's own domain "
                    + "(the captured entry domain, or a host from search_traffic).\"}",
                    false);
        }
    }

    /** P0-2: refuse to route off-target and strip credentials on cross-domain
     *  sends. Evaluated BEFORE any network IO so a malicious destination
     *  never even sees the request, let alone the live session cookie.
     *
     *  <p>Rules, in evaluation order:
     *  <ol>
     *    <li>Only {@code http}/{@code https} schemes are routable.
     *        {@code file://}/{@code ftp://}/{@code jar://}/{@code gopher://}
     *        and other exfiltration-friendly schemes are rejected.</li>
     *    <li>Private / internal IP space is rejected outright: RFC1918
     *        ({@code 10.*}, {@code 172.16-31.*}, {@code 192.168.*}),
     *        loopback ({@code 127.*}, {@code ::1}), link-local
     *        ({@code 169.254.*}, {@code fe80::/10}), the AWS/GCP/Azure
     *        IMDS well-known ({@code 169.254.169.254},
     *        {@code metadata.google.internal}, {@code metadata.azure.internal}),
     *        plus the obvious string-form hostnames ({@code localhost},
     *        {@code metadata}, and any {@code *.internal} suffix).</li>
     *    <li>When {@code hostOverride} resolves to a host other than the
     *        entry's own domain, credentials are stripped (return
     *        {@code stripAuth=true}) regardless of the caller's
     *        {@code use_original_auth}. The caller logs a warning and
     *        proceeds without auth — no UI confirmation is attempted in
     *        this pass (adding {@code bridge.askConfirmation} is a
     *        follow-up).</li>
     *  </ol>
     */
    private ScopeCheck enforceScope(String hostOverride, com.flechazo.apisentinel.model.ApiEntry entry) {
        if (hostOverride == null || hostOverride.isBlank()) {
            // No override → the request stays on the entry's own domain.
            // Nothing to gate.
            return ScopeCheck.ok();
        }

        // Scheme check — default to http:// when bare "host:port" so the
        // rest of the parser has a URI shape to work with.
        String uriText = hostOverride;
        if (!hostOverride.contains("://")) {
            uriText = "http://" + hostOverride;
        }
        java.net.URI uri;
        try {
            uri = new java.net.URI(uriText);
        } catch (Exception e) {
            return ScopeCheck.rejected("unparseable host '" + hostOverride + "'");
        }
        String scheme = uri.getScheme();
        if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
            return ScopeCheck.rejected("scheme '" + scheme + "' is not routable; only http/https are allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return ScopeCheck.rejected("no host in '" + hostOverride + "'");
        }
        String hostLower = host.toLowerCase(java.util.Locale.ROOT);

        // Fast path: same-domain sends skip every downstream gate. DNS
        // may fail in test / isolated environments (the entry's captured
        // domain may not be publicly resolvable from the runner); same-
        // domain sends are the tool's normal happy path and must never
        // be blocked by a resolution failure.
        String entryHost = extractEntryHost(entry != null ? entry.getDomain() : null);
        if (entryHost != null
                && hostLower.equalsIgnoreCase(entryHost.toLowerCase(java.util.Locale.ROOT))) {
            return ScopeCheck.ok();
        }

        // Hard-blocked hostnames — checked before the IP lookup so that
        // "localhost" and IMDS aliases fail fast without a DNS round-trip.
        if (hostLower.equals("localhost")
                || hostLower.equals("metadata")
                || hostLower.equals("metadata.google.internal")
                || hostLower.equals("metadata.azure.internal")
                || hostLower.endsWith(".internal")) {
            return ScopeCheck.rejected("host '" + host + "' is a reserved internal name");
        }

        // Resolve to IP for numeric / private-range checks. A failed
        // resolution here is a hard reject rather than "let the caller
        // see the DNS error" — a malicious LLM could otherwise probe
        // the internal name space via error messages.
        java.net.InetAddress addr;
        try {
            addr = java.net.InetAddress.getByName(host);
        } catch (java.net.UnknownHostException e) {
            return ScopeCheck.rejected("host '" + host + "' does not resolve");
        }
        if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()) {
            return ScopeCheck.rejected("host '" + host + "' (" + addr.getHostAddress()
                    + ") is private / loopback / link-local");
        }
        if ("169.254.169.254".equals(addr.getHostAddress())) {
            return ScopeCheck.rejected("host '" + host + "' resolves to the cloud IMDS address");
        }

        // No entry domain recorded → nothing to compare against, so we
        // can't tell whether this is same- or cross-domain. Err on the
        // side of stripping credentials (cross-domain behaviour) — the
        // rare branch, only hit when the Agent has no traffic to anchor
        // on, and logged by the caller for traceability.
        if (entryHost == null) {
            return ScopeCheck.withStrippedAuth();
        }
        // Cross-domain: strip credentials regardless of use_original_auth.
        return ScopeCheck.withStrippedAuth();
    }

    /** Pull the bare host portion out of the entry's captured domain
     *  string (which may carry a scheme, port, or path). Returns null
     *  when the entry has no domain recorded. */
    private static String extractEntryHost(String entryDomain) {
        if (entryDomain == null || entryDomain.isBlank()) return null;
        try {
            java.net.URI u = new java.net.URI(
                    entryDomain.contains("://") ? entryDomain : "http://" + entryDomain);
            if (u.getHost() != null) return u.getHost();
        } catch (Exception ignored) {
            // Fall through to the manual split below.
        }
        int colon = entryDomain.indexOf(':');
        int slash = entryDomain.indexOf('/');
        int end = entryDomain.length();
        if (colon > 0) end = Math.min(end, colon);
        if (slash > 0) end = Math.min(end, slash);
        return entryDomain.substring(0, end);
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
                               String extraHeaders, boolean useAuth, String hostOverride,
                               boolean multipart, int timeoutMs) {
        Target t = resolveTarget(hostOverride);
        if (t.error() != null) return t.error();
        var entry = ctx.entry();
        String rawReq = buildRawRequest(method, path, body, extraHeaders, useAuth, t.host(), t.port(), t.useHttps(), entry, multipart);
        return sendAndRecord(t.service(), rawReq, method, path, timeoutMs);
    }

    /** Send multiple payload variants concurrently and return all results. */
    private String executeBatch(String method, String path, String baseBody,
                                 String extraHeaders, boolean useAuth,
                                 com.google.gson.JsonArray variants, String hostOverride,
                                 boolean multipart, int timeoutMs) {
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
                    useAuth, host, port, useHttps, entry, multipart);

            futures.add(CompletableFuture.supplyAsync(() ->
                    sendAndRecord(service, rawReq, varMethod, varPath, timeoutMs))
                    .orTimeout(timeoutMs + 5000, java.util.concurrent.TimeUnit.MILLISECONDS));
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
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
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
                                    ApiEntry entry, boolean multipart) {
        // Multipart form data: build body with boundary
        if (multipart && body != null && !body.isEmpty()) {
            String boundary = "----ApiSentinel" + System.currentTimeMillis();
            StringBuilder mpBody = new StringBuilder();
            for (String field : body.split("\\\\n|\n")) {
                if (field.trim().isEmpty()) continue;
                int eq = field.indexOf('=');
                if (eq < 0) continue;
                String name = field.substring(0, eq).trim();
                String value = field.substring(eq + 1).trim();
                mpBody.append("--").append(boundary).append("\r\n");
                if (value.startsWith("file:")) {
                    // File field
                    String filePath = value.substring(5).replaceFirst("^@", "");
                    String fileName = filePath.substring(filePath.lastIndexOf('/') + 1);
                    mpBody.append("Content-Disposition: form-data; name=\"").append(name)
                          .append("\"; filename=\"").append(fileName).append("\"\r\n");
                    mpBody.append("Content-Type: application/octet-stream\r\n\r\n");
                    try {
                        byte[] fileBytes = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(filePath));
                        mpBody.append(new String(fileBytes)).append("\r\n");
                    } catch (Exception e) {
                        mpBody.append("[file read error: ").append(e.getMessage()).append("]\r\n");
                    }
                } else {
                    mpBody.append("Content-Disposition: form-data; name=\"").append(name).append("\"\r\n\r\n");
                    mpBody.append(value).append("\r\n");
                }
            }
            mpBody.append("--").append(boundary).append("--\r\n");
            String multipartBody = mpBody.toString();
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
            rawReqBuilder.append("Content-Type: multipart/form-data; boundary=").append(boundary).append("\r\n");
            rawReqBuilder.append("Content-Length: ").append(multipartBody.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
            rawReqBuilder.append("\r\n").append(multipartBody);
            return rawReqBuilder.toString();
        }

        // Standard (non-multipart) request
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

    private String sendAndRecord(HttpService service, String rawReq, String method, String path, int timeoutMs) {
        // P1-2 fix: Add probe marker so HttpTrafficHandler skips this request
        rawReq = HttpMessageUtils.addProbeMarker(rawReq);
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

        int execIdx = execCounter.getAndIncrement();
        payloadResults.add(new PayloadResult(null, sentRaw, recvRaw, statusCode, elapsed, false,
                start, execIdx, waf.vendor(), waf.score(),
                currentAuthSession, false));

        JsonObject out = new JsonObject();
        out.addProperty("status_code", statusCode);
        out.addProperty("response_time_ms", elapsed);
        // Surface the index so the LLM can cite it via cited_execution_index
        // when submitting a finding — unlocks VerdictValidator's strong O(1)
        // index binding instead of the weak text-match fallback.
        out.addProperty("execution_index", execIdx);
        String responseBody = result.response() != null ? result.response().bodyToString() : "";
        // P1-6: redact credentials UNLESS the user opted in to sending
        // raw credentials. The raw response stays in `payloadResults`
        // above (for WafDetector + VerdictValidator evidence anchoring),
        // so downstream verifiers still see the real bytes; only the
        // LLM-visible JSON is sanitised.
        boolean rawOk = ctx.includeRawCredentials();
        String llmBody = rawOk ? responseBody
                : com.flechazo.apisentinel.util.RequestRedactor.redact(responseBody);
        String llmHeaders = rawOk ? extractHeaders(result)
                : com.flechazo.apisentinel.util.RequestRedactor.redact(extractHeaders(result));
        out.addProperty("response_body", truncate(llmBody, 6000));
        out.addProperty("response_length", responseBody.length());
        out.addProperty("response_headers", truncate(llmHeaders, 2000));
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
