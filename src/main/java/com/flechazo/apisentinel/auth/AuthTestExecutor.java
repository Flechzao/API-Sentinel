package com.flechazo.apisentinel.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Executes authorization bypass tests using whole-header replacement strategy.
 *
 * <p>Auth-bypass rework (v1.1.0): expanded from path-only IDOR scanning to
 * also cover query-parameter and JSON-body resource IDs, added session B
 * expiry pre-check (so a 401 on session B isn't silently counted as
 * "auth works"), added request rate-limiting to avoid WAF / account
 * lockout, and added method-diversified template picking so a session
 * that only did GETs doesn't miss POST/PUT-level bypass.
 */
/** 越权测试执行器——多 session 交换 + IDOR 替换 + 未授权访问，Jaccard 相似度判定。 */
public class AuthTestExecutor {

    private static final Logger log = Logger.getLogger(AuthTestExecutor.class.getName());
    // P3-10: unified to single source of truth
    private static final Set<String> AUTH_HEADERS = com.flechazo.apisentinel.util.AuthHeaders.AUTH_HEADERS;

    /** How many distinct-path requests from session A to test. */
    private static final int MAX_TEMPLATES = 3;

    /**
     * Minimum delay between consecutive requests during the auth test
     * (ms). A small gap reduces the chance of triggering rate-limit /
     * WAF / account lockout on the target, which would otherwise turn
     * every subsequent round into a 429/403 and be mis-counted as
     * "auth enforced". 150ms is slow enough for most WAFs to see the
     * requests as distinct, fast enough that a full 15-round test still
     * completes in under 3 seconds.
     */
    private static final int INTER_REQUEST_DELAY_MS = 150;

    private static final Pattern NUMERIC_ID = Pattern.compile("/(\\d{2,})(?=/|$|[?])");
    private static final Pattern UUID_ID = Pattern.compile("/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$|[?])");

    /** Common query/body parameter names that carry resource IDs.
     *  Matched case-insensitively against parameter keys. */
    private static final List<String> ID_PARAM_PATTERNS = List.of(
            "id", "uid", "user_id", "userid", "user-id",
            "account_id", "accountid", "account-id",
            "order_id", "orderid", "order-id",
            "project_id", "projectid", "project-id",
            "resource_id", "resourceid", "resource-id",
            "item_id", "itemid", "item-id",
            "doc_id", "docid", "doc-id",
            "file_id", "fileid", "file-id",
            "record_id", "recordid", "record-id",
            "obj", "pk", "uuid"
    );

    private final MontoyaApi api;
    /** Optional LLM for gray-zone (SUSPICIOUS) arbitration; null = disabled. */
    private final com.flechazo.apisentinel.ai.provider.LlmProvider provider;
    private final boolean aiArbitrationEnabled;

    public AuthTestExecutor(MontoyaApi api) {
        this(api, null, false);
    }

    public AuthTestExecutor(MontoyaApi api,
                            com.flechazo.apisentinel.ai.provider.LlmProvider provider,
                            boolean aiArbitrationEnabled) {
        this.api = api;
        this.provider = provider;
        this.aiArbitrationEnabled = aiArbitrationEnabled;
    }

    /**
     * Execute pairwise auth bypass testing across multiple sessions.
     * For N sessions, runs C(N,2) pair comparisons and aggregates the results.
     * The overall verdict is the worst (most vulnerable) across all pairs.
     *
     * @param sessions list of configured sessions (2 or more)
     * @param targetDomain the API's domain for session filtering; empty = no filter
     * @return aggregated result with per-pair details in evidence
     */
    public AuthTestResult executePairwise(java.util.List<SessionConfig> sessions, String targetDomain) {
        // Filter sessions by domain
        java.util.List<SessionConfig> applicable = sessions.stream()
                .filter(s -> s.matchesDomain(targetDomain))
                .toList();

        if (applicable.size() < 2) {
            return AuthTestResult.skipped("仅发现 " + applicable.size()
                    + " 个适用于域名 " + (targetDomain.isEmpty() ? "(全部)" : targetDomain)
                    + " 的会话（需要至少 2 个）");
        }

        // Run pairwise comparisons
        java.util.List<AuthTestResult> pairResults = new java.util.ArrayList<>();
        for (int i = 0; i < applicable.size(); i++) {
            for (int j = i + 1; j < applicable.size(); j++) {
                SessionConfig a = applicable.get(i);
                SessionConfig b = applicable.get(j);
                SessionInfo infoA = a.toSessionInfo();
                SessionInfo infoB = b.toSessionInfo();

                // Identify auth params for this pair
                java.util.List<String> authCookieKeys = AuthParamIdentifier.identifyAuthCookieKeys(infoA, infoB);
                java.util.List<String> authHeaderKeys = AuthParamIdentifier.identifyAuthHeaders(infoA, infoB);

                if (authCookieKeys.isEmpty() && authHeaderKeys.isEmpty()) {
                    pairResults.add(AuthTestResult.skipped(
                            a.label() + " ↔ " + b.label() + ": 无差异鉴权参数"));
                    continue;
                }

                AuthTestResult pairResult = execute(infoA, infoB, authCookieKeys, authHeaderKeys);
                // Determine test type from level + group metadata
                String testType = determineTestType(a, b);
                // Override labels with user-configured labels + test type annotation
                pairResults.add(new AuthTestResult(
                        pairResult.verdict(), pairResult.vulnType(), pairResult.identifiedAuthParams(),
                        a.shortLabel(), b.shortLabel(),
                        pairResult.maxSimilarity(),
                        "[" + testType + "] " + a.label() + " ↔ " + b.label() + ": " + pairResult.evidence(),
                        pairResult.rounds()));
            }
        }

        return aggregatePairResults(pairResults, applicable);
    }

    /**
     * Determine the test type label for a pair of sessions based on their
     * privilege level and group/tenant metadata:
     * <ul>
     *   <li>Both levels set + different → "垂直越权" (vertical escalation)</li>
     *   <li>Same level + different group → "水平越权" (horizontal IDOR)</li>
     *   <li>Different level + different group → "跨租户越权"</li>
     *   <li>Neither set → "越权" (generic)</li>
     * </ul>
     * The agent sees this annotation in the evidence string and can use it
     * to frame its verdict reasoning (e.g. "horizontal IDOR confirmed" vs
     * "vertical privilege escalation confirmed").
     */
    private static String determineTestType(SessionConfig a, SessionConfig b) {
        String levelA = a.level();
        String levelB = b.level();
        String groupA = a.group();
        String groupB = b.group();

        boolean levelsDiffer = !levelA.isEmpty() && !levelB.isEmpty() && !levelA.equals(levelB);
        boolean groupsDiffer = !groupA.isEmpty() && !groupB.isEmpty() && !groupA.equals(groupB);

        if (levelsDiffer && groupsDiffer) return "跨租户越权";
        if (levelsDiffer) return "垂直越权";
        if (groupsDiffer) return "水平越权";
        if (!levelA.isEmpty() && !levelB.isEmpty() && levelA.equals(levelB)) return "水平越权";
        return "越权";
    }

    /** Aggregate multiple pair results into a single overall result. */
    private AuthTestResult aggregatePairResults(java.util.List<AuthTestResult> pairResults,
                                                 java.util.List<SessionConfig> sessions) {
        if (pairResults.isEmpty()) {
            return AuthTestResult.skipped("无可测试的会话对");
        }

        // Find worst verdict
        AuthTestResult.AuthVerdict worstVerdict = AuthTestResult.AuthVerdict.SAFE;
        String worstVulnType = "NONE";
        double maxSim = 0;
        java.util.List<AuthTestRound> allRounds = new java.util.ArrayList<>();
        StringBuilder evidence = new StringBuilder();
        java.util.List<String> allAuthParams = new java.util.ArrayList<>();

        for (AuthTestResult pr : pairResults) {
            if (pr.verdict() != AuthTestResult.AuthVerdict.SKIPPED
                    && pr.verdict().ordinal() > worstVerdict.ordinal()) {
                worstVerdict = pr.verdict();
                worstVulnType = pr.vulnType();
            }
            if (pr.maxSimilarity() > maxSim) maxSim = pr.maxSimilarity();
            allRounds.addAll(pr.rounds());
            evidence.append(pr.evidence()).append("\n");
            allAuthParams.addAll(pr.identifiedAuthParams());
        }

        String sessionSummary = sessions.size() + " 个会话, " + pairResults.size() + " 对比较";
        return new AuthTestResult(worstVerdict, worstVulnType,
                allAuthParams.stream().distinct().toList(),
                sessionSummary, "",
                maxSim, evidence.toString().trim(), allRounds);
    }

    public AuthTestResult execute(SessionInfo sessionA, SessionInfo sessionB,
                                  List<String> authCookieKeys, List<String> authHeaderKeys) {
        if (sessionA.getRequests().isEmpty()) {
            return AuthTestResult.skipped("No requests found for session A");
        }

        List<AuthTestRound> rounds = new ArrayList<>();
        double maxSimilarity = 0.0;
        String bestRoundDesc = "";
        String bestBaselineRaw = "";

        try {
            // Pre-check: verify session B is actually alive. A 401/403 on
            // session B's own request means its token is expired, and any
            // swap round would then show low similarity → false SAFE.
            if (!verifySessionAlive(sessionB)) {
                return AuthTestResult.skipped("Session B 的凭证已过期（请求返回 401/403），请刷新 token 后重试");
            }

            // Pick up to MAX_TEMPLATES distinct-method+path templates from
            // session A (newest first) so the test covers more than one
            // HTTP method on the same endpoint.
            List<HttpRequest> templates = pickTemplates(sessionA);

            boolean anyBaselineFailed = true;
            for (HttpRequest template : templates) {
                HttpRequestResponse baselineResp = api.http().sendRequest(template);
                HttpResponse baselineResponse = baselineResp.response();
                rateLimitDelay();
                if (baselineResponse == null) continue;
                anyBaselineFailed = false;

                if (baselineResponse.statusCode() == 401 || baselineResponse.statusCode() == 403) {
                    // Session A looks expired for this endpoint; skip its rounds
                    rounds.add(new AuthTestRound(
                            "基线请求 (原始鉴权) — 跳过 (Session A 返回 " + baselineResponse.statusCode() + ")",
                            baselineResponse.statusCode(), 0.0,
                            truncate(template.toString(), 200), truncate(baselineResponse.toString(), 200),
                            template.toString(), baselineResponse.toString()));
                    continue;
                }

                double sim = runSwapRounds(template, baselineResponse, sessionB, rounds);
                if (sim > maxSimilarity) {
                    maxSimilarity = sim; bestRoundDesc = "鉴权交换";
                    bestBaselineRaw = baselineResponse.toString();
                }

                double idorSim = runIdorRound(template, baselineResponse, sessionA, sessionB, rounds);
                if (idorSim > maxSimilarity) {
                    maxSimilarity = idorSim; bestRoundDesc = "IDOR 资源ID替换";
                    bestBaselineRaw = baselineResponse.toString();
                }
            }

            if (anyBaselineFailed) {
                return AuthTestResult.skipped("All baseline requests failed (no response)");
            }

            int baselineBodyLen = ResponseComparator.bodyLengthOf(bestBaselineRaw);
            AuthTestResult.AuthVerdict verdict = ResponseComparator.verdictFromSimilarity(maxSimilarity, baselineBodyLen);
            String vulnType = determineVulnType(rounds, maxSimilarity);
            StringBuilder evidence = new StringBuilder(String.format(
                    "最大相似度: %.1f%% [%s], 共执行 %d 轮测试 (跨 %d 个端点)",
                    maxSimilarity * 100, bestRoundDesc, rounds.size(), templates.size()));

            // Gray-zone AI arbitration (inspired by AutorizePro's semantic
            // response comparison, Apache-2.0 — see docs/THIRD-PARTY.md):
            // when Jaccard similarity lands in the SUSPICIOUS band, let the
            // LLM judge whether the swapped-credential response really still
            // carries the account's business data.
            if (verdict == AuthTestResult.AuthVerdict.SUSPICIOUS
                    && provider != null && aiArbitrationEnabled) {
                AuthTestRound best = null;
                for (AuthTestRound r : rounds) {
                    if (Math.abs(r.similarity() - maxSimilarity) < 1e-9) { best = r; break; }
                }
                String respB = best != null ? best.fullResponse() : "";
                AiArbitration arb = arbitrate(bestBaselineRaw, respB, maxSimilarity);
                evidence.append(" | AI 仲裁: ").append(arb.verdict())
                        .append(" — ").append(arb.reason());
                if (arb.verdict() == AiArbitrationVerdict.VULNERABLE) {
                    verdict = AuthTestResult.AuthVerdict.VULNERABLE;
                } else if (arb.verdict() == AiArbitrationVerdict.SAFE) {
                    verdict = AuthTestResult.AuthVerdict.SAFE;
                }
                // UNKNOWN / error → keep SUSPICIOUS (conservative).
            }

            String labelA = sessionA.shortLabel("Session A");
            String labelB = sessionB.shortLabel("Session B");

            return new AuthTestResult(verdict, vulnType, authCookieKeys, labelA, labelB,
                    maxSimilarity, evidence.toString(), rounds);

        } catch (Exception e) {
            log.warning("Auth test execution failed: " + e.getMessage());
            return AuthTestResult.skipped("Execution error: " + e.getMessage());
        }
    }

    /**
     * Verify that a session's credentials are still valid by replaying
     * the most recent request from its history. Returns false when the
     * response is 401/403 — meaning the token expired between the time
     * the session was captured and the time we're running the test.
     *
     * <p>Without this check, an expired session B would cause every
     * swap round to return a login-redirect or 401, producing low
     * similarity and a false "SAFE" verdict. Better to tell the user
     * up-front that their token needs refreshing.
     */
    private boolean verifySessionAlive(SessionInfo session) {
        List<ProxyHttpRequestResponse> reqs = session.getRequests();
        if (reqs.isEmpty()) return true; // no history to replay, trust the caller
        try {
            HttpRequest recent = reqs.get(reqs.size() - 1).finalRequest();
            HttpRequestResponse resp = api.http().sendRequest(recent);
            rateLimitDelay();
            if (resp.response() == null) return true; // network issue, don't blame the session
            int status = resp.response().statusCode();
            return status != 401 && status != 403;
        } catch (Exception e) {
            return true; // on error, don't block the test
        }
    }

    /**
     * Distinct-method+path templates from session A, newest first, capped
     * at MAX_TEMPLATES. Pre-rework only the URL path was used as the
     * dedup key, so a session that hit the same endpoint with GET and
     * POST would only test one of them — missing method-specific bypass
     * (common for REST APIs where GET is public but POST requires auth).
     */
    private List<HttpRequest> pickTemplates(SessionInfo sessionA) {
        List<HttpRequest> out = new ArrayList<>();
        Set<String> seenKeys = new LinkedHashSet<>();
        List<ProxyHttpRequestResponse> reqs = sessionA.getRequests();
        for (int i = reqs.size() - 1; i >= 0 && out.size() < MAX_TEMPLATES; i--) {
            try {
                HttpRequest req = reqs.get(i).finalRequest();
                String path = com.flechazo.apisentinel.util.UrlUtils.extractPath(req.url());
                String key = req.method() + " " + path;
                if (seenKeys.add(key)) out.add(req);
            } catch (Exception ignored) {}
        }
        if (out.isEmpty() && !reqs.isEmpty()) {
            out.add(reqs.get(reqs.size() - 1).finalRequest());
        }
        return out;
    }

    /** Run cookie/auth/full-swap + no-auth rounds; returns max similarity seen. */
    private double runSwapRounds(HttpRequest template, HttpResponse baseline,
                                 SessionInfo sessionB, List<AuthTestRound> rounds) {
        double max = 0.0;
        String sessionBCookie = sessionB.toCookieHeaderValue();
        Map<String, String> sessionBHeaders = sessionB.getAuthHeaders();

        if (sessionBCookie != null && !sessionBCookie.isEmpty()) {
            HttpRequest cookieSwap = template.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", sessionBCookie);
            max = Math.max(max, recordRound(cookieSwap, baseline, "替换完整Cookie (B→A)", rounds));
        }

        String sessionBAuth = sessionBHeaders.get("authorization");
        boolean hasAuthHeader = template.headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase("authorization"));
        if (sessionBAuth != null && !sessionBAuth.isEmpty() && hasAuthHeader) {
            HttpRequest authSwap = template.withRemovedHeader("Authorization")
                    .withAddedHeader("Authorization", sessionBAuth);
            max = Math.max(max, recordRound(authSwap, baseline, "替换Authorization (B→A)", rounds));
        }

        HttpRequest fullSwap = template;
        if (sessionBCookie != null && !sessionBCookie.isEmpty()) {
            fullSwap = fullSwap.withRemovedHeader("Cookie").withAddedHeader("Cookie", sessionBCookie);
        }
        for (Map.Entry<String, String> entry : sessionBHeaders.entrySet()) {
            String headerName = entry.getKey();
            boolean exists = fullSwap.headers().stream()
                    .anyMatch(h -> h.name().equalsIgnoreCase(headerName));
            if (exists) {
                fullSwap = fullSwap.withRemovedHeader(headerName).withAddedHeader(headerName, entry.getValue());
            }
        }
        max = Math.max(max, recordRound(fullSwap, baseline, "替换全部鉴权头 (B→A)", rounds));

        HttpRequest noAuth = template.withRemovedHeader("Cookie");
        for (String h : AUTH_HEADERS) noAuth = noAuth.withRemovedHeader(h);
        max = Math.max(max, recordRound(noAuth, baseline, "移除全部鉴权 (未登录)", rounds));

        return max;
    }

    /**
     * IDOR round: keep session A's OWN auth, but substitute a resource ID
     * found in the template (path / query / body) with one observed in
     * session B's history (different user's resource). A high similarity
     * to session A's baseline means session A can read session B's data
     * — horizontal IDOR.
     *
     * <p>Pre-rework only URL-path IDs were scanned. Modern APIs more often
     * pass resource IDs in query parameters ({@code ?user_id=123}) or
     * JSON bodies ({@code {"orderId": 456}}). This rework covers all
     * three channels.
     */
    private double runIdorRound(HttpRequest template, HttpResponse baseline,
                                SessionInfo sessionA, SessionInfo sessionB,
                                List<AuthTestRound> rounds) {
        double max = 0.0;

        // Try path-based IDOR first (the common case)
        String url = template.url();
        String pathId = findFirstId(url);
        if (pathId != null) {
            String altId = findAlternateId(sessionB, pathId, extractPathPattern(url));
            if (altId == null && pathId.matches("\\d+")) {
                altId = String.valueOf(Long.parseLong(pathId) + 1);
            }
            if (altId != null && !altId.equals(pathId)) {
                String newUrl = url.replace("/" + pathId, "/" + altId);
                if (!newUrl.equals(url)) {
                    try {
                        HttpRequest idorReq = HttpRequest.httpRequest(
                                template.httpService(), buildRawWithUrl(template, newUrl));
                        max = Math.max(max, recordRound(idorReq, baseline,
                                "IDOR 替换路径ID (" + pathId + "→" + altId + ", 保留A鉴权)", rounds));
                    } catch (Exception ignored) {}
                }
            }
        }

        // Try query-parameter IDOR
        Map<String, String> queryParams = parseQueryParams(url);
        for (var entry : queryParams.entrySet()) {
            if (!isIdLikeParam(entry.getKey())) continue;
            String currentVal = entry.getValue();
            if (currentVal.length() < 2) continue;
            String altVal = findAlternateId(sessionB, currentVal, null);
            if (altVal == null && currentVal.matches("\\d+")) {
                altVal = String.valueOf(Long.parseLong(currentVal) + 1);
            }
            if (altVal != null && !altVal.equals(currentVal)) {
                String newUrl = url.replace(entry.getKey() + "=" + currentVal,
                        entry.getKey() + "=" + altVal);
                if (!newUrl.equals(url)) {
                    try {
                        HttpRequest idorReq = HttpRequest.httpRequest(
                                template.httpService(), buildRawWithUrl(template, newUrl));
                        max = Math.max(max, recordRound(idorReq, baseline,
                                "IDOR 替换查询参数 " + entry.getKey() + " (" + currentVal + "→" + altVal + ")", rounds));
                    } catch (Exception ignored) {}
                }
            }
        }

        // Try JSON-body IDOR (only for POST/PUT/PATCH with JSON content)
        String method = template.method().toUpperCase();
        if (method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) {
            String body = template.bodyToString();
            if (body != null && !body.isBlank()) {
                String newBody = substituteBodyIds(body, sessionA, sessionB);
                if (newBody != null && !newBody.equals(body)) {
                    try {
                        HttpRequest idorReq = HttpRequest.httpRequest(
                                template.httpService(),
                                template.toString().replace("\r\n\r\n" + body, "\r\n\r\n" + newBody));
                        max = Math.max(max, recordRound(idorReq, baseline,
                                "IDOR 替换 JSON body 中的资源ID (保留A鉴权)", rounds));
                    } catch (Exception ignored) {}
                }
            }
        }

        return max;
    }

    /**
     * Substitute resource IDs in a JSON body with alternates from session
     * B. Only substitutes known ID-like keys (see {@link #ID_PARAM_PATTERNS}).
     * Returns null when no substitution was possible.
     */
    private String substituteBodyIds(String body, SessionInfo sessionA, SessionInfo sessionB) {
        String result = body;
        boolean anySubstituted = false;
        for (String pattern : ID_PARAM_PATTERNS) {
            // Match "key": "value" or "key": value (numeric)
            Pattern jsonPattern = Pattern.compile(
                    "\"" + Pattern.quote(pattern) + "\"\\s*:\\s*(\"([^\"]+)\"|(\\d+))",
                    Pattern.CASE_INSENSITIVE);
            Matcher m = jsonPattern.matcher(result);
            if (m.find()) {
                String currentVal = m.group(2) != null ? m.group(2) : m.group(3);
                String altVal = findAlternateId(sessionB, currentVal, null);
                if (altVal == null && currentVal.matches("\\d+")) {
                    altVal = String.valueOf(Long.parseLong(currentVal) + 1);
                }
                if (altVal != null && !altVal.equals(currentVal)) {
                    String replacement;
                    if (m.group(2) != null) {
                        replacement = "\"" + pattern + "\":\"" + altVal + "\"";
                    } else {
                        replacement = "\"" + pattern + "\":" + altVal;
                    }
                    result = result.substring(0, m.start()) + replacement + result.substring(m.end());
                    anySubstituted = true;
                }
            }
        }
        return anySubstituted ? result : null;
    }

    private double recordRound(HttpRequest request, HttpResponse baseline, String description,
                               List<AuthTestRound> rounds) {
        try {
            HttpRequestResponse resp = api.http().sendRequest(request);
            rateLimitDelay();
            HttpResponse response = resp.response();
            if (response == null) {
                rounds.add(new AuthTestRound(description, 0, 0.0,
                        truncate(request.toString(), 200), "No response",
                        request.toString(), ""));
                return 0.0;
            }
            double sim = ResponseComparator.compare(baseline, response);
            rounds.add(new AuthTestRound(description, response.statusCode(), sim,
                    truncate(request.toString(), 200), truncate(response.toString(), 200),
                    request.toString(), response.toString()));
            return sim;
        } catch (Exception e) {
            return 0.0;
        }
    }

    /** First numeric or UUID path segment, or null. */
    private static String findFirstId(String url) {
        // Strip query string first to avoid matching IDs in query
        int qIdx = url.indexOf('?');
        String pathOnly = qIdx >= 0 ? url.substring(0, qIdx) : url;
        Matcher m = UUID_ID.matcher(pathOnly);
        if (m.find()) return m.group(1);
        m = NUMERIC_ID.matcher(pathOnly);
        if (m.find()) return m.group(1);
        return null;
    }

    /** Extract a path pattern from a URL (path with numeric/UUID segments
     *  replaced by placeholders), used to match alternate IDs from the
     *  same type of endpoint. */
    private static String extractPathPattern(String url) {
        int qIdx = url.indexOf('?');
        String pathOnly = qIdx >= 0 ? url.substring(0, qIdx) : url;
        int scheme = pathOnly.indexOf("://");
        if (scheme >= 0) {
            int pathStart = pathOnly.indexOf('/', scheme + 3);
            if (pathStart >= 0) pathOnly = pathOnly.substring(pathStart);
        }
        // Replace UUIDs and numeric IDs with placeholders
        return UUID_ID.matcher(pathOnly).replaceAll("/{UUID}")
                .replaceAll(NUMERIC_ID.pattern(), "/{ID}");
    }

    /**
     * Find a different resource ID from session B's history that matches
     * the same path pattern. Pre-rework this took the first different
     * ID from any session B request, which could be from a completely
     * different endpoint (e.g. matching /api/users/{id} against
     * /api/orders/{id}). Now we prefer same-pattern matches and fall
     * back to any-match only when no pattern-aware candidate exists.
     *
     * @param currentId the ID currently in the request
     * @param pathPattern the path with IDs replaced by placeholders (nullable)
     */
    private static String findAlternateId(SessionInfo sessionB, String currentId, String pathPattern) {
        String fallback = null;
        for (ProxyHttpRequestResponse r : sessionB.getRequests()) {
            try {
                String u = r.finalRequest().url();
                String id = findFirstId(u);
                if (id == null || id.equals(currentId)) continue;
                // Prefer same-pattern match
                if (pathPattern != null) {
                    String candidatePattern = extractPathPattern(u);
                    if (pathPattern.equals(candidatePattern)) return id;
                }
                if (fallback == null) fallback = id;
            } catch (Exception ignored) {}
        }
        return fallback;
    }

    /** Parse query parameters from a URL into a key→value map. */
    private static Map<String, String> parseQueryParams(String url) {
        Map<String, String> params = new LinkedHashMap<>();
        int qIdx = url.indexOf('?');
        if (qIdx < 0) return params;
        String query = url.substring(qIdx + 1);
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        return params;
    }

    /** True when the parameter name looks like a resource ID. */
    private static boolean isIdLikeParam(String paramName) {
        String lower = paramName.toLowerCase();
        for (String pattern : ID_PARAM_PATTERNS) {
            if (lower.equals(pattern) || lower.endsWith("_" + pattern) || lower.endsWith(pattern)) {
                return true;
            }
        }
        return false;
    }

    /** Rebuild the raw request with a different URL/path line. */
    private static String buildRawWithUrl(HttpRequest template, String newUrl) {
        String raw = template.toString();
        // Replace the request-target in the first line. The first line looks like
        // "GET /path?x HTTP/2". Swap the path portion for the new URL's path+query.
        int nl = raw.indexOf("\r\n");
        if (nl < 0) nl = raw.indexOf('\n');
        String firstLine = nl > 0 ? raw.substring(0, nl) : raw;
        String[] parts = firstLine.split("\\s+", 3);
        if (parts.length < 2) return raw;
        String path = newUrl;
        int scheme = newUrl.indexOf("://");
        if (scheme >= 0) {
            int pathStart = newUrl.indexOf('/', scheme + 3);
            path = pathStart >= 0 ? newUrl.substring(pathStart) : "/";
        }
        parts[1] = path;
        String newFirst = String.join(" ", parts);
        return nl > 0 ? newFirst + raw.substring(nl) : newFirst;
    }

    private String determineVulnType(List<AuthTestRound> rounds, double maxSimilarity) {
        for (AuthTestRound r : rounds) {
            if (r.description().contains("IDOR") && r.similarity() >= 0.85) {
                return "IDOR/水平越权 (Insecure Direct Object Reference)";
            }
        }
        for (AuthTestRound r : rounds) {
            if (r.description().contains("未登录") && r.similarity() >= 0.85) {
                return "未授权访问 (Missing Authentication)";
            }
        }
        for (AuthTestRound r : rounds) {
            if (r.description().contains("替换") && r.similarity() >= 0.85) {
                return "越权访问 (Broken Access Control)";
            }
        }
        return "潜在鉴权问题";
    }

    /** Small delay between requests to avoid WAF / rate-limit triggers. */
    private void rateLimitDelay() {
        try {
            Thread.sleep(INTER_REQUEST_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }

    // ======================== Gray-zone AI arbitration ========================

    public enum AiArbitrationVerdict { VULNERABLE, SAFE, UNKNOWN }

    public record AiArbitration(AiArbitrationVerdict verdict, String reason) {}

    private static final int ARBITRATION_TIMEOUT_SEC = 60;
    private static final int MAX_RESP_CHARS = 4000;

    private static final String ARBITRATION_SYSTEM_PROMPT = """
            你是授权安全分析专家。根据两个 HTTP 响应判断是否存在越权（水平权限）漏洞。
            响应 A：账号 A 用自己的凭证请求接口得到的响应。
            响应 B：把请求中的凭证替换为账号 B 的凭证后重新请求得到的响应。
            判定标准：
            - 越权成功（VULNERABLE）：响应 B 仍返回账号 A 的业务数据（结构一致且包含真实业务字段/数据），
              或返回了属于其他账号的数据；
            - 越权失败（SAFE）：响应 B 明确拒绝（401/403、"权限不足"、"需要登录"等），
              或与 A 结构明显不同（错误页/空数据/登录重定向）；
            - 无法判断（UNKNOWN）：信息不足或存在歧义。
            输出严格 JSON，不要包含其他文字：
            {"verdict": "VULNERABLE|SAFE|UNKNOWN", "reason": "不超过100字的中文理由"}
            """;

    /** Call the LLM to arbitrate a SUSPICIOUS similarity result. Never
     *  throws — any failure yields UNKNOWN (caller keeps SUSPICIOUS). */
    private AiArbitration arbitrate(String baselineRaw, String swappedRaw, double similarity) {
        try {
            String userPrompt = "相似度: " + String.format("%.1f%%", similarity * 100)
                    + "\n\n=== 响应 A（账号 A 原始请求）===\n" + truncate(baselineRaw, MAX_RESP_CHARS)
                    + "\n\n=== 响应 B（替换凭证后）===\n" + truncate(swappedRaw, MAX_RESP_CHARS);
            var request = new com.flechazo.apisentinel.ai.provider.LlmRequest(
                    ARBITRATION_SYSTEM_PROMPT, userPrompt, 1024);
            var response = provider.complete(request).get(ARBITRATION_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS);
            if (!response.isSuccess()) {
                log.info("AI 越权仲裁调用失败: " + response.errorMessage());
                return new AiArbitration(AiArbitrationVerdict.UNKNOWN, "调用失败");
            }
            AiArbitration arb = parseArbitration(response.content());
            log.info("AI 越权仲裁结果: " + arb.verdict() + " — " + arb.reason());
            return arb;
        } catch (Exception e) {
            log.warning("AI 越权仲裁异常: " + e.getMessage());
            return new AiArbitration(AiArbitrationVerdict.UNKNOWN, "仲裁异常: " + e.getMessage());
        }
    }

    /** Pure parser for the arbitration JSON (unit-testable). */
    public static AiArbitration parseArbitration(String raw) {
        try {
            com.google.gson.JsonObject json =
                    com.flechazo.apisentinel.util.JsonExtractor.extract(raw);
            if (json == null) return new AiArbitration(AiArbitrationVerdict.UNKNOWN, "响应非JSON");
            String v = json.has("verdict") ? json.get("verdict").getAsString() : "";
            String reason = json.has("reason") ? json.get("reason").getAsString() : "";
            AiArbitrationVerdict verdict = switch (v.toUpperCase(java.util.Locale.ROOT)) {
                case "VULNERABLE", "TRUE", "BYPASSED" -> AiArbitrationVerdict.VULNERABLE;
                case "SAFE", "FALSE", "ENFORCED" -> AiArbitrationVerdict.SAFE;
                default -> AiArbitrationVerdict.UNKNOWN;
            };
            return new AiArbitration(verdict, reason);
        } catch (Exception e) {
            return new AiArbitration(AiArbitrationVerdict.UNKNOWN, "解析失败");
        }
    }
}
