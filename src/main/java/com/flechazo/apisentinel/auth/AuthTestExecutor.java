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
 * Tests multiple representative requests from session A (not just the last),
 * and adds an IDOR round that substitutes a resource ID observed in session B's
 * history while keeping session A's own auth — catching horizontal IDOR that a
 * pure session-swap would miss.
 */
/** 越权测试执行器——多 session 交换 + IDOR 替换 + 未授权访问，Jaccard 相似度判定。 */
public class AuthTestExecutor {

    private static final Logger log = Logger.getLogger(AuthTestExecutor.class.getName());
    private static final Set<String> AUTH_HEADERS = Set.of(
            "cookie", "authorization", "x-token", "x-access-token",
            "x-csrf-token", "x-xsrf-token", "x-api-key", "x-auth-token");

    /** How many distinct-path requests from session A to test. */
    private static final int MAX_TEMPLATES = 3;

    private static final Pattern NUMERIC_ID = Pattern.compile("/(\\d{2,})(?=/|$|[?])");
    private static final Pattern UUID_ID = Pattern.compile("/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$|[?])");

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
            // Pick up to MAX_TEMPLATES distinct-path templates from session A
            // (newest first) so the test covers more than one endpoint.
            List<HttpRequest> templates = pickTemplates(sessionA);

            boolean anyBaselineFailed = true;
            for (HttpRequest template : templates) {
                HttpRequestResponse baselineResp = api.http().sendRequest(template);
                HttpResponse baselineResponse = baselineResp.response();
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

                double idorSim = runIdorRound(template, baselineResponse, sessionB, rounds);
                if (idorSim > maxSimilarity) {
                    maxSimilarity = idorSim; bestRoundDesc = "IDOR 资源ID替换";
                    bestBaselineRaw = baselineResponse.toString();
                }
            }

            if (anyBaselineFailed) {
                return AuthTestResult.skipped("All baseline requests failed (no response)");
            }

            AuthTestResult.AuthVerdict verdict = ResponseComparator.verdictFromSimilarity(maxSimilarity);
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

    /** Distinct-path templates from session A, newest first, capped at MAX_TEMPLATES. */
    private List<HttpRequest> pickTemplates(SessionInfo sessionA) {
        List<HttpRequest> out = new ArrayList<>();
        Set<String> seenPaths = new LinkedHashSet<>();
        List<ProxyHttpRequestResponse> reqs = sessionA.getRequests();
        for (int i = reqs.size() - 1; i >= 0 && out.size() < MAX_TEMPLATES; i--) {
            try {
                HttpRequest req = reqs.get(i).finalRequest();
                String path = com.flechazo.apisentinel.util.UrlUtils.extractPath(req.url());
                if (seenPaths.add(path)) out.add(req);
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
     * IDOR round: keep session A's OWN auth, but substitute a resource ID in the
     * path with one observed in session B's history (different user's resource).
     * A high similarity to session A's baseline means session A can read session
     * B's data — horizontal IDOR.
     */
    private double runIdorRound(HttpRequest template, HttpResponse baseline,
                                SessionInfo sessionB, List<AuthTestRound> rounds) {
        String url = template.url();
        String currentId = findFirstId(url);
        if (currentId == null) return 0.0; // no resource ID to substitute

        String altId = findAlternateId(sessionB, currentId);
        if (altId == null || altId.equals(currentId)) {
            // No alternate from session B; try a numeric increment as a last resort
            if (currentId.matches("\\d+")) {
                altId = String.valueOf(Long.parseLong(currentId) + 1);
            } else {
                return 0.0;
            }
        }

        String newUrl = url.replace("/" + currentId, "/" + altId);
        if (newUrl.equals(url)) return 0.0;
        HttpRequest idorReq;
        try {
            idorReq = HttpRequest.httpRequest(template.httpService(), buildRawWithUrl(template, newUrl));
        } catch (Exception e) {
            return 0.0;
        }
        return recordRound(idorReq, baseline, "IDOR 替换资源ID (" + currentId + "→" + altId + ", 保留A鉴权)", rounds);
    }

    private double recordRound(HttpRequest request, HttpResponse baseline, String description,
                               List<AuthTestRound> rounds) {
        try {
            HttpRequestResponse resp = api.http().sendRequest(request);
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
        Matcher m = UUID_ID.matcher(url);
        if (m.find()) return m.group(1);
        m = NUMERIC_ID.matcher(url);
        if (m.find()) return m.group(1);
        return null;
    }

    /** Find a different resource ID for the same path-pattern in session B. */
    private static String findAlternateId(SessionInfo sessionB, String currentId) {
        for (ProxyHttpRequestResponse r : sessionB.getRequests()) {
            try {
                String u = r.finalRequest().url();
                String id = findFirstId(u);
                if (id != null && !id.equals(currentId)) return id;
            } catch (Exception ignored) {}
        }
        return null;
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
