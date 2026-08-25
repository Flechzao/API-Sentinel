package com.flechazo.apisentinel.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 4 (IMPROVEMENT_PLAN_4): tests for the authorization-bypass core
 * decision logic — ResponseComparator's Jaccard/weighted similarity and
 * AuthTestExecutor's round orchestration + verdict thresholds. This is the
 * security-critical judgment path that previously had zero coverage.
 */
class AuthTestExecutorTest {

    // ==================== verdict thresholds ====================

    @Test
    void verdictFromSimilarity_boundaries() {
        // Exact thresholds: >=0.85 VULNERABLE, >=0.60 SUSPICIOUS, else SAFE.
        assertEquals(AuthTestResult.AuthVerdict.VULNERABLE, ResponseComparator.verdictFromSimilarity(0.85));
        assertEquals(AuthTestResult.AuthVerdict.SUSPICIOUS, ResponseComparator.verdictFromSimilarity(0.8499));
        assertEquals(AuthTestResult.AuthVerdict.SUSPICIOUS, ResponseComparator.verdictFromSimilarity(0.60));
        assertEquals(AuthTestResult.AuthVerdict.SAFE, ResponseComparator.verdictFromSimilarity(0.5999));
        assertEquals(AuthTestResult.AuthVerdict.SAFE, ResponseComparator.verdictFromSimilarity(0.0));
        assertEquals(AuthTestResult.AuthVerdict.VULNERABLE, ResponseComparator.verdictFromSimilarity(1.0));
    }

    // ==================== ResponseComparator similarity ====================

    @Test
    void compare_identicalResponses_similarityOne() {
        HttpResponse a = responseStub(200, "{\"user\":\"alice\",\"role\":\"admin\"}");
        HttpResponse b = responseStub(200, "{\"user\":\"alice\",\"role\":\"admin\"}");
        double sim = ResponseComparator.compare(a, b);
        assertEquals(1.0, sim, 1e-9);
        assertEquals(AuthTestResult.AuthVerdict.VULNERABLE, ResponseComparator.verdictFromSimilarity(sim));
    }

    @Test
    void compare_testRejected403_similarityZero() {
        HttpResponse baseline = responseStub(200, "{\"user\":\"alice\"}");
        HttpResponse rejected = responseStub(403, "{\"error\":\"forbidden\"}");
        assertEquals(0.0, ResponseComparator.compare(baseline, rejected), 1e-9);
        HttpResponse unauth = responseStub(401, "");
        assertEquals(0.0, ResponseComparator.compare(baseline, unauth), 1e-9);
    }

    @Test
    void compare_testRedirectedToLogin_lowSimilarity() {
        HttpResponse baseline = responseStub(200, "{\"user\":\"alice\"}");
        HttpResponse redirect = responseStub(302, "");
        assertEquals(0.05, ResponseComparator.compare(baseline, redirect), 1e-9);
    }

    @Test
    void compare_onlyDynamicFieldsDiffer_stillHighSimilarity() {
        // timestamp/csrf style fields rotate per request and are normalized
        // away before comparison — they must not mask a true match.
        HttpResponse a = responseStub(200, "{\"data\":\"same\",\"timestamp\":\"2026-08-12T10:00:00Z\"}");
        HttpResponse b = responseStub(200, "{\"data\":\"same\",\"timestamp\":\"2026-08-12T10:00:05Z\"}");
        double sim = ResponseComparator.compare(a, b);
        assertTrue(sim >= 0.99, "dynamic-field-only difference must stay near 1.0, got " + sim);
    }

    @Test
    void compare_reorderedJsonKeys_stillHighSimilarity() {
        // Jaccard 3-gram shingling is order-robust: same keys/values in a
        // different order must still compare as (nearly) the same response —
        // the old positional compare returned ~0 here (false SAFE).
        HttpResponse a = responseStub(200, "{\"user\":\"alice\",\"role\":\"admin\",\"email\":\"a@x.com\"}");
        HttpResponse b = responseStub(200, "{\"email\":\"a@x.com\",\"user\":\"alice\",\"role\":\"admin\"}");
        double sim = ResponseComparator.compare(a, b);
        assertTrue(sim >= 0.85, "reordered keys must stay high-similarity, got " + sim);
    }

    @Test
    void compare_completelyDifferentBodies_safe() {
        HttpResponse a = responseStub(200, "{\"user\":\"alice\",\"role\":\"admin\"}");
        HttpResponse b = responseStub(200, "XXXXXXXXXXXXXXXXXXXXXXXX");
        double sim = ResponseComparator.compare(a, b);
        assertEquals(AuthTestResult.AuthVerdict.SAFE, ResponseComparator.verdictFromSimilarity(sim));
    }

    @Test
    void compare_nullInputs_zero() {
        assertEquals(0.0, ResponseComparator.compare(null, responseStub(200, "x")), 1e-9);
        assertEquals(0.0, ResponseComparator.compare(responseStub(200, "x"), null), 1e-9);
    }

    // ==================== AuthTestExecutor end-to-end (stubbed HTTP) ====================

    @Test
    void executor_swappedAuthGetsSameData_verdictVulnerable() {
        String sharedBody = "{\"user\":\"alice\",\"role\":\"admin\"}";
        // Baseline (session A cookie) and session-B-cookie requests both get
        // the data; the no-auth request is rejected.
        Function<ReqModel, HttpResponse> responder = req -> {
            String cookie = req.headers.getOrDefault("Cookie", "");
            if (cookie.contains("a=1") || cookie.contains("b=2")) {
                return responseStub(200, sharedBody);
            }
            return responseStub(403, "{\"error\":\"forbidden\"}");
        };

        SessionInfo sessionA = session("fpA", Map.of("a", "1"), Map.of(),
                reqModel("http://example.com/api/profile", Map.of("Cookie", "a=1")));
        SessionInfo sessionB = session("fpB", Map.of("b", "2"), Map.of());

        AuthTestExecutor executor = new AuthTestExecutor(apiStub(responder));
        AuthTestResult result = executor.execute(sessionA, sessionB, List.of("a"), List.of());

        assertEquals(AuthTestResult.AuthVerdict.VULNERABLE, result.verdict());
        assertTrue(result.maxSimilarity() >= 0.85, "max similarity should be ~1.0, got " + result.maxSimilarity());
        assertTrue(result.vulnType().contains("越权访问"),
                "vuln type should be broken-access-control, got: " + result.vulnType());
        assertFalse(result.rounds().isEmpty(), "rounds must be recorded");
        // The no-auth round must have been rejected (proves the endpoint does
        // require *some* auth — this is B's access, not public data).
        assertTrue(result.rounds().stream()
                        .anyMatch(r -> r.description().contains("未登录") && r.statusCode() == 403),
                "no-auth round should be a 403");
    }

    @Test
    void executor_allSwapsRejected_verdictSafe() {
        String protectedBody = "{\"user\":\"alice\",\"role\":\"admin\"}";
        Function<ReqModel, HttpResponse> responder = req -> {
            String cookie = req.headers.getOrDefault("Cookie", "");
            if (cookie.contains("a=1")) return responseStub(200, protectedBody);
            return responseStub(403, "{\"error\":\"forbidden\"}");
        };

        SessionInfo sessionA = session("fpA", Map.of("a", "1"), Map.of(),
                reqModel("http://example.com/api/profile", Map.of("Cookie", "a=1")));
        SessionInfo sessionB = session("fpB", Map.of("b", "2"), Map.of());

        AuthTestExecutor executor = new AuthTestExecutor(apiStub(responder));
        AuthTestResult result = executor.execute(sessionA, sessionB, List.of("a"), List.of());

        assertEquals(AuthTestResult.AuthVerdict.SAFE, result.verdict());
        assertEquals(0.0, result.maxSimilarity(), 1e-9);
    }

    @Test
    void executor_emptySessionA_skipped() {
        SessionInfo sessionA = session("fpA", Map.of(), Map.of());
        SessionInfo sessionB = session("fpB", Map.of("b", "2"), Map.of());
        AuthTestResult result = new AuthTestExecutor(apiStub(r -> responseStub(200, "")))
                .execute(sessionA, sessionB, List.of(), List.of());
        assertEquals(AuthTestResult.AuthVerdict.SKIPPED, result.verdict());
    }

    @Test
    void executor_allBaselinesFailed_skipped() {
        SessionInfo sessionA = session("fpA", Map.of("a", "1"), Map.of(),
                reqModel("http://example.com/api/profile", Map.of("Cookie", "a=1")));
        SessionInfo sessionB = session("fpB", Map.of("b", "2"), Map.of());
        // Every request gets no response at all.
        AuthTestResult result = new AuthTestExecutor(apiStub(r -> null))
                .execute(sessionA, sessionB, List.of("a"), List.of());
        assertEquals(AuthTestResult.AuthVerdict.SKIPPED, result.verdict());
        assertTrue(result.evidence().contains("baseline"), "reason should mention failed baselines: " + result.evidence());
    }

    // ==================== Stub plumbing ====================

    /** Minimal mutable request model backing the HttpRequest proxy. */
    static final class ReqModel {
        final String url;
        final LinkedHashMap<String, String> headers = new LinkedHashMap<>();

        ReqModel(String url, Map<String, String> headers) {
            this.url = url;
            this.headers.putAll(headers);
        }

        ReqModel without(String name) {
            ReqModel copy = new ReqModel(url, Map.of());
            headers.forEach((k, v) -> {
                if (!k.equalsIgnoreCase(name)) copy.headers.put(k, v);
            });
            return copy;
        }

        ReqModel with(String name, String value) {
            ReqModel copy = without(name);
            copy.headers.put(name, value);
            return copy;
        }

        String path() {
            int scheme = url.indexOf("://");
            int pathStart = scheme >= 0 ? url.indexOf('/', scheme + 3) : 0;
            return pathStart >= 0 ? url.substring(pathStart) : "/";
        }

        String raw() {
            StringBuilder sb = new StringBuilder("GET ").append(path()).append(" HTTP/1.1\r\n");
            headers.forEach((k, v) -> sb.append(k).append(": ").append(v).append("\r\n"));
            return sb.append("\r\n").toString();
        }
    }

    /** InvocationHandler carrying the ReqModel so sendRequest can inspect it. */
    private static final class RequestStubHandler implements InvocationHandler {
        final ReqModel model;

        RequestStubHandler(ReqModel model) {
            this.model = model;
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) {
            switch (method.getName()) {
                case "url": return model.url;
                case "method": return "GET";
                case "path": return model.path();
                case "toString": return model.raw();
                case "httpService": return null;
                case "toByteArray": throw new UnsupportedOperationException("stub");
                case "headers": {
                    List<HttpHeader> out = new ArrayList<>();
                    for (var e : model.headers.entrySet()) out.add(headerStub(e.getKey(), e.getValue()));
                    return out;
                }
                case "hasHeader": {
                    String n = String.valueOf(args[0]);
                    return model.headers.keySet().stream().anyMatch(k -> k.equalsIgnoreCase(n));
                }
                case "header": {
                    String n = String.valueOf(args[0]);
                    for (var e : model.headers.entrySet()) {
                        if (e.getKey().equalsIgnoreCase(n)) return headerStub(e.getKey(), e.getValue());
                    }
                    return null;
                }
                case "withRemovedHeader": return requestStub(model.without(String.valueOf(args[0])));
                case "withAddedHeader": return requestStub(model.with(String.valueOf(args[0]), String.valueOf(args[1])));
                case "withUpdatedHeader": return requestStub(model.with(String.valueOf(args[0]), String.valueOf(args[1])));
                case "bodyToString": return "";
                default: return defaultValue(method.getReturnType());
            }
        }
    }

    private static HttpRequest requestStub(ReqModel model) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(), new Class<?>[]{HttpRequest.class},
                new RequestStubHandler(model));
    }

    private static ReqModel modelOf(HttpRequest proxy) {
        return ((RequestStubHandler) Proxy.getInvocationHandler(proxy)).model;
    }

    private static HttpHeader headerStub(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
                HttpHeader.class.getClassLoader(), new Class<?>[]{HttpHeader.class},
                (p, m, a) -> switch (m.getName()) {
                    case "name" -> name;
                    case "value" -> value;
                    case "toString" -> name + ": " + value;
                    default -> defaultValue(m.getReturnType());
                });
    }

    private static HttpResponse responseStub(int status, String body) {
        return (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(), new Class<?>[]{HttpResponse.class},
                (p, m, a) -> switch (m.getName()) {
                    case "statusCode" -> (short) status;
                    case "bodyToString" -> body;
                    case "toString" -> "HTTP/1.1 " + status + "\r\n\r\n" + body;
                    default -> defaultValue(m.getReturnType());
                });
    }

    private static HttpRequestResponse requestResponseStub(HttpResponse response) {
        return (HttpRequestResponse) Proxy.newProxyInstance(
                HttpRequestResponse.class.getClassLoader(), new Class<?>[]{HttpRequestResponse.class},
                (p, m, a) -> switch (m.getName()) {
                    case "response" -> response;
                    default -> defaultValue(m.getReturnType());
                });
    }

    private static ProxyHttpRequestResponse proxyItemStub(HttpRequest request) {
        return (ProxyHttpRequestResponse) Proxy.newProxyInstance(
                ProxyHttpRequestResponse.class.getClassLoader(), new Class<?>[]{ProxyHttpRequestResponse.class},
                (p, m, a) -> switch (m.getName()) {
                    case "finalRequest" -> request;
                    default -> defaultValue(m.getReturnType());
                });
    }

    /** MontoyaApi stub whose http().sendRequest(req) applies the responder. */
    private static MontoyaApi apiStub(Function<ReqModel, HttpResponse> responder) {
        Http http = (Http) Proxy.newProxyInstance(
                Http.class.getClassLoader(), new Class<?>[]{Http.class},
                (p, m, a) -> {
                    if ("sendRequest".equals(m.getName())) {
                        ReqModel model = modelOf((HttpRequest) a[0]);
                        HttpResponse resp = responder.apply(model);
                        return requestResponseStub(resp);
                    }
                    return defaultValue(m.getReturnType());
                });
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class},
                (p, m, a) -> "http".equals(m.getName()) ? http : defaultValue(m.getReturnType()));
    }

    private static ReqModel reqModel(String url, Map<String, String> headers) {
        return new ReqModel(url, headers);
    }

    private static SessionInfo session(String fingerprint, Map<String, String> cookies,
                                       Map<String, String> authHeaders, ReqModel... requests) {
        SessionInfo s = new SessionInfo(fingerprint,
                new LinkedHashMap<>(cookies), new LinkedHashMap<>(authHeaders));
        for (ReqModel rm : requests) {
            s.addRequest(proxyItemStub(requestStub(rm)));
        }
        return s;
    }

    private static Object defaultValue(Class<?> rt) {
        if (!rt.isPrimitive() || rt == void.class) return null;
        if (rt == boolean.class) return false;
        if (rt == float.class) return 0f;
        if (rt == double.class) return 0d;
        if (rt == long.class) return 0L;
        if (rt == char.class) return (char) 0;
        if (rt == byte.class) return (byte) 0;
        if (rt == short.class) return (short) 0;
        return 0;
    }

    // ==================== Plan D: AI gray-zone arbitration parsing ====================

    @Test
    void parseArbitration_vulnerable() {
        var arb = AuthTestExecutor.parseArbitration(
                "{\"verdict\": \"VULNERABLE\", \"reason\": \"响应B仍返回A的订单数据\"}");
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.VULNERABLE, arb.verdict());
        assertTrue(arb.reason().contains("订单数据"));
    }

    @Test
    void parseArbitration_safe() {
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.SAFE,
                AuthTestExecutor.parseArbitration("{\"verdict\": \"SAFE\", \"reason\": \"返回403\"}").verdict());
    }

    @Test
    void parseArbitration_unknownKept() {
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.UNKNOWN,
                AuthTestExecutor.parseArbitration("{\"verdict\": \"UNKNOWN\", \"reason\": \"信息不足\"}").verdict());
    }

    @Test
    void parseArbitration_booleanAliases() {
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.VULNERABLE,
                AuthTestExecutor.parseArbitration("{\"verdict\": \"true\"}").verdict());
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.SAFE,
                AuthTestExecutor.parseArbitration("{\"verdict\": \"false\"}").verdict());
    }

    @Test
    void parseArbitration_wrappedInCodeBlock() {
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.VULNERABLE,
                AuthTestExecutor.parseArbitration(
                        "```json\n{\"verdict\": \"VULNERABLE\", \"reason\": \"x\"}\n```").verdict());
    }

    @Test
    void parseArbitration_malformedJson_unknown() {
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.UNKNOWN,
                AuthTestExecutor.parseArbitration("这不是JSON").verdict());
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.UNKNOWN,
                AuthTestExecutor.parseArbitration(null).verdict());
    }

    @Test
    void parseArbitration_unrecognizedVerdict_unknown() {
        assertEquals(AuthTestExecutor.AiArbitrationVerdict.UNKNOWN,
                AuthTestExecutor.parseArbitration("{\"verdict\": \"MAYBE\"}").verdict());
    }
}
