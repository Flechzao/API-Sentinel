package com.flechazo.apisentinel.handler;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.config.SensitiveRule;
import com.flechazo.apisentinel.detection.SensitiveInfoDetector;
import com.flechazo.apisentinel.detection.UnauthorizedDetector;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.matching.CompositeMatchEngine;
import com.flechazo.apisentinel.matching.FuzzyMatchEngine;
import com.flechazo.apisentinel.matching.TrieMatchEngine;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.repository.InMemoryApiRepository;
import com.flechazo.apisentinel.ui.UiEventBus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 1 (IMPROVEMENT_PLAN_4): verifies the passive-scan async split —
 * entry capture stays synchronous, the regex scans (sensitive + heuristic)
 * and their note/annotation effects still land (from the scan pool thread),
 * and unmatched/static traffic never triggers a scan.
 *
 * Montoya static factories (continueWith / HttpHeader / Annotations) delegate
 * to ObjectFactoryLocator.FACTORY which only Burp initializes at runtime, so
 * the tests install a stub factory here.
 */
class HttpTrafficHandlerTest {

    // ==================== Montoya stub factory ====================

    @BeforeAll
    static void installMontoyaFactory() {
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                MontoyaObjectFactory.class.getClassLoader(),
                new Class<?>[]{MontoyaObjectFactory.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "responseResult" -> stub(ResponseReceivedAction.class, null);
                    case "requestResult" -> stub(RequestToBeSentAction.class, null);
                    case "httpHeader" -> headerStub(
                            (String) args[0],
                            args.length > 1 && args[1] instanceof String s ? s : "");
                    case "annotations" -> annotationStub(new AnnotationRecorder());
                    default -> null;
                });
    }

    /** Dynamic proxy with per-method behavior + primitive defaults. */
    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> iface, InvocationHandler extra) {
        return (T) Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface},
                (proxy, method, args) -> {
                    if (extra != null) {
                        Object r = extra.invoke(proxy, method, args);
                        if (r != HANDLER_DECLINED) return r;
                    }
                    return defaultValue(method.getReturnType());
                });
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

    /** Sentinel meaning "this handler didn't handle the method". */
    private static final Object HANDLER_DECLINED = new Object();

    private static HttpHeader headerStub(String name, String value) {
        return stub(HttpHeader.class, (p, m, a) -> switch (m.getName()) {
            case "name" -> name;
            case "value" -> value;
            case "toString" -> name + ": " + value;
            default -> HANDLER_DECLINED;
        });
    }

    /** Mutable recording stand-in for Annotations (notes + highlight color). */
    private static final class AnnotationRecorder {
        volatile String notes;
        volatile HighlightColor color = HighlightColor.NONE;
    }

    private static Annotations annotationStub(AnnotationRecorder rec) {
        return stub(Annotations.class, (p, m, a) -> switch (m.getName()) {
            case "setNotes" -> { rec.notes = (String) a[0]; yield null; }
            case "setHighlightColor" -> { rec.color = (HighlightColor) a[0]; yield null; }
            case "notes" -> rec.notes;
            case "highlightColor" -> rec.color;
            case "hasNotes" -> rec.notes != null && !rec.notes.isEmpty();
            case "hasHighlightColor" -> rec.color != HighlightColor.NONE;
            default -> HANDLER_DECLINED;
        });
    }

    private static HttpRequest requestStub(String url, String path, String method) {
        return stub(HttpRequest.class, (p, m, a) -> switch (m.getName()) {
            case "url" -> url;
            case "method" -> method;
            case "path" -> path;
            case "bodyToString" -> "";
            case "headers" -> List.of();
            // Force HttpMessageUtils onto its manual fallback path (it catches
            // the exception), keeping the stub minimal.
            case "toByteArray" -> throw new UnsupportedOperationException("stub");
            default -> HANDLER_DECLINED;
        });
    }

    private static HttpResponseReceived responseStub(String url, String path, String method,
                                                     short status, String body,
                                                     List<HttpHeader> headers,
                                                     Annotations annotations) {
        HttpRequest req = requestStub(url, path, method);
        return stub(HttpResponseReceived.class, (p, m, a) -> switch (m.getName()) {
            case "initiatingRequest" -> req;
            case "statusCode" -> status;
            case "annotations" -> annotations;
            case "bodyToString" -> body;
            case "headers" -> headers;
            default -> HANDLER_DECLINED;
        });
    }

    // ==================== Fixture ====================

    private LeveledLogger logger;
    private ConfigManager configManager;
    private InMemoryApiRepository repo;
    private UnauthorizedDetector unauthorizedDetector;
    private HttpTrafficHandler handler;

    @BeforeEach
    void setUp() {
        logger = new LeveledLogger(null);
        configManager = new ConfigManager(logger);
        // Keep the probe-replaying detector out of unit tests entirely.
        configManager.getConfig().setUnauthorizedDetectionEnabled(false);
        configManager.getConfig().setSensitiveDetectionEnabled(true);
        configManager.getConfig().setHighlightEnabled(true);

        repo = new InMemoryApiRepository();
        unauthorizedDetector = new UnauthorizedDetector(
                null, new RateLimiter(100), logger, new UiEventBus(), repo);
    }

    /** Build a handler whose match engine already knows the given entries. */
    private void buildHandler(ApiEntry... entries) {
        for (ApiEntry e : entries) repo.add(e);
        CompositeMatchEngine engine =
                new CompositeMatchEngine(new TrieMatchEngine(), new FuzzyMatchEngine(), configManager);
        engine.rebuild(repo.findAll());
        handler = new HttpTrafficHandler(null, engine, repo, configManager,
                new SensitiveInfoDetector(configManager, logger), unauthorizedDetector,
                new UiEventBus(), new EventBus(), logger);
    }

    @AfterEach
    void tearDown() {
        if (handler != null) handler.shutdown();
        unauthorizedDetector.shutdown();
    }

    private static void waitFor(java.util.function.BooleanSupplier cond, long timeoutMs)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (cond.getAsBoolean()) return;
            Thread.sleep(20);
        }
    }

    // ==================== Tests ====================

    @Test
    void matchedResponse_syncCapture_thenAsyncHeuristicsWithHighlightUpgrade() throws Exception {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1001");
        buildHandler(entry);

        AnnotationRecorder rec = new AnnotationRecorder();
        HttpResponseReceived resp = responseStub(
                "http://example.com/api/users/1001", "/api/users/1001", "GET",
                (short) 200, "<html><body>user data</body></html>",
                List.of(headerStub("Content-Type", "text/html")),
                annotationStub(rec));

        ResponseReceivedAction action = handler.handleHttpResponseReceived(resp);
        assertNotNull(action, "handler must always return a response action");

        // ── Synchronous contract: traffic captured before the call returns ──
        assertEquals("http://example.com/api/users/1001", entry.getLastUrl());
        assertEquals(200, entry.getLastStatusCode());
        assertEquals(ApiStatus.UNDER_TEST, entry.getStatus());
        assertNotNull(rec.notes, "base annotation notes must be applied synchronously");

        // ── Async contract: heuristic findings + highlight upgrade land later ──
        // HTML 200 without security headers ⇒ missing-header findings (LOW ⇒ CYAN).
        waitFor(entry::hasPassiveFindings, 5000);
        assertTrue(entry.getPassiveFindings().stream()
                        .anyMatch(f -> f.source() == com.flechazo.apisentinel.model.PassiveFinding.Source.HEURISTIC),
                "heuristic findings must land as structured passive findings");
        assertTrue(entry.getNote() == null || entry.getNote().isEmpty(),
                "note must stay user-only, got: " + entry.getNote());
        waitFor(() -> rec.color != HighlightColor.NONE, 2000);
        assertNotEquals(HighlightColor.NONE, rec.color,
                "highlight color must be upgraded asynchronously by the passive scan");
    }

    @Test
    void matchedResponse_sensitiveFindingsLandAsync() throws Exception {
        // Deterministic test rule (independent of the user's on-disk rules file).
        configManager.getConfig().setSensitiveRules(
                List.of(new SensitiveRule("测试密钥", "X-SECRET-[0-9]{4,}", "0")));

        ApiEntry entry = new ApiEntry("GET", "/api/config/export");
        buildHandler(entry);

        AnnotationRecorder rec = new AnnotationRecorder();
        HttpResponseReceived resp = responseStub(
                "http://example.com/api/config/export", "/api/config/export", "GET",
                (short) 200, "{\"key\": \"X-SECRET-12345\"}",
                List.of(headerStub("Content-Type", "application/json")),
                annotationStub(rec));

        handler.handleHttpResponseReceived(resp);

        waitFor(entry::hasPassiveFindings, 5000);
        assertTrue(entry.getPassiveFindings().stream()
                        .anyMatch(f -> f.source() == com.flechazo.apisentinel.model.PassiveFinding.Source.SENSITIVE_INFO
                                && "测试密钥".equals(f.title())),
                "sensitive rule finding must land as structured passive finding");
        assertTrue(entry.getNote() == null || entry.getNote().isEmpty(),
                "note must stay user-only, got: " + entry.getNote());
    }

    @Test
    void unmatchedResponse_noScan_noAnnotationTouch() throws Exception {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1001");
        buildHandler(entry);

        AnnotationRecorder rec = new AnnotationRecorder();
        HttpResponseReceived resp = responseStub(
                "http://example.com/totally/different/xyz", "/totally/different/xyz", "GET",
                (short) 200, "<html><body>nothing</body></html>",
                List.of(headerStub("Content-Type", "text/html")),
                annotationStub(rec));

        ResponseReceivedAction action = handler.handleHttpResponseReceived(resp);
        assertNotNull(action);

        // Give any (incorrectly) scheduled async scan a chance to run.
        Thread.sleep(300);
        assertTrue(entry.getNote() == null || entry.getNote().isEmpty(),
                "unmatched entry must not receive findings");
        assertFalse(entry.hasPassiveFindings(),
                "unmatched entry must not receive passive findings");
        assertEquals(HighlightColor.NONE, rec.color,
                "annotations must not be touched for unmatched traffic");
        assertNull(rec.notes, "annotations must not be touched for unmatched traffic");
    }

    @Test
    void staticResource_skippedBeforeMatch() throws Exception {
        ApiEntry entry = new ApiEntry("GET", "/static/app.js");
        buildHandler(entry);

        AnnotationRecorder rec = new AnnotationRecorder();
        HttpResponseReceived resp = responseStub(
                "http://example.com/static/app.js", "/static/app.js", "GET",
                (short) 200, "var x = 1;",
                List.of(headerStub("Content-Type", "application/javascript")),
                annotationStub(rec));

        ResponseReceivedAction action = handler.handleHttpResponseReceived(resp);
        assertNotNull(action);

        Thread.sleep(200);
        assertTrue(entry.getNote() == null || entry.getNote().isEmpty());
        assertFalse(entry.hasPassiveFindings());
        assertNull(rec.notes);
        assertEquals(HighlightColor.NONE, rec.color);
    }
}
