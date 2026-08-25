package com.flechazo.apisentinel.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ApiEntryTest {

    @Test
    void synchronizedFields_readWriteConsistent() {
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        entry.setDomain("example.com");
        entry.setLastSeenTimestamp(12345L);
        entry.setNote("note");
        entry.setLastStatusCode(200);
        entry.setLastUrl("https://example.com/api/test");

        assertEquals("example.com", entry.getDomain());
        assertEquals(12345L, entry.getLastSeenTimestamp());
        assertEquals("note", entry.getNote());
        assertEquals(200, entry.getLastStatusCode());
        assertEquals("https://example.com/api/test", entry.getLastUrl());
    }

    @Test
    void appendHttpMethod_noDuplicates() {
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        entry.appendHttpMethod("POST");
        entry.appendHttpMethod("GET");
        entry.appendHttpMethod("PUT");
        entry.appendHttpMethod("POST");

        String methods = entry.getHttpMethod();
        assertEquals("GET/POST/PUT", methods);
    }

    @Test
    void concurrentFieldUpdates_noException() throws InterruptedException {
        ApiEntry entry = new ApiEntry("GET", "/api/concurrent");
        int threads = 10;
        int iterations = 200;
        CountDownLatch latch = new CountDownLatch(threads);
        AtomicInteger errors = new AtomicInteger(0);
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        for (int t = 0; t < threads; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    for (int i = 0; i < iterations; i++) {
                        entry.setDomain("domain-" + threadId);
                        entry.setLastSeenTimestamp(System.currentTimeMillis());
                        entry.appendHttpMethod("M" + threadId);
                        entry.setNote("note-" + threadId + "-" + i);
                        entry.setLastStatusCode(200 + threadId);
                        entry.setLastRawRequest("req-" + i);
                        entry.setLastRawResponse("resp-" + i);

                        // Read all fields
                        entry.getDomain();
                        entry.getLastSeenTimestamp();
                        entry.getHttpMethod();
                        entry.getNote();
                        entry.getLastStatusCode();
                        entry.getLastRawRequest();
                        entry.getLastRawResponse();
                        entry.toString();
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS), "threads should finish in time");
        executor.shutdown();
        assertEquals(0, errors.get(), "no exceptions during concurrent access");
    }

    @Test
    void analysisHistory_synchronizedCompoundOps() throws InterruptedException {
        ApiEntry entry = new ApiEntry("GET", "/api/history");
        AnalysisRecord record = new AnalysisRecord("MODE1",
                com.flechazo.apisentinel.ai.analysis.AnalysisResult.failed(null));
        entry.addAnalysisRecord(record);

        int threads = 5;
        CountDownLatch latch = new CountDownLatch(threads);
        AtomicInteger errors = new AtomicInteger(0);

        for (int t = 0; t < threads; t++) {
            new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        AnalysisRecord latest = entry.getLatestAnalysisRecord();
                        if (latest != null) {
                            entry.updateLatestAnalysisRecord(
                                    new AnalysisRecord("MODE_" + i,
                                            com.flechazo.apisentinel.ai.analysis.AnalysisResult.failed(null)));
                        }
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    latch.countDown();
                }
            }).start();
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        assertEquals(0, errors.get(), "no IndexOutOfBoundsException");
        assertNotNull(entry.getLatestAnalysisRecord());
    }

    // ===== Findings column display (OPTIMIZATION_PLAN_2 item B) =====

    private static AnalysisRecord recordWithVerdict(
            com.flechazo.apisentinel.ai.pipeline.FinalVerdict verdict) {
        var pipeline = new com.flechazo.apisentinel.ai.pipeline.PipelineResult(
                null, null, java.util.List.of(), java.util.List.of(),
                verdict, java.util.Map.of(), null, null);
        return new AnalysisRecord("PIPELINE", null).withPipelineResult(pipeline);
    }

    private static com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln confirmed(String type) {
        return new com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln(
                type, type + "标题", "evidence", "payload", "snippet", "curl ...");
    }

    private static com.flechazo.apisentinel.ai.pipeline.SuspectedVuln suspected(String type) {
        return new com.flechazo.apisentinel.ai.pipeline.SuspectedVuln(
                type, type + "标题", "reason", "curl ...");
    }

    @Test
    void displayFindings_confirmedAndSuspectedUnion() {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1001");
        entry.addAnalysisRecord(recordWithVerdict(
                new com.flechazo.apisentinel.ai.pipeline.FinalVerdict(
                        "HIGH",
                        java.util.List.of(confirmed("SQL注入"), confirmed("IDOR")),
                        java.util.List.of(suspected("SQL注入"), suspected("XSS")),
                        "summary", "recs", 100)));

        String display = entry.getDisplayFindings();
        // One type per line; confirmed types bare, suspected types prefixed.
        assertTrue(display.contains("SQL注入"), display);
        assertTrue(display.contains("IDOR"), display);
        assertTrue(display.contains("疑似: XSS"), display);
        // A suspected type already present as confirmed must not duplicate.
        assertFalse(display.contains("疑似: SQL注入"), display);
        assertFalse(display.contains("0/0"), "type names replace the old counts: " + display);
    }

    @Test
    void displayFindings_suspectedOnly() {
        ApiEntry entry = new ApiEntry("GET", "/api/a");
        entry.addAnalysisRecord(recordWithVerdict(
                new com.flechazo.apisentinel.ai.pipeline.FinalVerdict(
                        "MEDIUM", java.util.List.of(),
                        java.util.List.of(suspected("XSS")), "s", "r", 10)));
        assertTrue(entry.getDisplayFindings().contains("疑似: XSS"));
    }

    @Test
    void displayFindings_noFindings_fallsBackToCounts() {
        ApiEntry entry = new ApiEntry("GET", "/api/a");
        entry.addAnalysisRecord(recordWithVerdict(
                new com.flechazo.apisentinel.ai.pipeline.FinalVerdict(
                        "SAFE", java.util.List.of(), java.util.List.of(), "s", "r", 10)));
        assertEquals("0/0", entry.getDisplayFindings());
        assertNull(entry.getDisplayFindingsTooltip(), "no findings => no tooltip");
    }

    @Test
    void displayFindings_noAnalysisRecord_placeholder() {
        ApiEntry entry = new ApiEntry("GET", "/api/a");
        assertEquals("--", entry.getDisplayFindings());
        assertNull(entry.getDisplayFindingsTooltip());
    }

    @Test
    void displayFindingsTooltip_fullListWithCounts() {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1001");
        entry.addAnalysisRecord(recordWithVerdict(
                new com.flechazo.apisentinel.ai.pipeline.FinalVerdict(
                        "HIGH",
                        java.util.List.of(confirmed("SQL注入"), confirmed("IDOR")),
                        java.util.List.of(suspected("XSS")),
                        "s", "r", 100)));

        String tooltip = entry.getDisplayFindingsTooltip();
        assertNotNull(tooltip);
        assertTrue(tooltip.contains("SQL注入"), tooltip);
        assertTrue(tooltip.contains("IDOR"), tooltip);
        assertTrue(tooltip.contains("XSS"), tooltip);
        assertTrue(tooltip.contains("确认:2"), tooltip);
        assertTrue(tooltip.contains("疑似:1"), tooltip);
    }

    // ===== Passive findings =====

    private static PassiveFinding pf(PassiveFinding.Source src, String title, String risk) {
        return new PassiveFinding(PassiveFinding.newId(), src, risk, "类别", title, "证据", "", 1L);
    }

    @Test
    void passiveFindings_dedupBySourceAndTitle() {
        ApiEntry entry = new ApiEntry("GET", "/api/a");
        assertTrue(entry.addPassiveFindingIfAbsent(pf(PassiveFinding.Source.HEURISTIC, "缺少安全头", "LOW")));
        // Same source+title → rejected
        assertFalse(entry.addPassiveFindingIfAbsent(pf(PassiveFinding.Source.HEURISTIC, "缺少安全头", "LOW")));
        // Different source, same title → kept
        assertTrue(entry.addPassiveFindingIfAbsent(pf(PassiveFinding.Source.SENSITIVE_INFO, "缺少安全头", "INFO")));
        assertEquals(2, entry.getPassiveFindings().size());
    }

    @Test
    void passiveFindings_displaySummaryAndRisk() {
        ApiEntry entry = new ApiEntry("GET", "/api/a");
        assertEquals("--", entry.getDisplayPassiveSummary());
        assertNull(entry.getDisplayPassiveTooltip());
        assertEquals("", entry.getMaxPassiveRisk());

        entry.addPassiveFindingIfAbsent(pf(PassiveFinding.Source.HEURISTIC, "Origin反射", "MEDIUM"));
        entry.addPassiveFindingIfAbsent(pf(PassiveFinding.Source.SENSITIVE_INFO, "Email", "INFO"));
        entry.addPassiveFindingIfAbsent(pf(PassiveFinding.Source.UNAUTHORIZED, "未授权探测", "MEDIUM"));

        assertEquals("Origin反射 · Email +1", entry.getDisplayPassiveSummary());
        assertEquals("MEDIUM", entry.getMaxPassiveRisk());
        assertNotNull(entry.getDisplayPassiveTooltip());
        assertTrue(entry.buildPassiveFindingsText().contains("[HEURISTIC][MEDIUM]"));
    }

    @Test
    void passiveFindings_removeById() {
        ApiEntry entry = new ApiEntry("GET", "/api/a");
        PassiveFinding f = pf(PassiveFinding.Source.HEURISTIC, "t", "LOW");
        entry.addPassiveFindingIfAbsent(f);
        assertTrue(entry.hasPassiveFindings());
        entry.removePassiveFinding(f.id());
        assertFalse(entry.hasPassiveFindings());
    }

    @Test
    void copyConstructor_carriesPassiveFindingsAndManualRisk() {
        ApiEntry src = new ApiEntry("GET", "/api/old");
        src.addPassiveFindingIfAbsent(pf(PassiveFinding.Source.HEURISTIC, "t", "HIGH"));
        src.setManualRisk("HIGH");
        ApiEntry copy = new ApiEntry(src, "/api/new");
        assertEquals(1, copy.getPassiveFindings().size());
        assertEquals("HIGH", copy.getManualRisk());
        assertEquals("/api/new", copy.getApiPath());
    }
}
