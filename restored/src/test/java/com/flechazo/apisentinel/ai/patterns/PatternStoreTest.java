package com.flechazo.apisentinel.ai.patterns;

import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PatternStore is the success-pattern memory (P3): verified confirms are
 * aggregated into reusable (vulnType, technique, payload, endpoint, domain)
 * records, persisted, and replayed as prompt context for new analyses.
 */
class PatternStoreTest {

    @TempDir
    Path tempDir;

    private PatternStore store() {
        return new PatternStore(tempDir.resolve("patterns.json"), new LeveledLogger(null));
    }

    private static ApiEntry entry(String path, String domain) {
        ApiEntry e = new ApiEntry("GET", path);
        e.setDomain(domain);
        return e;
    }

    private static FinalVerdict verdict(ConfirmedVuln... vulns) {
        return new FinalVerdict("HIGH", List.of(vulns), List.of(), "summary", "", 100);
    }

    @Test
    void recordsAndAggregatesRepeatConfirmations() {
        PatternStore store = store();
        ApiEntry entry = entry("/api/users/1001", "vuln.app");
        ConfirmedVuln idor = new ConfirmedVuln("IDOR", "水平越权读取",
                "evidence", "GET /api/users/1001 with session B", "resp", "curl ...");

        store.recordConfirmations(entry, verdict(idor));
        assertThat(store.size()).isEqualTo(1);

        // Same technique on the same endpoint again: hits increment, no duplicate row.
        store.recordConfirmations(entry, verdict(idor));
        assertThat(store.size()).isEqualTo(1);
        assertThat(store.topPatterns("vuln.app", 5)).singleElement()
                .satisfies(p -> {
                    assertThat(p.vulnType()).isEqualTo("IDOR");
                    assertThat(p.hits()).isEqualTo(2);
                    assertThat(p.apiPattern()).isEqualTo("/api/users/1001");
                    assertThat(p.domain()).isEqualTo("vuln.app");
                });

        // Different endpoint = a separate pattern row.
        store.recordConfirmations(entry("/api/users/2002", "vuln.app"), verdict(idor));
        assertThat(store.size()).isEqualTo(2);
    }

    @Test
    void emptyOrSuspectedOnlyVerdictsRecordNothing() {
        PatternStore store = store();
        store.recordConfirmations(entry("/api/x", "d"), new FinalVerdict("LOW", List.of(), List.of(), "", "", 0));
        store.recordConfirmations(entry("/api/x", "d"), null);
        store.recordConfirmations(null, verdict(new ConfirmedVuln("IDOR", "t", "e", "p", "r", "v")));
        assertThat(store.size()).isZero();
    }

    @Test
    void topPatternsPrefersSameDomainAndRequiresTwoHitsForCrossDomain() {
        PatternStore store = store();
        ConfirmedVuln idor = new ConfirmedVuln("IDOR", "越权读", "e", "payload-a", "r", "v");
        ConfirmedVuln sqli = new ConfirmedVuln("SQLi", "注入", "e", "payload-b", "r", "v");

        // Same domain: single hit is enough (it IS this environment).
        store.recordConfirmations(entry("/api/users/1", "vuln.app"), verdict(idor));
        // Other domain: recorded twice so it clears the cross-domain bar.
        store.recordConfirmations(entry("/api/orders/1", "other.app"), verdict(sqli));
        store.recordConfirmations(entry("/api/orders/2", "other.app"), verdict(sqli));
        // Other domain with a single hit: must NOT surface.
        ConfirmedVuln xss = new ConfirmedVuln("XSS", "反射", "e", "payload-c", "r", "v");
        store.recordConfirmations(entry("/api/search", "third.app"), verdict(xss));

        List<PatternStore.SuccessPattern> top = store.topPatterns("vuln.app", 5);
        assertThat(top).extracting(PatternStore.SuccessPattern::vulnType)
                .containsExactly("IDOR", "SQLi")
                .doesNotContain("XSS");
    }

    @Test
    void persistsAcrossInstances() {
        PatternStore store = store();
        store.recordConfirmations(entry("/api/users/1001", "vuln.app"),
                verdict(new ConfirmedVuln("IDOR", "越权读", "e", "payload-a", "r", "v")));

        // Fresh instance over the same file reloads the pattern (hits intact).
        PatternStore reloaded = store();
        assertThat(reloaded.size()).isEqualTo(1);
        assertThat(reloaded.topPatterns("vuln.app", 5)).singleElement()
                .satisfies(p -> {
                    assertThat(p.vulnType()).isEqualTo("IDOR");
                    assertThat(p.hits()).isEqualTo(1);
                    assertThat(p.technique()).isEqualTo("越权读");
                });
    }

    @Test
    void promptSectionMentionsPatternsAndStaysEmptyWhenNothingUseful() {
        PatternStore store = store();
        ApiEntry target = entry("/api/orders/5001", "vuln.app");
        assertThat(store.buildPromptSection(target, 5)).isEmpty();

        store.recordConfirmations(entry("/api/users/1001", "vuln.app"),
                verdict(new ConfirmedVuln("IDOR", "越权读", "e", "GET /api/users/1001 (session B)", "r", "v")));
        store.recordConfirmations(entry("/api/users/1001", "vuln.app"),
                verdict(new ConfirmedVuln("IDOR", "越权读", "e", "GET /api/users/1001 (session B)", "r", "v")));

        String section = store.buildPromptSection(target, 5);
        assertThat(section).contains("历史成功模式");
        assertThat(section).contains("IDOR");
        assertThat(section).contains("命中 2 次");
        assertThat(section).contains("payload 预览");
        // Anti-hallucination caveat is part of every injected section.
        assertThat(section).contains("不是本次的结论");
    }

    @Test
    void payloadPreviewIsTruncated() {
        PatternStore store = store();
        String longPayload = "x".repeat(300);
        store.recordConfirmations(entry("/api/users/1", "d"),
                verdict(new ConfirmedVuln("IDOR", "t", "e", longPayload, "r", "v")));

        assertThat(store.topPatterns("d", 5)).singleElement()
                .satisfies(p -> assertThat(p.payloadPreview()).hasSizeLessThanOrEqualTo(83)); // 80 + "..."
    }
}
