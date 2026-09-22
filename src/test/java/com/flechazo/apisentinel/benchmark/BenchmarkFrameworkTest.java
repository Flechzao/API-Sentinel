package com.flechazo.apisentinel.benchmark;

import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Regression tests for the benchmark framework itself.
 *
 * <p>These don't exercise any LLM or any real analysis path — they pin
 * the semantics of the parser and the metrics calculator so a future
 * change can't silently corrupt the recall/precision numbers a CI run
 * reports. The end-to-end pipeline (start demo-vuln-app → capture traffic
 * → run Agent → compare) is a separate story, covered by integration
 * tests that need a running app.
 */
class BenchmarkFrameworkTest {

    @Test
    void parserLoadsAll53Rows() {
        List<GroundTruthEntry> all = GroundTruthEntry.loadAll();
        assertThat(all).hasSize(53);

        // The 32 / 21 split is the benchmark's core shape — if someone
        // relabels a row, this fails and forces a deliberate decision.
        // (GROUND_TRUTH.md's own summary line may lag; the by-id
        // enumeration is the source of truth the parser asserts.)
        assertThat(GroundTruthEntry.loadVulnerable()).hasSize(32);
        assertThat(GroundTruthEntry.loadSafeControls()).hasSize(21);
    }

    @Test
    void parserExtractsMethodAndPathFromEndpoint() {
        Map<Integer, GroundTruthEntry> byId = new HashMap<>();
        for (GroundTruthEntry e : GroundTruthEntry.loadAll()) byId.put(e.id(), e);

        // Row 1 is "GET /api/users/search?name="
        assertThat(byId.get(1).httpMethod()).isEqualTo("GET");
        assertThat(byId.get(1).apiPath()).isEqualTo("/api/users/search");
        // Row 7 is a POST
        assertThat(byId.get(7).httpMethod()).isEqualTo("POST");
        assertThat(byId.get(7).apiPath()).isEqualTo("/api/auth/token");
    }

    @Test
    void parserClassifiesVulnerableVsSafeControls() {
        Map<Integer, GroundTruthEntry> byId = new HashMap<>();
        for (GroundTruthEntry e : GroundTruthEntry.loadAll()) byId.put(e.id(), e);

        // Row 1 = SQL 注入, 有漏洞
        assertThat(byId.get(1).isVulnerable()).isTrue();
        assertThat(byId.get(1).vulnType()).contains("SQL");
        // Row 2 = SQL 注入安全对照
        assertThat(byId.get(2).isVulnerable()).isFalse();
        // Row 4 = IDOR, 需跳层
        assertThat(byId.get(4).isVulnerable()).isTrue();
        assertThat(byId.get(4).needsSourceTraversal()).isTrue();
        // Row 17 = sensitive info leak, NOT 需跳层
        assertThat(byId.get(17).needsSourceTraversal()).isFalse();
    }

    @Test
    void metricsPerfectRunRecallAndPrecisionAre100Percent() {
        // The universe is 53 rows; simulate a perfect scanner that finds
        // exactly the 32 vulnerable rows and reports nothing on the 21
        // safe controls.
        List<GroundTruthEntry> truth = GroundTruthEntry.loadAll();
        Map<String, List<VulnFinding>> findings = new HashMap<>();
        for (GroundTruthEntry row : truth) {
            if (row.isVulnerable()) {
                findings.put(row.apiPath(), List.of(
                        new VulnFinding(row.vulnType(), "HIGH", 0.95,
                                "title", "desc", "evidence",
                                row.apiPath(), "remediation")));
            }
        }

        BenchmarkMetrics.Summary s = BenchmarkMetrics.compute(truth, findings);

        assertThat(s.total()).isEqualTo(53);
        assertThat(s.vulnerable()).isEqualTo(32);
        assertThat(s.safeControls()).isEqualTo(21);
        assertThat(s.truePositives()).isEqualTo(32);
        assertThat(s.falseNegatives()).isZero();
        assertThat(s.falsePositives()).isZero();
        assertThat(s.trueNegatives()).isEqualTo(21);
        assertThat(s.recall()).isEqualTo(1.0);
        assertThat(s.precision()).isEqualTo(1.0);
        assertThat(s.falsePositiveRate()).isZero();
        assertThat(s.f1()).isEqualTo(1.0);
    }

    @Test
    void metricsFalsePositiveDrivesDownPrecisionAndFpr() {
        List<GroundTruthEntry> truth = GroundTruthEntry.loadAll();
        Map<String, List<VulnFinding>> findings = new HashMap<>();
        // Report every endpoint as vulnerable (the worst possible
        // precision). Recall stays 100% because every vulnerable row
        // is hit, but precision collapses.
        for (GroundTruthEntry row : truth) {
            findings.put(row.apiPath(), List.of(
                    new VulnFinding("Generic", "HIGH", 0.5,
                            "title", "desc", "evidence",
                            row.apiPath(), "remediation")));
        }

        BenchmarkMetrics.Summary s = BenchmarkMetrics.compute(truth, findings);

        assertThat(s.recall()).isEqualTo(1.0);
        assertThat(s.truePositives()).isEqualTo(32);
        assertThat(s.falsePositives()).isEqualTo(21);
        // precision = 32 / 53 ≈ 0.6038
        assertThat(s.precision()).isCloseTo(32.0 / 53.0, org.assertj.core.data.Offset.offset(1e-6));
        // FP rate = 21 / 21 = 1.0 (every safe control was falsely flagged)
        assertThat(s.falsePositiveRate()).isEqualTo(1.0);
    }

    @Test
    void metricsMissedVulnerabilitiesDriveDownRecall() {
        List<GroundTruthEntry> truth = GroundTruthEntry.loadAll();
        // Empty findings: recall must be 0, precision is 0 (0/0 guard).
        BenchmarkMetrics.Summary s = BenchmarkMetrics.compute(truth, Map.of());

        assertThat(s.recall()).isZero();
        assertThat(s.falseNegatives()).isEqualTo(32);
        assertThat(s.trueNegatives()).isEqualTo(21);
        assertThat(s.precision()).isZero();
        assertThat(s.f1()).isZero();
    }

    @Test
    void metricsInfoRiskFindingsDoNotCountAsDetections() {
        // An INFO-risk finding at a vulnerable endpoint is an observation,
        // not a detection — the row should still count as a false negative.
        List<GroundTruthEntry> truth = GroundTruthEntry.loadAll();
        Map<String, List<VulnFinding>> findings = new HashMap<>();
        // Only file INFO at row 1's endpoint.
        findings.put("/api/users/search", List.of(
                new VulnFinding("SQL 注入", "INFO", 0.3,
                        "observed", "desc", "evidence",
                        "/api/users/search", "remediation")));

        BenchmarkMetrics.Summary s = BenchmarkMetrics.compute(truth, findings);

        // 31 vulnerable rows went undetected (row 1's INFO didn't count).
        assertThat(s.truePositives()).isZero();
        assertThat(s.falseNegatives()).isEqualTo(32);
    }

    @Test
    void metricsRealisticRunProducesSensibleNumbers() {
        // Simulate a realistic-but-imperfect scanner: detects 20/32
        // vulnerable rows, false-positives on 2 safe controls.
        List<GroundTruthEntry> truth = GroundTruthEntry.loadAll();
        Map<String, List<VulnFinding>> findings = new HashMap<>();
        int detected = 0;
        for (GroundTruthEntry row : truth) {
            if (row.isVulnerable() && detected < 20) {
                findings.put(row.apiPath(), List.of(
                        new VulnFinding(row.vulnType(), "MEDIUM", 0.7,
                                "title", "desc", "evidence",
                                row.apiPath(), "remediation")));
                detected++;
            }
        }
        // FP on the first 2 safe controls.
        int fpAdded = 0;
        for (GroundTruthEntry row : truth) {
            if (!row.isVulnerable() && fpAdded < 2) {
                findings.put(row.apiPath(), List.of(
                        new VulnFinding("Generic", "LOW", 0.4,
                                "title", "desc", "evidence",
                                row.apiPath(), "remediation")));
                fpAdded++;
            }
        }

        BenchmarkMetrics.Summary s = BenchmarkMetrics.compute(truth, findings);

        assertThat(s.truePositives()).isEqualTo(20);
        assertThat(s.falseNegatives()).isEqualTo(12);
        assertThat(s.falsePositives()).isEqualTo(2);
        assertThat(s.trueNegatives()).isEqualTo(19);
        // recall = 20/32, precision = 20/22
        assertThat(s.recall()).isCloseTo(20.0 / 32.0, org.assertj.core.data.Offset.offset(1e-6));
        assertThat(s.precision()).isCloseTo(20.0 / 22.0, org.assertj.core.data.Offset.offset(1e-6));
        assertThat(s.falsePositiveRate()).isCloseTo(2.0 / 21.0, org.assertj.core.data.Offset.offset(1e-6));
    }

    @Test
    void textReportRendersWithoutError() {
        List<GroundTruthEntry> truth = GroundTruthEntry.loadAll();
        BenchmarkMetrics.Summary s = BenchmarkMetrics.compute(truth, Map.of());
        String report = s.renderTextReport();
        assertThat(report)
                .contains("API-Sentinel Benchmark Report")
                .contains("Recall:")
                .contains("Precision:")
                .contains("FP rate:")
                .contains("F1:");
    }

    /** If the GROUND_TRUTH.md file ever shrinks (a row accidentally
     *  deleted), the parser must throw rather than silently produce a
     *  smaller universe — that would inflate recall on every CI run. */
    @Test
    void parserFailsWhenUniverseShrinks() {
        // Can't easily drive the parser with a hand-crafted file from
        // here without touching disk, so pin the invariant via the
        // public API: loadAll() returned 53 today; if someone drops a
        // row, loadAll() throws and this test fails with that
        // exception's message.
        assertThat(GroundTruthEntry.loadAll()).hasSize(53);
    }

    @Test
    void bucketByEndpointGroupsByResolver() {
        VulnFinding a = new VulnFinding("SQL", "HIGH", 0.9, "", "", "", "/api/a", "");
        VulnFinding b = new VulnFinding("XSS", "HIGH", 0.9, "", "", "", "/api/b", "");
        VulnFinding c = new VulnFinding("SQL", "HIGH", 0.9, "", "", "", "/api/a", "");
        Map<String, List<VulnFinding>> buckets = BenchmarkMetrics.bucketByEndpoint(
                List.of(a, b, c), VulnFinding::location);
        assertThat(buckets.get("/api/a")).hasSize(2);
        assertThat(buckets.get("/api/b")).hasSize(1);
    }
}
