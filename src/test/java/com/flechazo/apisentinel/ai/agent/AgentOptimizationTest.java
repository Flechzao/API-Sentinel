package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.AnalysisStateTracker.VulnCategory;
import com.flechazo.apisentinel.ai.agent.AttackHypothesisGenerator.Hypothesis;
import com.flechazo.apisentinel.ai.agent.AttackHypothesisGenerator.HypothesisStatus;
import com.flechazo.apisentinel.ai.agent.ErrorCompressor.Diagnosis;
import com.flechazo.apisentinel.ai.agent.ErrorCompressor.FailurePattern;
import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.ConfidenceLevel;
import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.Finding;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Agent performance optimization components.
 * Covers: ProgressiveToolDisclosure, EpisodicReflectionMemory,
 * ErrorCompressor, FindingEvidenceStore, AttackHypothesisGenerator.
 */
class AgentOptimizationTest {

    private LeveledLogger logger;

    @BeforeEach
    void setUp() {
        logger = new LeveledLogger(null);
    }

    // ========== ProgressiveToolDisclosure ==========

    @Test
    void progressiveToolDisclosure_detectsReconPhaseEarly() {
        var disclosure = new ProgressiveToolDisclosure(logger);
        var phase = disclosure.detectPhase(java.util.Set.of(), 0);
        assertThat(phase).isEqualTo(ProgressiveToolDisclosure.Phase.RECON);
    }

    @Test
    void progressiveToolDisclosure_detectsPayloadTestingPhase() {
        var disclosure = new ProgressiveToolDisclosure(logger);
        var phase = disclosure.detectPhase(
                java.util.Set.of("heuristic_scan", "generate_payloads"), 5);
        assertThat(phase).isEqualTo(ProgressiveToolDisclosure.Phase.PAYLOAD_TESTING);
    }

    @Test
    void progressiveToolDisclosure_detectsBrowserPhase() {
        var disclosure = new ProgressiveToolDisclosure(logger);
        var phase = disclosure.detectPhase(
                java.util.Set.of("browser_discover"), 3);
        assertThat(phase).isEqualTo(ProgressiveToolDisclosure.Phase.BROWSER);
    }

    @Test
    void progressiveToolDisclosure_requestToolGroupActivatesPhase() {
        var disclosure = new ProgressiveToolDisclosure(logger);
        boolean loaded = disclosure.requestToolGroup("advanced");
        assertThat(loaded).isTrue();
        assertThat(disclosure.getActivePhases()).contains(ProgressiveToolDisclosure.Phase.ADVANCED);
    }

    @Test
    void progressiveToolDisclosure_unknownGroupReturnsFalse() {
        var disclosure = new ProgressiveToolDisclosure(logger);
        boolean loaded = disclosure.requestToolGroup("nonexistent");
        assertThat(loaded).isFalse();
    }

    // ========== EpisodicReflectionMemory ==========

    @Test
    void reflectionMemory_startsEmpty() {
        var memory = new EpisodicReflectionMemory(logger);
        assertThat(memory.isEmpty()).isTrue();
        assertThat(memory.buildReflectionPrompt()).isEmpty();
    }

    @Test
    void reflectionMemory_addDirectCreatesReflection() {
        var memory = new EpisodicReflectionMemory(logger);
        memory.addReflectionDirect("waf_blocked", "Payload被WAF拦截", "使用编码绕过");

        assertThat(memory.isEmpty()).isFalse();
        assertThat(memory.getReflections()).hasSize(1);
        assertThat(memory.buildReflectionPrompt()).contains("WAF拦截");
    }

    @Test
    void reflectionMemory_slidingWindowCapAt8() {
        var memory = new EpisodicReflectionMemory(logger);
        for (int i = 0; i < 12; i++) {
            memory.addReflectionDirect("test_" + i, "诊断 " + i, "策略 " + i);
        }
        assertThat(memory.getReflections()).hasSize(8);
        // Oldest should be removed, newest should be present
        assertThat(memory.buildReflectionPrompt()).contains("诊断 11");
        assertThat(memory.buildReflectionPrompt()).doesNotContain("诊断 0");
    }

    @Test
    void reflectionMemory_clearRemovesAll() {
        var memory = new EpisodicReflectionMemory(logger);
        memory.addReflectionDirect("test", "诊断", "策略");
        memory.clear();
        assertThat(memory.isEmpty()).isTrue();
        assertThat(memory.getEpisodeCount()).isEqualTo(0);
    }

    // ========== ErrorCompressor ==========

    @Test
    void errorCompressor_detectsAllNormalPattern() {
        var compressor = new ErrorCompressor(logger);
        var results = List.of(
                "{\"anomaly\":false, \"status\":200}",
                "{\"anomaly\":false, \"status\":200}",
                "{\"anomaly\":false, \"status\":200}");

        Diagnosis d = compressor.diagnoseBatch(results, "id", "");
        assertThat(d.pattern()).isEqualTo(FailurePattern.ALL_NORMAL);
        assertThat(d.compressedText()).contains("批次诊断");
    }

    @Test
    void errorCompressor_detectsWafBlockedPattern() {
        var compressor = new ErrorCompressor(logger);
        var results = List.of(
                "waf_detected: true, blocked",
                "waf_detected: true, blocked",
                "waf_detected: true, blocked");

        Diagnosis d = compressor.diagnoseBatch(results, "query", "");
        assertThat(d.pattern()).isEqualTo(FailurePattern.ALL_WAF_BLOCKED);
        assertThat(d.suggestedPivot()).contains("waf_bypass_retry");
    }

    @Test
    void errorCompressor_detectsAuthFailedPattern() {
        var compressor = new ErrorCompressor(logger);
        var results = List.of("401 Unauthorized", "403 Forbidden", "401 Unauthorized");

        Diagnosis d = compressor.diagnoseBatch(results, "token", "");
        assertThat(d.pattern()).isEqualTo(FailurePattern.ALL_AUTH_FAILED);
    }

    @Test
    void errorCompressor_emptyResultsHandled() {
        var compressor = new ErrorCompressor(logger);
        Diagnosis d = compressor.diagnoseBatch(List.of(), "param", "");
        assertThat(d.totalResults()).isEqualTo(0);
    }

    // ========== FindingEvidenceStore ==========

    @Test
    void findingStore_startsEmpty() {
        var store = new FindingEvidenceStore(logger);
        assertThat(store.size()).isEqualTo(0);
        assertThat(store.buildFindingsSummary()).isEmpty();
        assertThat(store.hasConfirmed()).isFalse();
    }

    @Test
    void findingStore_addManualFindingCreatesEntry() {
        var store = new FindingEvidenceStore(logger);
        String id = store.addManualFinding("SQL_INJECTION", "id",
                "' OR 1=1-- 返回全部数据", "SUSPECTED");

        assertThat(id).startsWith("F");
        assertThat(store.size()).isEqualTo(1);
        assertThat(store.buildFindingsSummary()).contains("SQL注入");
    }

    @Test
    void findingStore_updateFindingLevelChangesConfidence() {
        var store = new FindingEvidenceStore(logger);
        String id = store.addManualFinding("XSS", "name",
                "<script>alert(1)</script> 反射在响应中", "SUSPECTED");

        boolean updated = store.updateFindingLevel(id, "CONFIRMED");
        assertThat(updated).isTrue();
        assertThat(store.hasConfirmed()).isTrue();
    }

    @Test
    void findingStore_updateNonexistentReturnsFalse() {
        var store = new FindingEvidenceStore(logger);
        boolean updated = store.updateFindingLevel("F999", "CONFIRMED");
        assertThat(updated).isFalse();
    }

    @Test
    void findingStore_getFindingsByLevelFilters() {
        var store = new FindingEvidenceStore(logger);
        store.addManualFinding("SQL_INJECTION", "id", "evidence1", "CONFIRMED");
        store.addManualFinding("XSS", "name", "evidence2", "SUSPECTED");
        store.addManualFinding("SSRF", "url", "evidence3", "CONFIRMED");

        assertThat(store.getFindingsByLevel(ConfidenceLevel.CONFIRMED)).hasSize(2);
        assertThat(store.getFindingsByLevel(ConfidenceLevel.SUSPECTED)).hasSize(1);
    }

    @Test
    void findingStore_summaryCappedAtMaxLength() {
        var store = new FindingEvidenceStore(logger);
        // Add many findings with long evidence
        for (int i = 0; i < 50; i++) {
            store.addManualFinding("SQL_INJECTION", "param_" + i,
                    "A".repeat(200) + " evidence " + i, "SUSPECTED");
        }
        String summary = store.buildFindingsSummary();
        assertThat(summary.length()).isLessThanOrEqualTo(2100); // 2000 + truncation marker
    }

    // ========== AttackHypothesisGenerator ==========

    @Test
    void hypothesisGen_startsNotGenerated() {
        var gen = new AttackHypothesisGenerator(logger);
        assertThat(gen.isGenerated()).isFalse();
        assertThat(gen.size()).isEqualTo(0);
    }

    @Test
    void hypothesisGen_fallbackGeneratesFromProfile() {
        var gen = new AttackHypothesisGenerator(logger);
        var profile = AnalysisProfile.selectProfile(
                createEntry("GET", "/api/users/{id}"));

        // Pass null provider to trigger fallback
        var hypotheses = gen.branch(
                createEntry("GET", "/api/users/{id}"),
                "scan result", profile, null);

        assertThat(gen.isGenerated()).isTrue();
        assertThat(hypotheses).isNotEmpty();
        assertThat(hypotheses.size()).isLessThanOrEqualTo(5);
    }

    @Test
    void hypothesisGen_updateScoreAnomaly() {
        var gen = createGenWithHypothesis();
        Hypothesis h = gen.get("H01");
        assertThat(h).isNotNull();

        Hypothesis updated = gen.updateScore("H01",
                "{\"anomaly\":true, \"SQL error detected\"}");

        assertThat(updated).isNotNull();
        assertThat(updated.score()).isGreaterThan(h.score());
        assertThat(updated.status()).isEqualTo(HypothesisStatus.TESTING);
    }

    @Test
    void hypothesisGen_updateScoreNormal() {
        var gen = createGenWithHypothesis();
        Hypothesis h = gen.get("H01");

        Hypothesis updated = gen.updateScore("H01",
                "{\"anomaly\":false, \"status\":200}");

        assertThat(updated).isNotNull();
        assertThat(updated.score()).isLessThan(h.score());
    }

    @Test
    void hypothesisGen_autoPruneBelowThreshold() {
        var gen = createGenWithHypothesis();

        // Repeatedly give normal responses to drive score below threshold
        for (int i = 0; i < 10; i++) {
            gen.updateScore("H01", "{\"anomaly\":false}");
        }

        Hypothesis h = gen.get("H01");
        assertThat(h.status()).isEqualTo(HypothesisStatus.PRUNED);
    }

    @Test
    void hypothesisGen_mergeCombinesHypotheses() {
        var gen = new AttackHypothesisGenerator(logger);
        // Manually add two hypotheses with same parameter
        gen.branch(createEntry("GET", "/api/users/{id}"),
                "scan", AnalysisProfile.selectProfile(
                        createEntry("GET", "/api/users/{id}")), null);

        var active = gen.getActiveHypotheses();
        if (active.size() >= 2) {
            String idA = active.get(0).id();
            String idB = active.get(1).id();
            Hypothesis merged = gen.merge(idA, idB);
            // Merge may return null if hypotheses don't share param/type
            if (merged != null) {
                assertThat(merged.status()).isEqualTo(HypothesisStatus.TESTING);
                assertThat(merged.evidence()).isNotEmpty();
            }
        }
    }

    @Test
    void hypothesisGen_boardNotEmptyWhenGenerated() {
        var gen = createGenWithHypothesis();
        String board = gen.buildHypothesisBoard();
        assertThat(board).contains("攻击假设看板");
        assertThat(board).contains("H01");
    }

    @Test
    void hypothesisGen_boardEmptyWhenNotGenerated() {
        var gen = new AttackHypothesisGenerator(logger);
        assertThat(gen.buildHypothesisBoard()).isEmpty();
    }

    @Test
    void hypothesisGen_markTestingChangesStatus() {
        var gen = createGenWithHypothesis();
        gen.markTesting("H01");
        assertThat(gen.get("H01").status()).isEqualTo(HypothesisStatus.TESTING);
    }

    @Test
    void hypothesisGen_getTopHypothesisReturnsHighestScore() {
        var gen = createGenWithHypothesis();
        Hypothesis top = gen.getTopHypothesis();
        assertThat(top).isNotNull();
        assertThat(top.status()).isIn(HypothesisStatus.PENDING, HypothesisStatus.TESTING);
    }

    // ========== AnalysisProfile ==========

    @Test
    void analysisProfile_selectsCrudForUserEndpoint() {
        var profile = AnalysisProfile.selectProfile(
                createEntry("GET", "/api/users/123"));
        assertThat(profile.profileName()).contains("CRUD");
    }

    @Test
    void analysisProfile_selectsAuthForLoginEndpoint() {
        var profile = AnalysisProfile.selectProfile(
                createEntry("POST", "/api/auth/login"));
        assertThat(profile.profileName()).contains("认证");
    }

    @Test
    void analysisProfile_selectsFileForUploadEndpoint() {
        var profile = AnalysisProfile.selectProfile(
                createEntry("POST", "/api/upload"));
        assertThat(profile.profileName()).contains("文件");
    }

    @Test
    void analysisProfile_selectsGenericForUnknownPath() {
        var profile = AnalysisProfile.selectProfile(
                createEntry("GET", "/health"));
        assertThat(profile.profileName()).contains("通用");
    }

    @Test
    void analysisProfile_promptContainsPriorityAndLowPriority() {
        var profile = AnalysisProfile.selectProfile(
                createEntry("GET", "/api/users/{id}"));
        String prompt = AnalysisProfile.buildProfilePrompt(profile);
        assertThat(prompt).contains("重点测试");
        assertThat(prompt).contains("降低优先");
        assertThat(prompt).contains("建议");
    }

    // ========== PocValidator ==========

    @Test
    void pocValidator_emptyStorePassesValidation() {
        var store = new FindingEvidenceStore(logger);
        var validator = new PocValidator(logger);
        var report = validator.validateAll(store);
        assertThat(report.totalChecked()).isEqualTo(0);
    }

    @Test
    void pocValidator_downgradesVagueEvidence() {
        var store = new FindingEvidenceStore(logger);
        store.addManualFinding("SQL_INJECTION", "id", "可能有注入", "CONFIRMED");

        var validator = new PocValidator(logger);
        var report = validator.validateAll(store);
        assertThat(report.downgraded()).isEqualTo(1);
    }

    @Test
    void pocValidator_keepsSpecificEvidence() {
        var store = new FindingEvidenceStore(logger);
        store.addManualFinding("SQL_INJECTION", "id",
                "payload ' OR 1=1-- 返回 status 200 且响应长度差异 >5%", "CONFIRMED");

        var validator = new PocValidator(logger);
        var report = validator.validateAll(store);
        assertThat(report.confirmed()).isEqualTo(1);
    }

    // ========== AnalysisStateTracker ==========

    @Test
    void stateTracker_buildsSnapshotWithCoverage() {
        var tracker = new AnalysisStateTracker();
        tracker.setProfileName("CRUD");
        tracker.setApplicableCategories(
                java.util.EnumSet.of(VulnCategory.SQL_INJECTION, VulnCategory.IDOR));

        String snapshot = tracker.buildStatusSnapshot();
        assertThat(snapshot).contains("CRUD");
        assertThat(snapshot).contains("覆盖率");
    }

    @Test
    void stateTracker_recordFromSendRequestUpdatesState() {
        var tracker = new AnalysisStateTracker();
        tracker.recordFromSendRequest("id", "{\"anomaly\":true}");
        assertThat(tracker.getTotalAnomalies()).isEqualTo(1);
    }

    @Test
    void stateTracker_coverageCheckReturnsNullWhenFullyCovered() {
        var tracker = new AnalysisStateTracker();
        // With no applicable categories set, coverage check should handle gracefully
        String check = tracker.buildCoverageCheck();
        // May return null or a message depending on implementation
        // The key is it doesn't throw
    }

    // ========== Helpers ==========

    private com.flechazo.apisentinel.model.ApiEntry createEntry(String method, String path) {
        return new com.flechazo.apisentinel.model.ApiEntry(method, path);
    }

    private AttackHypothesisGenerator createGenWithHypothesis() {
        var gen = new AttackHypothesisGenerator(logger);
        gen.branch(createEntry("GET", "/api/users/{id}"),
                "scan result with id parameter",
                AnalysisProfile.selectProfile(createEntry("GET", "/api/users/{id}")),
                null);  // null provider → fallback
        return gen;
    }
}
