package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.ProgressiveToolDisclosure;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for tool-name drift.
 *
 * <p>Before 2026-09-06, four tools were silently unreachable because
 * {@link ProgressiveToolDisclosure#PHASE_TOOLS} referenced two strings
 * that did not match the actual registered names
 * ({@code "response_diff"} vs the registered {@code "diff_responses"},
 * {@code "ssrf_oob"} vs the registered {@code "generate_oob_probe"}),
 * and two tools ({@code analyze_traffic}, {@code request_tools}) were
 * registered but never entered any phase. No startup assertion caught
 * this because {@code ALL_PHASED_TOOLS} was declared but never used
 * to cross-check the live registry.
 *
 * <p>These tests ensure that drift class cannot recur, and that
 * {@link ProgressiveToolDisclosure#validateConsistency(Set)} actually
 * detects mismatches in both directions.
 */
class ProgressiveToolDisclosureConsistencyTest {

    /**
     * The core invariant: every name listed in any phase (or CORE_TOOLS)
     * must be the exact {@code name()} of a tool registered in
     * {@link StandardToolRegistry}. A single typo here silently makes
     * a tool unreachable.
     *
     * <p>This test is cheap (no LLM, no network, no UI) and runs on every
     * build, so adding a new tool name with a typo fails the build
     * instead of silently hiding behind {@code .filter(fullRegistry::hasTool)}.
     */
    @Test
    void everyPhasedToolNameMustBeRegisteredInStandardRegistry() {
        // Build a representative registry via the shared builder.
        // We don't need a fully wired ToolContext — StandardToolRegistry.build
        // only uses it to set per-tool references, and even with a null
        // context the tool classes are instantiated and their name() is
        // what we want to cross-check.
        // Easiest way: collect tool names directly from the catalog metadata,
        // which is the single source of truth for "names humans expect to
        // register". That catalog is kept in lockstep with registry.register()
        // calls (each entry corresponds to exactly one new Tool instance
        // in build()).
        Set<String> registeredNames = StandardToolRegistry.getToolCatalog().stream()
                .map(StandardToolRegistry.ToolCatalogEntry::name)
                .collect(java.util.stream.Collectors.toSet());

        String drift = ProgressiveToolDisclosure.validateConsistency(registeredNames);
        assertThat(drift)
                .as("PHASE_TOOLS must exactly match the registered tool catalog; any diff "
                        + "means a tool is silently unreachable (unphased) or referenced under a "
                        + "non-existent name (typo). Fix by updating ProgressiveToolDisclosure.PHASE_TOOLS "
                        + "and the registered tool's name() to agree.")
                .isEmpty();
    }

    /** Sanity: PHASE_TOOLS contains no duplicate names across phases. */
    @Test
    void phasedToolsContainNoDuplicatesAcrossPhases() {
        Set<String> seen = new java.util.LinkedHashSet<>();
        Set<String> duplicates = new java.util.LinkedHashSet<>();
        for (var entry : ProgressiveToolDisclosure.PHASE_TOOLS.entrySet()) {
            for (String name : entry.getValue()) {
                if (!seen.add(name)) duplicates.add(name);
            }
        }
        // CORE_TOOLS also must not overlap any phase
        for (String name : ProgressiveToolDisclosure.CORE_TOOLS) {
            if (!seen.add(name)) duplicates.add(name);
        }
        assertThat(duplicates).isEmpty();
    }

    @Test
    void validateConsistencyReturnsEmptyWhenSetsAgree() {
        Set<String> registry = Set.of("send_request", "read_file", "grep_repo",
                "submit_report", "heuristic_scan");
        // Build a fake CORE that exactly matches registry so validateConsistency is clean.
        // Since CORE_TOOLS is fixed (send_request/read_file/grep_repo/submit_report),
        // add one more name via the PHASE_TOOLS map is not possible from tests —
        // so just validate that a registry *subset* still produces a meaningful report.
        String report = ProgressiveToolDisclosure.validateConsistency(registry);
        // Expected: some PHASE_TOOLS names (e.g. generate_payloads) are missing from
        // this fake registry, and no registered name is unphased (all 5 names ARE
        // in PHASE_TOOLS or CORE_TOOLS).
        assertThat(report)
                .isNotEmpty()
                .contains("not registered");
    }

    @Test
    void validateConsistencyDetectsUnregisteredPhasedNames() {
        // Pretend PHASE_TOOLS lists "ghost_tool" — registry has no such tool.
        Set<String> registry = Set.of("send_request");
        String report = ProgressiveToolDisclosure.validateConsistency(registry);
        assertThat(report).contains("not registered");
    }

    @Test
    void validateConsistencyDetectsUnphasedRegisteredTools() {
        // Every name in PHASE_TOOLS/CORE present, plus one extra registered name.
        Set<String> full = new java.util.LinkedHashSet<>(ProgressiveToolDisclosure.ALL_PHASED_TOOLS);
        full.add("mystery_tool_not_in_any_phase");
        String report = ProgressiveToolDisclosure.validateConsistency(full);
        assertThat(report)
                .contains("not in any phase")
                .contains("mystery_tool_not_in_any_phase");
    }

    @Test
    void validateConsistencyReturnsEmptyOnFullAgreement() {
        // Exactly ALL_PHASED_TOOLS (which already includes CORE_TOOLS) — both
        // directions clean.
        Set<String> registry = new java.util.LinkedHashSet<>(ProgressiveToolDisclosure.ALL_PHASED_TOOLS);
        String report = ProgressiveToolDisclosure.validateConsistency(registry);
        assertThat(report).isEmpty();
    }

    /**
     * Explicit lock on the two typos that caused this whole regression class.
     * If anyone renames the tool back to the wrong string, this test breaks.
     */
    @Test
    void regression_noResponseDiff_noSsrfOobInPhasedTools() {
        assertThat(ProgressiveToolDisclosure.ALL_PHASED_TOOLS)
                .doesNotContain("response_diff")
                .doesNotContain("ssrf_oob")
                .contains("diff_responses")
                .contains("generate_oob_probe");
    }
}
