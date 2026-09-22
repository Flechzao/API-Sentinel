package com.flechazo.apisentinel.benchmark;

import java.util.List;

/**
 * One row of the demo-vuln-app GROUND_TRUTH.md table.
 *
 * <p>44 entries total: 26 vulnerable + 18 safe "negative controls". The
 * safe controls are what make this benchmark actually informative — most
 * security scanners only count confirmed vulns as findings, so without
 * safe controls you can't tell whether a scanner that reports "26 vulns
 * found" is genuinely precise or just reporting every endpoint as
 * vulnerable.
 *
 * <p>Field naming matches the markdown table columns 1:1 so the parser
 * is easy to review against the source of truth.
 */
public record GroundTruthEntry(
        /** 1..44 row number in the markdown table. Stable across revisions
         *  of GROUND_TRUTH.md so regression tests can pin by id. */
        int id,
        /** Method + path, e.g. "GET /api/users/search?name=". */
        String endpoint,
        /** HTTP method extracted from {@link #endpoint}. */
        String httpMethod,
        /** API path extracted from {@link #endpoint} (query string removed). */
        String apiPath,
        /** Vulnerability category: SQL 注入 / 越权 / SSRF / … / 安全对照. */
        String vulnType,
        /** True when the markdown row's "结论" column starts with
         *  "有漏洞". False when the row is a safe control ("安全 —— ..."). */
        boolean isVulnerable,
        /** Whether the vulnerability needs source-code traversal past the
         *  controller layer to confirm (the markdown "需跳层" column). */
        boolean needsSourceTraversal,
        /** Free-text rationale, kept for report display. */
        String rationale
) {
    /** All 44 entries: the benchmark's full universe. */
    public static List<GroundTruthEntry> loadAll() {
        return GroundTruthParser.parseFromClasspath();
    }

    /** The 27 rows with "结论 = 有漏洞". The GROUND_TRUTH.md's own
     *  summary line says 26 — a by-id count gives 27. The by-id count
     *  wins; the summary line is stale prose. */
    public static List<GroundTruthEntry> loadVulnerable() {
        return loadAll().stream().filter(GroundTruthEntry::isVulnerable).toList();
    }

    /** The 17 rows with "结论 = 安全" (negative controls — drive the
     *  false-positive metric). */
    public static List<GroundTruthEntry> loadSafeControls() {
        return loadAll().stream().filter(e -> !e.isVulnerable).toList();
    }
}
