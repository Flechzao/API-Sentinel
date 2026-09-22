package com.flechazo.apisentinel.benchmark;

import com.flechazo.apisentinel.ai.analysis.VulnFinding;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Computes recall / precision / false-positive rate for one benchmark run.
 *
 * <p>Matching a {@link VulnFinding} to a {@link GroundTruthEntry} is
 * intentionally <b>endpoint-scoped and type-tolerant</b>:
 *
 * <ul>
 *   <li>A finding hits a ground-truth row when the finding's endpoint
 *       (or the closest {@code apiPath} match the caller can give us)
 *       equals the row's path.</li>
 *   <li>A hit is a <b>true positive</b> iff the row is vulnerable AND
 *       the finding's risk is not INFO/NONE. A hit on a safe row is a
 *       <b>false positive</b>. A vulnerable row with no hit is a
 *       <b>false negative</b>.</li>
 *   <li>Vuln-type (SQL/XSS/IDOR/...) is <i>not</i> part of the match —
 *       the LLM often picks a sibling category (e.g. "Auth Bypass" for
 *       an IDOR), and penalising that would conflate category accuracy
 *       with detection accuracy. A separate "category accuracy" metric
 *       can be added on top when needed.</li>
 * </ul>
 */
public final class BenchmarkMetrics {

    /** One row's verdict in a benchmark run. Kept public so reporters and
     *  tests can iterate outcomes. */
    public record Outcome(
            GroundTruthEntry entry,
            boolean detected,
            /** Category label of the matching finding, or null when
             *  {@code detected == false}. */
            String matchedAsType,
            /** Risk the finding was filed under, or null. */
            String matchedRisk
    ) {}

    public record Summary(
            int total,
            int vulnerable,
            int safeControls,
            int truePositives,
            int falseNegatives,
            int falsePositives,
            int trueNegatives,
            double recall,
            double precision,
            double falsePositiveRate,
            double f1,
            List<Outcome> outcomes
    ) {
        /** Render a human-readable one-pager. Used both for console output
         *  (so the dev can eyeball a run) and as the body of the CI report
         *  artifact. */
        public String renderTextReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== API-Sentinel Benchmark Report ===\n");
            sb.append(String.format(Locale.ROOT,
                    "Total endpoints: %d  (vulnerable: %d, safe controls: %d)%n",
                    total, vulnerable, safeControls));
            sb.append(String.format(Locale.ROOT,
                    "Recall:    %.1f%%  (TP=%d / FN=%d)%n",
                    recall * 100, truePositives, falseNegatives));
            sb.append(String.format(Locale.ROOT,
                    "Precision: %.1f%%  (TP=%d / FP=%d)%n",
                    precision * 100, truePositives, falsePositives));
            sb.append(String.format(Locale.ROOT,
                    "FP rate:   %.1f%%  (FP=%d / TN+FP=%d)%n",
                    falsePositiveRate * 100, falsePositives, trueNegatives + falsePositives));
            sb.append(String.format(Locale.ROOT, "F1:        %.3f%n", f1));
            sb.append("\n--- Per-row outcomes ---\n");
            for (Outcome o : outcomes) {
                String status;
                if (o.entry.isVulnerable()) {
                    status = o.detected ? "TP" : "FN";
                } else {
                    status = o.detected ? "FP" : "TN";
                }
                sb.append(String.format(Locale.ROOT,
                        "  #%02d [%s] %-8s %s%n",
                        o.entry.id(), status, o.entry.httpMethod(), o.entry.endpoint()));
                if (o.detected && o.matchedAsType() != null) {
                    sb.append(String.format(Locale.ROOT,
                            "         detected-as: %s (%s)%n",
                            o.matchedAsType(), o.matchedRisk()));
                }
            }
            return sb.toString();
        }
    }

    /** Compute metrics for one run.
     *
     *  @param groundTruth the full 44-row benchmark universe.
     *  @param findingsByEndpoint findings keyed by apiPath (no query
     *         string, no method). Callers bucket their VulnFinding list
     *         by {@code VulnFinding.location} or equivalent; passing the
     *         same finding under multiple paths is allowed and counted
     *         once per row. */
    public static Summary compute(List<GroundTruthEntry> groundTruth,
                                  Map<String, List<VulnFinding>> findingsByEndpoint) {
        List<Outcome> outcomes = new ArrayList<>();
        int tp = 0, fn = 0, fp = 0, tn = 0;

        for (GroundTruthEntry row : groundTruth) {
            // Lookup by apiPath first, fall back to full endpoint (with
            // query) for endpoints whose path alone isn't unique.
            List<VulnFinding> hits = findingsByEndpoint.getOrDefault(row.apiPath(), List.of());
            if (hits.isEmpty() && !row.endpoint().equals(row.apiPath())) {
                hits = findingsByEndpoint.getOrDefault(row.endpoint(), List.of());
            }

            // A finding "detects" the row if it's filed at this endpoint
            // with a non-informational risk. Findings filed at INFO are
            // observations, not detections — they don't count as TP/FP.
            VulnFinding detection = hits.stream()
                    .filter(f -> f.risk() != null
                            && !"INFO".equalsIgnoreCase(f.risk())
                            && !"NONE".equalsIgnoreCase(f.risk()))
                    .findFirst()
                    .orElse(null);
            boolean detected = detection != null;

            if (row.isVulnerable()) {
                if (detected) { tp++; } else { fn++; }
            } else {
                if (detected) { fp++; } else { tn++; }
            }
            outcomes.add(new Outcome(row, detected,
                    detected ? detection.type() : null,
                    detected ? detection.risk() : null));
        }

        int vuln = tp + fn;
        int safe = fp + tn;
        double recall = vuln == 0 ? 0 : (double) tp / vuln;
        double precision = (tp + fp) == 0 ? 0 : (double) tp / (tp + fp);
        double fpr = safe == 0 ? 0 : (double) fp / safe;
        double f1 = (recall + precision) == 0
                ? 0
                : 2 * recall * precision / (recall + precision);
        return new Summary(groundTruth.size(), vuln, safe, tp, fn, fp, tn,
                recall, precision, fpr, f1, Collections.unmodifiableList(outcomes));
    }

    /** Convenience: bucket a flat VulnFinding list by a caller-supplied
     *  "endpoint-of-finding" resolver. Most callers have the apiPath on
     *  {@code VulnFinding.location()} in some form; the resolver is the
     *  one line that knows how that string is shaped. */
    public static Map<String, List<VulnFinding>> bucketByEndpoint(
            List<VulnFinding> findings,
            java.util.function.Function<VulnFinding, String> endpointOf) {
        return findings.stream().collect(Collectors.groupingBy(
                f -> {
                    String ep = endpointOf.apply(f);
                    return ep == null ? "" : ep;
                }));
    }
}
