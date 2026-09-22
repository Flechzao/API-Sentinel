package com.flechazo.apisentinel.benchmark;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for {@code easyshop-app/GROUND_TRUTH.md}'s vulnerability table.
 *
 * <p>Intentionally strict: if the table format drifts, this parser
 * <b>fails</b> rather than silently skipping rows. That's the point —
 * the ground truth is the benchmark's single source of truth, and a
 * silent skip would let recall drift undetected.
 *
 * <p>Expected row format (markdown table):
 * <pre>
 *   | # | 接口 | 类型 | 结论 | 需跳层 |
 *   |---|------|------|------|--------|
 *   | 1 | `GET /api/users/search?name=` | SQL 注入 | **有漏洞** —— ... | 否 |
 * </pre>
 */
public final class GroundTruthParser {

    /** Row-shape regex: captures the five columns of one markdown table
     *  row but does NOT try to interpret the endpoint column's content —
     *  that column may contain additional backticked code spans
     *  (e.g. {@code `Access-Control-Allow-Origin: *`}) further down the
     *  cell, and a greedy backtick match would terminate at the wrong
     *  position. We extract the endpoint in a separate step below. */
    private static final Pattern ROW = Pattern.compile(
            "^\\|\\s*(\\d+)\\s*\\|\\s*(.+?)\\s*\\|\\s*(.+?)\\s*\\|\\s*(.+?)\\s*\\|\\s*(.+?)\\s*\\|$");

    private GroundTruthParser() {}

    /** Load from {@code easyshop-app/GROUND_TRUTH.md} on disk. */
    public static List<GroundTruthEntry> parseFromFile(Path path) throws IOException {
        try (BufferedReader r = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return parseLines(r);
        }
    }

    /** Load from the JAR-bundled copy (test resources). */
    public static List<GroundTruthEntry> parseFromClasspath() {
        try (InputStream is = GroundTruthParser.class.getResourceAsStream("/benchmark/GROUND_TRUTH.md")) {
            if (is == null) {
                throw new IllegalStateException(
                        "Missing /benchmark/GROUND_TRUTH.md on classpath — copy "
                                + "easyshop-app/GROUND_TRUTH.md into src/test/resources/benchmark/ "
                                + "(or wire Gradle's processTestResources to include it).");
            }
            try (BufferedReader r = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                return parseLines(r);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read classpath GROUND_TRUTH.md", e);
        }
    }

    private static List<GroundTruthEntry> parseLines(BufferedReader reader) throws IOException {
        List<GroundTruthEntry> out = new ArrayList<>();
        String line;
        boolean inTable = false;
        while ((line = reader.readLine()) != null) {
            String trimmed = line.trim();

            // Detect a new table header (the file splits its 44 rows across
            // several consecutive tables, each starting with a `| # | 接口
            // | ...` header row). Must be checked BEFORE the "skip outside
            // table" guard below, since this IS the transition that flips
            // inTable to true.
            if (trimmed.startsWith("|") && trimmed.contains("接口")) {
                inTable = true;
                continue;
            }
            if (inTable && trimmed.startsWith("|---")) continue;

            // Blank lines / prose between the tables — skip, keep scanning
            // for the next table header rather than bailing out.
            if (!inTable) continue;
            // A non-`|` line while inTable. Two cases:
            //   * Blank line: the table's rows may continue after it (the
            //     file has a blank line between rows 20 and 21 with no
            //     header or separator in between). Stay in inTable=true
            //     and just skip — the next `|` line will parse as the next
            //     row.
            //   * Real prose (starts with a letter / # / etc.): the current
            //     table's region is over. Flip inTable off and let the
            //     next `| # | 接口 | ...` header flip it back on.
            if (!trimmed.startsWith("|")) {
                if (!trimmed.isEmpty()) {
                    inTable = false;
                }
                continue;
            }

            Matcher m = ROW.matcher(trimmed);
            if (!m.matches()) {
                throw new IOException("Malformed GROUND_TRUTH row: " + trimmed);
            }
            int id = Integer.parseInt(m.group(1));
            String endpointCell = m.group(2);
            String vulnType = m.group(3).trim();
            String conclusion = m.group(4).trim();
            String jumpLayer = m.group(5).trim();

            // The endpoint cell starts with a `METHOD /path` code span,
            // but some cells also carry trailing Chinese-annotation text
            // AND further inline code (e.g. "`Access-Control-Allow-Origin:
            // *`"). We extract ONLY the FIRST backticked span — that is
            // always the canonical endpoint.
            int btStart = endpointCell.indexOf('`');
            int btEnd = btStart >= 0 ? endpointCell.indexOf('`', btStart + 1) : -1;
            if (btStart < 0 || btEnd < 0) {
                throw new IOException("Endpoint cell missing backticks: " + endpointCell);
            }
            String endpoint = endpointCell.substring(btStart + 1, btEnd);

            String httpMethod;
            String apiPath;
            int sp = endpoint.indexOf(' ');
            if (sp > 0) {
                httpMethod = endpoint.substring(0, sp);
                String rest = endpoint.substring(sp + 1).trim();
                int q = rest.indexOf('?');
                apiPath = q >= 0 ? rest.substring(0, q) : rest;
            } else {
                httpMethod = "GET";
                apiPath = endpoint;
            }

            boolean isVulnerable = conclusion.contains("有漏洞");
            boolean needsTraversal = "是".equals(jumpLayer);

            out.add(new GroundTruthEntry(id, endpoint, httpMethod, apiPath,
                    vulnType, isVulnerable, needsTraversal, conclusion));
        }

        // The benchmark's universe size is fixed (53 rows); a silent drop
        // here would corrupt the recall denominator. Fail fast.
        if (out.size() != 53) {
            throw new IOException("Expected exactly 53 GROUND_TRUTH rows, got " + out.size()
                    + ". If the table grew, update this assertion; if it shrank, you lost a case.");
        }
        long vuln = out.stream().filter(GroundTruthEntry::isVulnerable).count();
        // By-id count gives 32 vulnerable / 21 safe (total 53).
        if (vuln != 32) {
            throw new IOException("Expected 32 vulnerable rows, got " + vuln);
        }
        return out;
    }
}
