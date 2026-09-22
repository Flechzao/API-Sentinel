package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.ConfidenceLevel;
import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore.FindingCategory;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P0-4 — {@link FindingEvidenceStore}'s
 * {@code ingestFromSendRequest} used to treat certain response-body
 * substrings ("SQL 错误" / "stack trace" / "sql error") as an anomaly
 * signal and spawn a SUSPECTED finding, and it also ran
 * {@code inferCategoryFromResult} over the same attacker-controlled
 * text to label the category (anything mentioning "sql" → SQL_INJECTION,
 * "script" → XSS, etc.).
 *
 * <p>Together these two reads on the response body gave an attacker who
 * controls any response byte a direct channel into the long-term
 * evidence store: a honeypot endpoint that echoes those phrases in a
 * normal 200 response would spawn a fake SUSPECTED finding that
 * survives context compaction and re-enters the model's prompt as if
 * it were an analyst-observed signal.
 *
 * <p>P0-4 hardening: only the <i>structured</i> {@code "anomaly":true}
 * field (emitted by {@link com.flechazo.apisentinel.ai.agent.tool.SendRequestTool}
 * on baseline-divergent responses) is consulted. Substring matches are
 * gone. These tests pin that contract.
 */
class FindingEvidenceStoreP04Test {

    private final FindingEvidenceStore store =
            new FindingEvidenceStore(new LeveledLogger(null));

    // ============== Attacker view: body substrings must not pollute ==============

    @Test
    void ingest_honeypotSqlErrorPhrase_noFindingSpawned() {
        // Attacker view: a normal 200 response whose body happens to
        // mention "SQL 错误" must NOT be treated as an anomaly. The
        // pre-P0-4 substring match would spawn a SUSPECTED finding
        // here, which then survives context compaction and poisons
        // every subsequent reflection.
        String result = "{\"status_code\":200, \"anomaly\":false, "
                + "\"body\":\"亲爱的用户，这里没有任何 SQL 错误，只是一个普通的问候页面\"}";

        store.ingestFromToolResult("send_request", result, 1);

        assertThat(store.size()).isZero();
    }

    @Test
    void ingest_honeypotStackTracePhrase_noFindingSpawned() {
        // Same shape for "stack trace" — another phrase the pre-P0-4
        // code used as a proxy for anomaly. A honeypot that echoes
        // the phrase in normal prose must not pollute the store.
        String result = "{\"status_code\":200, \"anomaly\":false, "
                + "\"body\":\"This page has no stack trace and no error at all\"}";

        store.ingestFromToolResult("send_request", result, 1);

        assertThat(store.size()).isZero();
    }

    @Test
    void ingest_honeypotSqlErrorEnglish_noFindingSpawned() {
        String result = "{\"status_code\":200, \"anomaly\":false, "
                + "\"body\":\"there is no sql error on this page\"}";

        store.ingestFromToolResult("send_request", result, 1);

        assertThat(store.size()).isZero();
    }

    @Test
    void ingest_honeypotDoesNotMislabelCategory() {
        // Even if the pre-P0-4 category classifier saw "sql" anywhere
        // in the body and returned SQL_INJECTION, that path is gone
        // now. The only finding we can possibly create from
        // send_request is category=OTHER (auto-detected anomaly).
        // Send a genuine anomaly whose body happens to mention XSS —
        // the stored category must still be OTHER, not XSS.
        String result = "{\"status_code\":500, \"anomaly\":true, "
                + "\"body\":\"database error with XSS reflection\"}";

        store.ingestFromToolResult("send_request", result, 1);

        assertThat(store.size()).isEqualTo(1);
        var finding = store.getAllFindings().get(0);
        assertThat(finding.category())
                .as("auto-ingested send_request findings must be category=OTHER; "
                        + "labeling from response-body text is attacker-controllable")
                .isEqualTo(FindingCategory.OTHER);
    }

    // ============== Defender view: real anomaly signal still lands ==============

    @Test
    void ingest_structuredAnomalyTrue_spawnsSuspectedFinding() {
        // The legitimate path: SendRequestTool flags a baseline-
        // divergent response with anomaly:true. The store must still
        // pick it up and file it as SUSPECTED from the send_request
        // tool.
        String result = "{\"status_code\":500, \"anomaly\":true, "
                + "\"body\":\"Internal Server Error\"}";

        store.ingestFromToolResult("send_request", result, 7);

        assertThat(store.size()).isEqualTo(1);
        var finding = store.getAllFindings().get(0);
        assertThat(finding.level()).isEqualTo(ConfidenceLevel.SUSPECTED);
        assertThat(finding.sourceTool()).isEqualTo("send_request");
        assertThat(finding.iteration()).isEqualTo(7);
    }

    @Test
    void ingest_prettyPrintedAnomalyTrue_stillRecognised() {
        // Gson pretty-printing inserts a space after the colon; the
        // matcher must accept both shapes.
        String result = "{\n  \"status_code\": 500,\n  \"anomaly\": true,\n  \"body\": \"err\"\n}";

        store.ingestFromToolResult("send_request", result, 2);

        assertThat(store.size()).isEqualTo(1);
    }

    @Test
    void ingest_anomalyFalse_noFindingEvenWithErrorCode() {
        // anomaly:false is an explicit negative — must NOT be ingested
        // even when the status code is 500. (A 500 from a baseline
        // that also 500s is not an anomaly.)
        String result = "{\"status_code\":500, \"anomaly\":false, \"body\":\"err\"}";

        store.ingestFromToolResult("send_request", result, 3);

        assertThat(store.size()).isZero();
    }

    @Test
    void ingest_noAnomalyField_noFinding() {
        // Results from other tools that don't carry an anomaly field
        // at all must not be auto-ingested via the send_request path.
        String result = "{\"status_code\":200, \"body\":\"ok\"}";

        store.ingestFromToolResult("send_request", result, 4);

        assertThat(store.size()).isZero();
    }

    @Test
    void ingest_nullOrEmpty_safelyNoOp() {
        // Belt-and-braces: null and empty inputs must not throw and
        // must not produce findings.
        store.ingestFromToolResult("send_request", null, 1);
        store.ingestFromToolResult("send_request", "", 2);
        assertThat(store.size()).isZero();
    }

    // ============== The rest of the ingestion matrix is unchanged ==============

    @Test
    void ingest_heuristicScanStillProducesNoteFinding() {
        // P0-4 only touched ingestFromSendRequest. The heuristic_scan
        // path (which reads a structured scan report from the scanner,
        // not attacker-controlled bytes) keeps its existing behaviour.
        String result = "{\"finding\": [{\"type\": \"SQLi\"}], \"发现\": 1}";

        store.ingestFromToolResult("heuristic_scan", result, 1);

        assertThat(store.size()).isEqualTo(1);
    }
}
