package com.flechazo.apisentinel.benchmark;

import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * End-to-end benchmark: drive the demo-vuln-app, run Agent/Pipeline
 * analysis over the captured traffic, compare against GROUND_TRUTH,
 * and assert recall/precision/FP targets.
 *
 * <p><b>Why this test is gated off by default</b>:
 * <ol>
 *   <li>It needs the demo-vuln-app Spring Boot service reachable at
 *       {@code http://localhost:8089}. CI runs it as a service container;
 *       local runs start it manually with
 *       {@code cd demo-vuln-app && mvn spring-boot:run}.</li>
 *   <li>It needs a configured LLM provider (Claude / OpenAI / Ollama)
 *       because the Agent is the thing under test. CI injects the API
 *       key via environment; local runs rely on {@code ai-config.json}.
 *       </li>
 *   <li>It's slow: ~44 endpoints × 30-120s per Agent run = 22-88 minutes
 *       for the full matrix. Not something to run on every commit — it's
 *       the nightly / release-gate test.</li>
 * </ol>
 *
 * <p><b>Enabling locally</b>: pass
 * {@code -Dbenchmark.enabled=true -Dbenchmark.baseUrl=http://localhost:8089}
 * to activate just this class. Without {@code benchmark.enabled=true} the
 * test aborts via {@link org.junit.jupiter.api.Assumptions}, so a plain
 * {@code ./gradlew test} still runs in seconds.
 *
 * <p><b>Enabling in CI</b>: the harness should:
 * <ol>
 *   <li>Start demo-vuln-app as a service container (see
 *       {@code demo-vuln-app/Dockerfile}, not yet present — see the
 *       follow-up "P1-10续: Docker 化" todo).</li>
 *   <li>Configure an LLM provider via {@code ai-config.json} or env.</li>
 *   <li>Run this test via Gradle:
 *       {@code ./gradlew test --tests BenchmarkIntegrationTest -Dbenchmark.enabled=true}</li>
 *   <li>Attach {@code build/benchmark-report.txt} as a build artifact.</li>
 * </ol>
 *
 * <p><b>Regression target</b>: once the pipeline produces its first
 * green run, the recall / precision / FP rate of that run become the
 * regression target. Lower bounds are asserted so a future change can't
 * silently ship a worse scanner — the numbers below are <i>placeholders</i>
 * and should be updated to the real first-run numbers.
 */
class BenchmarkIntegrationTest {

    private static final String DEFAULT_BASE_URL = "http://localhost:8089";
    /** Regression targets pinned from the first real run (2026-09-06,
     *  model: DeepSeek-V4-Pro-0813 via Alipay proxy, no Burp harness so
     *  Stage 4/5 HTTP execution was stubbed — numbers reflect Stage 1
     *  LLM static analysis only). Any future change that drops recall
     *  or precision below these, or raises FP rate above, fails the
     *  benchmark and must be justified or reverted.
     *
     *  First-run numbers:
     *    recall  = 24/27 = 0.889
     *    precision = 24/36 = 0.667
     *    FP rate = 12/17 = 0.706
     *  Buffers of 5 percentage points give legitimate prompt tuning
     *  room while still catching a real regression. */
    private static final double MIN_RECALL = 0.84;
    private static final double MIN_PRECISION = 0.60;
    private static final double MAX_FP_RATE = 0.75;

    /** Quick mode: test one representative per vulnerability category.
     *  ~15 endpoints covering all 15 vuln types. Runs in ~5 min instead of ~25 min.
     *  Includes both vulnerable and safe counterparts for each type.
     *  Activated via -Dbenchmark.mode=quick or BENCHMARK_MODE=quick env. */
    private static final java.util.Set<Integer> QUICK_MODE_IDS = java.util.Set.of(
            1, 2,     // SQLi
            4, 5,     // IDOR
            7, 8,     // JWT
            9,        // CORS
            11, 12,   // SSRF
            13, 14,   // Upload
            15,       // Deserialization
            19,       // Debug info leak
            21, 22,   // XSS
            23, 24,   // SSTI
            25, 26,   // Path traversal
            31, 32,   // Race condition
            35, 36,   // Hardcoded crypto
            41, 42,   // Mass assignment
            45, 46,   // Command injection
            47, 48,   // NoSQL injection
            49, 50,   // CRLF injection
            51, 52,   // Coupon replay (business logic)
            53        // Shadow API (deprecated endpoint)
    );

    private static String baseUrl;
    private static String mode;

    @BeforeAll
    static void readSystemProperties() {
        String baseUrl = System.getenv("BENCHMARK_BASE_URL");
        if (baseUrl == null || baseUrl.isEmpty()) {
            baseUrl = System.getProperty("benchmark.baseUrl", DEFAULT_BASE_URL);
        }
        BenchmarkIntegrationTest.baseUrl = baseUrl;

        String mode = System.getenv("BENCHMARK_MODE");
        if (mode == null || mode.isEmpty()) {
            mode = System.getProperty("benchmark.mode", "full");
        }
        BenchmarkIntegrationTest.mode = mode.toLowerCase();
    }

    @Test
    void fullBenchmarkRunProducesReportAndMeetsRegressionTargets() throws Exception {
        // Honor the BENCHMARK_ENABLED env var (preferred, works through
        // Gradle's daemon barrier without extra build config) OR the
        // -Dbenchmark.enabled flag. Without either, a plain
        // `./gradlew test` skips this class in <1s.
        String enabled = System.getenv("BENCHMARK_ENABLED");
        if (enabled == null) enabled = System.getProperty("benchmark.enabled");
        assumeThat(enabled)
                .as("BENCHMARK_ENABLED env var (or -Dbenchmark.enabled) must be set to 'true' "
                        + "— this test is gated off by default because it needs demo-vuln-app "
                        + "running at localhost:8089 and a configured LLM provider.")
                .isEqualTo("true");

        BenchmarkTrafficDriver driver = new BenchmarkTrafficDriver(baseUrl);
        assumeThat(driver.isReachable())
                .as("demo-vuln-app must be reachable at %s", baseUrl)
                .isTrue();

        // Step 1: capture traffic against every ground-truth row.
        Map<String, String> cookies = driver.loginBothUsers();
        List<BenchmarkTrafficDriver.CapturedExchange> traffic = driver.captureAll(cookies);

        // Quick mode: filter to representative subset (~15 vuln types × 2 = ~30 endpoints)
        if ("quick".equals(mode)) {
            traffic = traffic.stream()
                    .filter(x -> QUICK_MODE_IDS.contains(x.groundTruthId()))
                    .collect(java.util.stream.Collectors.toList());
            System.out.printf("[benchmark] QUICK mode: %d/%d endpoints selected%n",
                    traffic.size(), 48);
        }
        assertThat(traffic.size()).isGreaterThanOrEqualTo("quick".equals(mode) ? 20 : 53);

        // Step 2: run Agent / Pipeline analysis on the captured traffic.
        //         The actual invocation goes here — it depends on whether
        //         the harness runs inside Burp (the normal plugin path)
        //         or as a standalone CLI (a future "headless analysis"
        //         mode). For now this is a stub that returns no findings,
        //         which means the first enabled run will FAIL the target
        //         assertions below — that's intentional: it forces the
        //         integrator to wire the real analyzer in before the
        //         test can gate anything.
        List<VulnFinding> findings = runAnalysis(traffic);

        // Step 3: bucket findings by endpoint and compare to ground truth.
        Map<String, List<VulnFinding>> bucketed = BenchmarkMetrics.bucketByEndpoint(
                findings,
                f -> f.location() == null ? "" : f.location());
        BenchmarkMetrics.Summary summary = BenchmarkMetrics.compute(
                GroundTruthEntry.loadAll(), bucketed);

        // Step 4: emit the report (CI harvests this file as an artifact).
        String report = summary.renderTextReport();
        String modeBanner = String.format("%n=== Mode: %s (%d endpoints) ===%n", mode.toUpperCase(), traffic.size());
        report = modeBanner + report;
        java.nio.file.Path reportPath = java.nio.file.Path.of("build/benchmark-report.txt");
        java.nio.file.Files.createDirectories(reportPath.getParent());
        java.nio.file.Files.writeString(reportPath, report);
        System.out.println(report);

        // Step 5: assert regression targets. The MIN_* / MAX_* constants
        //         above start at the permissive values; the first real
        //         run sets them to that run's numbers, after which any
        //         regression trips this test.
        assertThat(summary.recall())
                .as("recall must not regress below the pinned target")
                .isGreaterThanOrEqualTo(MIN_RECALL);
        assertThat(summary.precision())
                .as("precision must not regress below the pinned target")
                .isGreaterThanOrEqualTo(MIN_PRECISION);
        assertThat(summary.falsePositiveRate())
                .as("false-positive rate must not exceed the pinned target")
                .isLessThanOrEqualTo(MAX_FP_RATE);
    }

    /** Bridges the benchmark's captured traffic into the real
     *  {@link com.flechazo.apisentinel.ai.pipeline.AnalysisPipeline}. For
     *  each exchange we:
     *  <ol>
     *    <li>Build an {@link com.flechazo.apisentinel.model.ApiEntry} with
     *        the captured lastRawRequest / lastRawResponse.</li>
     *    <li>Run the pipeline (Stages 1-6). Stage 1 (LLM traffic analysis)
     *        works without Burp; later stages that need
     *        {@code montoyaApi} may fail — the pipeline catches those and
     *        the verdict still reflects whatever stages completed.</li>
     *    <li>Map {@link ConfirmedVuln} / {@link SuspectedVuln} entries
     *        from the {@link FinalVerdict} into {@link VulnFinding}s for
     *        the benchmark comparison.</li>
     *  </ol>
     *
     *  <p><b>CI prerequisites</b>: an LLM provider must be configured via
     *  {@code ai-config.json} or {@code LLM_API_KEY} env; otherwise
     *  {@link com.flechazo.apisentinel.ai.provider.LlmProviderFactory#getFirstAvailable()}
     *  returns null and the test will abort via {@code assumeThat}. */
    private List<VulnFinding> runAnalysis(List<BenchmarkTrafficDriver.CapturedExchange> traffic) {
        com.flechazo.apisentinel.ai.provider.LlmProviderFactory factory =
                new com.flechazo.apisentinel.ai.provider.LlmProviderFactory();
        // Best-effort: try to auto-configure the provider from (in order):
        //   1. -Dbenchmark.apiKey / LLM_API_KEY (explicit, CI-friendly)
        //   2. ~/.api-sentinel/ai-config.json (what the Burp plugin reads)
        // Falling back to ai-config.json lets a local benchmark reuse the
        // user's existing setup without env-var ceremony.
        String apiKey = System.getProperty("benchmark.apiKey",
                System.getenv("LLM_API_KEY"));
        String model = System.getProperty("benchmark.model",
                System.getenv("LLM_MODEL"));
        String endpoint = System.getProperty("benchmark.endpoint",
                System.getenv("LLM_ENDPOINT"));
        String providerId = System.getProperty("benchmark.provider",
                System.getenv().getOrDefault("LLM_PROVIDER", null));

        if (apiKey == null || apiKey.isEmpty()) {
            // No explicit config → try the Burp plugin's ai-config.json.
            try {
                java.nio.file.Path aiCfg = com.flechazo.apisentinel.config.AppPaths.aiConfigFile();
                if (java.nio.file.Files.exists(aiCfg)) {
                    com.google.gson.JsonObject obj = com.google.gson.JsonParser
                            .parseString(java.nio.file.Files.readString(aiCfg))
                            .getAsJsonObject();
                    if (providerId == null && obj.has("provider")) {
                        providerId = obj.get("provider").getAsString();
                    }
                    if (obj.has("apiKey")) apiKey = obj.get("apiKey").getAsString();
                    if (endpoint == null && obj.has("endpoint")) {
                        endpoint = obj.get("endpoint").getAsString();
                    }
                    if (model == null && obj.has("model")) {
                        model = obj.get("model").getAsString();
                    }
                    System.out.printf("[benchmark] loaded ai-config.json: provider=%s endpoint=%s model=%s%n",
                            providerId, endpoint, model);
                }
            } catch (Exception e) {
                System.err.println("[benchmark] ai-config.json read failed: " + e.getMessage());
            }
        }
        if (providerId == null) providerId = "claude";

        if (apiKey != null && !apiKey.isEmpty()) {
            var provider = factory.get(providerId);
            if (provider != null) {
                provider.configure(endpoint, apiKey, model != null ? model : "");
            }
        }
        com.flechazo.apisentinel.ai.provider.LlmProvider llm = factory.getFirstAvailable();
        if (llm == null) {
            // Abort the benchmark — the assumption "an LLM is available"
            // doesn't hold and there's nothing to analyze with.
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "No LLM provider configured — set benchmark.apiKey or LLM_API_KEY");
            return List.of();
        }

        // Config + logger — minimal setup, everything else is defaulted.
        com.flechazo.apisentinel.config.ConfigManager configManager =
                new com.flechazo.apisentinel.config.ConfigManager(
                        new com.flechazo.apisentinel.logging.LeveledLogger(null));
        com.flechazo.apisentinel.ai.pipeline.AnalysisConfig pipelineConfig =
                new com.flechazo.apisentinel.ai.pipeline.AnalysisConfig(
                        true, 10, true, true,
                        "", "", "", "",
                        configManager.getConfig().getContextWindowTokens(), true,
                        true, false, false, false, 0, false, false);
        com.flechazo.apisentinel.logging.LeveledLogger logger =
                new com.flechazo.apisentinel.logging.LeveledLogger(null);

        com.flechazo.apisentinel.ai.pipeline.AnalysisPipeline pipeline =
                new com.flechazo.apisentinel.ai.pipeline.AnalysisPipeline(
                        llm,
                        /* montoyaApi */ null, // benchmark runs outside Burp
                        /* codeIndexService */ null, // no code repo configured by default
                        pipelineConfig,
                        List.of(),
                        logger);

        List<VulnFinding> allFindings = new java.util.ArrayList<>();
        // Sequential on purpose: the pipeline is already async internally,
        // and running 44 LLM-driven analyses in parallel would blow the
        // provider's rate limit on the first run.
        int done = 0;
        for (BenchmarkTrafficDriver.CapturedExchange x : traffic) {
            done++;
            System.out.printf("[benchmark] %d/%d  %s %s%n",
                    done, traffic.size(), x.httpMethod(), x.apiPath());
            try {
                com.flechazo.apisentinel.model.ApiEntry entry = toApiEntry(x);
                com.flechazo.apisentinel.ai.pipeline.PipelineResult result =
                        pipeline.execute(entry, new NoOpCallback()).get(5, java.util.concurrent.TimeUnit.MINUTES);
                if (result != null && result.verdict() != null) {
                    allFindings.addAll(mapToFindings(x, result.verdict()));
                }
            } catch (java.util.concurrent.TimeoutException te) {
                System.err.printf("[benchmark] timeout on #%d %s%n", x.groundTruthId(), x.apiPath());
            } catch (Exception e) {
                System.err.printf("[benchmark] pipeline error on #%d %s: %s%n",
                        x.groundTruthId(), x.apiPath(), e.getMessage());
            }
        }
        return allFindings;
    }

    /** Shape a captured exchange into an ApiEntry the pipeline can
     *  consume. lastRawRequest / lastRawResponse are written in plain
     *  HTTP/1.1 wire format so Stage 1 parses them correctly. */
    private static com.flechazo.apisentinel.model.ApiEntry toApiEntry(
            BenchmarkTrafficDriver.CapturedExchange x) {
        com.flechazo.apisentinel.model.ApiEntry e =
                new com.flechazo.apisentinel.model.ApiEntry(x.httpMethod(), x.apiPath());
        e.setLastUrl(x.url());
        // Derive a host from the URL for setDomain.
        try {
            java.net.URI u = java.net.URI.create(x.url());
            e.setDomain(u.getHost());
        } catch (Exception ignored) {
            e.setDomain("localhost");
        }
        // Build a minimal raw request (request line + Host header + body).
        String path = x.apiPath();
        int q = x.url().indexOf('?');
        if (q >= 0) path = x.url().substring(x.url().indexOf('/', 8)); // keep query
        StringBuilder req = new StringBuilder();
        req.append(x.httpMethod()).append(' ').append(path).append(" HTTP/1.1\r\n");
        req.append("Host: ").append(e.getDomain()).append("\r\n");
        if (x.requestBody() != null && !x.requestBody().isEmpty()) {
            req.append("Content-Length: ").append(x.requestBody().length()).append("\r\n");
            req.append("\r\n").append(x.requestBody());
        } else {
            req.append("\r\n");
        }
        e.setLastRawRequest(req.toString());

        // Build a minimal raw response: status line + headers + body.
        StringBuilder resp = new StringBuilder();
        resp.append("HTTP/1.1 ").append(x.statusCode()).append(' ')
           .append(statusText(x.statusCode())).append("\r\n");
        if (x.responseHeaders() != null) {
            x.responseHeaders().forEach((k, vals) -> {
                for (String v : vals) resp.append(k).append(": ").append(v).append("\r\n");
            });
        }
        resp.append("\r\n");
        if (x.responseBody() != null) resp.append(x.responseBody());
        e.setLastRawResponse(resp.toString());
        return e;
    }

    private static String statusText(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 201 -> "Created";
            case 204 -> "No Content";
            case 301 -> "Moved Permanently";
            case 302 -> "Found";
            case 304 -> "Not Modified";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            default -> "Unknown";
        };
    }

    /** Map every ConfirmedVuln / SuspectedVuln from the verdict into a
     *  {@link VulnFinding} the benchmark metrics can consume. The finding's
     *  {@code location} is set to the exchange's apiPath so
     *  {@link BenchmarkMetrics#compute} can match it to the ground-truth
     *  row. */
    private static List<VulnFinding> mapToFindings(
            BenchmarkTrafficDriver.CapturedExchange x,
            com.flechazo.apisentinel.ai.pipeline.FinalVerdict v) {
        List<VulnFinding> out = new java.util.ArrayList<>();
        if (v.confirmedVulns() != null) {
            for (var c : v.confirmedVulns()) {
                out.add(new VulnFinding(c.type(), "HIGH", 1.0,
                        c.title(), "", c.evidence(), x.apiPath(), ""));
            }
        }
        if (v.suspectedVulns() != null) {
            for (var s : v.suspectedVulns()) {
                out.add(new VulnFinding(s.type(), "MEDIUM", 0.6,
                        s.title(), s.reason(), "", x.apiPath(), ""));
            }
        }
        return out;
    }

    /** Stub callback — the benchmark doesn't care about stage-by-stage
     *  progress, only the final verdict. */
    private static class NoOpCallback implements com.flechazo.apisentinel.ai.pipeline.AnalysisPipeline.PipelineCallback {
        @Override public void onStageStart(int stage, String description) {}
        @Override public void onStageComplete(int stage, String summary) {}
        @Override public void onPayloadExecuted(int index, int total, String payload, int statusCode) {}
        @Override public void onPipelineComplete(com.flechazo.apisentinel.ai.pipeline.PipelineResult result) {}
        @Override public void onPipelineError(String error) {}
    }
}
