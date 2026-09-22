package com.flechazo.apisentinel.standalone;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.ai.agent.AgentLoop;
import com.flechazo.apisentinel.ai.agent.tool.ToolContext;
import com.flechazo.apisentinel.ai.budget.BudgetMode;
import com.flechazo.apisentinel.ai.budget.TokenBudgetManager;
import com.flechazo.apisentinel.ai.pipeline.AnalysisConfig;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.patterns.PatternStore;
import com.flechazo.apisentinel.ai.provider.DeepSeekProvider;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Standalone CLI entry point — runs API-Sentinel without Burp Suite.
 *
 * <p>Uses {@link HeadlessMontoyaApi} to replace Burp's API, so all 50+ agent
 * tools and the full AgentLoop analysis pipeline run unchanged.
 *
 * <p>Usage:
 * <pre>
 *   java -jar api-sentinel.jar \
 *     --target http://localhost:8089 \
 *     --path /api/users/search?name=x \
 *     --method GET \
 *     --repo ./easyshop-app/src \
 *     --model deepseek-chat \
 *     --endpoint http://your-llm:8080 \
 *     --api-key sk-xxx \
 *     --monitor-only \
 *     --output report.json
 * </pre>
 */
public class StandaloneMain {

    public static void main(String[] args) {
        Map<String, String> opts = parseArgs(args);

        if (opts.isEmpty() || opts.containsKey("help")) {
            printUsage();
            return;
        }

        String targetUrl = opts.get("target");
        String repoPath = opts.get("repo");
        String model = opts.get("model");
        String endpoint = opts.get("endpoint");
        String apiKey = opts.get("api-key");
        String outputPath = opts.getOrDefault("output", "api-sentinel-report.json");
        boolean monitorOnly = opts.containsKey("monitor-only");

        if (targetUrl == null || targetUrl.isEmpty()) {
            System.err.println("Error: --target is required");
            printUsage();
            return;
        }

        String apiPath = opts.get("path");
        String method = opts.getOrDefault("method", "GET");

        if (apiPath == null || apiPath.isEmpty()) {
            System.err.println("Error: --path is required (e.g. /api/users/search?name=x)");
            printUsage();
            return;
        }

        System.out.println("╔═══════════════════════════════════════════════════╗");
        System.out.println("║  API Sentinel — Standalone CLI v1.1                ║");
        System.out.println("╚═══════════════════════════════════════════════════╝");
        System.out.println("Target: " + targetUrl + apiPath);
        System.out.println("Method: " + method);
        System.out.println("Repo:   " + (repoPath != null ? repoPath : "(none)"));
        System.out.println("Model:  " + (model != null ? model : "(default)"));
        System.out.println("Output: " + outputPath);
        System.out.println("Budget: " + (monitorOnly ? "MONITOR_ONLY (unlimited)" : "ENFORCE (500K/day)"));
        System.out.println();

        // ===== 1. Headless infrastructure =====
        HeadlessObjectFactory.install(); // Must be before any Montoya factory call
        HeadlessMontoyaApi headlessApi = new HeadlessMontoyaApi();
        LeveledLogger logger = new LeveledLogger(headlessApi.logging());
        logger.info("[CLI] Headless MontoyaApi initialized (HTTP via java.net.http.HttpClient)");

        // ===== 2. LLM provider =====
        LlmProviderFactory factory = new LlmProviderFactory();

        // Try 1: Load from ~/.api-sentinel/ai-config.json (same as Burp extension)
        java.io.File aiConfigFile = new java.io.File(System.getProperty("user.home") + "/.api-sentinel/ai-config.json");
        if (aiConfigFile.exists()) {
            try {
                String jsonStr = java.nio.file.Files.readString(aiConfigFile.toPath());
                var aiConfig = com.google.gson.JsonParser.parseString(jsonStr).getAsJsonObject();
                String cfgProvider = aiConfig.has("provider") ? aiConfig.get("provider").getAsString() : "";
                String cfgEndpoint = aiConfig.has("endpoint") ? aiConfig.get("endpoint").getAsString() : "";
                String cfgApiKey = aiConfig.has("apiKey") ? aiConfig.get("apiKey").getAsString() : "";
                String cfgModel = aiConfig.has("model") ? aiConfig.get("model").getAsString() : "";
                logger.debug("[CLI] Loaded ai-config.json: provider=%s, model=%s", cfgProvider, cfgModel);
                // CLI args override config file
                if (endpoint != null) cfgEndpoint = endpoint;
                if (apiKey != null) cfgApiKey = apiKey;
                if (model != null) cfgModel = model;
                // Create provider based on type
                if ("claude".equalsIgnoreCase(cfgProvider)) {
                    com.flechazo.apisentinel.ai.provider.ClaudeProvider cp = new com.flechazo.apisentinel.ai.provider.ClaudeProvider();
                    cp.configure(cfgEndpoint, cfgApiKey, cfgModel);
                    factory.register(cp);
                    logger.debug("[CLI] ClaudeProvider configured: %s @ %s", cfgModel, cfgEndpoint);
                } else if ("deepseek".equalsIgnoreCase(cfgProvider)) {
                    DeepSeekProvider dp = new DeepSeekProvider();
                    dp.configure(cfgEndpoint, cfgApiKey, cfgModel);
                    factory.register(dp);
                    logger.debug("[CLI] DeepSeekProvider configured: %s @ %s", cfgModel, cfgEndpoint);
                } else if ("openai".equalsIgnoreCase(cfgProvider)) {
                    com.flechazo.apisentinel.ai.provider.OpenAiProvider op = new com.flechazo.apisentinel.ai.provider.OpenAiProvider();
                    op.configure(cfgEndpoint, cfgApiKey, cfgModel);
                    factory.register(op);
                    logger.debug("[CLI] OpenAiProvider configured: %s @ %s", cfgModel, cfgEndpoint);
                }
            } catch (Exception e) {
                logger.info("[CLI] Failed to load ai-config.json: %s", e.getMessage());
            }
        }

        // Try 2: CLI args only (if no config file loaded a provider)
        if (factory.getFirstAvailable() == null && endpoint != null && apiKey != null) {
            String modelToUse = model != null ? model : "deepseek-chat";
            DeepSeekProvider provider = new DeepSeekProvider();
            provider.configure(endpoint, apiKey, modelToUse);
            factory.register(provider);
            logger.debug("[CLI] Provider configured from CLI args: %s @ %s", modelToUse, endpoint);
        }
        // Budget manager
        AppConfig config = new AppConfig();
        TokenBudgetManager budgetManager = new TokenBudgetManager(
                config.getDailyBudgetTokens(), config.getPerRequestMaxTokens());
        if (monitorOnly) {
            budgetManager.setBudgetMode(BudgetMode.MONITOR_ONLY);
            logger.info("[CLI] Budget mode: MONITOR_ONLY — usage tracked but never blocked");
        }
        factory.setBudgetManager(budgetManager);

        LlmProvider provider = factory.getFirstAvailable();
        if (provider == null) {
            System.err.println("Error: No LLM provider available. Use --endpoint, --api-key, --model to configure.");
            return;
        }
        logger.info("[CLI] LLM provider ready: %s", provider.getDisplayName());

        // ===== 3. Code index (white-box analysis) =====
        CodeIndexService codeIndexService = new CodeIndexService(logger);
        List<CodeRepo> codeRepos = new ArrayList<>();
        if (repoPath != null && !repoPath.isEmpty()) {
            CodeRepo repo = new CodeRepo("target", repoPath, List.of());
            int routes = codeIndexService.indexRepo(repo);
            codeRepos.add(repo);
            logger.info("[CLI] Code repo indexed: %d routes, %d sinks",
                    routes, codeIndexService.getSinkMap() != null ? codeIndexService.getSinkMap().totalSinkCount() : 0);
        }

        // ===== 4. Pipeline config =====
        // useCodeRepo=true if repo provided, maxPayloads=20, autoExecute=true,
        // authTestEnabled=true, contextWindowTokens=100K
        AnalysisConfig pipelineConfig = new AnalysisConfig(
                repoPath != null, 20, true, true);

        // ===== 5. Pattern store (for cluster hunting) =====
        PatternStore patternStore = new PatternStore(logger);

        // ===== 6. Create ApiEntry =====
        String domain = targetUrl.replace("http://", "").replace("https://", "");
        ApiEntry entry = new ApiEntry(method, apiPath);
        entry.setDomain(domain);
        entry.setLastUrl(targetUrl + apiPath);

        // Optionally capture initial traffic by sending a baseline request
        logger.debug("[CLI] Sending baseline request to capture traffic...");
        captureBaseline(headlessApi, entry, targetUrl, apiPath, method);
        logger.info("[CLI] Baseline captured (status=%d, %d bytes response)",
                entry.getLastStatusCode(), entry.getLastRawResponse() != null ? entry.getLastRawResponse().length() : 0);

        // ===== 7. Run AgentLoop =====
        logger.info("[CLI] Starting AgentLoop analysis for %s %s", method, apiPath);

        AgentLoop agentLoop = new AgentLoop(
                provider, headlessApi, codeIndexService, pipelineConfig,
                codeRepos, logger, null, patternStore, null);

        // CLI callback — prints progress to stdout
        AgentLoop.AgentCallback callback = new AgentLoop.AgentCallback() {
            @Override public void onAgentThinking(String thought) {
                System.out.println("[Think] " + truncate(thought, 100));
            }
            @Override public void onToolCall(String toolName, String args) {
                System.out.println("[Tool] " + toolName + " " + truncate(args, 80));
            }
            @Override public void onToolResult(String toolName, String result) {
                System.out.println("[Result] " + toolName + " → " + truncate(result, 100));
            }
            @Override public void onAgentComplete(PipelineResult result) {
                System.out.println("[Done] Analysis complete");
            }
            @Override public void onAgentError(String error) {
                System.err.println("[Error] " + error);
            }
            @Override public void onIterationComplete(int iteration, int maxIterations) {
                System.out.printf("[Progress] Iteration %d/%d%n", iteration, maxIterations);
            }
        };

        try {
            PipelineResult result = agentLoop.execute(entry, callback).get();
            writeReport(result, outputPath, entry, budgetManager);
            System.out.println("\n✅ Done. Report: " + outputPath);
            System.out.println("   Budget used: " + budgetManager.getTodayUsed() + " tokens");
            System.out.println("   Budget mode: " + budgetManager.getBudgetMode());
            if (result.verdict() != null) {
                int confirmed = result.verdict().confirmedVulns().size();
                int suspected = result.verdict().suspectedVulns().size();
                System.out.printf("   Findings: %d confirmed, %d suspected%n", confirmed, suspected);
            }
        } catch (Exception e) {
            System.err.println("[Error] Analysis failed: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    /**
     * Send a baseline request via the headless HTTP client to capture
     * initial traffic data (request + response) into the ApiEntry.
     */
    private static void captureBaseline(MontoyaApi api, ApiEntry entry,
                                         String targetUrl, String apiPath, String method) {
        try {
            String domain = targetUrl.replace("http://", "").replace("https://", "");
            boolean https = targetUrl.startsWith("https://");
            String host = domain.contains(":") ? domain.split(":")[0] : domain;
            int port;
            try {
                port = domain.contains(":") ? Integer.parseInt(domain.split(":")[1]) : (https ? 443 : 80);
            } catch (NumberFormatException e) {
                port = https ? 443 : 80;
            }

            // Build a raw HTTP request and use HeadlessHttp directly (bypasses
            // Montoya's ObjectFactoryLocator which is null without Burp)
            String rawReq = method + " " + apiPath + " HTTP/1.1\r\n"
                    + "Host: " + host + (port != 80 && port != 443 ? ":" + port : "") + "\r\n\r\n";

            // Use HeadlessHttp to send — it handles HttpRequest construction internally
            HeadlessHttp headlessHttp = (api instanceof HeadlessMontoyaApi)
                    ? (HeadlessHttp) ((HeadlessMontoyaApi) api).http() : null;
            if (headlessHttp == null) {
                // Fallback: use Montoya's factory (works in Burp mode)
                burp.api.montoya.http.HttpService service =
                        burp.api.montoya.http.HttpService.httpService(host, port, https);
                burp.api.montoya.http.message.requests.HttpRequest httpReq =
                        burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, rawReq);
                var resp = api.http().sendRequest(httpReq);
                String sentRaw = com.flechazo.apisentinel.util.HttpMessageUtils.buildRawRequest(resp.request());
                String recvRaw = resp.response() != null
                        ? com.flechazo.apisentinel.util.HttpMessageUtils.buildRawResponse(resp.response()) : "";
                int statusCode = resp.response() != null ? resp.response().statusCode() : 0;
                entry.setLastRawRequest(sentRaw);
                entry.setLastRawResponse(recvRaw);
                entry.setLastStatusCode(statusCode);
                return;
            }

            // CLI mode: use HeadlessHttpService (bypasses Montoya ObjectFactoryLocator)
            burp.api.montoya.http.HttpService service = new HeadlessHttpService(host, port, https);
            burp.api.montoya.http.message.requests.HttpRequest httpReq =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, rawReq);
            var resp = headlessHttp.sendRequest(httpReq);

            String sentRaw = com.flechazo.apisentinel.util.HttpMessageUtils.buildRawRequest(resp.request());
            String recvRaw = resp.response() != null
                    ? com.flechazo.apisentinel.util.HttpMessageUtils.buildRawResponse(resp.response()) : "";
            int statusCode = resp.response() != null ? resp.response().statusCode() : 0;

            entry.setLastRawRequest(sentRaw);
            entry.setLastRawResponse(recvRaw);
            entry.setLastStatusCode(statusCode);
        } catch (Exception e) {
            System.err.println("[Warn] Baseline capture failed: " + e.getMessage());
        }
    }

    /**
     * Write the analysis report to a JSON file.
     */
    private static void writeReport(PipelineResult result, String outputPath,
                                      ApiEntry entry, TokenBudgetManager budget) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"target\": \"").append(entry.getHttpMethod()).append(" ")
              .append(entry.getDomain()).append(entry.getApiPath()).append("\",\n");
            sb.append("  \"status\": \"").append(result.verdict() != null ? "ANALYZED" : "COMPLETED").append("\",\n");

            if (result.verdict() != null) {
                var v = result.verdict();
                sb.append("  \"confirmed_vulns\": ").append(v.confirmedVulns().size()).append(",\n");
                sb.append("  \"suspected_vulns\": ").append(v.suspectedVulns().size()).append(",\n");
                sb.append("  \"findings\": [\n");
                boolean first = true;
                for (var cv : v.confirmedVulns()) {
                    if (!first) sb.append(",\n");
                    sb.append("    {\"level\": \"confirmed\", \"type\": \"").append(escape(cv.type()))
                      .append("\", \"title\": \"").append(escape(cv.title())).append("\"}");
                    first = false;
                }
                for (var sv : v.suspectedVulns()) {
                    if (!first) sb.append(",\n");
                    sb.append("    {\"level\": \"suspected\", \"type\": \"").append(escape(sv.type()))
                      .append("\", \"title\": \"").append(escape(sv.title())).append("\"}");
                    first = false;
                }
                sb.append("\n  ],\n");
            }

            sb.append("  \"payload_count\": ").append(result.payloadResults() != null ? result.payloadResults().size() : 0).append(",\n");
            sb.append("  \"budget_used\": ").append(budget.getTodayUsed()).append(",\n");
            sb.append("  \"budget_mode\": \"").append(budget.getBudgetMode()).append("\"\n");
            sb.append("}\n");

            java.nio.file.Files.writeString(Path.of(outputPath), sb.toString());
        } catch (Exception e) {
            System.err.println("[Error] Failed to write report: " + e.getMessage());
        }
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> opts = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--")) {
                String key = arg.substring(2);
                if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    opts.put(key, args[i + 1]);
                    i++;
                } else {
                    opts.put(key, "true");
                }
            }
        }
        return opts;
    }

    private static void printUsage() {
        System.out.println("""
                API Sentinel — Standalone CLI v1.1

                Usage:
                  java -jar api-sentinel.jar [options]

                Required:
                  --target URL          Target application URL (e.g. http://localhost:8089)
                  --path PATH           API path to analyze (e.g. /api/users/search?name=x)
                  --endpoint URL        LLM API endpoint
                  --api-key KEY         LLM API key

                Optional:
                  --method METHOD       HTTP method (default: GET)
                  --model MODEL         LLM model name (e.g. deepseek-chat)
                  --repo PATH           Source code repository path (for white-box analysis)
                  --output FILE         Report output file (default: api-sentinel-report.json)
                  --monitor-only        Don't block on budget — just track usage
                  --help                Show this help
                """);
    }
}
