package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.codeindex.parser.RouteEntry;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Pure query helpers shared by BatchOrchestrator (onAiAnalyze's WITH_CODE/
 * WITH_HISTORY modes) and ChatController (buildChatSystemPrompt) — extracted
 * out of the AiPresenter God Object so both can share one instance instead of
 * each reimplementing source/history lookup.
 */
class AnalysisContextLookup {

    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final CodeIndexService codeIndexService;
    private final LeveledLogger logger;

    AnalysisContextLookup(MontoyaApi api, ConfigManager configManager,
                          CodeIndexService codeIndexService, LeveledLogger logger) {
        this.api = api;
        this.configManager = configManager;
        this.codeIndexService = codeIndexService;
        this.logger = logger;
    }

    String lookupSourceCode(String apiPath, String domain) {
        try {
            List<CodeRepo> repos = configManager.getConfig().getCodeRepos();
            List<RouteEntry> routes = codeIndexService.findByPathAndDomain(apiPath, domain, repos);
            if (routes.isEmpty()) return "";

            StringBuilder sb = new StringBuilder();
            for (RouteEntry route : routes) {
                sb.append("// File: ").append(route.sourceFile()).append(" Line: ").append(route.startLine()).append("\n");
                sb.append("// Class: ").append(route.className()).append(" Method: ").append(route.methodName()).append("\n");
                sb.append(codeIndexService.getSourceCode(route)).append("\n\n");
            }
            return sb.toString();
        } catch (Exception e) {
            logger.debug("查找源码失败: %s", e.getMessage());
            return "";
        }
    }

    String gatherHistoryContext(ApiEntry entry) {
        return gatherHistoryContextDetailed(entry).contextText();
    }

    record HistoryLookupResult(int totalScanned, int matchCount, String contextText) {}

    HistoryLookupResult gatherHistoryContextDetailed(ApiEntry entry) {
        try {
            var proxyHistory = api.proxy().history();
            int total = proxyHistory.size();

            String declared = entry.getHttpMethod();
            Set<String> declaredMethods = new HashSet<>();
            if (declared != null && !declared.isEmpty()) {
                for (String m : declared.split("/")) declaredMethods.add(m.toUpperCase());
            }

            StringBuilder sb = new StringBuilder();
            int count = 0;
            for (var item : proxyHistory) {
                try {
                    String url = item.finalRequest().url();
                    String path = com.flechazo.apisentinel.util.UrlUtils.extractPath(url);
                    if (!com.flechazo.apisentinel.util.UrlUtils.pathsLikelyMatch(entry.getApiPath(), path)) continue;

                    String method = item.finalRequest().method();
                    boolean isNoiseMethod = "OPTIONS".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method);
                    if (isNoiseMethod && !declaredMethods.contains(method.toUpperCase())) continue;

                    sb.append(String.format("--- Request #%d ---\n", ++count));
                    sb.append(method).append(" ").append(path).append("\n");
                    String reqBody = item.finalRequest().bodyToString();
                    if (reqBody != null && !reqBody.isEmpty() && reqBody.length() < 500) {
                        sb.append("Body: ").append(reqBody).append("\n");
                    }
                    if (item.response() != null) {
                        sb.append("Status: ").append(item.response().statusCode()).append("\n");
                        String respBody = item.response().bodyToString();
                        if (respBody != null && !respBody.isEmpty() && respBody.length() < 500) {
                            sb.append("Response: ").append(respBody).append("\n");
                        }
                    }
                    sb.append("\n");
                    if (count >= 5) break;
                } catch (Exception ignored) {}
            }
            return new HistoryLookupResult(total, count, sb.toString());
        } catch (Exception e) {
            logger.debug("获取历史流量失败: %s", e.getMessage());
            return new HistoryLookupResult(0, 0, "");
        }
    }
}
