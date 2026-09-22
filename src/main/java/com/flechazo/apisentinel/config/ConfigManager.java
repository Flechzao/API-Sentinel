package com.flechazo.apisentinel.config;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * 配置管理器——加载/保存 config.json，提供配置读写和变更通知。
 */
public class ConfigManager {

    private static final String CONFIG_FILENAME = "config.json";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final AppConfig config;
    private final LeveledLogger logger;
    private final ConfigStore configStore;
    private final List<Consumer<AppConfig>> listeners = new CopyOnWriteArrayList<>();

    public ConfigManager(LeveledLogger logger) {
        this.config = new AppConfig();
        this.logger = logger;
        this.configStore = new ConfigStore(logger);
        loadConfig();
        loadSensitiveRules();
        // First-run discoverability: if no config file exists yet, persist the
        // defaults so a new user immediately sees ~/.api-sentinel/config.json
        // and knows where to edit. (No-op if the file already exists.)
        if (!java.nio.file.Files.exists(AppPaths.configFile())) {
            saveConfig();
        }
    }

    public AppConfig getConfig() {
        return config;
    }

    public ConfigStore getConfigStore() {
        return configStore;
    }

    public void setMatchMode(MatchMode mode) {
        config.setMatchMode(mode);
        notifyAndSave();
        if (logger != null) logger.debug("匹配模式已更新为: %s", mode.getDisplayName());
    }

    public void setCheckWholeRequest(boolean enabled) {
        config.setCheckWholeRequest(enabled);
        notifyAndSave();
    }

    public void setSensitiveDetectionEnabled(boolean enabled) {
        config.setSensitiveDetectionEnabled(enabled);
        notifyAndSave();
    }

    public void setUnauthorizedDetectionEnabled(boolean enabled) {
        config.setUnauthorizedDetectionEnabled(enabled);
        notifyAndSave();
    }

    public void setOobEnabled(boolean enabled) {
        config.setOobEnabled(enabled);
        notifyAndSave();
    }

    public void setHighlightEnabled(boolean enabled) {
        config.setHighlightEnabled(enabled);
        notifyAndSave();
    }

    public void setContextWindowTokens(int tokens) {
        config.setContextWindowTokens(tokens);
        notifyAndSave();
    }

    public void setAutoScanEnabled(boolean enabled) {
        config.setAutoScanEnabled(enabled);
        notifyAndSave();
    }

    public void setCascadeHuntEnabled(boolean enabled) {
        config.setCascadeHuntEnabled(enabled);
        notifyAndSave();
    }

    public void setWafDetectionEnabled(boolean enabled) {
        config.setWafDetectionEnabled(enabled);
        notifyAndSave();
    }

    public void setCodeExecutionAutoApprove(boolean enabled) {
        config.setCodeExecutionAutoApprove(enabled);
        notifyAndSave();
    }

    public void setSkipAllPermissions(boolean enabled) {
        config.setSkipAllPermissions(enabled);
        System.setProperty("api-sentinel.skip-permissions", String.valueOf(enabled));
        notifyAndSave();
    }

    public void setDisabledTools(java.util.Set<String> tools) {
        config.setDisabledTools(tools);
        notifyAndSave();
    }

    public void setToolsRequiringAuth(java.util.Set<String> tools) {
        config.setToolsRequiringAuth(tools);
        notifyAndSave();
    }

    public void setWafRetryEnabled(boolean enabled) {
        config.setWafRetryEnabled(enabled);
        notifyAndSave();
    }

    public void setActiveProbeEnabled(boolean enabled) {
        config.setActiveProbeEnabled(enabled);
        notifyAndSave();
    }

    public void setBusinessLogicVerificationEnabled(boolean enabled) {
        config.setBusinessLogicVerificationEnabled(enabled);
        notifyAndSave();
    }

    public void setOrganizerAutoSendEnabled(boolean enabled) {
        config.setOrganizerAutoSendEnabled(enabled);
        notifyAndSave();
    }

    public void setAuditHighRiskOnly(boolean enabled) {
        config.setAuditHighRiskOnly(enabled);
        notifyAndSave();
    }

    public void setAiAuthArbitrationEnabled(boolean enabled) {
        config.setAiAuthArbitrationEnabled(enabled);
        notifyAndSave();
    }

    public void setMcpServerEnabled(boolean enabled) {
        config.setMcpServerEnabled(enabled);
        notifyAndSave();
    }

    public void setMcpServerPort(int port) {
        config.setMcpServerPort(port);
        notifyAndSave();
    }

    public void setMcpAllowActiveTools(boolean allow) {
        config.setMcpAllowActiveTools(allow);
        notifyAndSave();
    }

    public void setMcpAuthToken(String token) {
        config.setMcpAuthToken(token);
        notifyAndSave();
    }

    public void setMcpRequireAuth(boolean require) {
        config.setMcpRequireAuth(require);
        notifyAndSave();
    }

    public void setModelTieringEnabled(boolean b) {
        config.setModelTieringEnabled(b);
        notifyAndSave();
    }

    public void setFilterOptionsPreflightEnabled(boolean b) {
        config.setFilterOptionsPreflightEnabled(b);
        notifyAndSave();
    }

    public void setBambdaHighlightEnabled(boolean b) {
        config.setBambdaHighlightEnabled(b);
        notifyAndSave();
    }

    public void setBambdaHighlightKeywords(String k) {
        config.setBambdaHighlightKeywords(k);
        notifyAndSave();
    }

    // --- F-1: Browser capabilities ---
    public void setBrowserEnabled(boolean enabled) {
        config.setBrowserEnabled(enabled);
        notifyAndSave();
    }

    // --- P1-6: Raw-credentials opt-in ---
    public boolean isIncludeRawCredentialsInLlm() {
        return config.isIncludeRawCredentialsInLlm();
    }

    public void setIncludeRawCredentialsInLlm(boolean include) {
        config.setIncludeRawCredentialsInLlm(include);
        notifyAndSave();
    }

    public boolean isFirstRunDisclosureDone() {
        return config.isFirstRunDisclosureDone();
    }

    public void setFirstRunDisclosureDone(boolean done) {
        config.setFirstRunDisclosureDone(done);
        notifyAndSave();
    }

    public void setBrowserHeadless(boolean headless) {
        config.setBrowserHeadless(headless);
        notifyAndSave();
    }

    public void setBrowserChromePath(String path) {
        config.setBrowserChromePath(path);
        notifyAndSave();
    }

    public void setBrowserMaxPages(int pages) {
        config.setBrowserMaxPages(pages);
        notifyAndSave();
    }

    public void setBrowserFrontendUrl(String url) {
        config.setBrowserFrontendUrl(url);
        notifyAndSave();
    }

    // --- Fun features ---
    public void setFunFeaturesEnabled(boolean enabled) {
        config.setFunFeaturesEnabled(enabled);
        notifyAndSave();
    }

    public void setEffectsEnabled(boolean enabled) {
        config.setEffectsEnabled(enabled);
        notifyAndSave();
    }

    public com.google.gson.JsonObject getFunFeaturesConfig() {
        try {
            String json = configStore.read("fun-features.json");
            if (json != null && !json.isBlank()) {
                return com.google.gson.JsonParser.parseString(json).getAsJsonObject();
            }
        } catch (Exception e) {
            if (logger != null) logger.warn("加载趣味功能配置失败: %s", e.getMessage());
        }
        return new com.google.gson.JsonObject();
    }

    public void setFunFeaturesConfig(com.google.gson.JsonObject config) {
        try {
            configStore.write("fun-features.json", GSON.toJson(config));
        } catch (Exception e) {
            if (logger != null) logger.warn("保存趣味功能配置失败: %s", e.getMessage());
        }
    }

    private void notifyAndSave() {
        notifyListeners();
        saveConfig();
    }

    private void notifyListeners() {
        for (Consumer<AppConfig> listener : listeners) {
            try {
                listener.accept(config);
            } catch (Exception e) {
                if (logger != null) logger.error("配置监听器异常", e);
            }
        }
    }

    public void saveConfig() {
        // Legacy wrapper: delegates to {@link #trySaveConfig()} and
        // discards the result. Retained so existing call sites
        // (ApiSentinelTab, AuthConfigPanel, OobConfigPanel, …) keep
        // compiling without edits.
        trySaveConfig();
    }

    /** P0-12 #8: explicit-success form of {@link #saveConfig}. Pre-P0-12,
     *  the save was {@code void} and silently swallowed every failure
     *  (IOException, ConfigStore returning false, serialization bugs).
     *  The in-memory {@code config} had already been mutated by the
     *  caller before saveConfig() was invoked, so a failed write left
     *  the next launch reading the stale on-disk copy with no signal
     *  that anything had been lost. With this method the caller gets a
     *  boolean and can surface a warning (e.g. "配置保存失败，请检查磁盘")
     *  instead of letting the user believe their change was persisted. */
    public boolean trySaveConfig() {
        try {
            JsonObject obj = new JsonObject();
            obj.addProperty("matchMode", config.getMatchMode().name());
            obj.addProperty("checkWholeRequest", config.isCheckWholeRequest());
            obj.addProperty("sensitiveDetectionEnabled", config.isSensitiveDetectionEnabled());
            obj.addProperty("unauthorizedDetectionEnabled", config.isUnauthorizedDetectionEnabled());
            obj.addProperty("rateLimitPerSecond", config.getRateLimitPerSecond());
            obj.addProperty("codeRepoPath", config.getCodeRepoPath());

            JsonArray reposArr = new JsonArray();
            for (CodeRepo repo : config.getCodeRepos()) {
                JsonObject repoObj = new JsonObject();
                repoObj.addProperty("name", repo.getName());
                repoObj.addProperty("path", repo.getPath());
                JsonArray domainsArr = new JsonArray();
                for (String d : repo.getDomains()) domainsArr.add(d);
                repoObj.add("domains", domainsArr);
                reposArr.add(repoObj);
            }
            obj.add("codeRepos", reposArr);
            obj.addProperty("configVersion", 2);

            // Auth session config
            obj.addProperty("authSessionACookie", config.getAuthSessionACookie());
            obj.addProperty("authSessionALabel", config.getAuthSessionALabel());
            obj.addProperty("authSessionAAuthHeaders", config.getAuthSessionAAuthHeaders());
            obj.addProperty("authSessionADomain", config.getAuthSessionADomain());
            obj.addProperty("authSessionALevel", config.getAuthSessionALevel());
            obj.addProperty("authSessionAGroup", config.getAuthSessionAGroup());
            obj.addProperty("authSessionBCookie", config.getAuthSessionBCookie());
            obj.addProperty("authSessionBLabel", config.getAuthSessionBLabel());
            obj.addProperty("authSessionBAuthHeaders", config.getAuthSessionBAuthHeaders());
            obj.addProperty("authSessionBDomain", config.getAuthSessionBDomain());
            obj.addProperty("authSessionBLevel", config.getAuthSessionBLevel());
            obj.addProperty("authSessionBGroup", config.getAuthSessionBGroup());
            obj.addProperty("authSessionCCookie", config.getAuthSessionCCookie());
            obj.addProperty("authSessionCLabel", config.getAuthSessionCLabel());
            obj.addProperty("authSessionCAuthHeaders", config.getAuthSessionCAuthHeaders());
            obj.addProperty("authSessionCDomain", config.getAuthSessionCDomain());
            obj.addProperty("authSessionCLevel", config.getAuthSessionCLevel());
            obj.addProperty("authSessionCGroup", config.getAuthSessionCGroup());

            // Split pane positions
            obj.addProperty("mainSplitLocation", config.getMainSplitLocation());

            obj.addProperty("focusExcludeMethods", config.getFocusExcludeMethods());

            // OOB (blind SSRF) detection
            obj.addProperty("oobEnabled", config.isOobEnabled());
            obj.addProperty("oobProvider", config.getOobProvider());
            obj.addProperty("oobInternalBaseDomain", config.getOobInternalBaseDomain());
            obj.addProperty("oobInternalTestUrl", config.getOobInternalTestUrl());

            // Highlight toggle
            obj.addProperty("highlightEnabled", config.isHighlightEnabled());

            // LLM context window (tokens) — used to size the Agent loop's budget
            obj.addProperty("contextWindowTokens", config.getContextWindowTokens());
            obj.addProperty("dailyBudgetTokens", config.getDailyBudgetTokens());
            obj.addProperty("perRequestMaxTokens", config.getPerRequestMaxTokens());

            // AgentController auto-pilot (background auto-scan), separate from
            // the per-entry Pipeline/Agent mode toggle
            obj.addProperty("autoScanEnabled", config.isAutoScanEnabled());
            obj.addProperty("cascadeHuntEnabled", config.isCascadeHuntEnabled());

            // WAF block detection + encoded-variant retry
            obj.addProperty("wafDetectionEnabled", config.isWafDetectionEnabled());
            obj.addProperty("codeExecutionAutoApprove", config.isCodeExecutionAutoApprove());
            obj.addProperty("skipAllPermissions", config.isSkipAllPermissions());
            // Tool management
            com.google.gson.JsonArray disabledArr = new com.google.gson.JsonArray();
            for (String t : config.getDisabledTools()) disabledArr.add(t);
            obj.add("disabledTools", disabledArr);
            com.google.gson.JsonArray authArr = new com.google.gson.JsonArray();
            for (String t : config.getToolsRequiringAuth()) authArr.add(t);
            obj.add("toolsRequiringAuth", authArr);
            obj.addProperty("wafRetryEnabled", config.isWafRetryEnabled());

            // Active probes (CORS/JWT/CRLF/NoSQL programmatic verification)
            obj.addProperty("activeProbeEnabled", config.isActiveProbeEnabled());

            // Blind SQLi verification (boolean + timing, capped)
            obj.addProperty("blindVerificationEnabled", config.isBlindVerificationEnabled());
            obj.addProperty("maxBlindProbeRequests", config.getMaxBlindProbeRequests());

            // Business-logic verification (real business ops — opt-in)
            obj.addProperty("businessLogicVerificationEnabled", config.isBusinessLogicVerificationEnabled());

            // AI arbitration for auth-test gray zone (SUSPICIOUS similarity band)
            obj.addProperty("aiAuthArbitrationEnabled", config.isAiAuthArbitrationEnabled());

            // Code analysis enhancements
            obj.addProperty("sinkMapEnabled", config.isSinkMapEnabled());
            obj.addProperty("fileWatcherEnabled", config.isFileWatcherEnabled());
            obj.addProperty("maxCodeFollowHops", config.getMaxCodeFollowHops());

            // MCP server (expose API-Sentinel to external Claude)
            obj.addProperty("mcpServerEnabled", config.isMcpServerEnabled());
            obj.addProperty("mcpServerPort", config.getMcpServerPort());
            obj.addProperty("mcpAllowActiveTools", config.isMcpAllowActiveTools());
            obj.addProperty("mcpAuthToken", config.getMcpAuthToken());
            obj.addProperty("mcpRequireAuth", config.isMcpRequireAuth());
            obj.addProperty("modelTieringEnabled", config.isModelTieringEnabled());
            obj.addProperty("filterOptionsPreflightEnabled", config.isFilterOptionsPreflightEnabled());
            obj.addProperty("bambdaHighlightEnabled", config.isBambdaHighlightEnabled());
            obj.addProperty("bambdaHighlightKeywords", config.getBambdaHighlightKeywords());
            obj.addProperty("organizerAutoSendEnabled", config.isOrganizerAutoSendEnabled());
            obj.addProperty("auditHighRiskOnly", config.isAuditHighRiskOnly());
            obj.addProperty("analysisReuseWindowMinutes", config.getAnalysisReuseWindowMinutes());

            // F-1: Browser capabilities
            obj.addProperty("browserEnabled", config.isBrowserEnabled());
            obj.addProperty("browserHeadless", config.isBrowserHeadless());
            obj.addProperty("browserChromePath", config.getBrowserChromePath());
            obj.addProperty("browserMaxPages", config.getBrowserMaxPages());
            obj.addProperty("browserFrontendUrl", config.getBrowserFrontendUrl());
            obj.addProperty("agentMode", config.isAgentMode());
            obj.addProperty("batchConcurrent", config.isBatchConcurrent());
            obj.addProperty("funFeaturesEnabled", config.isFunFeaturesEnabled());
            obj.addProperty("effectsEnabled", config.isEffectsEnabled());

            // P1-6: sensitive-data opt-in. Default false = redact
            // credentials before the LLM sees them. firstRunDisclosureDone
            // tracks whether the user has seen the "credentials go to the
            // LLM" warning at least once.
            obj.addProperty("includeRawCredentialsInLlm", config.isIncludeRawCredentialsInLlm());
            obj.addProperty("firstRunDisclosureDone", config.isFirstRunDisclosureDone());

            // P0-12 #8: honour the boolean ConfigStore.write() returns —
            // a false (disk full / read-only / permission denied) is
            // treated as a failure the same way an exception is, so the
            // caller sees a single unified "did this persist?" answer.
            boolean ok = configStore.write(CONFIG_FILENAME, GSON.toJson(obj));
            if (!ok && logger != null) {
                logger.error("保存配置失败: ConfigStore.write 返回 false (磁盘可能已满或只读)");
            }
            return ok;
        } catch (Exception e) {
            if (logger != null) logger.error("保存配置失败: %s", e.getMessage());
            return false;
        }
    }

    private void loadConfig() {
        try {
            String json = configStore.read(CONFIG_FILENAME);
            if (json == null) return;
            JsonObject obj = JsonParser.parseString(json).getAsJsonObject();

            if (obj.has("matchMode")) {
                try {
                    MatchMode loaded = MatchMode.valueOf(obj.get("matchMode").getAsString());
                    config.setMatchMode(loaded.normalize()); // normalize legacy SEMI_EXACT/AI_SMART → EXACT
                }
                catch (IllegalArgumentException ignored) {}
            }
            if (obj.has("checkWholeRequest")) config.setCheckWholeRequest(obj.get("checkWholeRequest").getAsBoolean());
            if (obj.has("sensitiveDetectionEnabled")) config.setSensitiveDetectionEnabled(obj.get("sensitiveDetectionEnabled").getAsBoolean());
            if (obj.has("unauthorizedDetectionEnabled")) config.setUnauthorizedDetectionEnabled(obj.get("unauthorizedDetectionEnabled").getAsBoolean());
            if (obj.has("rateLimitPerSecond")) config.setRateLimitPerSecond(obj.get("rateLimitPerSecond").getAsInt());
            if (obj.has("codeRepoPath")) config.setCodeRepoPath(obj.get("codeRepoPath").getAsString());

            if (obj.has("codeRepos") && obj.get("codeRepos").isJsonArray()) {
                List<CodeRepo> repos = new ArrayList<>();
                for (var elem : obj.getAsJsonArray("codeRepos")) {
                    if (!elem.isJsonObject()) continue;
                    JsonObject repoObj = elem.getAsJsonObject();
                    String rName = repoObj.has("name") ? repoObj.get("name").getAsString() : "";
                    String rPath = repoObj.has("path") ? repoObj.get("path").getAsString() : "";
                    List<String> rDomains = new ArrayList<>();
                    if (repoObj.has("domains") && repoObj.get("domains").isJsonArray()) {
                        for (var d : repoObj.getAsJsonArray("domains")) {
                            rDomains.add(d.getAsString());
                        }
                    }
                    repos.add(new CodeRepo(rName, rPath, rDomains));
                }
                config.setCodeRepos(repos);
            } else if (obj.has("codeRepoPath") && !obj.get("codeRepoPath").getAsString().isEmpty()) {
                String oldPath = obj.get("codeRepoPath").getAsString();
                java.nio.file.Path p = java.nio.file.Path.of(oldPath);
                String repoName = p.getFileName() != null ? p.getFileName().toString() : "default";
                config.setCodeRepos(List.of(new CodeRepo(repoName, oldPath, List.of())));
                if (logger != null) logger.info("已将旧版 codeRepoPath 迁移为多仓库配置");
            }

            // Auth session config
            if (obj.has("authSessionACookie")) config.setAuthSessionACookie(obj.get("authSessionACookie").getAsString());
            if (obj.has("authSessionALabel")) config.setAuthSessionALabel(obj.get("authSessionALabel").getAsString());
            if (obj.has("authSessionAAuthHeaders")) config.setAuthSessionAAuthHeaders(obj.get("authSessionAAuthHeaders").getAsString());
            if (obj.has("authSessionADomain")) config.setAuthSessionADomain(obj.get("authSessionADomain").getAsString());
            if (obj.has("authSessionALevel")) config.setAuthSessionALevel(obj.get("authSessionALevel").getAsString());
            if (obj.has("authSessionAGroup")) config.setAuthSessionAGroup(obj.get("authSessionAGroup").getAsString());
            if (obj.has("authSessionBCookie")) config.setAuthSessionBCookie(obj.get("authSessionBCookie").getAsString());
            if (obj.has("authSessionBLabel")) config.setAuthSessionBLabel(obj.get("authSessionBLabel").getAsString());
            if (obj.has("authSessionBAuthHeaders")) config.setAuthSessionBAuthHeaders(obj.get("authSessionBAuthHeaders").getAsString());
            if (obj.has("authSessionBDomain")) config.setAuthSessionBDomain(obj.get("authSessionBDomain").getAsString());
            if (obj.has("authSessionBLevel")) config.setAuthSessionBLevel(obj.get("authSessionBLevel").getAsString());
            if (obj.has("authSessionBGroup")) config.setAuthSessionBGroup(obj.get("authSessionBGroup").getAsString());
            if (obj.has("authSessionCCookie")) config.setAuthSessionCCookie(obj.get("authSessionCCookie").getAsString());
            if (obj.has("authSessionCLabel")) config.setAuthSessionCLabel(obj.get("authSessionCLabel").getAsString());
            if (obj.has("authSessionCAuthHeaders")) config.setAuthSessionCAuthHeaders(obj.get("authSessionCAuthHeaders").getAsString());
            if (obj.has("authSessionCDomain")) config.setAuthSessionCDomain(obj.get("authSessionCDomain").getAsString());
            if (obj.has("authSessionCLevel")) config.setAuthSessionCLevel(obj.get("authSessionCLevel").getAsString());
            if (obj.has("authSessionCGroup")) config.setAuthSessionCGroup(obj.get("authSessionCGroup").getAsString());

            // Split pane positions
            if (obj.has("mainSplitLocation")) config.setMainSplitLocation(obj.get("mainSplitLocation").getAsInt());

            if (obj.has("focusExcludeMethods")) config.setFocusExcludeMethods(obj.get("focusExcludeMethods").getAsString());

            // OOB (blind SSRF) detection
            if (obj.has("oobEnabled")) config.setOobEnabled(obj.get("oobEnabled").getAsBoolean());
            if (obj.has("oobProvider")) config.setOobProvider(obj.get("oobProvider").getAsString());
            if (obj.has("oobInternalBaseDomain")) config.setOobInternalBaseDomain(obj.get("oobInternalBaseDomain").getAsString());
            if (obj.has("oobInternalTestUrl")) config.setOobInternalTestUrl(obj.get("oobInternalTestUrl").getAsString());
            if (obj.has("highlightEnabled")) config.setHighlightEnabled(obj.get("highlightEnabled").getAsBoolean());
            if (obj.has("contextWindowTokens")) config.setContextWindowTokens(obj.get("contextWindowTokens").getAsInt());
            if (obj.has("dailyBudgetTokens")) config.setDailyBudgetTokens(obj.get("dailyBudgetTokens").getAsInt());
            if (obj.has("perRequestMaxTokens")) config.setPerRequestMaxTokens(obj.get("perRequestMaxTokens").getAsInt());
            if (obj.has("autoScanEnabled")) config.setAutoScanEnabled(obj.get("autoScanEnabled").getAsBoolean());
                        if (obj.has("cascadeHuntEnabled")) config.setCascadeHuntEnabled(obj.get("cascadeHuntEnabled").getAsBoolean());
            if (obj.has("wafDetectionEnabled")) config.setWafDetectionEnabled(obj.get("wafDetectionEnabled").getAsBoolean());
            if (obj.has("codeExecutionAutoApprove")) config.setCodeExecutionAutoApprove(obj.get("codeExecutionAutoApprove").getAsBoolean());
            if (obj.has("skipAllPermissions")) {
                config.setSkipAllPermissions(obj.get("skipAllPermissions").getAsBoolean());
                System.setProperty("api-sentinel.skip-permissions",
                        String.valueOf(obj.get("skipAllPermissions").getAsBoolean()));
            }
            if (obj.has("disabledTools") && obj.get("disabledTools").isJsonArray()) {
                java.util.Set<String> set = java.util.concurrent.ConcurrentHashMap.newKeySet();
                for (var e : obj.getAsJsonArray("disabledTools")) set.add(e.getAsString());
                config.setDisabledTools(set);
            }
            if (obj.has("toolsRequiringAuth") && obj.get("toolsRequiringAuth").isJsonArray()) {
                java.util.Set<String> set = java.util.concurrent.ConcurrentHashMap.newKeySet();
                for (var e : obj.getAsJsonArray("toolsRequiringAuth")) set.add(e.getAsString());
                config.setToolsRequiringAuth(set);
            }
            if (obj.has("wafRetryEnabled")) config.setWafRetryEnabled(obj.get("wafRetryEnabled").getAsBoolean());
            if (obj.has("activeProbeEnabled")) config.setActiveProbeEnabled(obj.get("activeProbeEnabled").getAsBoolean());
            if (obj.has("blindVerificationEnabled")) config.setBlindVerificationEnabled(obj.get("blindVerificationEnabled").getAsBoolean());
            if (obj.has("maxBlindProbeRequests")) config.setMaxBlindProbeRequests(obj.get("maxBlindProbeRequests").getAsInt());
            if (obj.has("businessLogicVerificationEnabled")) config.setBusinessLogicVerificationEnabled(obj.get("businessLogicVerificationEnabled").getAsBoolean());
            if (obj.has("aiAuthArbitrationEnabled")) config.setAiAuthArbitrationEnabled(obj.get("aiAuthArbitrationEnabled").getAsBoolean());
            if (obj.has("sinkMapEnabled")) config.setSinkMapEnabled(obj.get("sinkMapEnabled").getAsBoolean());
            if (obj.has("fileWatcherEnabled")) config.setFileWatcherEnabled(obj.get("fileWatcherEnabled").getAsBoolean());
            if (obj.has("maxCodeFollowHops")) config.setMaxCodeFollowHops(obj.get("maxCodeFollowHops").getAsInt());
            if (obj.has("mcpServerEnabled")) config.setMcpServerEnabled(obj.get("mcpServerEnabled").getAsBoolean());
            if (obj.has("mcpServerPort")) config.setMcpServerPort(obj.get("mcpServerPort").getAsInt());
            if (obj.has("mcpAllowActiveTools")) config.setMcpAllowActiveTools(obj.get("mcpAllowActiveTools").getAsBoolean());
            if (obj.has("mcpAuthToken")) config.setMcpAuthToken(obj.get("mcpAuthToken").getAsString());
            if (obj.has("mcpRequireAuth")) config.setMcpRequireAuth(obj.get("mcpRequireAuth").getAsBoolean());
            if (obj.has("modelTieringEnabled")) config.setModelTieringEnabled(obj.get("modelTieringEnabled").getAsBoolean());
            if (obj.has("filterOptionsPreflightEnabled")) config.setFilterOptionsPreflightEnabled(obj.get("filterOptionsPreflightEnabled").getAsBoolean());
            if (obj.has("bambdaHighlightEnabled")) config.setBambdaHighlightEnabled(obj.get("bambdaHighlightEnabled").getAsBoolean());
            if (obj.has("bambdaHighlightKeywords")) config.setBambdaHighlightKeywords(obj.get("bambdaHighlightKeywords").getAsString());
            if (obj.has("organizerAutoSendEnabled")) config.setOrganizerAutoSendEnabled(obj.get("organizerAutoSendEnabled").getAsBoolean());
            if (obj.has("auditHighRiskOnly")) config.setAuditHighRiskOnly(obj.get("auditHighRiskOnly").getAsBoolean());
            if (obj.has("analysisReuseWindowMinutes")) config.setAnalysisReuseWindowMinutes(obj.get("analysisReuseWindowMinutes").getAsInt());

            // F-1: Browser capabilities
            if (obj.has("browserEnabled")) config.setBrowserEnabled(obj.get("browserEnabled").getAsBoolean());
            if (obj.has("includeRawCredentialsInLlm")) config.setIncludeRawCredentialsInLlm(obj.get("includeRawCredentialsInLlm").getAsBoolean());
            if (obj.has("firstRunDisclosureDone")) config.setFirstRunDisclosureDone(obj.get("firstRunDisclosureDone").getAsBoolean());
            if (obj.has("browserHeadless")) config.setBrowserHeadless(obj.get("browserHeadless").getAsBoolean());
            if (obj.has("browserChromePath")) config.setBrowserChromePath(obj.get("browserChromePath").getAsString());
            if (obj.has("browserMaxPages")) config.setBrowserMaxPages(obj.get("browserMaxPages").getAsInt());
            if (obj.has("browserFrontendUrl")) config.setBrowserFrontendUrl(obj.get("browserFrontendUrl").getAsString());
            if (obj.has("agentMode")) config.setAgentMode(obj.get("agentMode").getAsBoolean());
            if (obj.has("batchConcurrent")) config.setBatchConcurrent(obj.get("batchConcurrent").getAsBoolean());
            if (obj.has("funFeaturesEnabled")) config.setFunFeaturesEnabled(obj.get("funFeaturesEnabled").getAsBoolean());
            if (obj.has("effectsEnabled")) config.setEffectsEnabled(obj.get("effectsEnabled").getAsBoolean());

            if (logger != null) logger.debug("已加载配置: %s", CONFIG_FILENAME);
        } catch (Exception e) {
            if (logger != null) logger.warn("加载配置失败，使用默认值: %s", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void loadSensitiveRules() {
        List<SensitiveRule> rules = new ArrayList<>();
        try (InputStream is = getClass().getResourceAsStream("/rules/sensitive.yml")) {
            if (is == null) {
                if (logger != null) logger.warn("未找到敏感信息规则文件: /rules/sensitive.yml");
                config.setSensitiveRules(rules);
                return;
            }
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(is);
            List<Map<String, String>> ruleList = (List<Map<String, String>>) data.get("rules");
            if (ruleList != null) {
                for (Map<String, String> ruleMap : ruleList) {
                    String name = ruleMap.get("name");
                    String regex = ruleMap.get("regex");
                    String group = ruleMap.getOrDefault("group", "default");
                    String filter = ruleMap.get("filter");
                    SensitiveRule.Scope scope = parseScope(ruleMap.get("scope"));
                    if (name != null && regex != null) {
                        try {
                            rules.add(new SensitiveRule(name, regex, group, filter, scope));
                        } catch (Exception e) {
                            if (logger != null) logger.warn("无效的正则规则 [%s]: %s", name, e.getMessage());
                        }
                    }
                }
            }
            if (logger != null) logger.debug("已加载 %d 条敏感信息规则", rules.size());
        } catch (Exception e) {
            if (logger != null) logger.error("加载敏感信息规则失败", e);
        }
        rules.addAll(loadUserSensitiveRules());
        config.setSensitiveRules(rules);
    }

    private static SensitiveRule.Scope parseScope(String raw) {
        if (raw == null) return SensitiveRule.Scope.RESPONSE;
        return switch (raw.trim().toLowerCase()) {
            case "request" -> SensitiveRule.Scope.REQUEST;
            case "any" -> SensitiveRule.Scope.ANY;
            default -> SensitiveRule.Scope.RESPONSE;
        };
    }

    /**
     * User-defined rules from sensitive-rules.json (managed by
     * SensitiveRulesPanel). Previously these were saved by the panel but
     * never read here — the detector only ever saw built-ins (broken chain).
     * User rules are treated as scope=ANY with no exclusion filter.
     */
    private List<SensitiveRule> loadUserSensitiveRules() {
        List<SensitiveRule> out = new ArrayList<>();
        try {
            java.nio.file.Path file = AppPaths.sensitiveRulesFile();
            if (!java.nio.file.Files.exists(file)) return out;
            String json = java.nio.file.Files.readString(file);
            com.google.gson.JsonArray arr = com.google.gson.JsonParser.parseString(json).getAsJsonArray();
            for (var el : arr) {
                if (!el.isJsonObject()) continue;
                var o = el.getAsJsonObject();
                String name = o.has("name") ? o.get("name").getAsString() : null;
                String regex = o.has("regex") ? o.get("regex").getAsString() : null;
                String group = o.has("group") ? o.get("group").getAsString() : "用户规则";
                if (name != null && regex != null) {
                    try {
                        out.add(new SensitiveRule(name, regex, group, null, SensitiveRule.Scope.ANY));
                    } catch (Exception e) {
                        if (logger != null) logger.warn("无效的用户规则 [%s]: %s", name, e.getMessage());
                    }
                }
            }
            if (!out.isEmpty() && logger != null) {
                logger.info("已合并 %d 条用户敏感信息规则", out.size());
            }
        } catch (Exception e) {
            if (logger != null) logger.warn("加载用户敏感信息规则失败: %s", e.getMessage());
        }
        return out;
    }

    /** Re-run the full rule load (built-ins + user file). Called by
     *  SensitiveRulesPanel after the user saves custom rules so they take
     *  effect immediately. */
    public void reloadSensitiveRules() {
        loadSensitiveRules();
    }
}
