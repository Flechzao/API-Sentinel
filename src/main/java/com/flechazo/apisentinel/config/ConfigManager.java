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



    public void addListener(Consumer<AppConfig> listener) {
        listeners.add(listener);
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
            obj.addProperty("authSessionBCookie", config.getAuthSessionBCookie());
            obj.addProperty("authSessionBLabel", config.getAuthSessionBLabel());

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

            // AgentController auto-pilot (background auto-scan), separate from
            // the per-entry Pipeline/Agent mode toggle
            obj.addProperty("autoScanEnabled", config.isAutoScanEnabled());
            obj.addProperty("cascadeHuntEnabled", config.isCascadeHuntEnabled());

            // WAF block detection + encoded-variant retry
            obj.addProperty("wafDetectionEnabled", config.isWafDetectionEnabled());
            obj.addProperty("codeExecutionAutoApprove", config.isCodeExecutionAutoApprove());
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
            obj.addProperty("organizerAutoSendEnabled", config.isOrganizerAutoSendEnabled());
            obj.addProperty("auditHighRiskOnly", config.isAuditHighRiskOnly());
            obj.addProperty("analysisReuseWindowMinutes", config.getAnalysisReuseWindowMinutes());

            configStore.write(CONFIG_FILENAME, GSON.toJson(obj));
        } catch (Exception e) {
            if (logger != null) logger.error("保存配置失败: %s", e.getMessage());
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
            if (obj.has("authSessionBCookie")) config.setAuthSessionBCookie(obj.get("authSessionBCookie").getAsString());
            if (obj.has("authSessionBLabel")) config.setAuthSessionBLabel(obj.get("authSessionBLabel").getAsString());

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
            if (obj.has("autoScanEnabled")) config.setAutoScanEnabled(obj.get("autoScanEnabled").getAsBoolean());
                        if (obj.has("cascadeHuntEnabled")) config.setCascadeHuntEnabled(obj.get("cascadeHuntEnabled").getAsBoolean());
            if (obj.has("wafDetectionEnabled")) config.setWafDetectionEnabled(obj.get("wafDetectionEnabled").getAsBoolean());
            if (obj.has("codeExecutionAutoApprove")) config.setCodeExecutionAutoApprove(obj.get("codeExecutionAutoApprove").getAsBoolean());
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
            if (obj.has("organizerAutoSendEnabled")) config.setOrganizerAutoSendEnabled(obj.get("organizerAutoSendEnabled").getAsBoolean());
            if (obj.has("auditHighRiskOnly")) config.setAuditHighRiskOnly(obj.get("auditHighRiskOnly").getAsBoolean());
            if (obj.has("analysisReuseWindowMinutes")) config.setAnalysisReuseWindowMinutes(obj.get("analysisReuseWindowMinutes").getAsInt());

            if (logger != null) logger.info("已加载配置: %s", CONFIG_FILENAME);
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
            if (logger != null) logger.info("已加载 %d 条敏感信息规则", rules.size());
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
