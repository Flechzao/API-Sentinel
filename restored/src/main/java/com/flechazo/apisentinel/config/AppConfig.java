package com.flechazo.apisentinel.config;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class AppConfig {

    private volatile MatchMode matchMode;
    private volatile boolean checkWholeRequest;
    private volatile boolean sensitiveDetectionEnabled;
    private volatile boolean unauthorizedDetectionEnabled;
    private volatile int rateLimitPerSecond;
    private volatile Path dataFilePath;
    private volatile List<SensitiveRule> sensitiveRules;
    private volatile String codeRepoPath;
    private volatile List<CodeRepo> codeRepos;
    private volatile double aiConfidenceThreshold;
    private volatile String authSessionACookie;
    private volatile String authSessionALabel;
    private volatile String authSessionBCookie;
    private volatile String authSessionBLabel;
    private volatile int mainSplitLocation;
    private volatile String focusExcludeMethods;
    // --- OOB (blind SSRF) detection: optional, off by default ---
    private volatile boolean oobEnabled;
    private volatile String oobProvider;          // "collaborator" | "internal"
    private volatile String oobInternalBaseDomain; // dnslog base, e.g. "xxx.dnslog.cn"
    private volatile String oobInternalTestUrl;    // reachability check URL (optional, internal only)
    /** Whether to apply highlight colors to Proxy history annotations.
     *  Turn off when testing many APIs and old tested entries' colors clutter. */
    private volatile boolean highlightEnabled;
    /** Approximate context window (tokens) of the configured LLM, used to size
     *  the Agent loop's compaction budget. Cloud models (Claude/GPT) can take a
     *  much larger value; local Ollama models vary widely, so this is not
     *  auto-detected — edit it here (or in config.json) to match your model. */
    private volatile int contextWindowTokens;
    /** AgentController auto-pilot: background auto-analysis of every matched
     *  API (not the per-entry Pipeline/Agent mode toggle — deliberately a
     *  separate switch since auto-scanning everything spends LLM budget
     *  continuously and shouldn't be a side effect of picking Agent mode
     *  for manual single-entry analysis). Off by default. */
    private volatile boolean autoScanEnabled;
    /** Cascade hunting (sibling-route spreading after verified confirms).
     *  Sub-switch of the auto-pilot: only meaningful while autoScan is on.
     *  Defaults on — the GoalState breaker already bounds the blast radius. */
    private volatile boolean cascadeHuntEnabled = true;
    // --- WAF block detection: passive fingerprinting of payload responses ---
    /** Detect WAF block/challenge pages among payload responses so blocked
     *  payloads aren't misread as "safe". Detection is passive (no extra
     *  traffic); enabled by default. */
    private volatile boolean wafDetectionEnabled;
    private volatile boolean codeExecutionAutoApprove;
    /** When a payload is WAF-blocked, retry with a few encoded variants.
     *  Only fires on blocked responses; capped per run. Config-file toggle
     *  (not in toolbar) since it adds request volume. */
    private volatile boolean wafRetryEnabled;
    // --- Active probes: programmatic CORS/JWT/CRLF/NoSQL verification ---
    /** Active probes send extra requests (CORS origin variants, alg:none
     *  replays, CRLF canaries, NoSQL operator tests) — opt-in like OOB. */
    private volatile boolean activeProbeEnabled;
    // --- Blind SQLi verification (targets only AI-flagged suspicious params) ---
    /** Programmatic boolean/timing blind verification, capped per run. */
    private volatile boolean blindVerificationEnabled;
    /** Max probe requests for blind verification per analysis run. */
    private volatile int maxBlindProbeRequests;
    /** Business-logic verification (price tamper / coupon replay / race…)
     *  performs REAL business operations — opt-in like activeProbe. */
    private volatile boolean businessLogicVerificationEnabled;
    /** LLM arbitration when auth-test Jaccard similarity lands in the
     *  SUSPICIOUS gray band (0.60-0.85). Costs one LLM call per gray-zone
     *  endpoint; enabled by default like blind verification. */
    private volatile boolean aiAuthArbitrationEnabled;
    // --- Code analysis enhancements ---
    private volatile boolean sinkMapEnabled;
    private volatile boolean fileWatcherEnabled;
    private volatile int maxCodeFollowHops;
    // --- MCP server: expose API-Sentinel to external Claude over MCP ---
    /** Expose API-Sentinel as an MCP server (loopback HTTP) so external Claude
     *  can query APIs / trigger analyses. Off by default (opens a port). */
    private volatile boolean mcpServerEnabled;
    /** After an analysis finds a vuln, auto-send the evidence request/response
     *  to Burp's native Organizer for review. On by default. */
    private volatile boolean organizerAutoSendEnabled;
    /** Global-audit scope control: when true, audit_codebase restricts to
     *  high-risk sink types only (cost control). Default false = audit every
     *  sink (finding vulns is worth more than saving tokens). */
    private volatile boolean auditHighRiskOnly;
    /** Cross-run reuse window (minutes): re-analyzing the same endpoint within
     *  this window injects the previous verdict as "known conclusions" context
     *  to reduce repeated reasoning. 0 disables reuse. */
    private volatile int analysisReuseWindowMinutes;
    /** Loopback port for the MCP server. */
    private volatile int mcpServerPort;

    public AppConfig() {
        this.matchMode = MatchMode.EXACT;
        this.checkWholeRequest = false;
        this.sensitiveDetectionEnabled = true;
        this.unauthorizedDetectionEnabled = true;
        this.rateLimitPerSecond = 5;
        this.dataFilePath = AppPaths.dataFile();
        this.sensitiveRules = List.of();
        this.codeRepoPath = "";
        this.codeRepos = new ArrayList<>();
        this.aiConfidenceThreshold = 0.5;
        this.authSessionACookie = "";
        this.authSessionALabel = "会话 A";
        this.authSessionBCookie = "";
        this.authSessionBLabel = "会话 B";
        this.mainSplitLocation = 300;
        this.focusExcludeMethods = "OPTIONS,HEAD";
        // OOB detection is opt-in (off by default) — user must configure a provider.
        this.oobEnabled = false;
        this.oobProvider = "collaborator";
        this.oobInternalBaseDomain = "";
        this.oobInternalTestUrl = "";
        this.highlightEnabled = true;
        this.contextWindowTokens = 150_000;
        this.autoScanEnabled = false;
        this.cascadeHuntEnabled = true;
        this.wafDetectionEnabled = true;
        // Default off — running generated code always requires an explicit
        // per-call human approval unless the user opts into autonomous mode.
        this.codeExecutionAutoApprove = false;
        this.wafRetryEnabled = true;
        this.activeProbeEnabled = false;
        this.blindVerificationEnabled = true;
        this.maxBlindProbeRequests = 10;
        this.businessLogicVerificationEnabled = false;
        this.aiAuthArbitrationEnabled = true;
        this.sinkMapEnabled = true;
        this.fileWatcherEnabled = false;
        this.maxCodeFollowHops = 3;
        this.mcpServerEnabled = false;
        this.mcpServerPort = 9877;
        this.organizerAutoSendEnabled = true;
        this.auditHighRiskOnly = false;
        this.analysisReuseWindowMinutes = 30;
    }

    public MatchMode getMatchMode() { return matchMode; }
    public void setMatchMode(MatchMode matchMode) { this.matchMode = matchMode; }

    public boolean isCheckWholeRequest() { return checkWholeRequest; }
    public void setCheckWholeRequest(boolean checkWholeRequest) { this.checkWholeRequest = checkWholeRequest; }

    public boolean isSensitiveDetectionEnabled() { return sensitiveDetectionEnabled; }
    public void setSensitiveDetectionEnabled(boolean enabled) { this.sensitiveDetectionEnabled = enabled; }

    public boolean isUnauthorizedDetectionEnabled() { return unauthorizedDetectionEnabled; }
    public void setUnauthorizedDetectionEnabled(boolean enabled) { this.unauthorizedDetectionEnabled = enabled; }

    public int getRateLimitPerSecond() { return rateLimitPerSecond; }
    public void setRateLimitPerSecond(int rate) { this.rateLimitPerSecond = rate; }

    public Path getDataFilePath() { return dataFilePath; }
    public void setDataFilePath(Path dataFilePath) { this.dataFilePath = dataFilePath; }

    public List<SensitiveRule> getSensitiveRules() { return sensitiveRules; }
    public void setSensitiveRules(List<SensitiveRule> rules) { this.sensitiveRules = rules; }

    public String getCodeRepoPath() { return codeRepoPath; }
    public void setCodeRepoPath(String path) { this.codeRepoPath = path != null ? path : ""; }

    public List<CodeRepo> getCodeRepos() { return codeRepos; }
    public void setCodeRepos(List<CodeRepo> repos) { this.codeRepos = repos != null ? repos : new ArrayList<>(); }

    public double getAiConfidenceThreshold() { return aiConfidenceThreshold; }
    public void setAiConfidenceThreshold(double threshold) { this.aiConfidenceThreshold = threshold; }

    public String getAuthSessionACookie() { return authSessionACookie; }
    public void setAuthSessionACookie(String cookie) { this.authSessionACookie = cookie != null ? cookie : ""; }

    public String getAuthSessionALabel() { return authSessionALabel; }
    public void setAuthSessionALabel(String label) { this.authSessionALabel = label != null && !label.isBlank() ? label : "会话 A"; }

    public String getAuthSessionBCookie() { return authSessionBCookie; }
    public void setAuthSessionBCookie(String cookie) { this.authSessionBCookie = cookie != null ? cookie : ""; }

    public String getAuthSessionBLabel() { return authSessionBLabel; }
    public void setAuthSessionBLabel(String label) { this.authSessionBLabel = label != null && !label.isBlank() ? label : "会话 B"; }

    public boolean hasManualAuthSessions() {
        return !authSessionACookie.isBlank() && !authSessionBCookie.isBlank();
    }

    public int getMainSplitLocation() { return mainSplitLocation; }
    public void setMainSplitLocation(int location) { this.mainSplitLocation = Math.max(50, location); }

    public String getFocusExcludeMethods() { return focusExcludeMethods; }
    public void setFocusExcludeMethods(String methods) { this.focusExcludeMethods = methods != null ? methods : ""; }

    public boolean isOobEnabled() { return oobEnabled; }
    public void setOobEnabled(boolean enabled) { this.oobEnabled = enabled; }

    public String getOobProvider() { return oobProvider; }
    public void setOobProvider(String provider) {
        this.oobProvider = ("internal".equalsIgnoreCase(provider)) ? "internal" : "collaborator";
    }

    public String getOobInternalBaseDomain() { return oobInternalBaseDomain; }
    public void setOobInternalBaseDomain(String domain) { this.oobInternalBaseDomain = domain != null ? domain : ""; }

    public String getOobInternalTestUrl() { return oobInternalTestUrl; }
    public void setOobInternalTestUrl(String url) { this.oobInternalTestUrl = url != null ? url : ""; }

    /** Whether OOB is usable with the current config (provider-appropriate fields set). */
    public boolean isOobUsable() {
        if (!oobEnabled) return false;
        if ("internal".equalsIgnoreCase(oobProvider)) {
            return oobInternalBaseDomain != null && !oobInternalBaseDomain.isBlank();
        }
        return true; // collaborator needs only Burp Pro
    }

    public boolean isHighlightEnabled() { return highlightEnabled; }
    public void setHighlightEnabled(boolean enabled) { this.highlightEnabled = enabled; }

    public int getContextWindowTokens() { return contextWindowTokens; }
    public void setContextWindowTokens(int tokens) { this.contextWindowTokens = Math.max(8_000, tokens); }

    public boolean isAutoScanEnabled() { return autoScanEnabled; }
    public void setAutoScanEnabled(boolean enabled) { this.autoScanEnabled = enabled; }

    public boolean isCascadeHuntEnabled() { return cascadeHuntEnabled; }
    public void setCascadeHuntEnabled(boolean enabled) { this.cascadeHuntEnabled = enabled; }

    public boolean isWafDetectionEnabled() { return wafDetectionEnabled; }
    public void setWafDetectionEnabled(boolean enabled) { this.wafDetectionEnabled = enabled; }

    public boolean isCodeExecutionAutoApprove() { return codeExecutionAutoApprove; }
    public void setCodeExecutionAutoApprove(boolean enabled) { this.codeExecutionAutoApprove = enabled; }

    public boolean isWafRetryEnabled() { return wafRetryEnabled; }
    public void setWafRetryEnabled(boolean enabled) { this.wafRetryEnabled = enabled; }

    public boolean isActiveProbeEnabled() { return activeProbeEnabled; }
    public void setActiveProbeEnabled(boolean enabled) { this.activeProbeEnabled = enabled; }

    public boolean isBlindVerificationEnabled() { return blindVerificationEnabled; }
    public void setBlindVerificationEnabled(boolean enabled) { this.blindVerificationEnabled = enabled; }

    public int getMaxBlindProbeRequests() { return maxBlindProbeRequests; }
    public void setMaxBlindProbeRequests(int max) { this.maxBlindProbeRequests = Math.max(2, max); }

    public boolean isBusinessLogicVerificationEnabled() { return businessLogicVerificationEnabled; }
    public void setBusinessLogicVerificationEnabled(boolean enabled) { this.businessLogicVerificationEnabled = enabled; }

    public boolean isAiAuthArbitrationEnabled() { return aiAuthArbitrationEnabled; }
    public void setAiAuthArbitrationEnabled(boolean enabled) { this.aiAuthArbitrationEnabled = enabled; }

    public boolean isSinkMapEnabled() { return sinkMapEnabled; }
    public void setSinkMapEnabled(boolean enabled) { this.sinkMapEnabled = enabled; }

    public boolean isFileWatcherEnabled() { return fileWatcherEnabled; }
    public void setFileWatcherEnabled(boolean enabled) { this.fileWatcherEnabled = enabled; }

    public int getMaxCodeFollowHops() { return maxCodeFollowHops; }
    public void setMaxCodeFollowHops(int hops) { this.maxCodeFollowHops = Math.max(0, Math.min(hops, 5)); }

    public boolean isMcpServerEnabled() { return mcpServerEnabled; }
    public void setMcpServerEnabled(boolean enabled) { this.mcpServerEnabled = enabled; }

    public boolean isOrganizerAutoSendEnabled() { return organizerAutoSendEnabled; }
    public void setOrganizerAutoSendEnabled(boolean enabled) { this.organizerAutoSendEnabled = enabled; }

    public boolean isAuditHighRiskOnly() { return auditHighRiskOnly; }
    public void setAuditHighRiskOnly(boolean enabled) { this.auditHighRiskOnly = enabled; }

    public int getAnalysisReuseWindowMinutes() { return analysisReuseWindowMinutes; }
    public void setAnalysisReuseWindowMinutes(int minutes) { this.analysisReuseWindowMinutes = Math.max(0, minutes); }

    public int getMcpServerPort() { return mcpServerPort; }
    public void setMcpServerPort(int port) { this.mcpServerPort = port > 0 ? port : 9877; }
}
