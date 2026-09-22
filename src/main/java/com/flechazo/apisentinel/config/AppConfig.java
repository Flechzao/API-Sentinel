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
    /** Multi-line "Key: Value" text for non-Cookie auth headers
     *  (Authorization, X-Token, etc.). Empty when the session uses
     *  Cookie-only auth. Persisted alongside {@link #authSessionACookie}
     *  so Bearer-token / API-key users have a working manual fallback. */
    private volatile String authSessionAAuthHeaders;
    /** Domain this session is scoped to. Empty = all domains.
     *  Cookies are domain-specific, so mixing sessions across domains
     *  produces false results. Auto-detect fills this from the request's Host. */
    private volatile String authSessionADomain;
    /** Privilege level for vertical-escalation direction inference.
     *  Values: "" (unknown), "HIGH", "MEDIUM", "LOW". Used by the auth
     *  test executor to label a bypass as horizontal vs vertical. */
    private volatile String authSessionALevel;
    /** Tenant/group label for horizontal vs vertical escalation inference.
     *  Same level + different group = horizontal IDOR.
     *  Different level + same group = vertical privilege escalation. */
    private volatile String authSessionAGroup;

    private volatile String authSessionBCookie;
    private volatile String authSessionBLabel;
    /** @see #authSessionAAuthHeaders */
    private volatile String authSessionBAuthHeaders;
    /** @see #authSessionADomain */
    private volatile String authSessionBDomain;
    /** @see #authSessionALevel */
    private volatile String authSessionBLevel;
    /** @see #authSessionAGroup */
    private volatile String authSessionBGroup;

    private volatile String authSessionCCookie;
    private volatile String authSessionCLabel;
    /** @see #authSessionAAuthHeaders */
    private volatile String authSessionCAuthHeaders;
    /** @see #authSessionADomain */
    private volatile String authSessionCDomain;
    /** @see #authSessionALevel */
    private volatile String authSessionCLevel;
    /** @see #authSessionAGroup */
    private volatile String authSessionCGroup;

    private volatile String authHeader;
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
    /** Daily soft cap on billable input+output tokens across every LLM
     *  call in the extension (P0-6: enforced at the provider boundary by
     *  {@code BudgetedLlmProvider} / {@code TokenBudgetManager}). Defaults
     *  to 500K — matches the pre-P0-6 hardcoded value in
     *  {@code TokenBudgetManager}, so users who haven't touched this field
     *  see no behavior change. */
    private volatile int dailyBudgetTokens;
    /** Per-call hard cap on estimated billable tokens. Requests whose
     *  estimate exceeds this are rejected pre-flight. Defaults to 50K
     *  (same historic value). */
    private volatile int perRequestMaxTokens;
    /** Budget enforcement mode: ENFORCE (block when exceeded) or MONITOR_ONLY
     *  (record but never block). Defaults to MONITOR_ONLY — most users don't
     *  want LLM calls blocked mid-analysis. Usage is still tracked and
     *  visible in UI/reports. */
    private volatile com.flechazo.apisentinel.ai.budget.BudgetMode budgetMode =
            com.flechazo.apisentinel.ai.budget.BudgetMode.MONITOR_ONLY;
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
    /** Skip all permission prompts (browser interact, code execution, ask_user).
     *  Equivalent to --dangerously-skip-permissions. Use with caution. */
    private volatile boolean skipAllPermissions;
    /** Tools disabled by the user (tool name strings). These won't be registered
     *  in StandardToolRegistry.build(). */
    private volatile java.util.Set<String> disabledTools = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** Tools that require explicit user authorization before each execution. */
    private volatile java.util.Set<String> toolsRequiringAuth = java.util.concurrent.ConcurrentHashMap.newKeySet();
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
     *  Code / Codex / Qoder can query APIs / trigger analyses / validate findings.
     *  On by default: loopback-only + Bearer-token authenticated. Toggling it in
     *  设置→高级→MCP starts/stops the server live (no extension reload needed). */
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
    /** Whether MCP clients may call active/dangerous agent tools (send_request,
     *  active_probe, run_sandboxed_code, browser_interact, verify_*, …). Default
     *  false: only read-only white-box + browser render/discover/dom_xss are
     *  exposed. Turning this on lets the external brain drive attack traffic
     *  through Burp — the same arsenal the built-in Agent uses. */
    private volatile boolean mcpAllowActiveTools;
    /** Persistent MCP bearer token. Empty on first run → generated once and
     *  saved, so the token stays stable across restarts (clients don't need
     *  reconfiguring every time). */
    private volatile String mcpAuthToken = "";
    /** Whether the MCP server requires the bearer token. Default true (secure).
     *  Turn off to match Burp's native MCP (loopback + Origin/Host guards only). */
    private volatile boolean mcpRequireAuth = true;
    /** Master switch: when on, cost-tiered nodes (payload generation, exploration
     *  sub-agents) also use the configured 轻量模型 (fastModel) instead of the
     *  main model. Off by default = no behaviour change. Judgment/verdict nodes
     *  always use the main model regardless. */
    private volatile boolean modelTieringEnabled = false;
    /** "Filter OPTIONS preflight": rewrite CORS-preflight OPTIONS proxy responses
     *  to text/css + a marker body so Burp's proxy history hides them (Burp's
     *  default MIME filter drops CSS). Off by default — this MUTATES the live
     *  response the browser receives, so it neutralizes real preflights while on. */
    private volatile boolean filterOptionsPreflightEnabled = false;
    /** Live, non-destructive highlight: mark proxy requests containing any of
     *  these keywords (comma-separated) with a green highlight — an in-Burp
     *  alternative to copy-pasting a keyword Bambda. Off by default. */
    private volatile boolean bambdaHighlightEnabled = false;
    private volatile String bambdaHighlightKeywords = "";

    // --- F-1: Browser capabilities (Playwright + Chromium) ---
    /** Enable browser-based analysis (DOM XSS, SPA discovery, JS secrets). */
    private volatile boolean browserEnabled;
    /** P1-6: when true (default), raw HTTP auth headers (Cookie /
     *  Authorization / x-*-token) are passed to the LLM verbatim —
     *  the Agent needs full auth context for IDOR/CSRF testing. When
     *  false, RequestRedactor strips them first (for compliance
     *  scenarios where the LLM provider is untrusted). Redaction
     *  belongs in the final report, not the analysis pipeline. */
    private volatile boolean includeRawCredentialsInLlm;
    /** P1-6: true once the first-run disclosure dialog has been shown
     *  and the user made a choice (accept or cancel). Until this is
     *  true, every analysis attempt triggers the disclosure dialog
     *  first so the user can't miss the "credentials go to the LLM"
     *  warning. */
    private volatile boolean firstRunDisclosureDone;
    /** Run browser in headless mode (no visible window). */
    private volatile boolean browserHeadless;
    /** Custom Chrome/Chromium path (empty = use Playwright's bundled browser). */
    private volatile String browserChromePath;
    /** Max pages to visit during browser_discover exploration. */
    private volatile int browserMaxPages;
    /** Frontend base URL for reverse page location (browser_find_page).
     *  E.g. "http://localhost:3000". Empty = disabled. */
    private volatile String browserFrontendUrl;
    /** Analysis mode: true = Agent (autonomous), false = Pipeline (6-stage).
     *  Default true — Agent is the more capable path. */
    private volatile boolean agentMode = true;
    /** Parallel batch analysis: true = 4 concurrent, false = serial. */
    private volatile boolean batchConcurrent = true;
    // --- Fun features: achievements, effects, sounds ---
    /** Master switch for fun features (achievements, particle effects, sounds). */
    private volatile boolean funFeaturesEnabled = true;
    /** Enable particle effects when discovering vulnerabilities. */
    private volatile boolean effectsEnabled = true;

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
        this.authSessionAAuthHeaders = "";
        this.authSessionADomain = "";
        this.authSessionALevel = "";
        this.authSessionAGroup = "";
        this.authSessionBCookie = "";
        this.authSessionBLabel = "会话 B";
        this.authSessionBAuthHeaders = "";
        this.authSessionBDomain = "";
        this.authSessionBLevel = "";
        this.authSessionBGroup = "";
        this.authSessionCCookie = "";
        this.authSessionCLabel = "会话 C";
        this.authSessionCAuthHeaders = "";
        this.authSessionCDomain = "";
        this.authSessionCLevel = "";
        this.authSessionCGroup = "";
        this.mainSplitLocation = 300;
        this.focusExcludeMethods = "OPTIONS,HEAD";
        // OOB detection is opt-in (off by default) — user must configure a provider.
        this.oobEnabled = false;
        this.oobProvider = "collaborator";
        this.oobInternalBaseDomain = "";
        this.oobInternalTestUrl = "";
        this.highlightEnabled = true;
        this.contextWindowTokens = 150_000;
        this.dailyBudgetTokens = 500_000;
        this.perRequestMaxTokens = 50_000;
        this.autoScanEnabled = false;
        this.cascadeHuntEnabled = true;
        this.wafDetectionEnabled = true;
        // Default off — running generated code always requires an explicit
        // per-call human approval unless the user opts into autonomous mode.
        this.codeExecutionAutoApprove = false;
        this.skipAllPermissions = false;
        // Default tools requiring authorization
        this.toolsRequiringAuth.add("browser_interact");
        this.toolsRequiringAuth.add("run_sandboxed_code");
        this.wafRetryEnabled = true;
        this.activeProbeEnabled = false;
        this.blindVerificationEnabled = true;
        this.maxBlindProbeRequests = 10;
        this.businessLogicVerificationEnabled = false;
        this.aiAuthArbitrationEnabled = true;
        this.sinkMapEnabled = true;
        this.fileWatcherEnabled = false;
        this.maxCodeFollowHops = 3;
        this.mcpServerEnabled = true;
        this.mcpServerPort = 9877;
        this.organizerAutoSendEnabled = true;
        this.auditHighRiskOnly = false;
        this.analysisReuseWindowMinutes = 30;
        // F-1: Browser defaults — disabled by default (opt-in)
        this.browserEnabled = false;
        this.browserHeadless = true;
        this.browserChromePath = "";
        this.browserMaxPages = 10;
        this.browserFrontendUrl = "";
        // P1-6: default true — Agent needs full auth context for
        // IDOR/CSRF testing. Redaction belongs in reports, not analysis.
        // Security default: do NOT send raw credentials to external LLM
        // providers unless the user explicitly opts in. Pre-fix the default
        // was true — credentials (Cookie, Authorization, etc.) were sent to
        // third-party LLM endpoints without explicit user action.
        this.includeRawCredentialsInLlm = false;
        this.firstRunDisclosureDone = false;
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

    // ===== Session A =====
    public String getAuthSessionACookie() { return authSessionACookie; }
    public void setAuthSessionACookie(String cookie) { this.authSessionACookie = cookie != null ? cookie : ""; }
    public String getAuthSessionALabel() { return authSessionALabel; }
    public void setAuthSessionALabel(String label) { this.authSessionALabel = label != null && !label.isBlank() ? label : "会话 A"; }
    public String getAuthSessionAAuthHeaders() { return authSessionAAuthHeaders; }
    public void setAuthSessionAAuthHeaders(String headers) { this.authSessionAAuthHeaders = headers != null ? headers : ""; }
    public String getAuthSessionADomain() { return authSessionADomain; }
    public void setAuthSessionADomain(String domain) { this.authSessionADomain = domain != null ? domain.trim().toLowerCase() : ""; }
    public String getAuthSessionALevel() { return authSessionALevel; }
    public void setAuthSessionALevel(String level) { this.authSessionALevel = level != null ? level : ""; }
    public String getAuthSessionAGroup() { return authSessionAGroup; }
    public void setAuthSessionAGroup(String group) { this.authSessionAGroup = group != null ? group.trim() : ""; }

    // ===== Session B =====
    public String getAuthSessionBCookie() { return authSessionBCookie; }
    public void setAuthSessionBCookie(String cookie) { this.authSessionBCookie = cookie != null ? cookie : ""; }
    public String getAuthSessionBLabel() { return authSessionBLabel; }
    public void setAuthSessionBLabel(String label) { this.authSessionBLabel = label != null && !label.isBlank() ? label : "会话 B"; }
    public String getAuthSessionBAuthHeaders() { return authSessionBAuthHeaders; }
    public void setAuthSessionBAuthHeaders(String headers) { this.authSessionBAuthHeaders = headers != null ? headers : ""; }
    public String getAuthSessionBDomain() { return authSessionBDomain; }
    public void setAuthSessionBDomain(String domain) { this.authSessionBDomain = domain != null ? domain.trim().toLowerCase() : ""; }
    public String getAuthSessionBLevel() { return authSessionBLevel; }
    public void setAuthSessionBLevel(String level) { this.authSessionBLevel = level != null ? level : ""; }
    public String getAuthSessionBGroup() { return authSessionBGroup; }
    public void setAuthSessionBGroup(String group) { this.authSessionBGroup = group != null ? group.trim() : ""; }

    // ===== Session C =====
    public String getAuthSessionCCookie() { return authSessionCCookie; }
    public void setAuthSessionCCookie(String cookie) { this.authSessionCCookie = cookie != null ? cookie : ""; }
    public String getAuthSessionCLabel() { return authSessionCLabel; }
    public void setAuthSessionCLabel(String label) { this.authSessionCLabel = label != null && !label.isBlank() ? label : "会话 C"; }
    public String getAuthSessionCAuthHeaders() { return authSessionCAuthHeaders; }
    public void setAuthSessionCAuthHeaders(String headers) { this.authSessionCAuthHeaders = headers != null ? headers : ""; }
    public String getAuthSessionCDomain() { return authSessionCDomain; }
    public void setAuthSessionCDomain(String domain) { this.authSessionCDomain = domain != null ? domain.trim().toLowerCase() : ""; }
    public String getAuthSessionCLevel() { return authSessionCLevel; }
    public void setAuthSessionCLevel(String level) { this.authSessionCLevel = level != null ? level : ""; }
    public String getAuthSessionCGroup() { return authSessionCGroup; }
    public void setAuthSessionCGroup(String group) { this.authSessionCGroup = group != null ? group.trim() : ""; }

    public String getAuthHeader() { return authHeader; }
    public void setAuthHeader(String header) { this.authHeader = header != null ? header : ""; }

    /**
     * True when the user has configured at least 2 sessions with credentials.
     * Either Cookie or non-Cookie auth headers count per session.
     */
    public boolean hasManualAuthSessions() {
        return countConfiguredSessions() >= 2;
    }

    /** Count how many sessions (A/B/C) have at least one credential channel set. */
    public int countConfiguredSessions() {
        int count = 0;
        if (!authSessionACookie.isBlank() || !authSessionAAuthHeaders.isBlank()) count++;
        if (!authSessionBCookie.isBlank() || !authSessionBAuthHeaders.isBlank()) count++;
        if (!authSessionCCookie.isBlank() || !authSessionCAuthHeaders.isBlank()) count++;
        return count;
    }

    /** Build a {@link com.flechazo.apisentinel.auth.SessionCredentials} for
     *  session A from the persisted config. */
    public com.flechazo.apisentinel.auth.SessionCredentials manualSessionACredentials() {
        return new com.flechazo.apisentinel.auth.SessionCredentials(
                com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(authSessionACookie),
                com.flechazo.apisentinel.auth.SessionCredentials.parseAuthHeadersText(authSessionAAuthHeaders));
    }

    /** Build a {@link com.flechazo.apisentinel.auth.SessionCredentials} for
     *  session B from the persisted config. */
    public com.flechazo.apisentinel.auth.SessionCredentials manualSessionBCredentials() {
        return new com.flechazo.apisentinel.auth.SessionCredentials(
                com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(authSessionBCookie),
                com.flechazo.apisentinel.auth.SessionCredentials.parseAuthHeadersText(authSessionBAuthHeaders));
    }

    /** Build a {@link com.flechazo.apisentinel.auth.SessionCredentials} for
     *  session C from the persisted config. */
    public com.flechazo.apisentinel.auth.SessionCredentials manualSessionCCredentials() {
        return new com.flechazo.apisentinel.auth.SessionCredentials(
                com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(authSessionCCookie),
                com.flechazo.apisentinel.auth.SessionCredentials.parseAuthHeadersText(authSessionCAuthHeaders));
    }

    public int getMainSplitLocation() { return mainSplitLocation; }
    public void setMainSplitLocation(int location) { this.mainSplitLocation = Math.max(50, location); }

    public String getFocusExcludeMethods() { return focusExcludeMethods; }
    public void setFocusExcludeMethods(String methods) { this.focusExcludeMethods = methods != null ? methods : ""; }
    /** Comma-separated domains to exclude from API capture (browser/CDN/analytics
     *  noise). Supports {@code *} wildcards. Pre-populated with common noise. */
    private volatile String focusExcludeDomains = "detectportal.firefox.com,firefox.settings.services.mozilla.com,"
            + "aus5.mozilla.org,safebrowsing.googleapis.com,contile.services.mozilla.com,"
            + "push.services.mozilla.com,content-signature-2.cdn.mozilla.net,"
            + "addons.firefox.com.cn,versioncheck-bg.addons.mozilla.org,"
            + "www.google-analytics.com,hm.baidu.com,fclog.baidu.com,"
            + "getpocket.cdn.mozilla.net,sb.firefox.com.cn,incoming.telemetry.mozilla.org,"
            + "firefox-settings-attachments.cdn.mozilla.net";
    public String getFocusExcludeDomains() { return focusExcludeDomains; }
    public void setFocusExcludeDomains(String d) { this.focusExcludeDomains = d != null ? d : ""; }

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

    public int getDailyBudgetTokens() { return dailyBudgetTokens; }
    public void setDailyBudgetTokens(int tokens) { this.dailyBudgetTokens = Math.max(10_000, tokens); }

    public int getPerRequestMaxTokens() { return perRequestMaxTokens; }
    public void setPerRequestMaxTokens(int tokens) { this.perRequestMaxTokens = Math.max(1_000, tokens); }

    public com.flechazo.apisentinel.ai.budget.BudgetMode getBudgetMode() { return budgetMode; }
    public void setBudgetMode(com.flechazo.apisentinel.ai.budget.BudgetMode mode) { this.budgetMode = mode; }

    public boolean isAutoScanEnabled() { return autoScanEnabled; }
    public void setAutoScanEnabled(boolean enabled) { this.autoScanEnabled = enabled; }

    public boolean isCascadeHuntEnabled() { return cascadeHuntEnabled; }
    public void setCascadeHuntEnabled(boolean enabled) { this.cascadeHuntEnabled = enabled; }

    public boolean isWafDetectionEnabled() { return wafDetectionEnabled; }
    public void setWafDetectionEnabled(boolean enabled) { this.wafDetectionEnabled = enabled; }

    public boolean isCodeExecutionAutoApprove() { return codeExecutionAutoApprove; }
    public void setCodeExecutionAutoApprove(boolean enabled) { this.codeExecutionAutoApprove = enabled; }

    public boolean isSkipAllPermissions() { return skipAllPermissions; }
    public void setSkipAllPermissions(boolean enabled) { this.skipAllPermissions = enabled; }

    public java.util.Set<String> getDisabledTools() { return disabledTools; }
    public void setDisabledTools(java.util.Set<String> tools) {
        this.disabledTools.clear();
        if (tools != null) this.disabledTools.addAll(tools);
    }
    public boolean isToolDisabled(String toolName) { return disabledTools.contains(toolName); }

    public java.util.Set<String> getToolsRequiringAuth() { return toolsRequiringAuth; }
    public void setToolsRequiringAuth(java.util.Set<String> tools) {
        this.toolsRequiringAuth.clear();
        if (tools != null) this.toolsRequiringAuth.addAll(tools);
    }
    public boolean toolRequiresAuth(String toolName) { return toolsRequiringAuth.contains(toolName); }

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
    public boolean isMcpAllowActiveTools() { return mcpAllowActiveTools; }
    public void setMcpAllowActiveTools(boolean allow) { this.mcpAllowActiveTools = allow; }
    public boolean isModelTieringEnabled() { return modelTieringEnabled; }
    public void setModelTieringEnabled(boolean b) { this.modelTieringEnabled = b; }
    public boolean isFilterOptionsPreflightEnabled() { return filterOptionsPreflightEnabled; }
    public void setFilterOptionsPreflightEnabled(boolean b) { this.filterOptionsPreflightEnabled = b; }
    public boolean isBambdaHighlightEnabled() { return bambdaHighlightEnabled; }
    public void setBambdaHighlightEnabled(boolean b) { this.bambdaHighlightEnabled = b; }
    public String getBambdaHighlightKeywords() { return bambdaHighlightKeywords != null ? bambdaHighlightKeywords : ""; }
    public void setBambdaHighlightKeywords(String k) { this.bambdaHighlightKeywords = k != null ? k : ""; }
    public String getMcpAuthToken() { return mcpAuthToken != null ? mcpAuthToken : ""; }
    public void setMcpAuthToken(String token) { this.mcpAuthToken = token != null ? token : ""; }
    public boolean isMcpRequireAuth() { return mcpRequireAuth; }
    public void setMcpRequireAuth(boolean require) { this.mcpRequireAuth = require; }

    // --- F-1: Browser capabilities ---
    public boolean isBrowserEnabled() { return browserEnabled; }
    public void setBrowserEnabled(boolean enabled) { this.browserEnabled = enabled; }

    public boolean isIncludeRawCredentialsInLlm() { return includeRawCredentialsInLlm; }
    public void setIncludeRawCredentialsInLlm(boolean include) { this.includeRawCredentialsInLlm = include; }

    public boolean isFirstRunDisclosureDone() { return firstRunDisclosureDone; }
    public void setFirstRunDisclosureDone(boolean done) { this.firstRunDisclosureDone = done; }

    public boolean isBrowserHeadless() { return browserHeadless; }
    public void setBrowserHeadless(boolean headless) { this.browserHeadless = headless; }

    public String getBrowserChromePath() { return browserChromePath; }
    public void setBrowserChromePath(String path) { this.browserChromePath = path != null ? path : ""; }

    public int getBrowserMaxPages() { return browserMaxPages; }
    public void setBrowserMaxPages(int pages) { this.browserMaxPages = Math.max(1, Math.min(pages, 50)); }

    public String getBrowserFrontendUrl() { return browserFrontendUrl; }
    public void setBrowserFrontendUrl(String url) { this.browserFrontendUrl = url != null ? url : ""; }

    public boolean isAgentMode() { return agentMode; }
    public void setAgentMode(boolean agent) { this.agentMode = agent; }

    public boolean isBatchConcurrent() { return batchConcurrent; }
    public void setBatchConcurrent(boolean concurrent) { this.batchConcurrent = concurrent; }

    // --- Fun features ---
    public boolean isFunFeaturesEnabled() { return funFeaturesEnabled; }
    public void setFunFeaturesEnabled(boolean enabled) { this.funFeaturesEnabled = enabled; }

    public boolean isEffectsEnabled() { return effectsEnabled; }
    public void setEffectsEnabled(boolean enabled) { this.effectsEnabled = enabled; }
}
