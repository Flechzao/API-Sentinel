package com.flechazo.apisentinel.ai.pipeline;

public record AnalysisConfig(
    boolean useCodeRepo,
    int maxPayloads,
    boolean autoExecute,
    boolean authTestEnabled,
    // Session A
    String manualSessionACookie,
    String manualSessionALabel,
    String manualSessionAAuthHeaders,
    String manualSessionADomain,
    String manualSessionALevel,
    String manualSessionAGroup,
    // Session B
    String manualSessionBCookie,
    String manualSessionBLabel,
    String manualSessionBAuthHeaders,
    String manualSessionBDomain,
    String manualSessionBLevel,
    String manualSessionBGroup,
    // Session C
    String manualSessionCCookie,
    String manualSessionCLabel,
    String manualSessionCAuthHeaders,
    String manualSessionCDomain,
    String manualSessionCLevel,
    String manualSessionCGroup,
    // Other settings
    int contextWindowTokens,
    boolean followOneCodeHop,
    boolean wafDetectionEnabled,
    boolean wafRetryEnabled,
    boolean activeProbeEnabled,
    boolean blindVerificationEnabled,
    int maxBlindProbeRequests,
    boolean businessLogicVerificationEnabled,
    boolean aiAuthArbitrationEnabled,
    int maxCodeFollowHops,
    boolean auditHighRiskOnly,
    boolean codeExecutionAutoApprove,
    boolean browserEnabled
) {
    // ===== Backward-compatible constructors =====
    // All old constructors pass "" for the 9 new fields (C session + domain/level for all 3).

    /** 23-arg pre-multi-session constructor. */
    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionAAuthHeaders,
                          String manualSessionBCookie, String manualSessionBLabel,
                          String manualSessionBAuthHeaders,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests, boolean businessLogicVerificationEnabled,
                          boolean aiAuthArbitrationEnabled, int maxCodeFollowHops,
                          boolean auditHighRiskOnly, boolean codeExecutionAutoApprove,
                          boolean browserEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionAAuthHeaders, "", "", "",
                manualSessionBCookie, manualSessionBLabel, manualSessionBAuthHeaders, "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled, maxCodeFollowHops,
                auditHighRiskOnly, codeExecutionAutoApprove, browserEnabled);
    }

    /** 21-arg backward-compatible constructor. */
    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests, boolean businessLogicVerificationEnabled,
                          boolean aiAuthArbitrationEnabled, int maxCodeFollowHops,
                          boolean auditHighRiskOnly, boolean codeExecutionAutoApprove,
                          boolean browserEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled, maxCodeFollowHops,
                auditHighRiskOnly, codeExecutionAutoApprove, browserEnabled);
    }

    /** 19-arg backward-compatible constructor. */
    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests, boolean businessLogicVerificationEnabled,
                          boolean aiAuthArbitrationEnabled, int maxCodeFollowHops,
                          boolean auditHighRiskOnly) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled, maxCodeFollowHops,
                auditHighRiskOnly, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute) {
        this(useCodeRepo, maxPayloads, autoExecute, false,
                "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                100_000, true, true, true, false, true, 10, false, true, 3, false, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                100_000, true, true, true, false, true, 10, false, true, 3, false, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                100_000, true, true, true, false, true, 10, false, true, 3, false, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, true, true, false, true, 10, false, true, 3,
                false, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                false, true, 10, false, true, 3, false, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, true, 10, false, true, 3, false, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                false, true, followOneCodeHop ? 3 : 0, false, false, false);
    }

    public AnalysisConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests, boolean businessLogicVerificationEnabled,
                          boolean aiAuthArbitrationEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, "", "", "", "",
                manualSessionBCookie, manualSessionBLabel, "", "", "", "",
                "", "", "", "", "", "",
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled,
                followOneCodeHop ? 3 : 0, false, false, false);
    }

    /** Return a copy with the global-audit scope flag toggled. */
    public AnalysisConfig withAuditHighRiskOnly(boolean enabled) {
        return new AnalysisConfig(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionAAuthHeaders, manualSessionADomain, manualSessionALevel, manualSessionAGroup,
                manualSessionBCookie, manualSessionBLabel, manualSessionBAuthHeaders, manualSessionBDomain, manualSessionBLevel, manualSessionBGroup,
                manualSessionCCookie, manualSessionCLabel, manualSessionCAuthHeaders, manualSessionCDomain, manualSessionCLevel, manualSessionCGroup,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled,
                maxCodeFollowHops, enabled, codeExecutionAutoApprove, browserEnabled);
    }

    /** Return a copy with the run_sandboxed_code confirmation gate toggled. */
    public AnalysisConfig withCodeExecutionAutoApprove(boolean enabled) {
        return new AnalysisConfig(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionAAuthHeaders, manualSessionADomain, manualSessionALevel, manualSessionAGroup,
                manualSessionBCookie, manualSessionBLabel, manualSessionBAuthHeaders, manualSessionBDomain, manualSessionBLevel, manualSessionBGroup,
                manualSessionCCookie, manualSessionCLabel, manualSessionCAuthHeaders, manualSessionCDomain, manualSessionCLevel, manualSessionCGroup,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled,
                maxCodeFollowHops, auditHighRiskOnly, enabled, browserEnabled);
    }

    /** F-1: Return a copy with browser capabilities toggled. */
    public AnalysisConfig withBrowserEnabled(boolean enabled) {
        return new AnalysisConfig(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionAAuthHeaders, manualSessionADomain, manualSessionALevel, manualSessionAGroup,
                manualSessionBCookie, manualSessionBLabel, manualSessionBAuthHeaders, manualSessionBDomain, manualSessionBLevel, manualSessionBGroup,
                manualSessionCCookie, manualSessionCLabel, manualSessionCAuthHeaders, manualSessionCDomain, manualSessionCLevel, manualSessionCGroup,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled,
                maxCodeFollowHops, auditHighRiskOnly, codeExecutionAutoApprove, enabled);
    }

    /**
     * True when at least 2 sessions have credentials configured.
     */
    public boolean hasManualSessions() {
        return countConfiguredSessions() >= 2;
    }

    /** Count how many sessions (A/B/C) have at least one credential channel set. */
    public int countConfiguredSessions() {
        int count = 0;
        if (hasCredentials(manualSessionACookie, manualSessionAAuthHeaders)) count++;
        if (hasCredentials(manualSessionBCookie, manualSessionBAuthHeaders)) count++;
        if (hasCredentials(manualSessionCCookie, manualSessionCAuthHeaders)) count++;
        return count;
    }

    private static boolean hasCredentials(String cookie, String headers) {
        return (cookie != null && !cookie.isBlank()) || (headers != null && !headers.isBlank());
    }

    /** Build session credentials list for the auth test executor.
     *  Returns only sessions that have at least one credential channel. */
    public java.util.List<com.flechazo.apisentinel.auth.SessionConfig> manualSessionConfigs() {
        java.util.List<com.flechazo.apisentinel.auth.SessionConfig> list = new java.util.ArrayList<>();
        addIfConfigured(list, "A", manualSessionACookie, manualSessionAAuthHeaders,
                manualSessionALabel, manualSessionADomain, manualSessionALevel, manualSessionAGroup);
        addIfConfigured(list, "B", manualSessionBCookie, manualSessionBAuthHeaders,
                manualSessionBLabel, manualSessionBDomain, manualSessionBLevel, manualSessionBGroup);
        addIfConfigured(list, "C", manualSessionCCookie, manualSessionCAuthHeaders,
                manualSessionCLabel, manualSessionCDomain, manualSessionCLevel, manualSessionCGroup);
        return list;
    }

    /** Backward-compatible convenience: session A credentials. */
    public com.flechazo.apisentinel.auth.SessionCredentials manualSessionACredentials() {
        return new com.flechazo.apisentinel.auth.SessionCredentials(
                com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(manualSessionACookie),
                com.flechazo.apisentinel.auth.SessionCredentials.parseAuthHeadersText(manualSessionAAuthHeaders));
    }

    /** Backward-compatible convenience: session B credentials. */
    public com.flechazo.apisentinel.auth.SessionCredentials manualSessionBCredentials() {
        return new com.flechazo.apisentinel.auth.SessionCredentials(
                com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(manualSessionBCookie),
                com.flechazo.apisentinel.auth.SessionCredentials.parseAuthHeadersText(manualSessionBAuthHeaders));
    }

    private static void addIfConfigured(java.util.List<com.flechazo.apisentinel.auth.SessionConfig> list,
                                         String slot, String cookie, String headers,
                                         String label, String domain, String level, String group) {
        if (!hasCredentials(cookie, headers)) return;
        list.add(new com.flechazo.apisentinel.auth.SessionConfig(
                slot, label,
                new com.flechazo.apisentinel.auth.SessionCredentials(
                        com.flechazo.apisentinel.auth.SessionDiscovery.parseCookies(cookie),
                        com.flechazo.apisentinel.auth.SessionCredentials.parseAuthHeadersText(headers)),
                domain != null ? domain : "",
                level != null ? level : "",
                group != null ? group : ""));
    }

    public static AnalysisConfig defaults() {
        return new AnalysisConfig(true, 10, true, false);
    }

    /**
     * Build a pipeline-ready config from the user-facing {@link
     * com.flechazo.apisentinel.config.AppConfig}, mapping all session
     * credential fields (Cookie + non-Cookie auth headers) in one place.
     */
    public static AnalysisConfig forPipeline(com.flechazo.apisentinel.config.AppConfig c,
                                              boolean authTestEnabled) {
        return new AnalysisConfig(true, 10, true, authTestEnabled,
                c.getAuthSessionACookie(), c.getAuthSessionALabel(), c.getAuthSessionAAuthHeaders(),
                c.getAuthSessionADomain(), c.getAuthSessionALevel(), c.getAuthSessionAGroup(),
                c.getAuthSessionBCookie(), c.getAuthSessionBLabel(), c.getAuthSessionBAuthHeaders(),
                c.getAuthSessionBDomain(), c.getAuthSessionBLevel(), c.getAuthSessionBGroup(),
                c.getAuthSessionCCookie(), c.getAuthSessionCLabel(), c.getAuthSessionCAuthHeaders(),
                c.getAuthSessionCDomain(), c.getAuthSessionCLevel(), c.getAuthSessionCGroup(),
                c.getContextWindowTokens(), true,
                c.isWafDetectionEnabled(), c.isWafRetryEnabled(),
                c.isActiveProbeEnabled(), c.isBlindVerificationEnabled(),
                c.getMaxBlindProbeRequests(),
                c.isBusinessLogicVerificationEnabled(), c.isAiAuthArbitrationEnabled(),
                c.getMaxCodeFollowHops(), c.isAuditHighRiskOnly(),
                c.isCodeExecutionAutoApprove(), c.isBrowserEnabled());
    }
}
