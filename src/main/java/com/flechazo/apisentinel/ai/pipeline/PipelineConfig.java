package com.flechazo.apisentinel.ai.pipeline;

public record PipelineConfig(
    boolean useCodeRepo,
    int maxPayloads,
    boolean autoExecute,
    boolean authTestEnabled,
    String manualSessionACookie,
    String manualSessionALabel,
    String manualSessionBCookie,
    String manualSessionBLabel,
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
    boolean codeExecutionAutoApprove
) {
    /** Backward-compatible 19-arg constructor (codeExecutionAutoApprove
     *  defaults to false — running generated code always requires per-call
     *  human approval unless a caller explicitly opts in via
     *  {@link #withCodeExecutionAutoApprove}). */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests, boolean businessLogicVerificationEnabled,
                          boolean aiAuthArbitrationEnabled, int maxCodeFollowHops,
                          boolean auditHighRiskOnly) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled, maxCodeFollowHops,
                auditHighRiskOnly, false);
    }
    /** Backward-compatible constructor (no authTestEnabled, no sessions, defaults for
     *  contextWindowTokens/followOneCodeHop). */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute) {
        this(useCodeRepo, maxPayloads, autoExecute, false, "", "", "", "", 100_000, true);
    }

    /** Backward-compatible constructor with authTestEnabled but no manual sessions. */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled, "", "", "", "", 100_000, true);
    }

    /** Backward-compatible constructor without contextWindowTokens/followOneCodeHop —
     *  existing call sites keep compiling; new fields fall back to a conservative
     *  default context budget and one-hop code-follow enabled. Prefer the canonical
     *  12-arg constructor for new call sites so the user's configured context window
     *  actually takes effect. */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                100_000, true);
    }

    /** Backward-compatible 10-arg constructor (WAF flags default to enabled). */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, true, true, false);
    }

    /** Backward-compatible 12-arg constructor (active probes default to off —
     *  they send extra requests and are opt-in like OOB). */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled, false,
                true, 10);
    }

    /** Backward-compatible 13-arg constructor (blind verification defaults:
     *  enabled, cap 10 requests). */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, true, 10, false, true);
    }

    /** Backward-compatible 15-arg constructor (business-logic verification
     *  defaults to off — real business operations are opt-in). */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests, false, true,
                followOneCodeHop ? 3 : 0, false);
    }

    /** Backward-compatible 17-arg constructor (maxCodeFollowHops defaults to 3). */
    public PipelineConfig(boolean useCodeRepo, int maxPayloads, boolean autoExecute, boolean authTestEnabled,
                          String manualSessionACookie, String manualSessionALabel,
                          String manualSessionBCookie, String manualSessionBLabel,
                          int contextWindowTokens, boolean followOneCodeHop,
                          boolean wafDetectionEnabled, boolean wafRetryEnabled,
                          boolean activeProbeEnabled, boolean blindVerificationEnabled,
                          int maxBlindProbeRequests, boolean businessLogicVerificationEnabled,
                          boolean aiAuthArbitrationEnabled) {
        this(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled,
                followOneCodeHop ? 3 : 0, false);
    }

    /** Return a copy with the global-audit scope flag toggled. When true,
     *  audit_codebase restricts to high-risk sink types (cost control); default
     *  false audits every sink (finding vulns > saving tokens). */
    public PipelineConfig withAuditHighRiskOnly(boolean enabled) {
        return new PipelineConfig(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled,
                maxCodeFollowHops, enabled, codeExecutionAutoApprove);
    }

    /** Return a copy with the run_sandboxed_code confirmation gate toggled.
     *  When true, the tool skips CodeExecutionConfirmDialog and runs generated
     *  code immediately — an explicit opt-in the caller must have read from
     *  AppConfig.isCodeExecutionAutoApprove(), not a default. */
    public PipelineConfig withCodeExecutionAutoApprove(boolean enabled) {
        return new PipelineConfig(useCodeRepo, maxPayloads, autoExecute, authTestEnabled,
                manualSessionACookie, manualSessionALabel, manualSessionBCookie, manualSessionBLabel,
                contextWindowTokens, followOneCodeHop, wafDetectionEnabled, wafRetryEnabled,
                activeProbeEnabled, blindVerificationEnabled, maxBlindProbeRequests,
                businessLogicVerificationEnabled, aiAuthArbitrationEnabled,
                maxCodeFollowHops, auditHighRiskOnly, enabled);
    }

    public boolean hasManualSessions() {
        return manualSessionACookie != null && !manualSessionACookie.isBlank()
                && manualSessionBCookie != null && !manualSessionBCookie.isBlank();
    }

    public static PipelineConfig defaults() {
        return new PipelineConfig(true, 10, true, false);
    }
}
