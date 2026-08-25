package com.flechazo.apisentinel.ai.agent.tool;

/**
 * Single place that builds the standard tool registry from a ToolContext.
 * Replaces what used to be 3 copy-pasted "construct 7 tools + register them"
 * blocks (AgentLoop, and AiPresenter's two chat loops) that had already
 * drifted out of sync with each other (different tool sets, different
 * submit_report handling). New tools only need to be added here once.
 */
public final class StandardToolRegistry {

    private StandardToolRegistry() {}

    /** Holds the registry plus typed references to individual tools, since
     *  callers need to reach into specific tools (e.g. SendRequestTool's
     *  collected PayloadResults) after the ReAct loop finishes. */
    public record Tools(
        AgentToolRegistry registry,
        HeuristicScanTool heuristicTool,
        AnalyzeTrafficTool analyzeTool,
        SearchSourceCodeTool codeTool,
        GeneratePayloadsTool genTool,
        SendRequestTool sendTool,
        AuthBypassTool authTool,
        SsrfOobTool ssrfTool,
        ReadFileTool readFileTool,
        GrepRepoTool grepTool,
        SearchTrafficTool trafficTool,
        ActiveProbeTool probeTool,
        ComponentFingerprintTool fingerprintTool,
        BooleanBlindTool booleanBlindTool,
        TimingBlindTool timingBlindTool,
        WafBypassTool wafBypassTool,
        BusinessLogicTool businessLogicTool,
        FindDefinitionTool findDefinitionTool,
        FindCallersTool findCallersTool,
        XssReflectionTool xssReflectionTool,
        SstiProbeTool sstiProbeTool,
        PathTraversalTool pathTraversalTool,
        XxeProbeTool xxeProbeTool,
        ResponseDiffTool responseDiffTool,
        SubmitReportTool reportTool // null when includeSubmitReport=false
    ) {}

    /**
     * @param includeSubmitReport true for the autonomous Agent loop (needs a
     *                            forced final-verdict tool); false for the
     *                            two conversational chat loops, which don't
     *                            require the model to submit a structured report.
     */
    public static Tools build(ToolContext ctx, boolean includeSubmitReport) {
        AgentToolRegistry registry = new AgentToolRegistry(ctx);

        HeuristicScanTool heuristicTool = new HeuristicScanTool(ctx);
        AnalyzeTrafficTool analyzeTool = new AnalyzeTrafficTool(ctx);
        SearchSourceCodeTool codeTool = new SearchSourceCodeTool(ctx);
        GeneratePayloadsTool genTool = new GeneratePayloadsTool(ctx);
        SendRequestTool sendTool = new SendRequestTool(ctx);
        AuthBypassTool authTool = new AuthBypassTool(ctx);
        ListSessionsTool listSessionsTool = new ListSessionsTool(ctx);
        SsrfOobTool ssrfTool = new SsrfOobTool(ctx);
        CheckOobResultsTool checkOobTool = new CheckOobResultsTool(ctx);
        ReadFileTool readFileTool = new ReadFileTool(ctx);
        GrepRepoTool grepTool = new GrepRepoTool(ctx);
        AuditCodebaseTool auditCodebaseTool = new AuditCodebaseTool(ctx);
        SearchTrafficTool trafficTool = new SearchTrafficTool(ctx);
        ActiveProbeTool probeTool = new ActiveProbeTool(ctx, sendTool);
        ComponentFingerprintTool fingerprintTool = new ComponentFingerprintTool(ctx);
        BooleanBlindTool booleanBlindTool = new BooleanBlindTool(ctx, sendTool);
        TimingBlindTool timingBlindTool = new TimingBlindTool(ctx, sendTool);
        WafBypassTool wafBypassTool = new WafBypassTool(ctx, sendTool);
        BusinessLogicTool businessLogicTool = new BusinessLogicTool(ctx, sendTool);
        FindDefinitionTool findDefinitionTool = new FindDefinitionTool(ctx);
        FindCallersTool findCallersTool = new FindCallersTool(ctx);
        XssReflectionTool xssReflectionTool = new XssReflectionTool(ctx, sendTool);
        SstiProbeTool sstiProbeTool = new SstiProbeTool(ctx, sendTool);
        PathTraversalTool pathTraversalTool = new PathTraversalTool(ctx, sendTool);
        XxeProbeTool xxeProbeTool = new XxeProbeTool(ctx);
        ResponseDiffTool responseDiffTool = new ResponseDiffTool(ctx);

        registry.register(heuristicTool);
        registry.register(analyzeTool);
        registry.register(codeTool);
        registry.register(genTool);
        registry.register(sendTool);
        registry.register(authTool);
        registry.register(listSessionsTool);
        registry.register(ssrfTool);
        registry.register(checkOobTool);
        registry.register(readFileTool);
        registry.register(grepTool);
        registry.register(auditCodebaseTool);
        registry.register(trafficTool);
        registry.register(probeTool);
        registry.register(fingerprintTool);
        registry.register(booleanBlindTool);
        registry.register(timingBlindTool);
        registry.register(wafBypassTool);
        registry.register(businessLogicTool);
        registry.register(findDefinitionTool);
        registry.register(findCallersTool);
        registry.register(xssReflectionTool);
        registry.register(sstiProbeTool);
        registry.register(pathTraversalTool);
        registry.register(xxeProbeTool);
        registry.register(responseDiffTool);
        registry.register(new MapSiblingEndpointsTool(ctx));
        registry.register(new DispatchExploreAgentTool(ctx));
        registry.register(new ChainHunterTool(ctx, sendTool));
        registry.register(new RunSandboxedCodeTool(ctx));
        registry.register(new TraceTaintSourceTool(ctx));
        // ask_user: only the PRIMARY loop may ask the operator. Deliberately
        // not registered in buildExploration/buildChainHunter — sub-agents run
        // unattended in the background and must decide on their own.
        registry.register(new AskUserTool(ctx));

        SubmitReportTool reportTool = null;
        if (includeSubmitReport) {
            reportTool = new SubmitReportTool();
            registry.register(reportTool);
        }

        return new Tools(registry, heuristicTool, analyzeTool, codeTool, genTool,
                sendTool, authTool, ssrfTool, readFileTool, grepTool, trafficTool, probeTool,
                fingerprintTool, booleanBlindTool, timingBlindTool, wafBypassTool,
                businessLogicTool, findDefinitionTool, findCallersTool,
                xssReflectionTool, sstiProbeTool, pathTraversalTool, xxeProbeTool,
                responseDiffTool, reportTool);
    }

    /**
     * Restricted, read-only registry for a delegated exploration sub-agent
     * (see DispatchExploreAgentTool / ExplorationSubAgent) — every tool here
     * is side-effect-free (no HTTP requests, no LLM-cost payload generation,
     * no submit_report). Deliberately does NOT register dispatch_explore_agent
     * itself, so a sub-agent can never spawn another one — recursion is
     * capped at one level by construction, no separate depth counter needed.
     */
    public static AgentToolRegistry buildExploration(ToolContext ctx) {
        AgentToolRegistry registry = new AgentToolRegistry(ctx);
        registry.register(new HeuristicScanTool(ctx));
        registry.register(new SearchSourceCodeTool(ctx));
        registry.register(new ReadFileTool(ctx));
        registry.register(new GrepRepoTool(ctx));
        registry.register(new AuditCodebaseTool(ctx));
        registry.register(new SearchTrafficTool(ctx));
        registry.register(new ComponentFingerprintTool(ctx));
        registry.register(new FindDefinitionTool(ctx));
        registry.register(new FindCallersTool(ctx));
        registry.register(new ListSessionsTool(ctx));
        registry.register(new TraceTaintSourceTool(ctx));
        // Read-only index lookup — exploration sub-agents benefit from sibling
        // mapping too (e.g. "which endpoints share this controller" questions).
        registry.register(new MapSiblingEndpointsTool(ctx));
        return registry;
    }

    /**
     * Registry for the delegated cluster-hunting sub-agent (see ChainHunterTool /
     * ChainHunterSubAgent). Unlike buildExploration this one MAY send real HTTP
     * requests: it gets the PARENT'S SendRequestTool instance so every request
     * lands in the parent's PayloadResults (VerdictValidator/Repeater coverage,
     * same reuse pattern as ActiveProbeTool) plus auth-bypass and response-diff
     * for IDOR-style sibling testing. Deliberately NOT registered: generate_payloads
     * (LLM cost — the sub-agent replays A's pattern, it doesn't invent new ones),
     * submit_report (grading stays with the parent), dispatch_explore_agent and
     * chain_hunter itself (recursion capped at one level by construction), and
     * the verify_* probe family (single-endpoint deep-dives are the parent's job).
     */
    public static AgentToolRegistry buildChainHunter(ToolContext ctx, SendRequestTool sharedSendTool) {
        AgentToolRegistry registry = new AgentToolRegistry(ctx);
        registry.register(new HeuristicScanTool(ctx));
        registry.register(new SearchSourceCodeTool(ctx));
        registry.register(new ReadFileTool(ctx));
        registry.register(new GrepRepoTool(ctx));
        registry.register(new SearchTrafficTool(ctx));
        registry.register(new ComponentFingerprintTool(ctx));
        registry.register(new FindDefinitionTool(ctx));
        registry.register(new FindCallersTool(ctx));
        registry.register(new ListSessionsTool(ctx));
        registry.register(new MapSiblingEndpointsTool(ctx));
        registry.register(new ResponseDiffTool(ctx));
        registry.register(new AuthBypassTool(ctx));
        if (sharedSendTool != null) {
            registry.register(sharedSendTool);
        }
        return registry;
    }
}
