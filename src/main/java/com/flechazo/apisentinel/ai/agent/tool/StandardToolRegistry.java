package com.flechazo.apisentinel.ai.agent.tool;

import java.util.List;

/**
 * Single place that builds the standard tool registry from a ToolContext.
 * Replaces what used to be 3 copy-pasted "construct 7 tools + register them"
 * blocks (AgentLoop, and AiPresenter's two chat loops) that had already
 * drifted out of sync with each other (different tool sets, different
 * submit_report handling). New tools only need to be added here once.
 */
public final class StandardToolRegistry {

    private StandardToolRegistry() {}

    /** Tool catalog entry for UI display. */
    public record ToolCatalogEntry(String name, String description) {}

    /** Static catalog of all tool names + descriptions for the management panel.
     *  No ToolContext needed — just metadata for display. */
    public static List<ToolCatalogEntry> getToolCatalog() {
        return List.of(
            // Core tools
            new ToolCatalogEntry("send_request", "发送HTTP请求到目标服务器并观察响应。验证漏洞的核心工具。免费。"),
            new ToolCatalogEntry("heuristic_scan", "启发式快速扫描。检测参数类型、反射点、敏感信息等。免费。"),
            new ToolCatalogEntry("fingerprint_components", "识别目标技术栈和组件指纹。免费。"),
            new ToolCatalogEntry("analyze_traffic", "分析捕获的HTTP流量，识别潜在漏洞。消耗AI。"),
            new ToolCatalogEntry("generate_payloads", "基于分析结果生成安全测试payload。消耗AI。"),
            // Code analysis
            new ToolCatalogEntry("search_source_code", "在代码仓库中搜索接口定义。免费。"),
            new ToolCatalogEntry("read_file", "读取代码仓库中的文件。免费。"),
            new ToolCatalogEntry("grep_repo", "在代码仓库中正则搜索。免费。"),
            new ToolCatalogEntry("audit_codebase", "全局白盒审计，扫描所有危险sink。免费。"),
            new ToolCatalogEntry("find_definition", "跳转到符号定义。免费。"),
            new ToolCatalogEntry("find_callers", "查找调用点。免费。"),
            new ToolCatalogEntry("trace_taint_source", "跨文件污点追踪（regex启发式）。免费。"),
            // Traffic search
            new ToolCatalogEntry("search_traffic", "搜索Burp代理历史流量。免费。"),
            new ToolCatalogEntry("list_sessions", "列出可用的认证会话。免费。"),
            new ToolCatalogEntry("get_burp_scan_issues", "查询Burp原生扫描器已报告的issue作为线索。免费。"),
            new ToolCatalogEntry("mine_history_idor", "确定性挖掘代理历史找越权(IDOR)——不replay、不需认证,对比同端点不同会话的响应。免费。"),
            // Verification
            new ToolCatalogEntry("test_auth_bypass", "测试认证/越权绕过。消耗AI。"),
            new ToolCatalogEntry("verify_boolean_blind", "布尔盲注验证。消耗AI。"),
            new ToolCatalogEntry("verify_timing_blind", "时序盲注验证。消耗AI。"),
            new ToolCatalogEntry("verify_xss_reflection", "XSS反射验证。消耗AI。"),
            new ToolCatalogEntry("verify_ssti", "SSTI模板注入验证。消耗AI。"),
            new ToolCatalogEntry("verify_path_traversal", "路径穿越验证。消耗AI。"),
            new ToolCatalogEntry("verify_xxe", "XXE注入验证。消耗AI。"),
            new ToolCatalogEntry("verify_business_logic", "业务逻辑验证。消耗AI。"),
            new ToolCatalogEntry("diff_responses", "响应差异比较。免费。"),
            // Advanced
            new ToolCatalogEntry("active_probe", "主动探针（CORS/JWT/CRLF/NoSQL）。消耗AI。"),
            new ToolCatalogEntry("generate_oob_probe", "SSRF带外检测。免费。"),
            new ToolCatalogEntry("check_oob_results", "检查带外回调结果。免费。"),
            new ToolCatalogEntry("waf_bypass_retry", "WAF绕过重试（编码变体）。消耗AI。"),
            new ToolCatalogEntry("run_sandboxed_code", "执行沙箱代码（Python/Node）。危险操作，建议启用授权确认。"),
            new ToolCatalogEntry("map_sibling_endpoints", "映射兄弟端点。免费。"),
            new ToolCatalogEntry("dispatch_explore_agent", "委派隔离子Agent探索。消耗AI。"),
            new ToolCatalogEntry("chain_hunter", "委派集群狩猎子Agent。消耗AI。"),
            new ToolCatalogEntry("submit_report", "提交最终分析报告。"),
            new ToolCatalogEntry("ask_user", "向用户提问（需要人工回答）。"),
            // Meta tools
            new ToolCatalogEntry("request_tools", "按需加载额外工具组。免费。"),
            new ToolCatalogEntry("update_analysis_notes", "记录/更新安全发现。免费。"),
            new ToolCatalogEntry("read_analysis_notes", "读回已记录的安全发现。免费。"),
            new ToolCatalogEntry("list_attack_types", "列出攻击类型分类和 Payload 库（27 类 150+ Payloads）。免费。"),
            new ToolCatalogEntry("generate_poc", "对已确认漏洞自动生成 PoC（cURL + Python + 复现步骤）。免费。"),
            new ToolCatalogEntry("orchestrate_agents", "多 Agent 协作编排（Planner/Explorer/Executor/Verifier）。消耗 AI。"),
            new ToolCatalogEntry("custom_detection", "自定义检测模板（YAML DSL，类似 Nuclei）。免费。"),
            new ToolCatalogEntry("scan_mcp_servers", "MCP 服务器安全扫描（发现暴露端点，检测认证缺失）。免费。"),
            // Browser tools
            new ToolCatalogEntry("browser_discover", "浏览器接口发现（SPA路由/JS Bundle）。消耗资源。"),
            new ToolCatalogEntry("browser_render", "渲染页面提取DOM/console/CSP。消耗资源。"),
            new ToolCatalogEntry("browser_dom_xss", "DOM XSS检测。消耗资源。"),
            new ToolCatalogEntry("browser_find_page", "反向定位API对应的前端页面。消耗资源。"),
            new ToolCatalogEntry("browser_interact", "浏览器UI交互操作。需授权。消耗资源。"),
            new ToolCatalogEntry("browser_login", "自动登录获取Cookie。消耗资源。"),
            new ToolCatalogEntry("browser_explore", "智能探索触发目标API。消耗AI+资源。"),
            new ToolCatalogEntry("browser_auto_crawl", "一键全站扫描：登录→发现→探索→注册。消耗AI+资源。"),
            new ToolCatalogEntry("register_discovered_apis", "注册发现的API到仓库。免费。")
        );
    }

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
        registry.register(new GetBurpScanIssuesTool(ctx));
        registry.register(new DispatchExploreAgentTool(ctx));
        registry.register(new ChainHunterTool(ctx, sendTool));
        registry.register(new MineHistoryIdorTool(ctx));
        registry.register(new RunSandboxedCodeTool(ctx));
        registry.register(new TraceTaintSourceTool(ctx));
        registry.register(new ListAttackTypesTool(ctx));
        registry.register(new GeneratePocTool(ctx));
        registry.register(new OrchestrateAgentsTool(ctx));
        registry.register(new ScanMcpServersTool(ctx));

        // Custom detection templates — look in the user config dir first
        // (~/.api-sentinel/custom-templates/), then fall back to CWD/custom-templates/
        // (useful when running from the project root during development).
        // Burp's CWD is whatever directory it was launched from, which is
        // rarely the plugin's source tree, so the project-root-relative path
        // is not a reliable default for end users.
        java.nio.file.Path homeTemplateDir = com.flechazo.apisentinel.config.AppPaths.configDir()
                .resolve("custom-templates");
        java.nio.file.Path cwdTemplateDir = java.nio.file.Paths.get("custom-templates");
        java.nio.file.Path templateDir = java.nio.file.Files.isDirectory(homeTemplateDir)
                ? homeTemplateDir : cwdTemplateDir;
        registry.register(new CustomDetectionTool(ctx, templateDir));
        // ask_user: only the PRIMARY loop may ask the operator. Deliberately
        // not registered in buildExploration/buildChainHunter — sub-agents run
        // unattended in the background and must decide on their own.
        registry.register(new AskUserTool(ctx));

        // request_tools: meta-tool for Progressive Tool Disclosure — lets the
        // agent request loading of additional tool groups on demand.
        // Registered unconditionally (low token cost, essential for phase transitions).
        if (ctx.progressiveToolDisclosure() != null) {
            registry.register(new RequestToolsTool(ctx.progressiveToolDisclosure()));
        }

        // update_analysis_notes: agent self-managed memory for security findings.
        // Lets the agent persist important discoveries that might otherwise be lost
        // during context compaction. (MemGPT-style memory management)
        if (ctx.findingEvidenceStore() != null) {
            registry.register(new UpdateAnalysisNotesTool(ctx.findingEvidenceStore()));
            // P2-7: read-side counterpart — lets the agent recover findings
            // after context compaction without re-calling the original tools.
            registry.register(new ReadAnalysisNotesTool(ctx.findingEvidenceStore()));
        }

        // F-1: Browser tools for client-side security testing
        // Gracefully degrade if browserService is null (browser disabled in settings)
        if (ctx.browserService() != null) {
            registry.register(new BrowserDiscoverTool(ctx, ctx.browserService()));
            registry.register(new BrowserRenderTool(ctx, ctx.browserService()));
            registry.register(new BrowserDomXssTool(ctx, ctx.browserService()));
            // F-1b: Reverse page location + UI interaction tools
            registry.register(new BrowserFindPageTool(ctx, ctx.browserService()));
            registry.register(new BrowserInteractTool(ctx, ctx.browserService()));
            // FE-1: Automatic browser login
            if (ctx.loginProfileManager() != null) {
                registry.register(new BrowserLoginTool(ctx,
                        ctx.browserService().getBrowserManager(),
                        ctx.appConfig(),
                        ctx.loginProfileManager()));
            }
            // FE-2: Intelligent exploration
            registry.register(new BrowserExploreTool(ctx, ctx.browserService(), ctx.provider()));
            // FE-3: Auto-crawl (full-site scanning)
            if (ctx.loginProfileManager() != null) {
                registry.register(new BrowserAutoCrawlTool(ctx, ctx.browserService(),
                        ctx.loginProfileManager(), ctx.apiRepository()));
            }
            if (ctx.apiRepository() != null) {
                registry.register(new RegisterDiscoveredApisTool(ctx, ctx.browserService(), ctx.apiRepository()));
            }
        }

        SubmitReportTool reportTool = null;
        if (includeSubmitReport) {
            reportTool = new SubmitReportTool();
            registry.register(reportTool);
        }

        // Post-registration: unregister tools disabled by the user
        if (ctx.disabledTools() != null && !ctx.disabledTools().isEmpty()) {
            for (String name : ctx.disabledTools()) {
                if (registry.hasTool(name)) {
                    registry.unregister(name);
                }
            }
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
        // Burp scanner issues as leads — read-only, helps exploration
        // sub-agents prioritise endpoints the native scanner already flagged.
        registry.register(new GetBurpScanIssuesTool(ctx));
        // Attack type taxonomy — read-only, zero cost, helps sub-agents
        // understand what payloads/detectors are available.
        registry.register(new ListAttackTypesTool(ctx));
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
