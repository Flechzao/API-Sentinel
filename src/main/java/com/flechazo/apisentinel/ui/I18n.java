package com.flechazo.apisentinel.ui;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class I18n {

    public enum Lang { ZH, EN }

    private static volatile Lang current = Lang.ZH;

    private static final Map<String, String> ZH_MAP = new HashMap<>();
    private static final Map<String, String> EN_MAP = new HashMap<>();
    private static final List<Consumer<Lang>> listeners = new ArrayList<>();

    /** Register a callback that fires when the language is toggled.
     *  Panels should call this in their constructor to auto-refresh I18n text
     *  instead of needing a manual refreshI18n() method. */
    public static void addLangListener(Consumer<Lang> callback) {
        listeners.add(callback);
    }

    static {
        // Toolbar & buttons
        put("import_api", "导入 API", "Import API");
        put("filter_label", "筛选:", "Filter:");
        put("filter_all", "全部", "All");
        put("filter_untested", "未测试", "Untested");
        put("filter_testing", "测试中", "Testing");
        put("filter_passed", "已通过", "Passed");
        put("filter_vuln", "漏洞", "Vuln");
        put("filter_risk", "风险:", "Risk:");
        put("filter_unanalyzed", "未分析", "Unanalyzed");
        put("remove", "删除", "Remove");
        put("toggle_status", "切换状态", "Toggle Status");
        put("toggle_vuln", "切换漏洞", "Toggle Vuln");
        put("move_top", "置顶已测", "Tested to Top");
        put("add_scope", "加入Scope", "Add to Scope");
        put("csv", "导出CSV", "Export CSV");
        put("report", "导出报告", "Export Report");
        put("full_report", "完整报告", "Full Report");
        put("ai_analyze", "AI 分析", "AI Analyze");
        put("find", "查找", "Find");

        // Table columns
        put("col_method", "方法", "Method");
        put("col_path", "接口路径", "API Path");
        put("col_domain", "域名", "Domain");
        put("col_status_code", "响应码", "Status");
        put("col_risk", "风险", "Risk");
        put("col_findings", "发现", "Findings");
        put("col_passive", "被动", "Passive");
        put("col_state", "状态", "State");
        put("col_traffic", "流量", "Traffic");
        put("col_note", "备注", "Note");
        put("col_action", "操作", "Action");
        put("status_untested", "未测试", "Untested");
        put("status_under_test", "接口测试中", "Testing");
        put("status_pending", "待评估", "Pending Review");
        put("status_passed", "测试通过，安全", "Passed");
        put("status_vulnerable", "存在漏洞", "Vulnerable");
        put("status_analyzing", "分析中…", "Analyzing…");

        // AI mode
        put("ai_mode_group", "AI分析", "AI Mode");
        put("ai_mode_pipeline", "Pipeline", "Pipeline");
        put("ai_mode_agent", "Agent", "Agent");

        // Tab titles
        put("tab_analysis", "分析", "Analysis");
        put("tab_ai", "AI 分析", "AI Analysis");
        put("tab_ai_result", "分析结果", "Results");
        put("tab_ai_chat", "AI 对话", "AI Chat");
        put("tab_task_queue", "任务队列", "Task Queue");
        put("tab_source", "源码", "Source");
        put("tab_testcase", "测试用例", "Test Cases");
        put("tab_settings", "AI 设置", "AI Settings");
        put("tab_rules", "检测规则", "Rules");
        put("tab_repo", "代码仓库", "Code Repo");
        put("tab_test", "测试", "Testing");
        put("tab_settings_group", "设置", "Settings");
        put("tab_repeater", "请求测试", "Repeater");
        put("tab_task_center", "任务中心", "Task Center");

        // Match mode
        put("match_exact", "精确", "Exact");
        put("match_semi", "半精确", "Semi");
        put("match_fuzzy", "模糊", "Fuzzy");
        put("match_exact_mode", "精确匹配", "Exact");
        put("match_fuzzy_mode", "模糊匹配", "Fuzzy");
        put("match_mode", "匹配模式:", "Match:");
        put("check_full", "完整包", "Full Packet");
        put("regex", "正则替换", "Regex");
        put("url_encode", "URL编码", "URL Encode");
        put("history_scan", "历史扫描", "Scan History");
        put("sensitive", "敏感检测", "Sensitive");
        put("unauth", "越权检测", "Auth Bypass");
        put("waf_detect", "WAF识别", "WAF Detect");
        put("active_probe", "主动探针", "Active Probe");
        put("business_logic", "业务逻辑", "Biz Logic");
        put("organizer_auto_send", "漏洞存 Organizer", "Vuln→Organizer");
        put("audit_high_risk_only", "全局审计仅高危sink", "Audit high-risk only");
        put("code_exec_auto_approve", "代码执行自动批准", "Auto-approve Code Exec");
        put("oob_probe", "OOB探针", "OOB Probe");
        put("highlight", "高亮", "Highlight");
        put("auto_scan", "自动扫描", "Auto Scan");
        put("tab_oob", "回连平台", "OOB Platform");
        put("result_waf_blocked", "🛡 WAF拦截", "🛡 WAF Blocked");
        put("result_waf_review", "🛡? 待确认", "🛡? Review");
        put("detection", "检测", "Detection");
        put("detect_options", "检测", "Detect");
        put("tab_auth_config", "越权配置", "Auth Config");
        put("tab_browser", "浏览器", "Browser");



        // Dashboard
        put("dash_overview", "概览", "Overview");
        put("dash_total_api", "总接口", "Total APIs");
        put("dash_analyzed", "已分析", "Analyzed");
        put("dash_vuln_count", "漏洞", "Vulns");
        put("dash_pending", "待验证", "Pending");
        put("dash_agent_on", "开启", "On");
        put("dash_agent_off", "关闭", "Off");
        put("dash_cascade", "级联", "Cascade");
        put("dash_cascade_off", "已关闭", "Off");
        put("dash_cascade_blocked", "已熔断", "Tripped");

        // Cascade hunting & success patterns
        put("cascade_hunt", "级联狩猎", "Cascade Hunt");
        put("tab_patterns", "成功模式", "Patterns");
        put("patterns_title", "已学习的成功模式", "Learned Success Patterns");
        put("patterns_hint", "每次验证确认的漏洞会沉淀为可复用模式，并自动注入新分析的初始消息（同域优先，Top 5）", "Each verified vuln becomes a reusable pattern injected into new analyses' initial messages (same-domain first, top 5)");
        put("patterns_refresh", "刷新", "Refresh");
        put("patterns_clear", "清空", "Clear All");
        put("patterns_clear_confirm", "确定清空全部已学习的成功模式？此操作不可撤销。", "Clear all learned success patterns? This cannot be undone.");
        put("patterns_summary", "共 %d 条模式", "%d patterns");
        put("patterns_unavailable", "模式库未加载", "Pattern store unavailable");
        put("patterns_col_type", "漏洞类型", "Vuln Type");
        put("patterns_col_technique", "技术手法", "Technique");
        put("patterns_col_endpoint", "端点", "Endpoint");
        put("patterns_col_domain", "域", "Domain");
        put("patterns_col_hits", "命中", "Hits");
        put("patterns_col_last_seen", "最近确认", "Last Seen");


        // Import
        put("import_hint", "每行一个API，支持: GET /api/v1/users", "One API per line, e.g.: GET /api/v1/users");

        // ImportDialog
        put("import_dialog_title", "导入 API", "Import APIs");
        put("import_list_border", "API 列表（每行一个）", "API List (one per line)");
        put("import_format_header", "格式（每行一个）：", "Format (one per line):");
        put("import_format_no_method", "HTTP 方法可有可无", "With/without HTTP method");
        put("import_format_path_var", "{id} 路径占位符", "{id} path placeholders");
        put("import_format_wildcard", "/** 匹配所有子路径", "/** matches all sub-paths");
        put("import_format_domain", "末尾加域名可自动填入域名列", "Append domain to auto-fill domain column");
        put("import_format_dedup", "重复 API 自动跳过", "Duplicate APIs are auto-skipped");
        put("import_options_label", "选项：", "Options:");
        put("import_url_encode", "URL-encode 路径", "URL-encode path");
        put("import_url_encode_tip", "把 / 编码为 %2F，便于匹配某些系统中已编码的路径流量", "Encode / as %2F, for matching encoded path traffic in some systems");
        put("import_scan_history", "导入后扫描 History", "Scan history after import");
        put("import_scan_history_tip", "导入后扫描 Burp Proxy History 补充匹配信息", "After import, scan Burp Proxy History to supplement matching info");
        put("import_from_file", "从文件导入：", "Import from file:");
        put("import_txt_btn", "文本文件 (.txt)", "Text file (.txt)");
        put("import_swagger_btn", "Swagger / OpenAPI", "Swagger / OpenAPI");
        put("import_cancel", "取消", "Cancel");
        put("import_choose_txt", "选择 API 列表文件", "Select API list file");
        put("import_filter_txt", "文本文件 (*.txt)", "Text files (*.txt)");
        put("import_filter_all", "所有支持的格式", "All supported formats");
        put("import_read_err", "读取文件失败：", "Failed to read file: ");
        put("import_err_title", "错误", "Error");
        put("import_choose_swagger", "选择 Swagger / OpenAPI 文件", "Select Swagger / OpenAPI file");
        put("import_filter_swagger", "Swagger/OpenAPI (*.json, *.yaml, *.yml)", "Swagger/OpenAPI (*.json, *.yaml, *.yml)");
        put("import_swagger_empty", "未找到 API 端点。\n请确认这是合法的 Swagger 2.0 或 OpenAPI 3.0 文档。", "No API endpoints found.\nPlease verify this is a valid Swagger 2.0 or OpenAPI 3.0 document.");
        put("import_swagger_empty_title", "解析结果", "Parse Result");
        put("import_swagger_ok", "已解析 %d 个 API 端点。点击「导入」继续。", "Parsed %d API endpoints. Click Import to proceed.");
        put("import_swagger_ok_title", "Swagger 导入", "Swagger Import");
        put("import_swagger_err", "解析 Swagger 失败：", "Failed to parse Swagger: ");
        put("import_comment_from", "# 来源：", "# Imported from: ");
        put("import_comment_found", "# 找到 %d 个端点", "# Found %d endpoints");

        // Common buttons
        put("btn_save", "保存", "Save");
        put("btn_clear", "清除", "Clear");
        put("btn_cancel", "取消", "Cancel");
        put("label_colon", "标签：", "Label: ");

        // AuthConfigPanel
        put("auth_title", "鉴权检测 — 会话配置", "Authz Detection — Session Config");
        put("auth_hint", "手动配置两个会话的认证凭证（Cookie 和/或 Auth 头）用于越权检测。\n若 Proxy History 中能找到多个会话，建议优先使用自动检测。\nCookie 格式：key1=val1; key2=val2\nAuth 头格式：Authorization: Bearer eyJ...（每行一个）\n或：HTTP History → 右键 → 提取为会话 A/B。",
                "Manually configure two sessions' credentials (Cookie and/or Auth headers) for authz testing.\nIf multiple sessions are found in Proxy History, auto-detection is preferred.\nCookie format: key1=val1; key2=val2\nAuth header format: Authorization: Bearer eyJ... (one per line)\nOr: HTTP History → right-click → Extract as Session A/B.");
        put("auth_session_a_border", "会话 A（如 管理员/用户A）", "Session A (e.g. Admin/User A)");
        put("auth_session_b_border", "会话 B（如 普通用户/用户B）", "Session B (e.g. Regular User/User B)");
        put("auth_session_c_border", "会话 C（可选，第三层级）", "Session C (optional, 3rd tier)");
        put("auth_auto_detect", "从流量自动检测", "Auto-Detect from Traffic");
        put("auth_auto_detect_tip", "扫描 Proxy History 自动发现已认证会话并填充 A/B/C",
                "Scan Proxy History to auto-discover authenticated sessions and fill A/B/C");
        put("auth_label_tip", "例如：管理员、用户A、测试账号", "e.g. Admin, UserA, TestAccount");
        put("auth_domain_colon", "域名:", "Domain:");
        put("auth_domain_tip", "此会话适用的域名（留空则适用于所有域名）。\nCookie 是域名相关的，建议填写。",
                "Domain this session applies to (empty = all domains).\nCookies are domain-specific, recommended to fill.");
        put("auth_level_colon", "权限:", "Level:");
        put("auth_level_tip", "权限等级，用于推断垂直越权方向", "Privilege level for vertical escalation direction inference");
        put("auth_group_colon", "组:", "Group:");
        put("auth_group_tip", "租户或组标识。相同级别+不同组=水平越权，不同级别+同组=垂直越权",
                "Tenant/group ID. Same level+different group=horizontal IDOR, different level+same group=vertical escalation");
        put("auth_level_unknown", "未设置", "Unset");
        put("auth_level_high", "高（管理员）", "High (Admin)");
        put("auth_level_medium", "中（经理）", "Medium (Manager)");
        put("auth_level_low", "低（普通用户）", "Low (Regular User)");
        put("auth_cookie_tip", "粘贴 Cookie 值，格式：key1=val1; key2=val2",
                "Paste Cookie value, format: key1=val1; key2=val2");
        put("auth_cookie_border", "Cookie", "Cookie");
        put("auth_headers_tip", "粘贴 Auth 头，每行一个，格式：Authorization: Bearer eyJ...\n或：X-Token: abc123",
                "Paste Auth headers, one per line, format: Authorization: Bearer eyJ...\nOr: X-Token: abc123");
        put("auth_headers_border", "Auth Headers（Bearer / X-Token / API-Key）",
                "Auth Headers (Bearer / X-Token / API-Key)");
        put("auth_auto_scanning", "扫描中...", "Scanning...");
        put("auth_default_label_a", "会话 A", "Session A");
        put("auth_default_label_b", "会话 B", "Session B");
        put("auth_saved_ok_n", "已保存（已配置 %d 个会话）", "Saved (%d sessions configured)");
        put("auth_saved_empty", "已保存（无会话配置）", "Saved (no sessions configured)");
        put("auth_validate", "验证会话", "Validate Sessions");
        put("auth_validate_tip", "向各会话域名发送测试请求，验证凭证是否仍然有效",
                "Send test requests to each session's domain to verify credentials are still valid");
        put("auth_led_unknown", "未验证", "Not validated");
        put("auth_led_checking", "验证中...", "Validating...");
        put("auth_led_alive", "会话 %s 有效 (HTTP %d)", "Session %s alive (HTTP %d)");
        put("auth_led_expired", "会话 %s 已过期 (HTTP %d)", "Session %s expired (HTTP %d)");
        put("auth_led_unreachable", "会话 %s 不可达: %s", "Session %s unreachable: %s");
        put("auth_led_no_domain", "未配置域名，无法验证", "No domain configured, cannot validate");
        put("auth_validate_none", "无已配置的会话可验证", "No configured sessions to validate");
        put("auth_validate_ok", "全部 %d 个会话有效", "All %d sessions alive");
        put("auth_validate_partial", "%d/%d 个会话有效", "%d/%d sessions alive");
        put("auth_validate_expired", "%d/%d 个会话已过期，请刷新 token", "%d/%d sessions expired, refresh token");
        put("auth_cleared", "已清除", "Cleared");
        put("auth_cleared_on_import", "已清除（导入数据时自动重置）", "Cleared (auto-reset on data import)");
        put("auth_burp_unavailable", "Burp API 不可用", "Burp API unavailable");
        put("auth_no_sessions", "Proxy History 中未找到已认证会话", "No authenticated sessions found in Proxy History");
        put("auth_auto_label_a", "自动检测会话 A（%d 个请求）", "Auto-detected Session A (%d requests)");
        put("auth_auto_label_b", "自动检测会话 B（%d 个请求）", "Auto-detected Session B (%d requests)");
        put("auth_auto_label_n", "自动检测会话 %s（%d 个请求）", "Auto-detected Session %s (%d requests)");
        put("auth_auto_ok", "自动检测到 %d 个会话，已填充 A/B", "Auto-detected %d sessions, filled A/B");
        put("auth_auto_partial", "仅检测到 1 个会话（已填充 A）；越权测试需要 2+，请用其他账号再访问一次",
                "Only 1 session detected (filled A); authz testing needs 2+, visit with another account");

        // RepeaterPanel
        put("repeater_send_btn", "发送", "Send");
        put("repeater_cannot_parse", "无法解析请求", "Cannot parse request");
        put("repeater_request_empty", "请求为空", "Request is empty");
        put("repeater_sending", "发送中…", "Sending...");
        put("repeater_error_prefix", "错误：", "Error: ");
        put("repeater_no_request", "无请求", "No request");
        put("repeater_send_failed_prefix", "发送失败：", "Send failed: ");
        put("repeater_select_2_rows", "请选 2 行（Ctrl/⌘ 多选）后点击并排对比",
                "Select 2 rows (Ctrl/⌘ multi-select) then click side-by-side");
        put("repeater_no_response", "无响应", "No response");
        put("repeater_comparer_failed_prefix", "对比失败：", "Comparer failed: ");

        // ToolManagementDialog
        put("tool_mgmt_title", "Agent 工具管理（%d 个工具）", "Agent Tool Management (%d tools)");
        put("tool_mgmt_enable_all", "全部启用", "Enable All");
        put("tool_mgmt_disable_all", "全部禁用", "Disable All");
        put("tool_mgmt_reset", "重置", "Reset");
        put("tool_mgmt_col_name", "名称", "Name");
        put("tool_mgmt_col_desc", "描述", "Description");
        put("tool_mgmt_col_status", "状态", "Status");
        put("tool_mgmt_col_free", "免费", "Free");
        put("tool_mgmt_col_auth", "需授权", "Auth Required");
        put("tool_mgmt_yes", "是", "Yes");
        put("tool_mgmt_no", "否", "No");

        // McpConfigPanel
        put("mcp_redetect", "重新检测", "Re-detect");
        put("mcp_applying", "应用配置中…", "Applying…");
        put("mcp_start_failed", "启动失败：", "Start failed: ");
        put("mcp_unknown_error", "未知错误", "unknown error");
        put("mcp_running", "运行中 · http://127.0.0.1:%d/mcp", "Running · http://127.0.0.1:%d/mcp");
        put("mcp_enabled_not_running",
                "已启用但未运行（端口 %d 可能被占用，换一个端口试试）",
                "Enabled but not running (port %d may be in use — try a different port)");
        put("mcp_disabled", "已禁用", "Disabled");

        // ToolbarPanel
        put("toolbar_whole_req_tip",
                "仅在模糊模式下生效：同时搜索请求体里的 API 关键词",
                "Only effective in fuzzy mode: search API keywords in request body too");
        put("toolbar_ai_mode_tip",
                "Pipeline：固定 6 阶段分析流程 | Agent：AI 自主决定工具调用",
                "Pipeline: fixed 6-stage analysis flow | Agent: AI autonomously decides tool calls");

        // AI panels (Model/Tokens labels)
        put("ai_model_label", "模型：%s", "Model: %s");
        put("ai_model_default", "模型：--", "Model: --");
        put("ai_tokens_label", "Tokens：%s", "Tokens: %s");
        put("ai_tokens_zero", "Tokens：0", "Tokens: 0");
        put("ai_current_model_tip", "当前 AI Provider 模型", "Current AI Provider model");

        // StepProgressPanel
        put("step_no_content", "无内容", "No content");

        // Settings
        put("dark_mode", "深色模式", "Dark Mode");
        put("lang_switch", "English", "中文");
        put("test_conn", "测试连接", "Test Connection");
        put("save_config", "保存配置", "Save Config");
        put("repo_path", "仓库路径:", "Repo Path:");
        put("index_now", "立即索引", "Index Now");

        // Status
        put("status_ready", "就绪", "Ready");
        put("status_analyzing", "分析中...", "Analyzing...");
        put("conn_ok", "连接成功 ✓", "Connected ✓");
        put("conn_fail", "连接失败 ✗", "Failed ✗");

        // Code repo panel
        put("repo_mgmt", "代码仓库管理", "Code Repository Management");
        put("repo_add", "添加仓库", "Add Repo");
        put("repo_edit", "编辑", "Edit");
        put("repo_remove", "删除选中", "Remove Selected");
        put("repo_index_selected", "索引选中", "Index Selected");
        put("repo_index_all", "全部索引", "Index All");
        put("repo_name", "名称", "Name");
        put("repo_domains", "关联域名", "Domains");
        put("repo_routes", "路由数", "Routes");
        put("repo_status", "状态", "Status");
        put("repo_indexed", "已索引", "Indexed");
        put("repo_not_indexed", "未索引", "Not Indexed");
        put("repo_indexing", "正在索引...", "Indexing...");
        put("repo_domain_hint", "关联域名/IP (逗号分隔):", "Domains/IPs (comma separated):");
        put("repo_dialog_add", "添加仓库", "Add Repository");
        put("repo_dialog_edit", "编辑仓库", "Edit Repository");
        put("repo_browse", "浏览...", "Browse...");
        put("repo_frameworks", "(Spring / Flask / FastAPI / Django / Express / Koa)", "(Spring / Flask / FastAPI / Django / Express / Koa)");

        // Sensitive rules panel
        put("rules_title", "敏感信息检测规则", "Sensitive Detection Rules");
        put("rules_loaded", "%d 条规则已加载", "%d rules loaded");
        put("rules_add", "添加规则", "Add Rule");
        put("rules_remove", "删除选中", "Remove Selected");
        put("rules_reload", "重新加载", "Reload");
        put("rules_learned", "已学习规则 (AI 自动提取)", "Learned Rules (AI Auto-extracted)");
        put("rules_refresh", "刷新", "Refresh");
        put("rules_name", "名称:", "Name:");
        put("rules_regex", "正则:", "Regex:");
        put("rules_group", "分组:", "Group:");
        put("rules_invalid", "无效正则: ", "Invalid regex: ");

        // Context menu
        put("ctx_ai_analyze", "AI 分析此请求", "AI Analyze This Request");
        put("ctx_add_api", "添加此 API", "Add This API");
        put("ctx_mark_vuln", "标记漏洞", "Mark Vulnerability");

        // Analysis panel
        put("analysis_mode_traffic", "纯流量分析", "Traffic Only");
        put("analysis_mode_code", "关联代码", "With Code");
        put("analysis_mode_history", "关联历史", "With History");
        put("analysis_mode_comprehensive", "综合分析", "Comprehensive");
        put("analysis_waiting", "等待分析", "Waiting for Analysis");
        put("analysis_pipeline_progress", "Pipeline 执行进度", "Pipeline Progress");
        put("analysis_pipeline_running", "Pipeline 执行中...", "Pipeline Running...");
        put("analysis_pipeline_done", "Pipeline 完成", "Pipeline Complete");
        put("analysis_pipeline_failed", "Pipeline 失败", "Pipeline Failed");
        put("analysis_final_report", "最终安全研判报告", "Final Security Assessment Report");
        put("analysis_vuln_found", "发现漏洞: ", "Vulnerabilities: ");
        put("analysis_suspected", "待验证: ", "Suspected: ");

        // Dashboard (agent card) — "自动模式" NOT "Agent": the card tracks the
        // passive traffic auto-analysis switch, and relabeling it "Agent"
        // reads as "the agent is dead" while a manual Agent-mode analysis
        // is in fact running.
        put("dash_agent", "自动模式", "Auto Mode");

        // Export
        put("export_success", "导出成功: ", "Export successful: ");
        put("export_failed", "导出失败: ", "Export failed: ");

        // Toast
        put("toast_high_risk", "发现高危漏洞: ", "High-risk vulnerability found: ");
        put("toast_analysis_failed", "分析失败: ", "Analysis failed: ");

        // UI refactor
        put("more_actions", "更多 ▾", "More ▾");
        put("testcase_summary", "测试用例", "Test Cases");
        put("source_code", "关联源码", "Source Code");

        // === AiSettingsPanel ===
        put("ai_settings_provider_config_title", "AI Provider 配置", "AI Provider Configuration");
        put("ai_settings_provider", "服务商:", "Provider:");
        put("ai_settings_endpoint", "接口地址:", "Endpoint:");
        put("ai_settings_api_key", "API 密钥:", "API Key:");
        put("ai_settings_model", "模型:", "Model:");
        put("ai_settings_fast_model", "轻量模型(初筛):", "Fast Model (Triage):");
        put("ai_settings_fast_model_tooltip", "可选。用于 Pipeline 第 1 阶段流量初筛 + 浏览器探索视觉识别的便宜/快速模型（同一 endpoint 与 key，仅模型名不同）。推荐视觉模型: DeepSeek-V4-Flash-Vision-Exp。深挖（payload 生成、最终研判）仍用上方主模型。留空 = 不分层，全程用主模型。", "Optional. A cheaper/faster model for Pipeline Stage-1 traffic triage + browser exploration visual recognition (same endpoint and key, only model name differs). Recommended vision model: DeepSeek-V4-Flash-Vision-Exp. Deep analysis (payload generation, final verdict) still uses the main model above. Leave empty = no tiering, use main model throughout.");
        put("ai_settings_model_tiering", "低成本分层：payload 生成 / 探索子agent 也用轻量模型", "Low-cost tiering: payload generation / exploration sub-agents also use fast model");
        put("ai_settings_model_tiering_tooltip", "开启后，payload 生成和探索/集群狩猎子 agent 也走上面的「轻量模型」，以降低成本（坏结果会被验证与防幻觉门拦下）。越权仲裁、盲注确认、最终研判等判定类节点始终用主模型。默认关。需填了轻量模型才生效。", "When enabled, payload generation and exploration/cluster hunting sub-agents also use the fast model above to reduce costs (bad results are caught by verification and anti-hallucination gates). Authorization arbitration, blind injection confirmation, final verdict and other judgment nodes always use the main model. Default off. Requires a fast model to be filled in to take effect.");
        put("ai_settings_context_window", "上下文窗口(tokens):", "Context Window (tokens):");
        put("ai_settings_context_window_tooltip", "Agent/对话模式的上下文压缩预算。按你所选模型的真实上下文窗口填——Claude/GPT 等云端模型可以填大一些，本地 Ollama 模型请按实际拉取的模型规格填，不会自动检测。最小 %d。", "Context compaction budget for Agent/conversation mode. Fill in based on your selected model's real context window — Claude/GPT and other cloud models can take a larger value; for local Ollama models, fill according to the actual model specs you pulled; not auto-detected. Minimum %d.");
        put("ai_settings_daily_budget", "日预算(tokens):", "Daily Budget (tokens):");
        put("ai_settings_daily_budget_tooltip", "每天所有 LLM 调用的总预算（含缓存写入/读取）。超过即拒绝后续调用直到第二天，防止意外失控烧钱。最小 %d。", "Total budget for all LLM calls per day (including cache write/read). Exceeding this rejects subsequent calls until the next day, preventing accidental runaway spending. Minimum %d.");
        put("ai_settings_per_request_max", "单请求上限(tokens):", "Per-Request Max (tokens):");
        put("ai_settings_per_request_max_tooltip", "单次 LLM 调用允许的最大 token 估算值。超出的调用会被预飞拒绝，防止单次失控请求吞掉大部分日预算。最小 %d。", "Maximum estimated token value allowed for a single LLM call. Calls exceeding this are rejected pre-flight, preventing a single runaway request from consuming most of the daily budget. Minimum %d.");
        put("ai_settings_unlimited_budget", "不限额（仅记录用量，不阻断调用）", "Unlimited (record usage only, do not block calls)");
        put("ai_settings_unlimited_budget_tooltip", "勾选后取消日预算/单请求上限限制，LLM 调用不会被阻断。\nToken 用量仍会记录和显示，便于成本监控。\n适合内部 API / 不限量的模型。", "When checked, removes the daily budget / per-request max limits; LLM calls will not be blocked.\nToken usage is still recorded and displayed for cost monitoring.\nSuitable for internal APIs / unlimited models.");
        put("ai_settings_test_connection", "测试连接", "Test Connection");
        put("ai_settings_save_config", "保存配置", "Save Config");
        put("ai_settings_tool_management", "🔧 工具管理", "🔧 Tool Management");
        put("ai_settings_tool_management_tooltip", "启用/禁用工具，设置需要授权的工具", "Enable/disable tools, set tools requiring authorization");
        put("ai_settings_tool_mgmt_open_failed", "工具管理面板打开失败: ", "Tool management panel failed to open: ");
        put("ai_settings_error_title", "错误", "Error");
        put("ai_settings_browser_capabilities", "浏览器能力", "Browser Capabilities");
        put("ai_settings_browser_enabled", "启用浏览器分析 (Playwright + Chromium)", "Enable browser analysis (Playwright + Chromium)");
        put("ai_settings_browser_enabled_tooltip", "启用后 Agent 可使用 browser_discover/browser_render/browser_dom_xss 工具进行前端安全测试，包括 DOM XSS 检测、SPA 接口发现、JS Bundle 密钥扫描。首次使用需安装独立 Chromium (不影响系统 Chrome)，详见 docs/BROWSER.md。浏览器配置变更后无需重启扩展，下次使用时自动生效。", "When enabled, Agent can use browser_discover/browser_render/browser_dom_xss tools for front-end security testing, including DOM XSS detection, SPA interface discovery, JS Bundle key scanning. First-time use requires installing a standalone Chromium (does not affect system Chrome); see docs/BROWSER.md. Browser config changes take effect on next use without restarting the extension.");
        put("ai_settings_browser_headless", "无头模式 (不显示浏览器窗口)", "Headless mode (no browser window)");
        put("ai_settings_browser_headless_tooltip", "运行时是否显示 Chromium 窗口。调试时可关闭以观察浏览器行为。", "Whether to show the Chromium window at runtime. Turn off during debugging to observe browser behavior.");
        put("ai_settings_redact_credentials", "LLM 发送前脱敏凭证 (仅合规/不信任 LLM 提供商时开启)", "Redact credentials before sending to LLM (enable only for compliance / untrusted LLM providers)");
        put("ai_settings_redact_credentials_tooltip", "关闭(默认): Cookie / Authorization / x-*-token 等凭证原文发给 LLM，Agent 能看到完整认证上下文做越权/CSRF 测试。开启: 凭证脱敏为 ⟨REDACTED:abc1…978f⟩ 形式，仅适用于不信任 LLM 提供商或合规审计场景。注意：分析阶段脱敏可能影响越权类漏洞的检出率。", "Off (default): Cookie / Authorization / x-*-token and other credentials are sent to the LLM in plaintext; Agent can see the full authentication context for IDOR/CSRF testing. On: credentials are redacted to ⟨REDACTED:abc1...978f⟩ form, only for untrusted LLM providers or compliance audit scenarios. Note: redaction during analysis may affect the detection rate of authorization-related vulnerabilities.");
        put("ai_settings_redact_disclosure_title", "脱敏可能影响分析质量", "Redaction may affect analysis quality");
        put("ai_settings_chrome_path", "Chrome 路径:", "Chrome Path:");
        put("ai_settings_chrome_path_tooltip",
                "浏览器检测优先级: 1.此处填写的路径 2.Playwright Chromium 3.系统浏览器 4.Playwright 默认。留空=自动检测。安装: npx playwright install chromium",
                "Browser detection priority: 1.Path here 2.Playwright Chromium 3.System browser 4.Playwright default. Leave empty=auto-detect. Install: npx playwright install chromium");
        put("ai_settings_max_pages", "最大页面数:", "Max Pages:");
        put("ai_settings_max_pages_tooltip", "browser_discover 探索时最多访问的页面数 (1-50)。", "Maximum number of pages to visit during browser_discover exploration (1-50).");
        put("ai_settings_frontend_base_url", "前端 Base URL:", "Frontend Base URL:");
        put("ai_settings_frontend_base_url_tooltip", "前端应用的 Base URL，用于 browser_find_page 反向定位调用 API 的前端页面。例: http://localhost:3000。留空 = 仅使用路径推断（低置信度）。", "Base URL of the front-end application, used by browser_find_page to reverse-locate the front-end page that calls the API. Example: http://localhost:3000. Leave empty = use path inference only (low confidence).");
        put("ai_settings_testing", "测试中...", "Testing...");
        put("ai_settings_testing_connection", "正在测试连接...", "Testing connection...");
        put("ai_settings_unknown_provider", "未知 Provider: ", "Unknown Provider: ");
        put("ai_settings_conn_timeout", "连接超时 (15s) ✗", "Connection timeout (15s) ✗");
        put("ai_settings_conn_success", "连接成功 ✓", "Connection successful ✓");
        put("ai_settings_conn_failed", "连接失败 ✗", "Connection failed ✗");
        put("ai_settings_conn_error", "连接异常: ", "Connection error: ");
        put("ai_settings_unknown_error", "未知错误", "Unknown error");
        put("ai_settings_saved", "已保存", "Saved");

        // === BambdaBuilderPanel ===
        put("bambda_exclude_method", "排除方法", "Exclude Method");
        put("bambda_include_keywords", "包含关键字（仅作用于请求）", "Include Keywords (request only)");
        put("bambda_exclude_keywords", "排除关键字（仅作用于请求）", "Exclude Keywords (request only)");
        put("bambda_exclude_domain", "排除域名（逗号分隔，支持 * 通配）", "Exclude Domains (comma-separated, * wildcards supported)");
        put("bambda_in_scope_only", "仅显示作用域内", "Show In-Scope Only");
        put("bambda_hide_no_response", "隐藏无响应项", "Hide Items Without Response");
        put("bambda_parameterized_only", "仅显示带参数的请求", "Show Parameterized Requests Only");
        put("bambda_search_filter_enabled", "启用搜索过滤（请求+响应）", "Enable Search Filter (Request + Response)");
        put("bambda_search_regex", "正则", "Regex");
        put("bambda_search_case_sensitive", "区分大小写", "Case Sensitive");
        put("bambda_search_negative", "反向匹配", "Negative Match");
        put("bambda_show_only_ext", "仅显示后缀", "Show Only Extensions");
        put("bambda_hide_ext", "隐藏后缀", "Hide Extensions");
        put("bambda_notes_only", "仅显示带备注项", "Show Annotated Items Only");
        put("bambda_highlight_only", "仅显示高亮项", "Show Highlighted Items Only");
        put("bambda_runtime_filter", "运行时过滤", "Runtime Filter");
        put("bambda_filter_options_preflight", "自动过滤 OPTIONS 预检", "Auto-Filter OPTIONS Preflight");
        put("bambda_filter_options_preflight_tooltip", "改写 OPTIONS 代理响应为 text/css，在代理历史中隐藏。", "Rewrites OPTIONS proxy responses to text/css and hides them in proxy history.");
        put("bambda_highlight_keywords", "实时高亮关键字", "Highlight Keywords in Real-Time");
        put("bambda_highlight_keywords_tooltip", "代理历史中含指定关键字的请求自动绿色高亮。非破坏式。", "Requests containing the specified keywords in proxy history are automatically highlighted in green. Non-destructive.");
        put("bambda_keywords_label", "  关键字:", "  Keywords:");
        put("bambda_generate_from_assets", "从接口资产生成", "Generate from API Assets");
        put("bambda_scope_all_apis", "全部接口（含无流量）", "All APIs (including no traffic)");
        put("bambda_scope_traffic_only", "仅有流量的接口", "APIs with Traffic Only");
        put("bambda_scope_in_scope", "仅作用域内(in-scope)", "In-Scope Only");
        put("bambda_scope_risk", "仅高/中风险", "High/Medium Risk Only");
        put("bambda_include_filters", "包含扩展过滤", "Include Extension Filters");
        put("bambda_include_filters_tooltip", "勾选:生成的 Bambda 同时包含方法/域名/关键字等扩展过滤条件。不勾:仅路径匹配。无论是否勾选,始终排除 OPTIONS 预检。", "Checked: the generated Bambda includes method/domain/keyword and other extension filter conditions. Unchecked: path matching only. OPTIONS preflight is always excluded regardless of this setting.");
        put("bambda_generate_filter_code", "生成过滤代码", "Generate Filter Code");
        put("bambda_scope_label", "范围:", "Scope:");
        put("bambda_tab_extension_filter", "扩展过滤", "Extension Filter");
        put("bambda_tab_burp_filter", "Burp 风格过滤", "Burp-Style Filter");
        put("bambda_generated_code_title", "生成的 Bambda 代码", "Generated Bambda Code");
        put("bambda_generate_code", "生成代码", "Generate Code");
        put("bambda_apply_to_burp", "应用到 Burp", "Apply to Burp");
        put("bambda_apply_to_burp_tooltip", "复制 Bambda 代码到剪贴板", "Copy Bambda code to clipboard");
        put("bambda_copy", "复制", "Copy");
        put("bambda_save_config", "保存配置", "Save Config");
        put("bambda_load_config", "加载配置", "Load Config");
        put("bambda_preset_label", "  预设:", "  Preset:");
        put("bambda_preset_default", "重置默认", "Reset to Default");
        put("bambda_preset_static_noise", "静态资源降噪", "Static Asset Noise Reduction");
        put("bambda_preset_dynamic_apis", "只看动态接口", "Dynamic APIs Only");
        put("bambda_preset_write_ops", "只看写操作", "Write Operations Only");
        put("bambda_no_apis_in_scope", "没有符合该范围的已捕获接口。", "No captured APIs match the selected scope.");
        put("bambda_asset_filter_comment", "个接口资产过滤", "API assets filter");
        put("bambda_asset_filter_ext_comment", "个接口资产过滤 + 扩展过滤", "API assets filter + extension filter");
        put("bambda_copied_to_clipboard_msg", "✅ Bambda 代码已复制到剪贴板！\n\n应用步骤:\n1. Burp → Proxy → HTTP history\n2. 点击顶部过滤栏，切换到 Bambda 模式\n3. 粘贴 (Ctrl+V) 代码", "Bambda code copied to clipboard!\n\nSteps to apply:\n1. Burp → Proxy → HTTP history\n2. Click the top filter bar, switch to Bambda mode\n3. Paste (Ctrl+V) the code");
        put("bambda_copied_title", "已复制", "Copied");
        put("search_tooltip", "搜索 API 路径（实时过滤）", "Search API path (live filter)");
        put("source_placeholder", "选中 API 后自动展示关联源码（需先在「代码仓库」中索引仓库）", "Source code shown automatically after selecting an API (index repos first)");
        put("chat_window_title", "API Sentinel — AI 对话", "API Sentinel — AI Chat");
        put("chat_send", "发送", "Send");
        put("chat_send_tooltip", "发送消息 (Enter)", "Send message (Enter)");
        put("chat_stop", "停止", "Stop");
        put("chat_stop_tooltip", "停止当前分析", "Stop current analysis");
        put("chat_stopping", "停止中…", "Stopping…");
        put("chat_stop_requested", "⛔ 已请求停止分析…", "⛔ Stop requested…");
        put("chat_running", "分析中", "Analyzing");
        put("chat_idle", "就绪", "Ready");
        put("chat_history", "历史", "History");
        put("chat_history_tooltip", "查看此 API 的对话历史", "View chat history for this API");
        put("chat_no_history", "暂无历史记录", "No history yet");
        put("chat_step_view", "步骤视图", "Step View");
        put("chat_view_toggle_tooltip", "切换步骤卡片/普通对话视图", "Toggle step cards / plain chat view");
        put("chat_chat_view", "对话视图", "Chat View");
        put("chat_input_tooltip", "输入消息… 支持追问、利用建议、修复方案", "Type a message… ask follow-ups, exploitation tips, fix suggestions");
        put("chat_no_api_selected", "未选中 API", "No API selected");
        put("chat_start", "🤖 开始对话", "🤖 Start a Conversation");
        put("chat_hint1", "💡 选中一个 API 后，可以问我关于漏洞利用、修复建议等问题", "💡 Select an API, then ask about exploitation, fixes, etc.");
        put("chat_hint2", "⌨ 按 Enter 发送，Shift+Enter 换行", "⌨ Enter to send, Shift+Enter for newline");
        put("chat_new_messages", "↓ 新消息", "↓ New messages");
        put("chat_cleared", "🗑 对话已清空", "🗑 Chat cleared");
        put("chat_context_suffix", " 的对话", " conversation");
        put("chat_global_session", "全局会话", "Global Session");
        put("chat_global_session_full", "全局对话（未选中 API）", "Global chat (no API selected)");
        put("chat_switched_to", "已切换到 ", "Switched to ");
        put("chat_switched_session", " 的会话", " session");
        put("domain_label", "域名:", "Domain:");
        put("all_domains", "所有域名", "All Domains");
        put("settings_general", "⚙ 通用", "⚙ General");
        put("settings_rules", "📋 检测规则", "📋 Rules");
        put("settings_advanced", "🔧 高级", "🔧 Advanced");
        put("settings_bambda", "🧩 Bambda", "🧩 Bambda");
        put("bambda_config_saved", "配置已保存", "Configuration saved");
        put("bambda_save_failed", "保存失败：", "Save failed: ");
        put("bambda_section_extension_filter", "扩展过滤", "Extension Filter");
        put("bambda_section_http_method", "HTTP 方法", "HTTP Method");
        put("bambda_section_keywords", "关键字", "Keywords");
        put("bambda_section_domain_filter", "域名过滤", "Domain Filter");
        put("bambda_section_burp_filter", "Burp 风格过滤", "Burp-Style Filter");
        put("bambda_section_request_type", "请求类型", "Request Type");
        put("bambda_section_mime_type", "MIME 类型", "MIME Type");
        put("bambda_section_status_code", "状态码", "Status Code");
        put("bambda_section_search", "搜索", "Search");
        put("bambda_section_extension", "文件后缀", "File Extension");
        put("bambda_section_annotation_listener", "注释 / 监听", "Annotation / Listener");
        put("bambda_section_advanced", "高级（搜索 / 后缀 / 注释 / 端口）", "Advanced (Search / Extension / Annotation / Port)");
        put("bambda_listener_port_label", "端口:", "Port:");
        put("bambda_show_advanced", "显示高级", "Show Advanced");
        put("bambda_select_preset", "选择预设...", "Select preset...");

        // === AiAnalysisPanel ===
        put("ai_analysis_start", "开始分析", "Start Analysis");
        put("ai_analysis_history_tooltip", "选择查看此 API 的历次分析记录", "View analysis history for this API");
        put("ai_analysis_delete", "删除本次分析", "Delete Analysis");
        put("ai_analysis_delete_tooltip", "从该接口的历史记录中删除当前查看的这次分析", "Delete the currently viewed analysis record from this API's history");
        put("ai_analysis_open_chat_tooltip", "打开 AI 对话浮窗（分析过程、沙箱确认、提问交互都在其中；关闭窗口不会中断分析）", "Open AI chat window (analysis process, sandbox confirmation, Q&A; closing does not interrupt)");
        put("ai_analysis_status_label", "状态:", "Status:");
        put("ai_analysis_waiting", "等待分析", "Waiting for analysis");
        put("ai_analysis_risk_label", "风险:", "Risk:");
        put("ai_analysis_view_report", "查看报告", "View Report");
        put("ai_analysis_view_json", "完整日志(JSON)", "Full Log (JSON)");
        put("ai_analysis_view_json_tooltip", "打开完整的 AI 分析日志（JSON，含各阶段原始数据）", "Open full AI analysis log (JSON, includes raw data per stage)");
        put("ai_analysis_show_low_risk", "显示低风险", "Show Low Risk");
        put("ai_analysis_col_type", "类型", "Type");
        put("ai_analysis_col_risk", "风险", "Risk");
        put("ai_analysis_col_confidence", "置信度", "Confidence");
        put("ai_analysis_col_title", "标题", "Title");
        put("ai_analysis_col_location", "位置", "Location");
        put("ai_analysis_evidence_compare", "证据对比（前后包）", "Evidence Compare (Before/After)");
        put("ai_analysis_replay_verify", "重放验证", "Replay Verify");
        put("ai_analysis_mark_fp", "标为误报 (抑制未来相同发现)", "Mark as False Positive (suppress future matches)");
        put("ai_analysis_tab_results", "分析结果", "Analysis Results");
        put("ai_analysis_tab_timeline", "调用链", "Call Chain");
        put("ai_analysis_delete_running", "分析进行中，结束后才能删除记录", "Analysis in progress, delete after completion");
        put("ai_analysis_report_no_path", "报告文件路径未设置。分析可能未正确保存报告。", "Report path not set. Analysis may not have saved the report.");
        put("ai_analysis_cannot_open_report", "无法打开报告", "Cannot Open Report");
        put("ai_analysis_report_not_found", "报告文件不存在: ", "Report file not found: ");
        put("ai_analysis_file_not_exist", "文件不存在", "File Not Found");
        put("ai_analysis_path_copied", "路径已复制", "Path Copied");
        put("ai_analysis_no_auto_open", "系统不支持自动打开文件。路径已复制到剪贴板:\\n", "Auto-open not supported. Path copied to clipboard:\\n");
        put("ai_analysis_no_desktop", "系统不支持桌面操作。路径已复制到剪贴板:\\n", "Desktop not supported. Path copied to clipboard:\\n");
        put("ai_analysis_open_failed", "打开文件失败: ", "Failed to open file: ");
        put("ai_analysis_error_title", "错误", "Error");
        put("ai_analysis_running_delete", "分析正在进行中，等分析结束后再删除记录。", "Analysis in progress. Delete after analysis completes.");
        put("ai_analysis_running_title", "分析运行中", "Analysis Running");
        put("ai_analysis_no_records", "当前没有可删除的分析记录。", "No analysis records to delete.");
        put("ai_analysis_no_records_title", "无记录", "No Records");
        put("ai_analysis_confirm_delete", "确定删除这次分析记录吗？\\n\\n时间: ", "Delete this analysis record?\\n\\nTime: ");
        put("ai_analysis_confirm_delete_suffix", "\\n模式: ", "\\nMode: ");
        put("ai_analysis_confirm_delete_title", "删除分析记录", "Delete Analysis Record");
        put("ai_analysis_failed", "分析失败: ", "Analysis failed: ");
        put("ai_analysis_batch_progress", "批量分析进度: ", "Batch progress: ");
        put("ai_analysis_stage_0", "阶段 0/6", "Stage 0/6");
        put("ai_analysis_latest_record", "最新记录", "Latest Record");
        put("ai_analysis_not_analyzed", "未分析 - 点击「开始分析」按钮开始", "Not analyzed - Click Start Analysis to begin");
        put("ai_analysis_failed_status", "失败: ", "Failed: ");
        put("ai_analysis_complete", "分析完成", "Analysis Complete");
        put("ai_analysis_no_result", "无结果", "No Result");
        put("ai_analysis_select_finding_fp", "请先选中一条 finding 再标为误报。", "Select a finding before marking as false positive.");
        put("ai_analysis_cannot_operate", "无法操作", "Cannot Operate");
        put("ai_analysis_marked_fp_prefix", "已将 [", "Marked [");
        put("ai_analysis_marked_fp_suffix", "] 标记为误报并持久化。后续分析将抑制该组合的重复发现。", "] as false positive. Future analysis will suppress this combination.");
        put("ai_analysis_marked_title", "已标记", "Marked");
        put("ai_analysis_analyzing", "分析中...", "Analyzing...");
        put("ai_analysis_no_compare", "当前没有可对比的分析结果（请选择一次 Pipeline/Agent 分析记录）", "No analysis result to compare (select a Pipeline/Agent record)");
        put("ai_analysis_select_finding_first", "请先在发现列表中选中一个漏洞", "Select a vulnerability in the findings list first");
        put("ai_analysis_no_payload", "这条发现没有关联的实测请求记录，无法做前后包对比。\\n（多为纯代码/流量静态分析得出，或该记录未保存 payload。）", "No associated test request records, cannot compare.\\n(Likely from static analysis, or no payload saved.)");
        put("ai_analysis_evidence_title", "证据对比 — ", "Evidence Compare — ");
        put("ai_analysis_no_vuln_selected", "未选中漏洞", "No Vulnerability Selected");
        put("ai_analysis_result_not_ready", "分析结果未就绪，请等待分析完成", "Analysis result not ready, wait for completion");
        put("ai_analysis_no_result_title", "无分析结果", "No Analysis Result");
        put("ai_analysis_replay_failed", "打开重放对话框失败: ", "Failed to open replay dialog: ");
        put("ai_analysis_stage_prefix", "阶段 ", "Stage ");

        // AiAnalysisPanel — remaining complex strings
        put("ai_analysis_tool_calls_suffix", " 次工具调用", " tool calls");
        put("ai_analysis_agent_tooltip_prefix", "Agent 运行中 · 已 ", "Agent running · ");
        put("ai_analysis_agent_tooltip_suffix", " 次工具调用", " tool calls");
        put("ai_analysis_current_tool", " · 当前: ", " · current: ");
        put("ai_analysis_delete_irreversible", "\n\n删除后不可恢复。", "\n\nThis cannot be undone.");
        put("ai_analysis_pipeline_error", "Pipeline 执行失败:\n\n", "Pipeline execution failed:\n\n");
        put("ai_analysis_static_analysis_note", "（多为纯代码/流量静态分析得出，或该记录未保存 payload。）", "(Likely from static code/traffic analysis, or no payload saved.)");
        put("ai_analysis_attack_session", "② 越权会话", "② Authz session");
        put("ai_analysis_attack_payload", "② 攻击/payload 包", "② Attack/payload packet");
        put("ai_analysis_no_baseline", "（无基线包）", "(no baseline packet)");
        put("ai_analysis_owner_session", "① 属主会话", "① Owner session");
        put("ai_analysis_baseline_label", "① 基线包", "① Baseline packet");
        put("ai_analysis_detail_format", "=== %s ===\n%s: %s | %s: %s | %s: %.0f%%\n\n%s:\n%s\n\n%s:\n%s\n\n%s:\n%s", "=== %s ===\n%s: %s | %s: %s | %s: %.0f%%\n\n%s:\n%s\n\n%s:\n%s\n\n%s:\n%s");
        put("ai_analysis_label_type", "类型", "Type");
        put("ai_analysis_label_risk", "风险", "Risk");
        put("ai_analysis_label_confidence", "置信度", "Confidence");
        put("ai_analysis_label_desc", "描述", "Description");
        put("ai_analysis_label_evidence", "证据", "Evidence");
        put("ai_analysis_label_remediation", "修复建议", "Remediation");
        put("ai_analysis_confirmed_prefix", "[已确认] ", "[Confirmed] ");
        put("ai_analysis_suspected_prefix", "[疑似] ", "[Suspected] ");
        put("ai_analysis_history_placeholder", "（历史记录）", "(History)");
        put("ai_analysis_chat", "AI 对话", "AI Chat");
        put("ai_analysis_agent_running", "Agent 运行中", "Agent running");
        put("ai_analysis_agent_terminated", "Agent 已终止", "Agent terminated");
        put("ai_analysis_complete_short", " 完成", " complete");
        put("ai_analysis_pipeline_failed", "Pipeline 失败", "Pipeline failed");
        put("ai_analysis_agent_starting", "Agent 启动中...", "Agent starting...");
        put("ai_analysis_agent_analyzing", "Agent 分析中...", "Agent analyzing...");
        put("ai_analysis_pipeline_running", "Pipeline 执行中...", "Pipeline running...");
        put("ai_analysis_fp_prefix", "[误报] ", "[False Positive] ");

        // === RepeaterPanel ===
        put("repeater_col_name", "名称", "Name");
        put("repeater_col_category", "类别", "Category");
        put("repeater_col_target_param", "目标参数", "Target Param");
        put("repeater_col_payload", "Payload", "Payload");
        put("repeater_col_result", "验证结果", "Result");
        put("repeater_col_status_code", "响应码", "Status");
        put("repeater_col_resp_size", "响应大小", "Resp Size");
        put("repeater_test_case_list", " 测试用例列表", " Test Case List");
        put("repeater_collapse", "▲ 折叠", "▲ Collapse");
        put("repeater_expand", "▼ 展开", "▼ Expand");
        put("repeater_collapse_tooltip", "收起/展开测试用例列表，给 Request/Response 腾出更多空间", "Collapse/expand test case list to give more space to Request/Response");
        put("repeater_to_burp_repeater_tooltip", "发送到 Burp 原生 Repeater", "Send to Burp native Repeater");
        put("repeater_to_comparer_tooltip", "发送基线 + 当前响应到 Comparer 对比", "Send baseline + current response to Comparer");
        put("repeater_side_by_side", "▤ 并排对比", "▤ Side by Side");
        put("repeater_side_by_side_tooltip", "在列表中选中 2 行（如越权的两个会话包，Ctrl/⌘ 多选）并排对比确认", "Select 2 rows in the list (e.g. two IDOR session packets, Ctrl/⌘ multi-select) for side-by-side comparison");
        put("repeater_add_case", "+ 添加测试用例", "+ Add Test Case");
        put("repeater_add_case_tooltip", "手动添加一个测试用例行（可编辑名称/参数/Payload）", "Manually add a test case row (editable name/param/payload)");
        put("repeater_new_case", "新测试用例", "New Test Case");
        put("repeater_manual", "手动", "Manual");
        put("repeater_pending", "待验证", "Pending");
        put("repeater_ai_chat_tooltip", "打开 AI 对话分析当前请求", "Open AI chat to analyze current request");
        put("repeater_no_risk", "✓ 无风险", "✓ No Risk");
        put("repeater_anomaly", "⚠ 异常", "⚠ Anomaly");
        put("repeater_confirmed", "⚡ 已确认", "⚡ Confirmed");
        put("repeater_no_response", "无响应", "No Response");
        put("repeater_pending_analysis", "⏳ 待分析", "⏳ Analyzing");
        put("repeater_followup", "追问测试", "Follow-up");
        put("repeater_authz_idor", "越权/IDOR", "Authz/IDOR");
        put("repeater_sql_injection", "SQL注入", "SQL Injection");
        put("repeater_path_traversal", "路径穿越", "Path Traversal");
        put("repeater_ssti", "SSTI/表达式注入", "SSTI/Expression Injection");
        put("repeater_baseline", "基线", "Baseline");
        put("repeater_authz_detect", "越权检测", "Authz Detection");
        put("repeater_session_suffix", " · 会话", " · session");
        put("repeater_verify_result_fmt", "验证结果 — %d — %dms", "Result — %d — %dms");
        put("repeater_followup_fmt", "追问测试 — %d — %dms", "Follow-up — %d — %dms");
        put("repeater_authz_fmt", "越权检测 — %s (最大相似度 %.0f%%)", "Authz Detection — %s (max similarity %.0f%%)");
        put("repeater_authz_detail_fmt", "越权检测 — %s — HTTP %d (相似度 %.0f%%)", "Authz Detection — %s — HTTP %d (similarity %.0f%%)");
        put("repeater_authz_round_prefix", "越权: ", "Authz: ");
        put("repeater_no_risk_text", "无风险", "No Risk");

        // === McpConfigPanel ===
        put("mcp_config_title", "MCP Server 配置（外脑模式）", "MCP Server Config (External Brain Mode)");
        put("mcp_config_desc", "开启后把插件暴露为 MCP Server（仅绑定 127.0.0.1），让 Claude Code / Codex / Qoder\n等外部客户端当「大脑」，调用资产查询 / 白盒源码 / 分析触发 / validate_findings 校验工具。\n切换开关或改端口即时生效（直接启停 MCP 服务，无需重载扩展）。", "Enables the plugin as an MCP Server (127.0.0.1 only), letting Claude Code / Codex / Qoder\nact as the \"brain\", calling asset query / white-box source / analysis trigger / validate_findings tools.\nToggle or port change takes effect immediately (starts/stops MCP service, no reload needed).");
        put("mcp_enable", "启用 MCP Server（Claude Code / Codex / Qoder 等外部客户端连接）", "Enable MCP Server (Claude Code / Codex / Qoder external client connection)");
        put("mcp_active_tools", "允许调用主动/攻击类工具", "Allow active/attack tools");
        put("mcp_active_tools_tooltip", "开启后,外部大脑可通过 Burp 发送真实攻击流量（发包/主动探测/浏览器交互等）。仅在授权测试中开启。", "When enabled, the external brain can send real attack traffic through Burp (requests/probes/browser interaction). Enable only in authorized testing.");
        put("mcp_require_auth", "要求 Bearer Token 鉴权（默认开；关闭则同 Burp 原生，仅本机防护）", "Require Bearer Token auth (default on; off = Burp-native, loopback only)");
        put("mcp_require_auth_tooltip", "关闭后本机任意进程都可直接连接 MCP,便捷但降低安全性。仅绑定 127.0.0.1,并保留 Origin/Host 防护。", "When off, any local process can connect to MCP directly — convenient but less secure. Bound to 127.0.0.1, with Origin/Host guards retained.");
        put("mcp_port_label", "监听端口:", "Listen Port:");
        put("mcp_restart", "应用并（重）启动服务", "Apply & (Re)start Service");
        put("mcp_status_label", "运行状态:", "Status:");
        put("mcp_copy", "复制", "Copy");
        put("mcp_token_copied", "Auth token 已复制", "Auth token copied");
        put("mcp_regen_token", "重新生成", "Regenerate");
        put("mcp_regen_tooltip", "生成一个新的持久 token 并重启服务（旧 token 立即失效，需更新客户端配置）", "Generate a new persistent token and restart the service (old token invalidated immediately, update client config)");
        put("mcp_burp_section", "Burp 官方 MCP（流量桥）", "Burp Native MCP (Traffic Bridge)");
        put("mcp_burp_port_label", "官方端口:", "Native Port:");
        put("mcp_burp_port_tooltip", "Burp 官方 MCP Server BApp 默认监听端口（SSE）。改了官方端口才需改这里。", "Burp native MCP Server BApp default listen port (SSE). Change here only if you changed the native port.");
        put("mcp_bridge_label", "流量桥:", "Bridge:");
        put("mcp_detecting", "检测中…", "Detecting…");
        put("mcp_connected", "已连接 · http://127.0.0.1:", "Connected · http://127.0.0.1:");
        put("mcp_not_detected", "未检测到（BApp Store 装「MCP Server」并在其 MCP tab 启用）", "Not detected (install \"MCP Server\" from BApp Store and enable in its MCP tab)");
        put("mcp_auth_token", "Auth Token:", "Auth Token:");
        put("mcp_token_placeholder", "（启用并成功运行后在此显示；或见 Burp 扩展控制台）", "(Shown here after successful start; or see Burp extension console)");
        put("mcp_token_disabled", "（已关闭鉴权，无需 token）", "(Auth disabled, no token needed)");
        put("mcp_client_config_title", "客户端配置（粘贴到 Claude Code / Codex / Qoder 的 MCP 配置）", "Client Config (paste into Claude Code / Codex / Qoder MCP config)");
        put("mcp_copy_config", "复制配置", "Copy Config");
        put("mcp_config_copied", "MCP 客户端配置已复制", "MCP client config copied");
        put("mcp_started_ok", "MCP started OK", "MCP started OK");
        put("mcp_start_failed", "MCP start FAILED: ", "MCP start FAILED: ");

        // === EmptyStateView ===
        put("empty_subtitle", "API 安全自动检测 · Agent + Pipeline 双模式", "API Security Auto-Detection · Agent + Pipeline Dual Mode");
        put("empty_not_enabled", "未启用", "Not Enabled");
        put("empty_not_configured", "未配置", "Not Configured");
        put("empty_not_linked", "未关联", "Not Linked");
        put("empty_rules", "检测规则", "Detection Rules");
        put("empty_auth_session", "认证会话", "Auth Session");
        put("empty_source", "源码", "Source Code");
        put("empty_mode", "模式", "Mode");
        put("empty_configured", "已设置", "Configured");
        put("empty_linked", "已关联", "Linked");
        put("empty_step1", "导入 API 列表", "Import API List");
        put("empty_step2", "AI 分析", "AI Analysis");
        put("empty_step3", "查看结果", "View Results");
        put("empty_quick_config", "快速配置（可选）", "Quick Setup (Optional)");
        put("empty_llm_provider", "配置 LLM 提供商", "Configure LLM Provider");
        put("empty_auth_session_setup", "配置认证会话", "Configure Auth Session");
        put("empty_auth_set", "Session A/B 已设置", "Session A/B configured");
        put("empty_auth_unavailable", "越权检测不可用", "Authz detection unavailable");
        put("empty_source_code", "关联源码仓库", "Link Source Repository");
        put("empty_source_linked", "已关联", "Linked");
        put("empty_source_not_linked", "未关联（白盒分析不可用）", "Not linked (white-box unavailable)");
        put("empty_rules_count_suffix", " 条", " rules");
        put("empty_agent_mode", "Agent", "Agent");
        put("empty_pipeline_mode", "Pipeline", "Pipeline");
        put("empty_session_ab_set", "Session A/B 已设置", "Session A/B configured");
        put("empty_advanced_config", "高级配置", "Advanced Config");
        put("empty_browser_features", "浏览器功能", "Browser Features");
        put("empty_browser_not_enabled", "未启用 · 在设置面板中勾选「启用浏览器分析」并重启扩展", "Not enabled - check Enable browser analysis in settings and reload");
        put("empty_browser_ready", "驱动已就绪", "Driver ready");
        put("empty_browser_not_installed", "驱动未安装 · 需在终端执行: java -cp playwright-cli.jar com.microsoft.playwright.CLI install chromium", "Driver not installed · run: java -cp playwright-cli.jar com.microsoft.playwright.CLI install chromium");
        put("empty_setup_steps", "安装步骤：", "Setup Steps:");
        put("empty_restart_hint", "3. 重启扩展生效", "3. Reload extension to take effect");
        put("empty_no_api_key", "未配置 API Key", "No API Key configured");
        put("empty_default_model", "默认模型", "Default model");
        // --- setup section items (were hardcoded English) ---
        put("empty_detection_config", "检测配置", "Detection Config");
        put("empty_detection_config_desc", "敏感 / 越权 / WAF / 主动探针 / OOB", "Sensitive / Authz / WAF / Active Probe / OOB");
        put("empty_code_audit_ready", "代码审计就绪", "Code audit ready");
        put("empty_code_audit_unavailable", "代码审计不可用", "Code audit unavailable");
        put("empty_tool_management", "AI 工具管理", "AI Tool Management");
        put("empty_tools_suffix", " 个工具", " tools");
        put("empty_tools_disabled_prefix", "（禁用 ", " (disabled ");
        put("empty_analysis_mode", "分析模式", "Analysis Mode");
        put("empty_agent_autonomous", "Agent（自主）", "Agent (autonomous)");
        put("empty_pipeline_6stage", "Pipeline（6 阶段）", "Pipeline (6-stage)");
        put("empty_sensitive_rules_suffix", " 条敏感规则", " sensitive rules");
        // --- advanced section rows (were hardcoded English) ---
        put("empty_oob_title", "OOB 带外检测", "OOB Out-of-Band Detection");
        put("empty_oob_enabled_desc", "已启用 · DNSLog OOB 验证就绪", "Enabled · DNSLog OOB verification ready");
        put("empty_oob_disabled_desc", "未启用 · 盲漏洞无 OOB 验证（SSRF/XXE/RCE）", "Disabled · no OOB verification for blind vulns (SSRF/XXE/RCE)");
        put("empty_mcp_title", "MCP 外脑模式", "MCP External Brain");
        put("empty_mcp_enabled_bridge", "已启用 · 外脑 + 原生桥已连接", "Enabled · External brain + native bridge connected");
        put("empty_mcp_enabled_no_bridge", "已启用 · 外脑（未检测到原生桥）", "Enabled · External brain (native bridge not detected)");
        put("empty_mcp_disabled_desc", "未启用 · 可让 Claude Code/Codex/Qoder 当大脑", "Disabled · Let Claude Code/Codex/Qoder be the brain");

        // ApiTablePanel
        put("table_risk_auto", "自动", "Auto");
        put("table_traffic_tooltip", "是否已捕获真实流量", "Whether real traffic has been captured");
        put("table_confirm_suspect", "确认/疑似", "Confirmed/Suspected");
        put("table_select_all", "全选可见行  (", "Select all visible (");
        put("table_ai_analyze_suffix", "AI 分析", "AI Analyze");
        put("table_joint_analyze", "🔬 联合分析 (", "🔬 Joint Analyze (");
        put("table_joint_suffix", " 个接口)", " APIs)");
        put("table_joint_tooltip", "一个 Agent 循环分析所有选中接口，共享上下文，可交叉推理", "One Agent loop analyzes all selected APIs, shared context, cross-reasoning");
        put("table_ai_chat", "AI 对话分析", "AI Chat Analysis");
        put("table_view_traffic", "查看历史流量", "View Traffic History");
        put("table_view_findings", "查看发现详情", "View Findings");
        put("table_view_passive", "查看被动检测详情", "View Passive Detection");
        put("table_send_organizer", "发送到 Organizer", "Send to Organizer");
        put("table_copy_path", "复制 API 路径", "Copy API Path");
        put("table_mark_safe", "标记为安全", "Mark as Safe");
        put("table_batch_set_domain", "批量设置域名", "Batch Set Domain");
        put("table_batch_set_domain_tip", "为选中的多个接口统一设置域名", "Set domain for all selected APIs at once");
        put("table_batch_set_domain_prompt", "输入域名（留空则清除域名）：", "Enter domain (empty to clear):");
        put("table_batch_set_domain_title", "批量设置域名", "Batch Set Domain");
        put("table_delete", "删除", "Delete");
        put("table_showing", "显示 %d / %d 条", "Showing %d / %d");
        put("table_total", "共 %d 条", "Total %d");
        put("table_selected", "  |  已选 %d 条", "  |  %d selected");

        // FindingsRenderer
        put("findings_confirmed", "已确认", "Confirmed");
        put("findings_not_reproduced", "未复现", "Not Reproduced");
        put("findings_high_suspected", "高度疑似", "High Suspected");
        put("findings_med_suspected", "中度疑似", "Medium Suspected");
        put("findings_low_suspected", "低度疑似", "Low Suspected");
        put("findings_type", "类型: ", "Type: ");
        put("findings_title", "标题: ", "Title: ");
        put("findings_evidence", "证据:\n", "Evidence:\n");
        put("findings_payload", "使用 Payload:\n", "Payload Used:\n");
        put("findings_response", "响应片段:\n", "Response Snippet:\n");
        put("findings_verify_cmd", "\n🔧 建议验证命令:\n", "\n🔧 Suggested Verify Command:\n");
        put("findings_reason", "疑似原因:\n", "Suspected Reason:\n");
        put("findings_escalation", "\n🔗 链式升级路径:\n", "\n🔗 Chain Escalation Path:\n");
        put("findings_not_found", "（未找到该行对应的发现）", "(No finding found for this row)");
        put("findings_remediation", "修复建议: ", "Remediation: ");
        put("findings_none", "（无）", "(none)");
        put("findings_report_title", "========== 最终安全研判报告 ==========\n\n", "========== Final Security Assessment Report ==========\n\n");
        put("findings_overall_risk", "总体风险: ", "Overall Risk: ");
        put("findings_confirmed_section", "--- 已确认漏洞 (", "--- Confirmed Vulnerabilities (");
        put("findings_suspected_section", "--- 疑似漏洞 (", "--- Suspected Vulnerabilities (");
        put("findings_stage1_section", "--- 阶段1初步评估 (流量分析, 共 ", "--- Stage 1 Initial Assessment (traffic analysis, ");
        put("findings_items_suffix", " 项, 待Payload验证) ---\n\n", " items, pending payload verification) ---\n\n");
        put("findings_remediation_section", "--- 修复建议 ---\n\n", "--- Remediation ---\n\n");
        put("findings_evidence_label", "   证据: ", "   Evidence: ");
        put("findings_payload_label", "   使用Payload: ", "   Payload Used: ");
        put("findings_response_label", "   响应片段: ", "   Response Snippet: ");
        put("findings_verify_label", "   🔧 建议验证命令: ", "   🔧 Suggested Verify Command: ");
        put("findings_reason_label", "   原因: ", "   Reason: ");
        put("findings_escalation_label", "   🔗 链式升级: ", "   🔗 Chain Escalation: ");
    }

    private static void put(String key, String zh, String en) {
        ZH_MAP.put(key, zh);
        EN_MAP.put(key, en);
    }

    public static String get(String key) {
        Map<String, String> map = current == Lang.ZH ? ZH_MAP : EN_MAP;
        return map.getOrDefault(key, key);
    }

    public static void setLang(Lang lang) {
        current = lang;
    }

    public static Lang getLang() {
        return current;
    }

    public static void toggle() {
        current = current == Lang.ZH ? Lang.EN : Lang.ZH;
        for (Consumer<Lang> listener : listeners) {
            try { listener.accept(current); } catch (Exception ignored) {}
        }
    }

    /** P3-5: test-only reset. Resets the language to the default (ZH)
     *  and clears the listeners list so tests that register temporary
     *  listeners don't leak them into subsequent tests. */
    public static void resetForTest() {
        current = Lang.ZH;
        listeners.clear();
    }

}
