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

    static {
        // Toolbar & buttons
        put("import_api", "导入 API", "Import API");
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

    public static void addLocaleChangeListener(Consumer<Lang> listener) {
        listeners.add(listener);
    }
}
