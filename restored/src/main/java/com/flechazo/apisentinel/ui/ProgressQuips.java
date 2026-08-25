package com.flechazo.apisentinel.ui;

import java.util.List;
import java.util.Map;

/**
 * 进度条"发疯文学"语料库。纯静态、无状态：给定工具名 + 当前工具调用次数，
 * 返回一句吐槽挂在进度条上，给漫长的 AI 分析找点乐子。
 *
 * 优先级：进度彩蛋（到阈值触发）> 工具名梗 > 思考间隙轮播。
 * 文案刻意写短（进度条宽度有限），完整句子由调用方塞进 tooltip。
 */
public final class ProgressQuips {

    private ProgressQuips() {}

    /** 工具名 → 一句吐槽。 */
    private static final Map<String, String> TOOL_QUIPS = Map.ofEntries(
            Map.entry("send_request", "🚪 敲门，不应就踹"),
            Map.entry("heuristic_scan", "🔍 免费扫一眼，不包准"),
            Map.entry("generate_payloads", "🧪 在调一些很新的东西"),
            Map.entry("audit_codebase", "📚 翻代码，假装看得懂"),
            Map.entry("grep_repo", "🗑️ 垃圾堆里刨宝"),
            Map.entry("read_file", "📖 逐字阅读，眼睛要瞎了"),
            Map.entry("test_auth_bypass", "🎭 戴上头套，现在我是管理员"),
            Map.entry("analyze_traffic", "🚦 看流量，假装看得懂"),
            Map.entry("search_source_code", "🔎 接口接口你藏哪了"),
            Map.entry("submit_report", "📝 写判决书，手在抖"),
            Map.entry("verify_boolean_blind", "🙈 猜是或否，掷骰子"),
            Map.entry("verify_timing_blind", "⏱️ 掐秒表，一秒不敢差"),
            Map.entry("waf_bypass_retry", "🛡️ 跟门卫斗智斗勇"),
            Map.entry("fingerprint_components", "🧬 这框架是个啥"),
            Map.entry("map_sibling_endpoints", "👨‍👩‍👧 这户人家还有几个兄弟"),
            Map.entry("chain_hunter", "🔗 顺藤摸瓜，一锅端"),
            Map.entry("run_sandboxed_code", "🧪 瓶子里做实验，别炸"),
            Map.entry("find_definition", "📍 这方法住哪我看看"),
            Map.entry("find_callers", "📞 谁在偷偷调用你"),
            Map.entry("search_traffic", "🕵️ 翻旧账，找你的案底"),
            Map.entry("list_sessions", "🪪 看看你有几个身份"),
            Map.entry("active_probe", "👉 戳一下，看你疼不疼"),
            Map.entry("diff_responses", "🔬 找不同十级选手"),
            Map.entry("verify_xss_reflection", "🪞 弹回来了吗"),
            Map.entry("verify_ssti", "🧙 念咒语，模板听令"),
            Map.entry("verify_path_traversal", "🚪 ../ 串门，层层递进"),
            Map.entry("verify_xxe", "🦆 让鸭子读个文件"),
            Map.entry("verify_business_logic", "💰 老板，我改个价格试试"),
            Map.entry("generate_oob_probe", "📡 架好天线，等回信"),
            Map.entry("check_oob_results", "📬 信到了没，我看看"),
            Map.entry("ask_user", "🙋 喂，你过来看看这个"),
            Map.entry("dispatch_explore_agent", "🤖 派个小弟去跑腿"),
            Map.entry("trace_taint_source", "🩸 顺着血缘往上摸")
    );

    /** 思考间隙自嘲，按工具次数取模轮播。 */
    private static final List<String> FILLERS = List.of(
            "🤔 AI 在假装深度思考，其实在转圈圈",
            "💸 正在用 token 贿赂模型，心在滴血",
            "🎲 这轮一定出洞，不出我下轮再说一遍",
            "👀 程序员在盯着我，我在盯着代码，互相装",
            "🥲 没洞≠安全，也可能是我菜，别扣工资",
            "⏳ 快了快了真快了（我上上轮就这么说）",
            "🍳 模型在烹饪，希望别糊锅",
            "🧠 我的判断标准：不报错就是没洞（开玩笑的别信）",
            "⛏️ 挖地三尺，挖不到就再挖三尺",
            "🫠 这代码是前人写的，我看不懂很正常"
    );

    /** 进度彩蛋：到达某工具次数时触发一次。 */
    private static final Map<Integer, String> MILESTONES = Map.of(
            10, "🔟 已经问了 10 次，老板路过看了一眼",
            20, "🔥 20 轮了，token 账单在燃烧",
            30, "🥲 30 轮，模型说'快好了'，别信",
            40, "😱 40 轮，逼近下班时间，没有加班费",
            48, "🚨 最后的冲刺，这轮打完我就下班"
    );

    /** Pipeline 六阶段梗。 */
    private static final Map<Integer, String> STAGE_QUIPS = Map.of(
            1, "🚦 阶段1：先瞅瞅流量长啥样",
            2, "📚 阶段2：翻代码对答案",
            3, "🧪 阶段3：调 payload，上强度",
            4, "💥 阶段4：真刀真枪发请求",
            5, "🎭 阶段5：试试能不能越权",
            6, "⚖️ 阶段6：最终审判，落槌"
    );

    /** 给定阶段号返回一句阶段梗；未知阶段回退到朴素 "阶段 N/6"。 */
    public static String stageQuip(int stage) {
        return STAGE_QUIPS.getOrDefault(stage, "阶段 " + stage + "/6");
    }

    /** 完成播报（按最终确认/疑似数量挑一句）。 */
    public static String completionQuip(int confirmed, int suspected) {
        if (confirmed > 0) {
            return confirmed >= 3
                    ? "🚨 挖到 " + confirmed + " 个确认漏洞，建议程序员连夜跑路"
                    : "⚖️ 判决完毕，" + confirmed + " 个确认漏洞，程序员表情管理失败";
        }
        if (suspected > 0) {
            return "🤨 没抓到实锤，但有 " + suspected + " 个疑似，你最好晚上想想";
        }
        return "✅ 一个洞没有，要么代码固若金汤，要么我菜";
    }

    /** 中断/失败播报。 */
    public static String abortQuip() {
        return "🫠 寄了，先歇会儿，剩下的你看着办";
    }

    /**
     * 给定当前工具名 + 已发生的工具调用次数，返回该挂哪句梗。
     * 优先级：进度彩蛋 > 工具名梗 > 思考间隙轮播；都没有返回 null。
     */
    public static String quipFor(String toolName, int toolCallCount) {
        String milestone = MILESTONES.get(toolCallCount);
        if (milestone != null) return milestone;
        if (toolName != null && !toolName.isEmpty()) {
            String q = TOOL_QUIPS.get(toolName);
            if (q != null) return q;
        }
        if (FILLERS.isEmpty()) return null;
        int idx = Math.floorMod(toolCallCount, FILLERS.size());
        return FILLERS.get(idx);
    }
}
