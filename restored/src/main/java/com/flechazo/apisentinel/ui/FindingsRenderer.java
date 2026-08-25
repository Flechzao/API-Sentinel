package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared rendering logic for a FinalVerdict's findings table rows and detail
 * text — extracted so AiAnalysisPanel's embedded results panel and
 * FindingsDetailDialog's standalone popup don't duplicate the same
 * formatting. Pure functions, no Swing state.
 */
final class FindingsRenderer {

    private FindingsRenderer() {}

    /** Row shape: [type, severity, status, title, payload]. */
    static List<Object[]> buildFindingsRows(FinalVerdict verdict) {
        List<Object[]> rows = new ArrayList<>();
        boolean isSafe = "SAFE".equalsIgnoreCase(verdict.overallRisk());

        for (ConfirmedVuln cv : verdict.confirmedVulns()) {
            rows.add(new Object[]{cv.type(), "HIGH", "已确认", cv.title(), cv.payloadUsed()});
        }
        for (SuspectedVuln sv : verdict.suspectedVulns()) {
            String displayRisk = isSafe ? "INFO" : "MEDIUM";
            String displayConf = isSafe ? "未复现" : switch (sv.confidence()) {
                case "HIGH" -> "高度疑似";
                case "LOW" -> "低度疑似";
                default -> "中度疑似";
            };
            rows.add(new Object[]{sv.type(), displayRisk, displayConf, sv.title(), ""});
        }
        return rows;
    }

    /**
     * Detail text for exactly one row of buildFindingsRows()'s output — rows
     * 0..confirmedCount-1 are confirmed vulns, the rest are suspected, in the
     * same order buildFindingsRows() emits them.
     */
    static String buildSingleFindingDetailText(FinalVerdict verdict, int rowIndex) {
        int confirmedCount = verdict.confirmedVulns().size();
        StringBuilder sb = new StringBuilder();
        if (rowIndex >= 0 && rowIndex < confirmedCount) {
            ConfirmedVuln cv = verdict.confirmedVulns().get(rowIndex);
            sb.append("状态: 已确认（通过程序化校验，payload 确实发送过）\n\n");
            sb.append("类型: ").append(cv.type()).append("\n");
            sb.append("标题: ").append(cv.title()).append("\n\n");
            sb.append("证据:\n").append(nullToDash(cv.evidence())).append("\n\n");
            sb.append("使用 Payload:\n").append(nullToDash(cv.payloadUsed())).append("\n\n");
            sb.append("响应片段:\n").append(nullToDash(cv.response())).append("\n");
            if (cv.verifyCommand() != null && !cv.verifyCommand().isEmpty()) {
                sb.append("\n🔧 建议验证命令:\n").append(cv.verifyCommand()).append("\n");
            }
        } else {
            int idx = rowIndex - confirmedCount;
            List<SuspectedVuln> suspected = verdict.suspectedVulns();
            if (idx >= 0 && idx < suspected.size()) {
                SuspectedVuln sv = suspected.get(idx);
                sb.append("状态: 疑似（未通过程序化校验 / 未实测确认，没有 payload）\n\n");
                sb.append("类型: ").append(sv.type()).append("\n");
                sb.append("标题: ").append(sv.title()).append("\n\n");
                sb.append("疑似原因:\n").append(nullToDash(sv.reason())).append("\n");
                if (sv.escalationPath() != null && !sv.escalationPath().isBlank()) {
                    sb.append("\n🔗 链式升级路径:\n").append(sv.escalationPath()).append("\n");
                }
                if (sv.verifyCommand() != null && !sv.verifyCommand().isEmpty()) {
                    sb.append("\n🔧 建议验证命令:\n").append(sv.verifyCommand()).append("\n");
                }
            } else {
                sb.append("（未找到该行对应的发现）");
            }
        }
        return sb.toString();
    }

    /** Summary + recommendations — global to the verdict, shown regardless
     *  of which finding row is selected. */
    static String buildSummaryText(FinalVerdict verdict) {
        StringBuilder sb = new StringBuilder();
        if (verdict.summary() != null && !verdict.summary().isEmpty()) {
            sb.append(verdict.summary());
        }
        if (verdict.recommendations() != null && !verdict.recommendations().isEmpty()) {
            if (sb.length() > 0) sb.append("\n\n");
            sb.append("修复建议: ").append(verdict.recommendations());
        }
        return sb.toString();
    }

    private static String nullToDash(String s) {
        return (s == null || s.isEmpty()) ? "（无）" : s;
    }

    static String buildDetailText(FinalVerdict verdict, AnalysisResult trafficAnalysis) {
        boolean isSafe = "SAFE".equalsIgnoreCase(verdict.overallRisk());
        StringBuilder detail = new StringBuilder();
        detail.append("========== 最终安全研判报告 ==========\n\n");
        detail.append("总体风险: ").append(verdict.overallRisk()).append("\n");

        if (isSafe && !verdict.suspectedVulns().isEmpty()) {
            detail.append("\n⚠ 风险等级说明：阶段1初步分析发现了潜在风险点，但经过阶段4的 Payload 实际验证，");
            detail.append("所有测试均未能复现漏洞，因此最终研判为 SAFE。");
            detail.append("下方「疑似漏洞」为理论风险，仅供参考。\n");
        }
        detail.append("\n");

        if (!verdict.confirmedVulns().isEmpty()) {
            detail.append("--- 已确认漏洞 (").append(verdict.confirmedVulns().size()).append(") ---\n\n");
            for (int i = 0; i < verdict.confirmedVulns().size(); i++) {
                ConfirmedVuln cv = verdict.confirmedVulns().get(i);
                detail.append(String.format("%d. [%s] %s\n", i + 1, cv.type(), cv.title()));
                detail.append("   证据: ").append(cv.evidence()).append("\n");
                detail.append("   使用Payload: ").append(cv.payloadUsed()).append("\n");
                detail.append("   响应片段: ").append(cv.response()).append("\n");
                if (cv.verifyCommand() != null && !cv.verifyCommand().isEmpty()) {
                    detail.append("   🔧 建议验证命令: ").append(cv.verifyCommand()).append("\n");
                }
                detail.append("\n");
            }
        }

        if (!verdict.suspectedVulns().isEmpty()) {
            detail.append("--- 疑似漏洞 (").append(verdict.suspectedVulns().size()).append(") ---\n\n");
            for (int i = 0; i < verdict.suspectedVulns().size(); i++) {
                SuspectedVuln sv = verdict.suspectedVulns().get(i);
                detail.append(String.format("%d. [%s] %s\n", i + 1, sv.type(), sv.title()));
                detail.append("   原因: ").append(sv.reason()).append("\n");
                if (sv.escalationPath() != null && !sv.escalationPath().isBlank()) {
                    detail.append("   🔗 链式升级: ").append(sv.escalationPath()).append("\n");
                }
                if (sv.verifyCommand() != null && !sv.verifyCommand().isEmpty()) {
                    detail.append("   🔧 建议验证命令: ").append(sv.verifyCommand()).append("\n");
                }
                detail.append("\n");
            }
        }

        if (trafficAnalysis != null && trafficAnalysis.findings() != null && !trafficAnalysis.findings().isEmpty()) {
            detail.append("--- 阶段1初步评估 (流量分析, 共 ").append(trafficAnalysis.findings().size()).append(" 项, 待Payload验证) ---\n\n");
            for (int i = 0; i < trafficAnalysis.findings().size(); i++) {
                VulnFinding f = trafficAnalysis.findings().get(i);
                detail.append(String.format("%d. [%s][%s] %s\n", i + 1, f.risk(), f.type(), f.title()));
                if (f.evidence() != null && !f.evidence().isEmpty()) {
                    detail.append("   证据: ").append(f.evidence()).append("\n");
                }
                detail.append("\n");
            }
        }

        if (verdict.recommendations() != null && !verdict.recommendations().isEmpty()) {
            detail.append("--- 修复建议 ---\n\n");
            detail.append(verdict.recommendations()).append("\n");
        }

        return detail.toString();
    }
}
