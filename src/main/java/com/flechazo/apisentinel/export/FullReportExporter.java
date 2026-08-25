package com.flechazo.apisentinel.export;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;
import com.flechazo.apisentinel.testgen.model.TestCase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Generates a comprehensive penetration test report in Markdown format.
 * Includes executive summary, per-API findings, test cases, statistics, and remediation.
 */
public class FullReportExporter implements ReportExporter {

    @Override
    public void export(List<ApiEntry> entries, Path outputPath) throws IOException {
        StringBuilder sb = new StringBuilder();
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // ============================
        // 1. Title & Executive Summary
        // ============================
        sb.append("# API 安全渗透测试完整报告\n\n");
        sb.append("> 由 API Sentinel 自动生成\n\n");
        sb.append("---\n\n");
        sb.append("## 1. 报告概览\n\n");
        sb.append("| 项目 | 值 |\n");
        sb.append("|------|----|\n");
        sb.append("| 生成时间 | ").append(timestamp).append(" |\n");
        sb.append("| API 总数 | ").append(entries.size()).append(" |\n");

        long tested = entries.stream().filter(ApiEntry::isTested).count();
        long untested = entries.size() - tested;
        long vulnerable = entries.stream().filter(e -> e.getStatus() == ApiStatus.VULNERABLE).count();
        long passed = entries.stream().filter(e -> e.getStatus() == ApiStatus.PASSED).count();
        long underTest = entries.stream().filter(e -> e.getStatus() == ApiStatus.UNDER_TEST).count();

        double testedPct = entries.isEmpty() ? 0 : tested * 100.0 / entries.size();
        sb.append(String.format("| 已测试 | %d (%.1f%%) |\n", tested, testedPct));
        sb.append("| 测试通过 | ").append(passed).append(" |\n");
        sb.append("| 存在漏洞 | ").append(vulnerable).append(" |\n");
        sb.append("| 测试中 | ").append(underTest).append(" |\n");
        sb.append("| 未测试 | ").append(untested).append(" |\n\n");

        // Count findings by risk level across all entries
        int highCount = 0, medCount = 0, lowCount = 0, infoCount = 0;
        int totalFindings = 0;
        for (ApiEntry entry : entries) {
            for (AnalysisRecord record : entry.getAnalysisHistory()) {
                if (record.result() != null && record.result().isSuccess()) {
                    for (VulnFinding f : record.result().findings()) {
                        totalFindings++;
                        switch (f.risk().toUpperCase()) {
                            case "HIGH" -> highCount++;
                            case "MEDIUM" -> medCount++;
                            case "LOW" -> lowCount++;
                            default -> infoCount++;
                        }
                    }
                }
            }
        }

        sb.append("### 风险统计\n\n");
        sb.append("| 风险等级 | 数量 |\n");
        sb.append("|----------|------|\n");
        sb.append("| 高危 (HIGH) | ").append(highCount).append(" |\n");
        sb.append("| 中危 (MEDIUM) | ").append(medCount).append(" |\n");
        sb.append("| 低危 (LOW) | ").append(lowCount).append(" |\n");
        sb.append("| 信息 (INFO) | ").append(infoCount).append(" |\n");
        sb.append("| **总计** | **").append(totalFindings).append("** |\n\n");

        // ============================
        // 2. Statistics Charts (text-based)
        // ============================
        sb.append("## 2. 统计图表\n\n");
        sb.append("### 测试覆盖率\n\n");
        sb.append("```\n");
        appendBarChart(sb, "已通过", (int) passed, entries.size());
        appendBarChart(sb, "有漏洞", (int) vulnerable, entries.size());
        appendBarChart(sb, "测试中", (int) underTest, entries.size());
        appendBarChart(sb, "未测试", (int) untested, entries.size());
        sb.append("```\n\n");

        sb.append("### 风险分布\n\n");
        sb.append("```\n");
        int maxFindings = Math.max(1, Math.max(highCount, Math.max(medCount, Math.max(lowCount, infoCount))));
        appendBarChart(sb, "HIGH  ", highCount, maxFindings);
        appendBarChart(sb, "MEDIUM", medCount, maxFindings);
        appendBarChart(sb, "LOW   ", lowCount, maxFindings);
        appendBarChart(sb, "INFO  ", infoCount, maxFindings);
        sb.append("```\n\n");

        // ============================
        // 3. Domain breakdown
        // ============================
        Map<String, List<ApiEntry>> byDomain = entries.stream()
                .filter(e -> e.getDomain() != null && !e.getDomain().isEmpty())
                .collect(Collectors.groupingBy(ApiEntry::getDomain));

        if (!byDomain.isEmpty()) {
            sb.append("## 3. 域名分布\n\n");
            sb.append("| 域名 | 接口数 | 漏洞数 | 已测试 |\n");
            sb.append("|------|--------|--------|--------|\n");
            for (Map.Entry<String, List<ApiEntry>> de : byDomain.entrySet()) {
                long domVuln = de.getValue().stream().filter(e -> e.getStatus() == ApiStatus.VULNERABLE).count();
                long domTested = de.getValue().stream().filter(ApiEntry::isTested).count();
                sb.append("| ").append(de.getKey())
                        .append(" | ").append(de.getValue().size())
                        .append(" | ").append(domVuln)
                        .append(" | ").append(domTested)
                        .append(" |\n");
            }
            sb.append("\n");
        }

        // ============================
        // 4. Vulnerability Details
        // ============================
        sb.append("## 4. 漏洞详情\n\n");

        List<ApiEntry> vulnEntries = entries.stream()
                .filter(e -> e.getStatus() == ApiStatus.VULNERABLE || hasFindings(e))
                .collect(Collectors.toList());

        if (vulnEntries.isEmpty()) {
            sb.append("*未发现漏洞*\n\n");
        } else {
            int vulnIdx = 1;
            for (ApiEntry entry : vulnEntries) {
                sb.append("### 4.").append(vulnIdx++).append(" ").append(entry.getHttpMethod())
                        .append(" ").append(entry.getApiPath()).append("\n\n");
                sb.append("- **域名**: ").append(entry.getDomain()).append("\n");
                sb.append("- **状态**: ").append(entry.getStatus().getDisplayName()).append("\n");
                if (entry.getVulnType() != null) {
                    sb.append("- **漏洞类型**: ").append(entry.getVulnType().getDisplayName()).append("\n");
                }
                if (entry.getNote() != null && !entry.getNote().isEmpty()) {
                    sb.append("- **备注**: ").append(entry.getNote()).append("\n");
                }
                if (entry.hasPassiveFindings()) {
                    sb.append("- **被动检测**:\n");
                    for (String line : entry.buildPassiveFindingsText().split("\n")) {
                        sb.append("  ").append(line).append("\n");
                    }
                }
                sb.append("\n");

                // AI Analysis findings
                for (AnalysisRecord record : entry.getAnalysisHistory()) {
                    if (record.result() == null || !record.result().isSuccess()) continue;
                    AnalysisResult result = record.result();

                    sb.append("#### AI 分析结果 (").append(record.mode()).append(")\n\n");
                    sb.append("- 风险等级: **").append(result.overallRisk()).append("**\n");
                    sb.append("- 模型: ").append(result.modelUsed()).append("\n");
                    sb.append("- 分析耗时: ").append(result.analysisTimeMs()).append("ms\n");
                    if (result.summary() != null && !result.summary().isEmpty()) {
                        sb.append("- 摘要: ").append(result.summary()).append("\n");
                    }
                    sb.append("\n");

                    if (!result.findings().isEmpty()) {
                        sb.append("| # | 类型 | 风险 | 置信度 | 标题 |\n");
                        sb.append("|---|------|------|--------|------|\n");
                        int fIdx = 1;
                        for (VulnFinding f : result.findings()) {
                            sb.append("| ").append(fIdx++).append(" | ").append(f.type())
                                    .append(" | ").append(f.risk())
                                    .append(" | ").append(String.format("%.0f%%", f.confidence() * 100))
                                    .append(" | ").append(f.title()).append(" |\n");
                        }
                        sb.append("\n");

                        // Detailed findings
                        for (VulnFinding f : result.findings()) {
                            sb.append("**").append(f.title()).append("** (").append(f.risk()).append(")\n\n");
                            if (f.description() != null && !f.description().isEmpty()) {
                                sb.append(f.description()).append("\n\n");
                            }
                            if (f.evidence() != null && !f.evidence().isEmpty()) {
                                sb.append("证据:\n```\n").append(f.evidence()).append("\n```\n\n");
                            }
                            if (f.location() != null && !f.location().isEmpty()) {
                                sb.append("位置: `").append(f.location()).append("`\n\n");
                            }
                            if (f.remediation() != null && !f.remediation().isEmpty()) {
                                sb.append("修复建议: ").append(f.remediation()).append("\n\n");
                            }
                        }
                    }

                    // Test cases
                    if (record.testCases() != null && !record.testCases().isEmpty()) {
                        sb.append("#### 测试用例\n\n");
                        int tcIdx = 1;
                        for (TestCase tc : record.testCases()) {
                            sb.append("**用例 ").append(tcIdx++).append("**: ").append(tc.name()).append("\n\n");
                            sb.append("- 类型: ").append(tc.category()).append("\n");
                            sb.append("- 方法: ").append(tc.method()).append("\n");
                            sb.append("- 路径: `").append(tc.path()).append("`\n");
                            if (tc.payload() != null && !tc.payload().isEmpty()) {
                                sb.append("- Payload:\n```\n").append(tc.payload()).append("\n```\n");
                            }
                            if (tc.expectedIfVulnerable() != null && !tc.expectedIfVulnerable().isEmpty()) {
                                sb.append("- 预期特征: `").append(tc.expectedIfVulnerable()).append("`\n");
                            }
                            sb.append("\n");
                        }
                    }

                    // AI verdict + validation gate (Phase 4)
                    if (record.hasPipelineResult() && record.pipelineResult().verdict() != null) {
                        FinalVerdict verdict = record.pipelineResult().verdict();
                        sb.append("#### AI 研判与验证门禁\n\n");
                        sb.append("- 综合风险: **").append(verdict.overallRisk()).append("**\n");
                        if (verdict.confirmedVulns() != null && !verdict.confirmedVulns().isEmpty()) {
                            sb.append("- 已确认:\n");
                            for (ConfirmedVuln cv : verdict.confirmedVulns()) {
                                sb.append("  - [").append(cv.type()).append("] ").append(cv.title());
                                if (cv.cvss() != null && !cv.cvss().isEmpty()) {
                                    sb.append("（CVSS: ").append(cv.cvss()).append("）");
                                }
                                sb.append("\n");
                                if (cv.identityProof() != null && !cv.identityProof().isEmpty()) {
                                    sb.append("    - 身份证据: ").append(cv.identityProof()).append("\n");
                                }
                            }
                        }
                        if (verdict.suspectedVulns() != null && !verdict.suspectedVulns().isEmpty()) {
                            sb.append("- 疑似:\n");
                            for (SuspectedVuln sv : verdict.suspectedVulns()) {
                                sb.append("  - [").append(sv.type()).append("] ").append(sv.title())
                                  .append("（置信度: ").append(sv.confidence()).append("）\n");
                            }
                        }
                        sb.append("- 验证门禁: ");
                        if (verdict.rejectionReasons() == null || verdict.rejectionReasons().isEmpty()) {
                            sb.append("全部校验通过\n");
                        } else {
                            sb.append("\n");
                            for (String r : verdict.rejectionReasons()) {
                                sb.append("  - ").append(r).append("\n");
                            }
                        }
                        sb.append("\n");
                    }
                }

                sb.append("---\n\n");
            }
        }

        // ============================
        // 5. Sensitive Info Findings
        // ============================
        // Structured filter (post passive-structuring refactor): entries with
        // at least one SENSITIVE_INFO finding — replaces the old guesswork of
        // scanning the free-text note for keywords like "敏感"/"token".
        List<ApiEntry> sensitiveEntries = entries.stream()
                .filter(e -> e.getPassiveFindings().stream()
                        .anyMatch(f -> f.source() == com.flechazo.apisentinel.model.PassiveFinding.Source.SENSITIVE_INFO))
                .collect(Collectors.toList());

        if (!sensitiveEntries.isEmpty()) {
            sb.append("## 5. 敏感信息发现\n\n");
            sb.append("| API | 域名 | 发现 |\n");
            sb.append("|-----|------|------|\n");
            for (ApiEntry e : sensitiveEntries) {
                String rules = e.getPassiveFindings().stream()
                        .filter(f -> f.source() == com.flechazo.apisentinel.model.PassiveFinding.Source.SENSITIVE_INFO)
                        .map(f -> f.title())
                        .collect(Collectors.joining("; "));
                sb.append("| ").append(escapeMd(e.getHttpMethod())).append(" ").append(escapeMd(e.getApiPath()))
                        .append(" | ").append(escapeMd(e.getDomain()))
                        .append(" | ").append(escapeMd(rules))
                        .append(" |\n");
            }
            sb.append("\n");
        }

        // ============================
        // 6. Full API List
        // ============================
        sb.append("## 6. 完整 API 列表\n\n");
        sb.append("| # | Method | API | 状态 | 结果 | 域名 |\n");
        sb.append("|---|--------|-----|------|------|------|\n");
        for (int i = 0; i < entries.size(); i++) {
            ApiEntry e = entries.get(i);
            sb.append("| ").append(i + 1)
                    .append(" | ").append(escapeMd(e.getHttpMethod()))
                    .append(" | ").append(escapeMd(e.getApiPath()))
                    .append(" | ").append(escapeMd(e.getStatus().getDisplayName()))
                    .append(" | ").append(escapeMd(e.getResult()))
                    .append(" | ").append(escapeMd(e.getDomain()))
                    .append(" |\n");
        }
        sb.append("\n");

        // ============================
        // 7. Remediation Summary
        // ============================
        Set<String> remediations = new LinkedHashSet<>();
        for (ApiEntry entry : entries) {
            for (AnalysisRecord record : entry.getAnalysisHistory()) {
                if (record.result() != null && record.result().isSuccess()) {
                    for (VulnFinding f : record.result().findings()) {
                        if (f.remediation() != null && !f.remediation().isEmpty()) {
                            remediations.add(f.remediation());
                        }
                    }
                }
            }
        }

        if (!remediations.isEmpty()) {
            sb.append("## 7. 修复建议汇总\n\n");
            int rIdx = 1;
            for (String r : remediations) {
                sb.append(rIdx++).append(". ").append(r).append("\n");
            }
            sb.append("\n");
        }

        sb.append("---\n\n");
        sb.append("*报告结束 - API Sentinel v" + com.flechazo.apisentinel.ApiSentinelExtension.VERSION + "*\n");

        Files.writeString(outputPath, sb.toString());
    }

    private boolean hasFindings(ApiEntry entry) {
        for (AnalysisRecord record : entry.getAnalysisHistory()) {
            if (record.result() != null && record.result().isSuccess() && !record.result().findings().isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private void appendBarChart(StringBuilder sb, String label, int value, int total) {
        int barWidth = 40;
        int filled = total > 0 ? (int) Math.round((double) value / total * barWidth) : 0;
        filled = Math.max(0, Math.min(filled, barWidth));
        sb.append(String.format("%-8s ", label));
        sb.append("│");
        sb.append("█".repeat(filled));
        sb.append("░".repeat(barWidth - filled));
        sb.append("│ ").append(value).append("\n");
    }

    @Override
    public String getFileExtension() {
        return "md";
    }

    @Override
    public String getDescription() {
        return "完整渗透测试报告（Markdown）";
    }

    private static String escapeMd(String value) {
        if (value == null) return "";
        return value.replace("|", "\\|").replace("\n", " ");
    }
}
