package com.flechazo.apisentinel.export;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.VulnType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class MarkdownExporter implements ReportExporter {

    @Override
    public void export(List<ApiEntry> entries, Path outputPath) throws IOException {
        StringBuilder sb = new StringBuilder();
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        sb.append("# API 安全测试报告\n\n");
        sb.append("- **生成时间**: ").append(timestamp).append("\n");
        sb.append("- **API总数**: ").append(entries.size()).append("\n");

        long tested = entries.stream().filter(ApiEntry::isTested).count();
        long vulnerable = entries.stream().filter(e -> e.getStatus() == ApiStatus.VULNERABLE).count();
        long passed = entries.stream().filter(e -> e.getStatus() == ApiStatus.PASSED).count();
        long untested = entries.size() - tested;

        sb.append("- **已测试**: ").append(tested);
        if (!entries.isEmpty()) {
            sb.append(String.format(" (%.0f%%)", tested * 100.0 / entries.size()));
        }
        sb.append("\n");
        sb.append("- **存在漏洞**: ").append(vulnerable).append("\n\n");

        // Summary table
        sb.append("## 统计摘要\n\n");
        sb.append("| 状态 | 数量 |\n");
        sb.append("|------|------|\n");
        sb.append("| 测试通过 | ").append(passed).append(" |\n");
        sb.append("| 存在漏洞 | ").append(vulnerable).append(" |\n");
        sb.append("| 测试中 | ").append(entries.stream().filter(e -> e.getStatus() == ApiStatus.UNDER_TEST).count()).append(" |\n");
        sb.append("| 未测试 | ").append(untested).append(" |\n\n");

        // Vulnerabilities by type
        if (vulnerable > 0) {
            sb.append("## 发现的漏洞\n\n");

            Map<VulnType, List<ApiEntry>> vulnGroups = entries.stream()
                    .filter(e -> e.getVulnType() != null)
                    .collect(Collectors.groupingBy(ApiEntry::getVulnType));

            for (Map.Entry<VulnType, List<ApiEntry>> group : vulnGroups.entrySet()) {
                sb.append("### ").append(group.getKey().getDisplayName())
                        .append(" (").append(group.getValue().size()).append(")\n\n");
                sb.append("| API | Method | Domain | Note |\n");
                sb.append("|-----|--------|--------|------|\n");
                for (ApiEntry e : group.getValue()) {
                    sb.append("| ").append(escapeMd(e.getApiPath()))
                            .append(" | ").append(escapeMd(e.getHttpMethod()))
                            .append(" | ").append(escapeMd(e.getDomain()))
                            .append(" | ").append(escapeMd(e.getNote()))
                            .append(" |\n");
                }
                sb.append("\n");
            }
        }

        // Full API list
        sb.append("## 完整API列表\n\n");
        sb.append("| # | Method | API | Status | Result | Note | Passive | Domain |\n");
        sb.append("|---|--------|-----|--------|--------|-------|---------|--------|\n");
        for (int i = 0; i < entries.size(); i++) {
            ApiEntry e = entries.get(i);
            sb.append("| ").append(i + 1)
                    .append(" | ").append(escapeMd(e.getHttpMethod()))
                    .append(" | ").append(escapeMd(e.getApiPath()))
                    .append(" | ").append(escapeMd(e.getStatus().getDisplayName()))
                    .append(" | ").append(escapeMd(e.getResult()))
                    .append(" | ").append(escapeMd(e.getNote()))
                    .append(" | ").append(escapeMd(e.getDisplayPassiveSummary()))
                    .append(" | ").append(escapeMd(e.getDomain()))
                    .append(" |\n");
        }

        Files.writeString(outputPath, sb.toString());
    }

    @Override
    public String getFileExtension() {
        return "md";
    }

    @Override
    public String getDescription() {
        return "Markdown格式安全测试报告";
    }

    private static String escapeMd(String value) {
        if (value == null) return "";
        return value.replace("|", "\\|").replace("\n", " ");
    }
}
