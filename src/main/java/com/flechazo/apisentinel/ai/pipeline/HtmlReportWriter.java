package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

/**
 * Writes a self-contained HTML report whenever a pipeline/agent analysis
 * confirms or suspects a vulnerability — a shareable, standalone artifact
 * (single file, inline CSS, no external assets — opens directly in a
 * browser) that preserves the real request/response evidence behind each
 * finding. Complements PipelineReportWriter's JSON (complete but not meant
 * for skimming) and FullReportExporter's batch Markdown (covers every API
 * at once, not a focused per-finding writeup) — this is specifically for
 * "here's the one request that proves this bug is real."
 *
 * Auto-generated on every completed run that has at least one confirmed or
 * suspected vuln, same as PipelineReportWriter's JSON reports — no separate
 * on/off setting, kept consistent with that existing behavior.
 */
public class HtmlReportWriter {

    private static final DateTimeFormatter FILE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
    private static final int MAX_REPORTS = 200;

    private final Path reportsDir;
    private final LeveledLogger logger;

    public HtmlReportWriter(LeveledLogger logger) {
        // Same directory as the JSON report (reportsDir) so a single run's
        // .json + .html sit side-by-side with matching filenames.
        this.reportsDir = com.flechazo.apisentinel.config.AppPaths.reportsDir();
        this.logger = logger;
    }

    /**
     * @return the saved file's path, or null if there was nothing to report
     *         (no confirmed/suspected vulns) or saving failed.
     */
    public Path saveReport(ApiEntry entry, PipelineResult result) {
        SaveOutcome outcome = saveReportEx(entry, result);
        return outcome.path();
    }

    /** P0-12 #6 hardening: explicit-result form of {@link #saveReport}.
     *  Pre-P0-12, both "no findings to report" and "disk write failed"
     *  collapsed to {@code null}, so callers (PipelineFacade) couldn't
     *  tell a successful no-op from a silent failure — "no HTML button"
     *  looked identical to "we tried and failed". The new record
     *  distinguishes the three outcomes:
     *  <ul>
     *    <li><b>SAVED</b>: wrote successfully, path is non-null.</li>
     *    <li><b>NO_CONTENT</b>: verdict had nothing worth reporting —
     *        designed no-op, not a failure.</li>
     *    <li><b>FAILED</b>: write failed; errorMessage has details.</li>
     *  </ul>
     *  PipelineFacade should show "查看报告" only for SAVED, log an
     *  explicit "report save failed" note for FAILED, and the existing
     *  "no findings" note for NO_CONTENT. */
    public SaveOutcome saveReportEx(ApiEntry entry, PipelineResult result) {
        FinalVerdict verdict = result.verdict();
        if (verdict == null || (verdict.confirmedVulns().isEmpty() && verdict.suspectedVulns().isEmpty())) {
            return SaveOutcome.noContent();
        }
        try {
            Files.createDirectories(reportsDir);

            String timestamp = FILE_FMT.format(LocalDateTime.now());
            String method = entry.getHttpMethod() != null ? entry.getHttpMethod().replace("/", "-") : "GET";
            String pathSlug = sanitizeForFilename(entry.getApiPath());
            String filename = String.format("%s_%s_%s.html", timestamp, method, pathSlug);
            Path file = reportsDir.resolve(filename);

            String html = buildHtml(entry, result, verdict);
            Files.writeString(file, html);
            logger.info("[HTML报告] 已保存: %s (%d bytes)", file.getFileName(), html.length());

            cleanupOldReports();
            return SaveOutcome.saved(file);
        } catch (IOException e) {
            logger.error("[HTML报告] 保存失败: %s", e.getMessage());
            return SaveOutcome.failed(e.getMessage() == null
                    ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    /** Result of {@link #saveReportEx}. Use {@link #kind()} to switch on
     *  the outcome; {@link #path()} is non-null only for SAVED,
     *  {@link #errorMessage()} only for FAILED. */
    public record SaveOutcome(Kind kind, Path path, String errorMessage) {
        public enum Kind { SAVED, NO_CONTENT, FAILED }
        static SaveOutcome saved(Path p) { return new SaveOutcome(Kind.SAVED, p, null); }
        static SaveOutcome noContent() { return new SaveOutcome(Kind.NO_CONTENT, null, null); }
        static SaveOutcome failed(String reason) { return new SaveOutcome(Kind.FAILED, null, reason); }
    }

    public Path getReportsDir() { return reportsDir; }

    /** Same "keep the newest MAX_REPORTS, delete the rest" policy as
     *  PipelineReportWriter, scoped to this directory's own .html files. */
    private void cleanupOldReports() {
        try (var stream = Files.list(reportsDir)) {
            List<Path> files = stream
                    .filter(p -> p.toString().endsWith(".html"))
                    .sorted(Comparator.comparingLong(p -> {
                        try { return Files.getLastModifiedTime(p).toMillis(); }
                        catch (IOException e) { return 0L; }
                    }))
                    .collect(java.util.stream.Collectors.toList());

            if (files.size() > MAX_REPORTS) {
                int toDelete = files.size() - MAX_REPORTS;
                for (int i = 0; i < toDelete; i++) {
                    try {
                        Files.delete(files.get(i));
                        logger.debug("[HTML报告] 自动清理旧报告: %s", files.get(i).getFileName());
                    } catch (IOException ignored) {}
                }
                logger.info("[HTML报告] 自动清理了 %d 个旧报告，保留最新 %d 个", toDelete, MAX_REPORTS);
            }
        } catch (IOException e) {
            logger.warn("[HTML报告] 清理旧报告失败: %s", e.getMessage());
        }
    }

    private String buildHtml(ApiEntry entry, PipelineResult result, FinalVerdict verdict) {
        String title = escapeHtml((entry.getHttpMethod() != null ? entry.getHttpMethod() : "") + " " + entry.getApiPath());
        String riskClass = verdict.overallRisk() != null ? verdict.overallRisk().toLowerCase() : "info";

        StringBuilder body = new StringBuilder();
        body.append("<div class=\"header\">");
        body.append("<h1>").append(title).append("</h1>");
        body.append("<div class=\"meta\">");
        body.append("<span>域名: ").append(escapeHtml(entry.getDomain())).append("</span>");
        body.append("<span>生成时间: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</span>");
        body.append("<span class=\"risk risk-").append(escapeHtml(riskClass)).append("\">总体风险: ")
                .append(escapeHtml(verdict.overallRisk())).append("</span>");
        body.append("</div></div>");

        if (verdict.summary() != null && !verdict.summary().isBlank()) {
            body.append(section("研判摘要", "<p class=\"prose\">" + escapeHtml(verdict.summary()) + "</p>"));
        }

        // Analysis reasoning from stage descriptions
        if (result.stageDescriptions() != null && !result.stageDescriptions().isEmpty()) {
            StringBuilder reasoning = new StringBuilder();
            reasoning.append("<ol class=\"reasoning\">");
            for (var e : result.stageDescriptions().entrySet()) {
                String desc = e.getValue();
                if (desc != null && !desc.isBlank() && desc.length() > 20) {
                    String truncated = desc.length() > 500 ? desc.substring(0, 500) + "..." : desc;
                    reasoning.append("<li>").append(escapeHtml(truncated)).append("</li>");
                }
            }
            reasoning.append("</ol>");
            body.append(section("分析思路", reasoning.toString()));
        }

        // Test cases with curl commands
        if (result.payloadResults() != null && !result.payloadResults().isEmpty()) {
            StringBuilder casesHtml = new StringBuilder();
            casesHtml.append("<table class=\"cases-table\"><thead><tr><th>#</th><th>请求</th><th>状态码</th><th>耗时</th><th>curl 命令</th></tr></thead><tbody>");
            int idx = 0;
            for (PayloadResult pr : result.payloadResults()) {
                idx++;
                String reqSummary = extractRequestLine(pr.sentRequest());
                String curl = rawRequestToCurl(pr.sentRequest(), entry.getDomain(),
                        entry.getLastUrl() != null && entry.getLastUrl().startsWith("https"));
                casesHtml.append("<tr><td>").append(idx).append("</td>");
                casesHtml.append("<td><code>").append(escapeHtml(reqSummary)).append("</code></td>");
                casesHtml.append("<td>").append(pr.statusCode()).append("</td>");
                casesHtml.append("<td>").append(pr.responseTimeMs()).append("ms</td>");
                casesHtml.append("<td><code class=\"curl\">").append(escapeHtml(curl)).append("</code></td>");
                casesHtml.append("</tr>");
            }
            casesHtml.append("</tbody></table>");
            body.append(section("测试用例 (" + result.payloadResults().size() + ")", casesHtml.toString()));
        }

        if (!verdict.confirmedVulns().isEmpty()) {
            StringBuilder inner = new StringBuilder();
            for (ConfirmedVuln cv : verdict.confirmedVulns()) {
                PayloadResult pr = VerdictValidator.findPayloadResult(result.payloadResults(), cv.payloadUsed());
                inner.append(renderVuln("confirmed", "已确认", cv.type(), cv.title(), cv.evidence(), cv.verifyCommand(), pr));
            }
            body.append(section("已确认漏洞 (" + verdict.confirmedVulns().size() + ")", inner.toString()));
        }

        if (!verdict.suspectedVulns().isEmpty()) {
            StringBuilder inner = new StringBuilder();
            for (SuspectedVuln sv : verdict.suspectedVulns()) {
                inner.append(renderVuln("suspected", "疑似", sv.type(), sv.title(), sv.reason(), sv.verifyCommand(), null));
            }
            body.append(section("疑似漏洞 (" + verdict.suspectedVulns().size() + ")", inner.toString()));
        }

        if (verdict.recommendations() != null && !verdict.recommendations().isBlank()) {
            body.append(section("修复建议", "<p class=\"prose\">" + escapeHtml(verdict.recommendations()) + "</p>"));
        }

        body.append("<div class=\"footer\">由 API Sentinel 自动生成 &middot; Tokens: ")
                .append(verdict.totalTokensUsed()).append("</div>");

        return "<!DOCTYPE html>\n<html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><title>"
                + title + " — API Sentinel 报告</title><style>" + CSS + "</style></head><body>"
                + body + "</body></html>";
    }

    private static String section(String heading, String innerHtml) {
        return "<div class=\"section\"><h2>" + escapeHtml(heading) + "</h2>" + innerHtml + "</div>";
    }

    private static String renderVuln(String kind, String kindLabel, String type, String title,
                                      String evidenceOrReason, String verifyCommand, PayloadResult pr) {
        StringBuilder sb = new StringBuilder();
        sb.append("<div class=\"vuln vuln-").append(kind).append("\">");
        sb.append("<h3><span class=\"badge badge-").append(kind).append("\">").append(escapeHtml(kindLabel)).append("</span> ")
                .append("[").append(escapeHtml(type)).append("] ").append(escapeHtml(title)).append("</h3>");
        sb.append("<p class=\"evidence\">").append(escapeHtml(evidenceOrReason)).append("</p>");
        if (verifyCommand != null && !verifyCommand.isBlank()) {
            sb.append("<p><b>验证命令:</b> <code>").append(escapeHtml(verifyCommand)).append("</code></p>");
        }
        if (pr != null && pr.sentRequest() != null && !pr.sentRequest().isEmpty()) {
            sb.append("<div class=\"http-pair\">");
            sb.append("<div class=\"http-block\"><div class=\"http-label\">Request</div><pre>")
                    .append(escapeHtml(pr.sentRequest())).append("</pre></div>");
            if (pr.receivedResponse() != null && !pr.receivedResponse().isEmpty()) {
                sb.append("<div class=\"http-block\"><div class=\"http-label\">Response</div><pre>")
                        .append(escapeHtml(pr.receivedResponse())).append("</pre></div>");
            }
            sb.append("</div>");
        } else {
            sb.append("<p class=\"no-evidence\">（没有可关联的真实请求/响应 — 该发现未经程序化验证）</p>");
        }
        sb.append("</div>");
        return sb.toString();
    }

    private static final String CSS = """
            body{font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;padding:0;background:#f5f6f8;color:#222}
            .header{background:#1f2430;color:#fff;padding:20px 32px}
            .header h1{margin:0 0 10px;font-size:20px;font-family:Consolas,Monaco,monospace;word-break:break-all}
            .meta{display:flex;gap:20px;font-size:13px;color:#c7cbd4;flex-wrap:wrap}
            .risk{font-weight:bold;padding:2px 10px;border-radius:4px;color:#fff}
            .risk-high{background:#c0392b}
            .risk-medium{background:#e08e0b}
            .risk-low{background:#c8a415}
            .risk-safe{background:#2e8b57}
            .risk-info{background:#607080}
            .section{max-width:960px;margin:24px auto;padding:0 24px}
            .section h2{font-size:16px;border-bottom:2px solid #e0e0e0;padding-bottom:6px;color:#1f2430}
            .prose{white-space:pre-wrap;line-height:1.6}
            .vuln{background:#fff;border-radius:6px;padding:16px 20px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,.1)}
            .vuln-confirmed{border-left:5px solid #c0392b}
            .vuln-suspected{border-left:5px solid #e08e0b}
            .vuln h3{margin:0 0 8px;font-size:15px}
            .badge{font-size:11px;font-weight:bold;padding:2px 8px;border-radius:10px;color:#fff;margin-right:6px}
            .badge-confirmed{background:#c0392b}
            .badge-suspected{background:#e08e0b}
            .evidence{color:#444;white-space:pre-wrap;line-height:1.5}
            .no-evidence{color:#999;font-style:italic;font-size:13px}
            .http-pair{display:flex;gap:12px;margin-top:12px;flex-wrap:wrap}
            .http-block{flex:1;min-width:280px}
            .http-label{font-size:11px;font-weight:bold;color:#888;text-transform:uppercase;margin-bottom:4px}
            pre{background:#282c34;color:#abb2bf;padding:12px;border-radius:4px;overflow-x:auto;font-size:12px;line-height:1.5;margin:0;white-space:pre-wrap;word-break:break-all}
            code{background:#eef;padding:2px 6px;border-radius:3px;font-family:Consolas,Monaco,monospace}
            .reasoning{line-height:1.8;padding-left:20px}
            .reasoning li{margin:4px 0;color:#333}
            .cases-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}
            .cases-table th{background:#f0f1f3;text-align:left;padding:6px 10px;border-bottom:2px solid #ddd;font-weight:600}
            .cases-table td{padding:6px 10px;border-bottom:1px solid #eee;vertical-align:top}
            .cases-table tr:hover{background:#f8f9fb}
            .curl{font-size:11px;word-break:break-all;display:block;max-width:400px;white-space:pre-wrap}
            .footer{text-align:center;color:#999;font-size:12px;padding:24px}
            """;

    private static String extractRequestLine(String rawRequest) {
        if (rawRequest == null || rawRequest.isEmpty()) return "N/A";
        int end = rawRequest.indexOf('\n');
        if (end < 0) end = rawRequest.length();
        String line = rawRequest.substring(0, Math.min(end, 100)).trim();
        return line.isEmpty() ? "N/A" : line;
    }

    private static String rawRequestToCurl(String rawRequest, String domain, boolean https) {
        if (rawRequest == null || rawRequest.isEmpty()) return "";
        String[] lines = rawRequest.split("\r?\n");
        if (lines.length == 0) return "";

        // Parse request line
        String[] requestLine = lines[0].trim().split("\\s+");
        String method = requestLine.length > 0 ? requestLine[0] : "GET";
        String path = requestLine.length > 1 ? requestLine[1] : "/";

        // Build URL
        String scheme = https ? "https" : "http";
        String host = domain != null ? domain : "localhost";
        // Check if Host header provides a better value
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isEmpty() || lines[i].equals("\r")) break;
            if (lines[i].toLowerCase().startsWith("host:")) {
                host = lines[i].substring(5).trim();
                break;
            }
        }
        String url = scheme + "://" + host + path;

        StringBuilder curl = new StringBuilder("curl");
        if (!method.equalsIgnoreCase("GET")) {
            curl.append(" -X ").append(method);
        }

        // Collect headers (skip Host and Content-Length, curl handles those)
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty() || line.equals("\r")) break;
            String lower = line.toLowerCase();
            if (lower.startsWith("host:") || lower.startsWith("content-length:")) continue;
            curl.append(" -H '").append(line.replace("'", "'\\''").trim()).append("'");
        }

        // Body
        int bodyStart = rawRequest.indexOf("\r\n\r\n");
        if (bodyStart < 0) bodyStart = rawRequest.indexOf("\n\n");
        if (bodyStart >= 0) {
            String body = rawRequest.substring(bodyStart).trim();
            if (!body.isEmpty()) {
                curl.append(" -d '").append(body.replace("'", "'\\''")).append("'");
            }
        }

        curl.append(" '").append(url).append("'");
        return curl.toString();
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    /** Same filename-sanitizing rule as PipelineReportWriter, kept identical
     *  so the two report kinds' filenames line up for the same run. */
    private static String sanitizeForFilename(String path) {
        if (path == null || path.isEmpty()) return "unknown";
        String sanitized = path.replaceAll("[^a-zA-Z0-9._-]", "-")
                               .replaceAll("-+", "-")
                               .replaceAll("^-|-$", "");
        if (sanitized.length() > 80) {
            sanitized = sanitized.substring(0, 80);
        }
        return sanitized.isEmpty() ? "unknown" : sanitized;
    }
}
