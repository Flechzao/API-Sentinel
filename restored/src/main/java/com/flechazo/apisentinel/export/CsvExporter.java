package com.flechazo.apisentinel.export;

import com.flechazo.apisentinel.model.ApiEntry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class CsvExporter implements ReportExporter {

    @Override
    public void export(List<ApiEntry> entries, Path outputPath) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append('﻿'); // UTF-8 BOM for Excel compatibility
        sb.append("HTTP Method,API Path,Status,Vulnerability Type,Result,Note,Passive Findings,Domain,Risk,Findings(confirmed/suspected),TestCase Count\n");

        for (ApiEntry entry : entries) {
            sb.append(escapeCsv(entry.getHttpMethod())).append(',');
            sb.append(escapeCsv(entry.getApiPath())).append(',');
            sb.append(escapeCsv(entry.getStatus().getDisplayName())).append(',');
            sb.append(escapeCsv(entry.getVulnType() != null ? entry.getVulnType().getDisplayName() : "")).append(',');
            sb.append(escapeCsv(entry.getResult())).append(',');
            sb.append(escapeCsv(entry.getNote())).append(',');
            sb.append(escapeCsv(passiveTitles(entry))).append(',');
            sb.append(escapeCsv(entry.getDomain())).append(',');
            sb.append(escapeCsv(entry.getDisplayRisk())).append(',');
            sb.append(escapeCsv(entry.getDisplayFindings())).append(',');
            sb.append(escapeCsv(getTestCaseCount(entry))).append('\n');
        }

        Files.writeString(outputPath, sb.toString());
    }

    private static String passiveTitles(ApiEntry entry) {
        if (!entry.hasPassiveFindings()) return "";
        StringBuilder sb = new StringBuilder();
        for (var f : entry.getPassiveFindings()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(f.title());
        }
        return sb.toString();
    }

    private static String getTestCaseCount(ApiEntry entry) {
        var latest = entry.getLatestAnalysisRecord();
        if (latest != null && latest.hasPipelineResult()
                && latest.pipelineResult().testCases() != null) {
            return String.valueOf(latest.pipelineResult().testCases().size());
        }
        return "--";
    }

    @Override
    public String getFileExtension() {
        return "csv";
    }

    @Override
    public String getDescription() {
        return "CSV格式报告";
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
