package com.flechazo.apisentinel.codeindex;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Sink 标注器——扫描代码中 7 类危险 sink 并在片段中标注 [⚠ SQL SINK] 等。 */
public final class SinkAnnotator {

    private static final Map<SinkMap.SinkType, String> LABELS = java.util.Map.ofEntries(
            java.util.Map.entry(SinkMap.SinkType.SQL, "⚠ SQL SINK"),
            java.util.Map.entry(SinkMap.SinkType.COMMAND, "⚠ CMD SINK"),
            java.util.Map.entry(SinkMap.SinkType.FILE_ACCESS, "⚠ FILE SINK"),
            java.util.Map.entry(SinkMap.SinkType.DESERIALIZATION, "⚠ DESER SINK"),
            java.util.Map.entry(SinkMap.SinkType.SSRF, "⚠ SSRF SINK"),
            java.util.Map.entry(SinkMap.SinkType.CRYPTO, "⚠ WEAK CRYPTO"),
            java.util.Map.entry(SinkMap.SinkType.INSECURE_RANDOM, "⚠ INSECURE RNG"),
            java.util.Map.entry(SinkMap.SinkType.XXE, "⚠ XXE SINK"),
            java.util.Map.entry(SinkMap.SinkType.SSTI, "⚠ SSTI SINK"),
            java.util.Map.entry(SinkMap.SinkType.CRLF, "⚠ CRLF SINK"),
            java.util.Map.entry(SinkMap.SinkType.OPEN_REDIRECT, "⚠ OPEN REDIRECT"),
            java.util.Map.entry(SinkMap.SinkType.NOSQL, "⚠ NOSQL SINK")
    );

    /** Backward-taint-tracing nudge appended to injection-prone sinks, pushing the
     *  agent to trace the interpolated variables back to their (possibly stored,
     *  cross-endpoint) source instead of stopping at the sink line. */
    private static final Map<SinkMap.SinkType, String> TRACE_HINTS = java.util.Map.ofEntries(
            java.util.Map.entry(SinkMap.SinkType.SQL, "追踪拼接变量来源·查是否用户可控且未参数化"),
            java.util.Map.entry(SinkMap.SinkType.COMMAND, "追踪命令插值变量来源·查是否用户可控且未quote·若变量来自存储请用find_callers找写入接口(二阶注入)"),
            java.util.Map.entry(SinkMap.SinkType.FILE_ACCESS, "追踪路径变量来源·查是否用户可控且未限制目录"),
            java.util.Map.entry(SinkMap.SinkType.DESERIALIZATION, "追踪反序列化数据来源·查是否用户可控"),
            java.util.Map.entry(SinkMap.SinkType.SSRF, "追踪URL变量来源·查是否用户可控且无白名单"),
            java.util.Map.entry(SinkMap.SinkType.XXE, "检查XML解析器是否禁用了外部实体(setFeature FEATURE_SECURE_PROCESSING / disallow-doctype-decl)"),
            java.util.Map.entry(SinkMap.SinkType.SSTI, "追踪模板字符串变量来源·查是否用户输入被当作模板编译"),
            java.util.Map.entry(SinkMap.SinkType.CRLF, "追踪Header值变量来源·查是否含CRLF字符且未过滤"),
            java.util.Map.entry(SinkMap.SinkType.OPEN_REDIRECT, "追踪重定向URL变量来源·查是否用户可控且无白名单"),
            java.util.Map.entry(SinkMap.SinkType.NOSQL, "追踪查询条件变量来源·查是否用户可控且未过滤$操作符")
    );

    private SinkAnnotator() {}

    /** Human label for a sink type (e.g. "⚠ CMD SINK"). */
    public static String label(SinkMap.SinkType type) {
        return LABELS.getOrDefault(type, "⚠ SINK");
    }

    /** Backward-taint-tracing hint for a sink type ("" when none). */
    public static String traceHint(SinkMap.SinkType type) {
        return TRACE_HINTS.getOrDefault(type, "");
    }

    /** Build one annotated source line: the sink label plus (for injection-prone
     *  sinks) a backward-taint-tracing hint. */
    private static String annotatedLine(String line, SinkMap.SinkType type) {
        String label = LABELS.getOrDefault(type, "⚠ SINK");
        StringBuilder sb = new StringBuilder(line).append("  // [").append(label).append("]");
        String hint = TRACE_HINTS.get(type);
        if (hint != null) sb.append(" → ").append(hint);
        return sb.append("\n").toString();
    }

    public static String annotate(String code, String sourceFile, SinkMap sinkMap) {
        if (code == null || code.isBlank() || sinkMap == null) return code;

        List<SinkMap.SinkEntry> fileSinks = sinkMap.allSinksOfType(null);
        if (fileSinks == null || fileSinks.isEmpty()) {
            fileSinks = findSinksForFile(sinkMap, sourceFile);
        }
        if (fileSinks.isEmpty()) return code;

        Map<Integer, SinkMap.SinkType> sinkLines = fileSinks.stream()
                .filter(s -> s.file() != null && s.file().equals(sourceFile))
                .collect(Collectors.toMap(
                        SinkMap.SinkEntry::line,
                        SinkMap.SinkEntry::type,
                        (a, b) -> a));

        if (sinkLines.isEmpty()) return code;

        String[] lines = code.split("\n");
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            int lineNum = extractLineNumber(line);
            if (lineNum > 0 && sinkLines.containsKey(lineNum)) {
                sb.append(annotatedLine(line, sinkLines.get(lineNum)));
            } else {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    public static String annotateWithSinks(String code, List<SinkMap.SinkEntry> sinks) {
        if (code == null || code.isBlank() || sinks == null || sinks.isEmpty()) return code;

        Map<Integer, SinkMap.SinkType> sinkLines = sinks.stream()
                .collect(Collectors.toMap(
                        SinkMap.SinkEntry::line,
                        SinkMap.SinkEntry::type,
                        (a, b) -> a));

        String[] lines = code.split("\n");
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            int lineNum = extractLineNumber(line);
            if (lineNum > 0 && sinkLines.containsKey(lineNum)) {
                sb.append(annotatedLine(line, sinkLines.get(lineNum)));
            } else {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    private static int extractLineNumber(String codeLine) {
        if (codeLine == null || codeLine.length() < 5) return -1;
        String trimmed = codeLine.stripLeading();
        int pipeIdx = trimmed.indexOf('|');
        if (pipeIdx <= 0) return -1;
        try {
            return Integer.parseInt(trimmed.substring(0, pipeIdx).trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static List<SinkMap.SinkEntry> findSinksForFile(SinkMap sinkMap, String sourceFile) {
        if (sourceFile == null) return List.of();
        return sinkMap.classesWithSinks().stream()
                .flatMap(cls -> sinkMap.sinksInClass(cls).stream())
                .filter(s -> s.file() != null && s.file().equals(sourceFile))
                .toList();
    }
}
