package com.flechazo.apisentinel.ai.pipeline;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Aggregated statistics from multiple matching requests in Burp Proxy History.
 * Provides contextual awareness to Stage 1 AI analysis without sending all full requests.
 */
public record TrafficStats(
    int totalMatched,
    Map<String, Integer> methodDistribution,
    Map<Integer, Integer> statusCodeDistribution,
    int minResponseSize,
    int maxResponseSize,
    long avgResponseSize,
    long firstSeenMs,
    long lastSeenMs,
    Set<String> contentTypes,
    Set<String> observedParamKeys,
    List<String> distinctPaths
) {

    public static TrafficStats empty() {
        return new TrafficStats(0, Map.of(), Map.of(), 0, 0, 0, 0, 0,
                Set.of(), Set.of(), List.of());
    }

    public boolean isEmpty() {
        return totalMatched == 0;
    }

    /**
     * Build a human-readable summary for injection into the AI prompt.
     */
    public String toPromptSection() {
        if (isEmpty()) return "";

        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault());

        StringBuilder sb = new StringBuilder();
        sb.append("## 历史流量统计\n");
        sb.append("以下是该接口在 Burp Proxy History 中的聚合统计（共匹配 ")
          .append(totalMatched).append(" 条请求），供参考判断接口行为模式：\n\n");

        // Method distribution
        sb.append("- **请求方法分布**: ");
        sb.append(methodDistribution.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .map(e -> e.getKey() + "(" + e.getValue() + ")")
                .collect(Collectors.joining(", ")));
        sb.append("\n");

        // Status code distribution
        sb.append("- **状态码分布**: ");
        sb.append(statusCodeDistribution.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> e.getKey() + "(" + e.getValue() + ")")
                .collect(Collectors.joining(", ")));
        sb.append("\n");

        // Response size range
        sb.append("- **响应大小范围**: ")
          .append(humanSize(minResponseSize)).append(" ~ ").append(humanSize(maxResponseSize))
          .append(" (平均 ").append(humanSize(avgResponseSize)).append(")\n");

        // Time range
        if (firstSeenMs > 0 && lastSeenMs > 0) {
            sb.append("- **时间跨度**: ")
              .append(fmt.format(Instant.ofEpochMilli(firstSeenMs)))
              .append(" ~ ")
              .append(fmt.format(Instant.ofEpochMilli(lastSeenMs)))
              .append("\n");
        }

        // Content types
        if (!contentTypes.isEmpty()) {
            sb.append("- **Content-Type**: ").append(String.join(", ", contentTypes)).append("\n");
        }

        // Observed parameter keys
        if (!observedParamKeys.isEmpty()) {
            sb.append("- **观察到的参数 key**: ").append(String.join(", ", observedParamKeys)).append("\n");
        }

        // Distinct paths (for parameterized routes like /api/users/{id})
        if (distinctPaths.size() > 1) {
            sb.append("- **不同路径变体** (").append(distinctPaths.size()).append("): ");
            int show = Math.min(5, distinctPaths.size());
            sb.append(String.join(", ", distinctPaths.subList(0, show)));
            if (distinctPaths.size() > show) {
                sb.append(", ...等").append(distinctPaths.size() - show).append("条");
            }
            sb.append("\n");
        }

        // Highlight anomalies
        boolean has4xx = statusCodeDistribution.keySet().stream().anyMatch(c -> c >= 400 && c < 500);
        boolean has5xx = statusCodeDistribution.keySet().stream().anyMatch(c -> c >= 500);
        boolean mixedStatus = statusCodeDistribution.size() > 1;

        if (has5xx) {
            int count5xx = statusCodeDistribution.entrySet().stream()
                    .filter(e -> e.getKey() >= 500).mapToInt(Map.Entry::getValue).sum();
            sb.append("\n⚠ 注意: 历史流量中出现了 ").append(count5xx).append(" 次 5xx 服务端错误\n");
        }
        if (mixedStatus && has4xx) {
            sb.append("⚠ 注意: 状态码不一致，可能存在权限差异或参数校验差异\n");
        }

        sb.append("\n");
        return sb.toString();
    }

    /**
     * Convert to a Map for JSON serialization.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("totalMatched", totalMatched);
        map.put("methodDistribution", methodDistribution);
        map.put("statusCodeDistribution", statusCodeDistribution);
        map.put("minResponseSize", minResponseSize);
        map.put("maxResponseSize", maxResponseSize);
        map.put("avgResponseSize", avgResponseSize);
        map.put("firstSeenMs", firstSeenMs);
        map.put("lastSeenMs", lastSeenMs);
        map.put("contentTypes", new ArrayList<>(contentTypes));
        map.put("observedParamKeys", new ArrayList<>(observedParamKeys));
        map.put("distinctPaths", distinctPaths);
        return map;
    }

    private static String humanSize(long bytes) {
        if (bytes < 1024) return bytes + "B";
        if (bytes < 1024 * 1024) return String.format("%.1fKB", bytes / 1024.0);
        return String.format("%.1fMB", bytes / (1024.0 * 1024));
    }

    /**
     * Builder for collecting stats from multiple history entries.
     */
    public static class Collector {
        private int count = 0;
        private final Map<String, Integer> methods = new LinkedHashMap<>();
        private final Map<Integer, Integer> statusCodes = new LinkedHashMap<>();
        private int minSize = Integer.MAX_VALUE;
        private int maxSize = 0;
        private long totalSize = 0;
        private long firstSeen = Long.MAX_VALUE;
        private long lastSeen = 0;
        private final Set<String> contentTypes = new LinkedHashSet<>();
        private final Set<String> paramKeys = new LinkedHashSet<>();
        private final Set<String> paths = new LinkedHashSet<>();

        public void add(String method, String path, int statusCode, int responseSize,
                        long timestampMs, String contentType, Set<String> queryParamKeys) {
            count++;
            methods.merge(method, 1, Integer::sum);
            if (statusCode > 0) statusCodes.merge(statusCode, 1, Integer::sum);
            if (responseSize > 0) {
                minSize = Math.min(minSize, responseSize);
                maxSize = Math.max(maxSize, responseSize);
                totalSize += responseSize;
            }
            if (timestampMs > 0) {
                firstSeen = Math.min(firstSeen, timestampMs);
                lastSeen = Math.max(lastSeen, timestampMs);
            }
            if (contentType != null && !contentType.isEmpty()) {
                // Normalize: "application/json; charset=utf-8" → "application/json"
                int semi = contentType.indexOf(';');
                contentTypes.add(semi > 0 ? contentType.substring(0, semi).trim() : contentType.trim());
            }
            if (queryParamKeys != null) paramKeys.addAll(queryParamKeys);
            if (path != null) paths.add(path);
        }

        public TrafficStats build() {
            if (count == 0) return TrafficStats.empty();
            return new TrafficStats(
                    count,
                    Map.copyOf(methods),
                    Map.copyOf(statusCodes),
                    minSize == Integer.MAX_VALUE ? 0 : minSize,
                    maxSize,
                    count > 0 ? totalSize / count : 0,
                    firstSeen == Long.MAX_VALUE ? 0 : firstSeen,
                    lastSeen,
                    Set.copyOf(contentTypes),
                    Set.copyOf(paramKeys),
                    new ArrayList<>(paths).subList(0, Math.min(paths.size(), 10))
            );
        }
    }
}
