package com.flechazo.apisentinel.detection.template;

import java.util.List;
import java.util.Map;

/**
 * 自定义检测模板（参考 Nuclei YAML DSL）
 *
 * 允许用户通过 YAML 文件定义自定义检测规则，无需修改 Java 代码。
 *
 * 示例模板：
 * ```yaml
 * id: custom-sqli-detection
 * name: Custom SQL Injection Detection
 * severity: high
 * type: response-pattern
 *
 * matchers:
 *   - type: regex
 *     pattern: "(?i)(SQL syntax|mysql_fetch|ORA-\\d{5})"
 *     condition: or
 *
 *   - type: word
 *     words: ["syntax error", "mysql error"]
 *     condition: or
 *
 * tags: sqli,injection,owasp-a03
 * ```
 *
 * @since 1.2.0
 */
public record DetectionTemplate(
        String id,
        String name,
        String severity,
        String type,
        List<Matcher> matchers,
        List<String> tags,
        String description,
        String remediation,
        Map<String, String> metadata
) {

    /**
     * 匹配器定义
     *
     * @param type      匹配类型（regex/word/status/dsl）
     * @param pattern   正则表达式（regex 类型）
     * @param words     关键词列表（word 类型）
     * @param status    HTTP 状态码（status 类型）
     * @param dsl       DSL 表达式（dsl 类型）
     * @param condition 条件（and/or）
     * @param part      匹配部分（body/headers/status/all）
     * @param negative  是否反向匹配（匹配时视为失败）
     */
    public record Matcher(
            String type,
            String pattern,
            List<String> words,
            Integer status,
            String dsl,
            String condition,
            String part,
            boolean negative
    ) {
        /** 默认构造函数 */
        public Matcher {
            if (condition == null) condition = "or";
            if (part == null) part = "body";
        }

        /** 检查匹配器类型是否有效 */
        public boolean isValidType() {
            return type != null && (
                    type.equals("regex") ||
                    type.equals("word") ||
                    type.equals("status") ||
                    type.equals("dsl")
            );
        }

        /** 获取匹配器描述 */
        public String describe() {
            return switch (type) {
                case "regex" -> "Regex: " + pattern;
                case "word" -> "Words: " + String.join(", ", words);
                case "status" -> "Status: " + status;
                case "dsl" -> "DSL: " + dsl;
                default -> "Unknown";
            };
        }
    }

    /** 验证模板是否有效 */
    public boolean isValid() {
        return id != null && !id.isBlank()
                && name != null && !name.isBlank()
                && severity != null
                && matchers != null && !matchers.isEmpty()
                && matchers.stream().allMatch(Matcher::isValidType);
    }

    /** 获取模板摘要 */
    public String summary() {
        return String.format("[%s] %s (%s) - %d matchers, tags: %s",
                severity.toUpperCase(),
                name,
                type,
                matchers.size(),
                tags != null ? String.join(", ", tags) : "none"
        );
    }
}
