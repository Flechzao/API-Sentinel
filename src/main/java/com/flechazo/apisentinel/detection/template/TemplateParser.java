package com.flechazo.apisentinel.detection.template;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * YAML 模板解析器（简化版，无需外部依赖）
 *
 * 解析自定义检测模板的 YAML 文件。
 *
 * @since 1.2.0
 */
public class TemplateParser {

    private static final Pattern KEY_VALUE = Pattern.compile("^([a-z_]+):\\s*(.*)$");
    private static final Pattern LIST_ITEM = Pattern.compile("^\\s*-\\s*(.*)$");
    private static final Pattern INDENTED_KEY = Pattern.compile("^\\s+([a-z_]+):\\s*(.*)$");

    /**
     * 从文件解析模板
     */
    public static DetectionTemplate parse(Path yamlFile) throws IOException {
        String content = Files.readString(yamlFile);
        return parse(content);
    }

    /**
     * 从字符串解析模板
     */
    public static DetectionTemplate parse(String yaml) {
        Map<String, Object> data = new HashMap<>();
        String[] lines = yaml.split("\n");

        String currentKey = null;
        List<String> currentList = null;
        List<Map<String, String>> matchers = null;
        Map<String, String> currentMatcher = null;
        boolean inMatchers = false;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();

            // Skip comments and empty lines
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }

            // Check for top-level key-value (no leading whitespace)
            if (!line.startsWith(" ") && !line.startsWith("\t")) {
                // Save previous context
                if (currentMatcher != null && matchers != null) {
                    matchers.add(currentMatcher);
                    currentMatcher = null;
                }
                if (matchers != null && inMatchers) {
                    data.put("matchers", matchers);
                    matchers = null;
                    inMatchers = false;
                }
                if (currentKey != null && currentList != null) {
                    data.put(currentKey, currentList);
                    currentList = null;
                }

                Matcher kv = KEY_VALUE.matcher(trimmed);
                if (kv.matches()) {
                    currentKey = kv.group(1);
                    String value = kv.group(2).trim();

                    if (value.isEmpty()) {
                        // Next lines will be a list or nested structure
                        if ("matchers".equals(currentKey)) {
                            inMatchers = true;
                            matchers = new ArrayList<>();
                        } else {
                            currentList = new ArrayList<>();
                        }
                    } else {
                        // Simple key-value
                        data.put(currentKey, unquoteYaml(value));
                        currentKey = null;
                    }
                }
                continue;
            }

            // Check for list item (starts with "- ")
            Matcher listItem = LIST_ITEM.matcher(line);
            if (listItem.matches()) {
                String item = listItem.group(1).trim();

                if (inMatchers) {
                    // This is a new matcher
                    if (currentMatcher != null) {
                        matchers.add(currentMatcher);
                    }
                    currentMatcher = new HashMap<>();

                    // Parse inline key-value (e.g., "type: regex")
                    if (item.contains(":")) {
                        String[] parts = item.split(":", 2);
                        currentMatcher.put(parts[0].trim(), unquoteYaml(parts[1].trim()));
                    } else {
                        currentList.add(item);
                    }
                } else if (currentList != null) {
                    currentList.add(item);
                }
                continue;
            }

            // Check for indented key-value (within a matcher)
            Matcher indentedKey = INDENTED_KEY.matcher(line);
            if (indentedKey.matches() && currentMatcher != null) {
                String key = indentedKey.group(1);
                String value = indentedKey.group(2).trim();
                currentMatcher.put(key, unquoteYaml(value));
            }
        }

        // Finalize
        if (currentMatcher != null && matchers != null) {
            matchers.add(currentMatcher);
        }
        if (matchers != null && inMatchers) {
            data.put("matchers", matchers);
        }
        if (currentKey != null && currentList != null) {
            data.put(currentKey, currentList);
        }

        return buildTemplate(data);
    }

    /**
     * 处理 YAML 双引号标量：去除外层引号并反转义转义序列。
     * <p>手写解析器此前只剥外层引号、不反转义，导致 pattern 中的 {@code \"} / {@code \\s} /
     * {@code \\d} 仍是字面反斜杠+字符，使含转义的检测模板（如内置 sensitive-data 的
     * {@code "[^"]+"}）无法匹配。此方法补齐标准 YAML 双引号反转义。
     */
    private static String unquoteYaml(String value) {
        if (value == null) return null;
        String v = value.trim();
        if (v.length() < 2 || !v.startsWith("\"") || !v.endsWith("\"")) {
            return v;
        }
        v = v.substring(1, v.length() - 1);
        StringBuilder sb = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\\' && i + 1 < v.length()) {
                char n = v.charAt(i + 1);
                switch (n) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    default -> { sb.append('\\'); sb.append(n); } // 未知转义保留原样
                }
                i++;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static DetectionTemplate buildTemplate(Map<String, Object> data) {
        String id = (String) data.get("id");
        String name = (String) data.get("name");
        String severity = (String) data.get("severity");
        String type = (String) data.getOrDefault("type", "response-pattern");
        String description = (String) data.get("description");
        String remediation = (String) data.get("remediation");

        List<String> tags = new ArrayList<>();
        Object tagsObj = data.get("tags");
        if (tagsObj instanceof List) {
            tags = (List<String>) tagsObj;
        } else if (tagsObj instanceof String) {
            // Comma-separated
            String tagsStr = (String) tagsObj;
            for (String tag : tagsStr.split(",")) {
                tags.add(tag.trim());
            }
        }

        List<DetectionTemplate.Matcher> matchers = new ArrayList<>();
        Object matchersObj = data.get("matchers");
        if (matchersObj instanceof List) {
            List<Map<String, String>> matcherMaps = (List<Map<String, String>>) matchersObj;
            for (Map<String, String> m : matcherMaps) {
                matchers.add(buildMatcher(m));
            }
        }

        Map<String, String> metadata = new HashMap<>();
        // Add any extra fields as metadata
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String key = entry.getKey();
            if (!key.equals("id") && !key.equals("name") && !key.equals("severity")
                    && !key.equals("type") && !key.equals("matchers") && !key.equals("tags")
                    && !key.equals("description") && !key.equals("remediation")) {
                metadata.put(key, String.valueOf(entry.getValue()));
            }
        }

        return new DetectionTemplate(id, name, severity, type, matchers, tags,
                description, remediation, metadata);
    }

    private static DetectionTemplate.Matcher buildMatcher(Map<String, String> m) {
        String type = m.get("type");
        String pattern = m.get("pattern");
        String condition = m.getOrDefault("condition", "or");
        String part = m.getOrDefault("part", "body");
        boolean negative = "true".equalsIgnoreCase(m.get("negative"));

        List<String> words = null;
        String wordsStr = m.get("words");
        if (wordsStr != null) {
            words = new ArrayList<>();
            // Parse "[word1, word2]" format
            if (wordsStr.startsWith("[") && wordsStr.endsWith("]")) {
                wordsStr = wordsStr.substring(1, wordsStr.length() - 1);
                for (String w : wordsStr.split(",")) {
                    words.add(unquoteYaml(w.trim()));
                }
            }
        }

        Integer status = null;
        String statusStr = m.get("status");
        if (statusStr != null) {
            try {
                status = Integer.parseInt(statusStr);
            } catch (NumberFormatException ignored) {}
        }

        String dsl = m.get("dsl");

        return new DetectionTemplate.Matcher(type, pattern, words, status, dsl, condition, part, negative);
    }
}
