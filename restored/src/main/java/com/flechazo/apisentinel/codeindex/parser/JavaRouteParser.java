package com.flechazo.apisentinel.codeindex.parser;

import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JavaRouteParser implements RouteParser {

    private static final Pattern CLASS_DECL = Pattern.compile(
            "(?:public\\s+)?class\\s+(\\w+)");

    private static final Pattern CLASS_MAPPING = Pattern.compile(
            "@RequestMapping\\s*\\(\\s*(?:value\\s*=\\s*)?[\"']([^\"']+)[\"']");

    private static final Pattern SHORTCUT_MAPPING = Pattern.compile(
            "@(Get|Post|Put|Delete|Patch)Mapping\\s*\\(\\s*(?:value\\s*=\\s*|path\\s*=\\s*)?[\"']([^\"']+)[\"']");

    private static final Pattern SHORTCUT_MAPPING_NO_PATH = Pattern.compile(
            "@(Get|Post|Put|Delete|Patch)Mapping\\s*(?:\\(\\s*\\)|$)");

    private static final Pattern REQUEST_METHOD = Pattern.compile(
            "method\\s*=\\s*RequestMethod\\.(\\w+)");

    private static final Pattern MAPPING_VALUE = Pattern.compile(
            "(?:value|path)\\s*=\\s*[\"']([^\"']+)[\"']");

    private static final Pattern SIMPLE_MAPPING_VALUE = Pattern.compile(
            "@RequestMapping\\s*\\(\\s*[\"']([^\"']+)[\"']");

    private static final Pattern METHOD_DECL = Pattern.compile(
            "(?:public|private|protected)\\s+(?:static\\s+)?(?:final\\s+)?\\S+\\s+(\\w+)\\s*\\(");

    @Override
    public Set<String> supportedFrameworks() { return Set.of("spring", "spring-boot"); }

    @Override
    public Set<String> supportedExtensions() { return Set.of(".java", ".kt"); }

    @Override
    public boolean canParse(Path filePath) {
        String name = filePath.getFileName().toString().toLowerCase();
        return name.endsWith(".java") || name.endsWith(".kt");
    }

    @Override
    public List<RouteEntry> parseFile(Path filePath, String content) {
        List<RouteEntry> routes = new ArrayList<>();
        String[] lines = content.split("\n");

        String classPrefix = "";
        String className = "";

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            Matcher classMatcher = CLASS_DECL.matcher(line);
            if (classMatcher.find()) {
                className = classMatcher.group(1);
            }

            // --- Shortcut annotations: @GetMapping, @PostMapping, etc. ---
            Matcher shortcutMatcher = SHORTCUT_MAPPING.matcher(line);
            if (shortcutMatcher.find()) {
                String httpMethod = mapMappingType(shortcutMatcher.group(1));
                String path = shortcutMatcher.group(2);
                String fullPath = combinePath(classPrefix, path);
                String methodName = findMethodName(lines, i);
                routes.add(new RouteEntry(httpMethod, fullPath, RouteEntry.normalize(fullPath),
                        filePath, i + 1, i + 1, methodName, className));
                continue;
            }

            Matcher shortcutNoPathMatcher = SHORTCUT_MAPPING_NO_PATH.matcher(line);
            if (shortcutNoPathMatcher.find() && !classPrefix.isEmpty()) {
                String httpMethod = mapMappingType(shortcutNoPathMatcher.group(1));
                String methodName = findMethodName(lines, i);
                routes.add(new RouteEntry(httpMethod, classPrefix, RouteEntry.normalize(classPrefix),
                        filePath, i + 1, i + 1, methodName, className));
                continue;
            }

            // --- @RequestMapping with method = RequestMethod.XXX → method-level ---
            Matcher reqMethodMatcher = REQUEST_METHOD.matcher(line);
            if (line.contains("@RequestMapping") && reqMethodMatcher.find()) {
                String httpMethod = reqMethodMatcher.group(1).toUpperCase();
                String path = extractRequestMappingValue(line);
                String fullPath = path != null ? combinePath(classPrefix, path) : classPrefix;
                String methodName = findMethodName(lines, i);
                if (!fullPath.isEmpty()) {
                    routes.add(new RouteEntry(httpMethod, fullPath, RouteEntry.normalize(fullPath),
                            filePath, i + 1, i + 1, methodName, className));
                }
                continue;
            }

            // --- @RequestMapping without method → class-level prefix ---
            Matcher classMappingMatcher = CLASS_MAPPING.matcher(line);
            if (classMappingMatcher.find()) {
                classPrefix = classMappingMatcher.group(1);
                if (!classPrefix.startsWith("/")) classPrefix = "/" + classPrefix;
                if (classPrefix.endsWith("/") && classPrefix.length() > 1)
                    classPrefix = classPrefix.substring(0, classPrefix.length() - 1);
            }
        }
        return routes;
    }

    private String extractRequestMappingValue(String line) {
        Matcher valueMatcher = MAPPING_VALUE.matcher(line);
        if (valueMatcher.find()) return valueMatcher.group(1);
        Matcher simpleMatcher = SIMPLE_MAPPING_VALUE.matcher(line);
        if (simpleMatcher.find()) return simpleMatcher.group(1);
        return null;
    }

    private String combinePath(String prefix, String path) {
        if (path == null || path.isEmpty()) return prefix;
        String p = path.startsWith("/") ? path : "/" + path;
        return prefix + p;
    }

    private String mapMappingType(String type) {
        return switch (type) {
            case "Get" -> "GET";
            case "Post" -> "POST";
            case "Put" -> "PUT";
            case "Delete" -> "DELETE";
            case "Patch" -> "PATCH";
            default -> "*";
        };
    }

    private String findMethodName(String[] lines, int annotationLine) {
        for (int i = annotationLine + 1; i < Math.min(annotationLine + 10, lines.length); i++) {
            String trimmed = lines[i].trim();
            if (trimmed.isEmpty() || trimmed.startsWith("@") || trimmed.startsWith("//")) continue;
            Matcher m = METHOD_DECL.matcher(lines[i]);
            if (m.find()) return m.group(1);
        }
        return "unknown";
    }
}
