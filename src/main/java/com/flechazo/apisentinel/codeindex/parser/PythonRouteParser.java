package com.flechazo.apisentinel.codeindex.parser;

import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PythonRouteParser implements RouteParser {

    private static final Pattern FLASK_ROUTE = Pattern.compile(
            "@(?:app|blueprint|bp|router)\\.(get|post|put|delete|patch|route)\\s*\\([\"']([^\"']+)[\"']");
    private static final Pattern FASTAPI_ROUTE = Pattern.compile(
            "@(?:app|router)\\.(get|post|put|delete|patch)\\s*\\([\"']([^\"']+)[\"']");
    private static final Pattern DJANGO_PATH = Pattern.compile(
            "path\\s*\\([\"']([^\"']+)[\"']\\s*,\\s*(\\w+)");
    private static final Pattern FUNC_DEF = Pattern.compile(
            "(?:async\\s+)?def\\s+(\\w+)");

    @Override
    public Set<String> supportedFrameworks() { return Set.of("flask", "fastapi", "django"); }

    @Override
    public Set<String> supportedExtensions() { return Set.of(".py"); }

    @Override
    public boolean canParse(Path filePath) {
        return filePath.getFileName().toString().endsWith(".py");
    }

    @Override
    public List<RouteEntry> parseFile(Path filePath, String content) {
        List<RouteEntry> routes = new ArrayList<>();
        String[] lines = content.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();

            // Flask / FastAPI routes
            Matcher flaskMatcher = FLASK_ROUTE.matcher(line);
            if (flaskMatcher.find()) {
                String method = flaskMatcher.group(1).toUpperCase();
                if (method.equals("ROUTE")) method = "*";
                String path = flaskMatcher.group(2);
                String funcName = findPythonFunc(lines, i);

                routes.add(new RouteEntry(method, path, RouteEntry.normalize(path),
                        filePath, i + 1, i + 1, funcName, ""));
                continue;
            }

            // Django url patterns
            Matcher djangoMatcher = DJANGO_PATH.matcher(line);
            if (djangoMatcher.find()) {
                String path = "/" + djangoMatcher.group(1);
                String viewName = djangoMatcher.group(2);
                routes.add(new RouteEntry("*", path, RouteEntry.normalize(path),
                        filePath, i + 1, i + 1, viewName, ""));
            }
        }
        return routes;
    }

    private String findPythonFunc(String[] lines, int decoratorLine) {
        for (int i = decoratorLine + 1; i < Math.min(decoratorLine + 4, lines.length); i++) {
            Matcher m = FUNC_DEF.matcher(lines[i]);
            if (m.find()) return m.group(1);
        }
        return "unknown";
    }
}
