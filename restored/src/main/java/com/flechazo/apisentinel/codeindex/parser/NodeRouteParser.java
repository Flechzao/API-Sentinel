package com.flechazo.apisentinel.codeindex.parser;

import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NodeRouteParser implements RouteParser {

    private static final Pattern EXPRESS_ROUTE = Pattern.compile(
            "(?:router|app|server)\\.(get|post|put|delete|patch|all)\\s*\\([\"'`]([^\"'`]+)[\"'`]");
    private static final Pattern KOA_ROUTE = Pattern.compile(
            "router\\.(get|post|put|delete|patch|all)\\s*\\([\"'`]([^\"'`]+)[\"'`]");

    @Override
    public Set<String> supportedFrameworks() { return Set.of("express", "koa", "fastify"); }

    @Override
    public Set<String> supportedExtensions() { return Set.of(".js", ".ts", ".mjs"); }

    @Override
    public boolean canParse(Path filePath) {
        String name = filePath.getFileName().toString().toLowerCase();
        return name.endsWith(".js") || name.endsWith(".ts") || name.endsWith(".mjs");
    }

    @Override
    public List<RouteEntry> parseFile(Path filePath, String content) {
        List<RouteEntry> routes = new ArrayList<>();
        String[] lines = content.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher matcher = EXPRESS_ROUTE.matcher(line);
            if (!matcher.find()) matcher = KOA_ROUTE.matcher(line);
            else matcher.reset(); // reset to re-find with the express pattern

            matcher = EXPRESS_ROUTE.matcher(line);
            if (matcher.find()) {
                String method = matcher.group(1).toUpperCase();
                if (method.equals("ALL")) method = "*";
                String path = matcher.group(2);
                routes.add(new RouteEntry(method, path, RouteEntry.normalize(path),
                        filePath, i + 1, i + 1, "", ""));
                continue;
            }

            matcher = KOA_ROUTE.matcher(line);
            if (matcher.find()) {
                String method = matcher.group(1).toUpperCase();
                if (method.equals("ALL")) method = "*";
                String path = matcher.group(2);
                routes.add(new RouteEntry(method, path, RouteEntry.normalize(path),
                        filePath, i + 1, i + 1, "", ""));
            }
        }
        return routes;
    }
}
