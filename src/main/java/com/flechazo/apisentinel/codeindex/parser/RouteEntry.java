package com.flechazo.apisentinel.codeindex.parser;

import java.nio.file.Path;
import java.util.List;

public record RouteEntry(
    String httpMethod,
    String routePattern,
    String normalizedPattern,
    Path sourceFile,
    int startLine,
    int endLine,
    String methodName,
    String className
) {
    public String displayLocation() {
        return sourceFile.getFileName() + ":" + startLine;
    }

    public static String normalize(String pattern) {
        String result = pattern
                .replaceAll("\\{[^}]+\\}", ":param")
                .replaceAll("<[^>]+>", ":param")
                .replaceAll(":[a-zA-Z_]+", ":param");
        if (!result.startsWith("/")) result = "/" + result;
        if (result.endsWith("/") && result.length() > 1) result = result.substring(0, result.length() - 1);
        return result.toLowerCase();
    }
}
