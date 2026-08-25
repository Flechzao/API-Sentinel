package com.flechazo.apisentinel.importer;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Imports API endpoints from Swagger 2.0 and OpenAPI 3.0 documents (JSON/YAML).
 * Uses the existing Gson and SnakeYAML dependencies.
 */
public class SwaggerImporter {

    /**
     * Represents a parsed API endpoint.
     */
    public record ApiEndpoint(String method, String path, String summary, String operationId) {
        @Override
        public String toString() {
            String desc = method.toUpperCase() + " " + path;
            if (summary != null && !summary.isEmpty()) desc += " — " + summary;
            return desc;
        }
    }

    /**
     * Parse a Swagger/OpenAPI file and return all endpoints.
     */
    public static List<ApiEndpoint> parseFile(Path file) throws IOException {
        String content = Files.readString(file);
        String fileName = file.getFileName().toString().toLowerCase();

        if (fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
            return parseYaml(content);
        } else {
            return parseJson(content);
        }
    }

    /**
     * Parse a Swagger/OpenAPI JSON string.
     */
    public static List<ApiEndpoint> parseJson(String json) {
        Gson gson = new Gson();
        JsonObject root = gson.fromJson(json, JsonObject.class);
        return parseJsonObject(root);
    }

    /**
     * Parse a Swagger/OpenAPI YAML string.
     */
    public static List<ApiEndpoint> parseYaml(String yaml) {
        Yaml yamlParser = new Yaml();
        Object parsed = yamlParser.load(yaml);
        if (!(parsed instanceof Map)) {
            return List.of();
        }
        // Convert YAML map to Gson JsonObject for unified processing
        Gson gson = new Gson();
        String json = gson.toJson(parsed);
        JsonObject root = gson.fromJson(json, JsonObject.class);
        return parseJsonObject(root);
    }

    /**
     * Auto-detect format and parse.
     */
    public static List<ApiEndpoint> parse(String content) {
        String trimmed = content.trim();
        if (trimmed.startsWith("{")) {
            return parseJson(trimmed);
        } else {
            return parseYaml(trimmed);
        }
    }

    private static List<ApiEndpoint> parseJsonObject(JsonObject root) {
        List<ApiEndpoint> endpoints = new ArrayList<>();

        // Detect base path (Swagger 2.0)
        String basePath = "";
        if (root.has("basePath") && !root.get("basePath").isJsonNull()) {
            basePath = root.get("basePath").getAsString();
            if ("/".equals(basePath)) basePath = "";
        }

        // OpenAPI 3.0: extract basePath from servers[0].url
        if (root.has("openapi") && root.has("servers")) {
            try {
                var servers = root.getAsJsonArray("servers");
                if (servers != null && !servers.isEmpty()) {
                    String serverUrl = servers.get(0).getAsJsonObject().get("url").getAsString();
                    // Extract path portion from URL
                    if (serverUrl.startsWith("http")) {
                        int schemeEnd = serverUrl.indexOf("//") + 2;
                        int pathStart = serverUrl.indexOf('/', schemeEnd);
                        if (pathStart > 0) {
                            basePath = serverUrl.substring(pathStart);
                            if (basePath.endsWith("/")) {
                                basePath = basePath.substring(0, basePath.length() - 1);
                            }
                        }
                    } else if (serverUrl.startsWith("/")) {
                        basePath = serverUrl;
                        if (basePath.endsWith("/")) {
                            basePath = basePath.substring(0, basePath.length() - 1);
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        // Parse paths
        if (root.has("paths") && root.get("paths").isJsonObject()) {
            JsonObject paths = root.getAsJsonObject("paths");
            for (Map.Entry<String, JsonElement> pathEntry : paths.entrySet()) {
                String path = basePath + pathEntry.getKey();
                if (!pathEntry.getValue().isJsonObject()) continue;

                JsonObject methods = pathEntry.getValue().getAsJsonObject();
                for (Map.Entry<String, JsonElement> methodEntry : methods.entrySet()) {
                    String method = methodEntry.getKey().toUpperCase();
                    // Skip non-HTTP method keys (e.g. "parameters", "$ref")
                    if (!isHttpMethod(method)) continue;
                    if (!methodEntry.getValue().isJsonObject()) continue;

                    JsonObject operation = methodEntry.getValue().getAsJsonObject();
                    String summary = "";
                    String operationId = "";

                    if (operation.has("summary") && !operation.get("summary").isJsonNull()) {
                        summary = operation.get("summary").getAsString();
                    }
                    if (operation.has("operationId") && !operation.get("operationId").isJsonNull()) {
                        operationId = operation.get("operationId").getAsString();
                    }

                    endpoints.add(new ApiEndpoint(method, path, summary, operationId));
                }
            }
        }

        return endpoints;
    }

    private static boolean isHttpMethod(String method) {
        return switch (method) {
            case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE" -> true;
            default -> false;
        };
    }
}
