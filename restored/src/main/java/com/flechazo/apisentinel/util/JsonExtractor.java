package com.flechazo.apisentinel.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class JsonExtractor {

    private static final Pattern JSON_BLOCK = Pattern.compile("```(?:json)?\\s*\\n?(\\{.*?})\\s*```", Pattern.DOTALL);

    private JsonExtractor() {}

    public static JsonObject extract(String raw) {
        if (raw == null) return null;
        raw = raw.trim();

        JsonObject result = tryParse(raw);
        if (result != null) return result;

        Matcher blockMatcher = JSON_BLOCK.matcher(raw);
        if (blockMatcher.find()) {
            result = tryParse(blockMatcher.group(1));
            if (result != null) return result;
        }

        result = extractByBracketCounting(raw);
        return result;
    }

    private static JsonObject extractByBracketCounting(String raw) {
        int len = raw.length();
        int searchFrom = 0;

        while (searchFrom < len) {
            int start = raw.indexOf('{', searchFrom);
            if (start < 0) break;

            int depth = 0;
            boolean inString = false;
            boolean escape = false;

            for (int i = start; i < len; i++) {
                char c = raw.charAt(i);

                if (escape) {
                    escape = false;
                    continue;
                }
                if (c == '\\' && inString) {
                    escape = true;
                    continue;
                }
                if (c == '"') {
                    inString = !inString;
                    continue;
                }
                if (inString) continue;

                if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        String candidate = raw.substring(start, i + 1);
                        JsonObject result = tryParse(candidate);
                        if (result != null) return result;
                        break;
                    }
                }
            }
            searchFrom = start + 1;
        }
        return null;
    }

    private static JsonObject tryParse(String json) {
        try {
            var elem = JsonParser.parseString(json);
            if (elem.isJsonObject()) return elem.getAsJsonObject();
        } catch (JsonSyntaxException ignored) {}
        return null;
    }

    public static String getStr(JsonObject obj, String key, String defaultVal) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            try {
                return obj.get(key).getAsString();
            } catch (Exception e) {
                return obj.get(key).toString();
            }
        }
        return defaultVal;
    }

    public static double getDouble(JsonObject obj, String key, double defaultVal) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            try {
                return obj.get(key).getAsDouble();
            } catch (Exception e) {
                return defaultVal;
            }
        }
        return defaultVal;
    }

    public static String truncate(String text, int maxLen) {
        if (text == null) return "";
        return text.length() <= maxLen ? text : text.substring(0, maxLen) + "...";
    }
}
