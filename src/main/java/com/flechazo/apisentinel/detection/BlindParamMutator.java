package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Applies a parameter mutation to a captured raw request, based on where the
 * parameter lives (query / body_json / body_form / header / cookie). Shared
 * by the blind-injection and business-logic verifiers.
 */
public final class BlindParamMutator {

    public static final String LOC_QUERY = "query";
    public static final String LOC_BODY_JSON = "body_json";
    public static final String LOC_BODY_FORM = "body_form";
    public static final String LOC_HEADER = "header";
    public static final String LOC_COOKIE = "cookie";

    private BlindParamMutator() {}

    /**
     * Return a copy of rawRequest where paramName's value is replaced by
     * newValue (in the given location), or null when the location is unknown
     * or the mutation cannot be applied.
     */
    public static String mutate(String rawRequest, String paramName, String paramLocation, String newValue) {
        if (rawRequest == null || paramName == null || paramName.isEmpty()) return null;
        String loc = paramLocation == null ? "" : paramLocation.toLowerCase(Locale.ROOT);
        return switch (loc) {
            case LOC_QUERY -> HttpMessageUtils.setQueryParam(rawRequest, paramName, newValue);
            case LOC_BODY_JSON -> setJsonStringField(rawRequest, paramName, newValue);
            case LOC_BODY_FORM -> HttpMessageUtils.setFormParam(rawRequest, paramName, newValue);
            case LOC_HEADER -> HttpMessageUtils.replaceOrInsertHeader(rawRequest, paramName, newValue);
            case LOC_COOKIE -> HttpMessageUtils.setCookieValue(rawRequest, paramName, newValue);
            default -> null;
        };
    }

    /** Set a JSON body field to a string value (properly JSON-escaped). */
    private static String setJsonStringField(String raw, String name, String value) {
        String body = HttpMessageUtils.bodyOf(raw);
        JsonObject obj = HttpMessageUtils.parseJsonObject(body);
        if (obj == null) return null;
        // Nested support: "a.b" walks into nested objects one level deep.
        if (name.contains(".")) {
            String[] parts = name.split("\\.", 2);
            if (obj.has(parts[0]) && obj.get(parts[0]).isJsonObject()) {
                obj.getAsJsonObject(parts[0]).add(parts[1], new JsonPrimitive(value));
                return HttpMessageUtils.replaceBody(raw, obj.toString());
            }
            return null;
        }
        return HttpMessageUtils.setJsonField(raw, name, new JsonPrimitive(value).toString());
    }

    // ======================== Candidate discovery ========================

    /** Param names that typically flow into SQL (query string + JSON body). */
    private static final Pattern SQL_CANDIDATE = Pattern.compile(
            "(?i)(^|_)(id|uid|pid|oid|orderid|userid|search|query|keyword|filter|sort|order|"
          + "name|username|account|email|mobile|phone|key|word|text|title|category|type|status|tag)(s)?($|_)");

    /**
     * Extract candidate SQL-injection parameters from the entry's captured
     * request (query params + top-level JSON body keys), capped.
     */
    public static List<String> candidateSqlParams(ApiEntry entry, int max) {
        List<String> out = new ArrayList<>();
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) return out;
        for (String name : HttpMessageUtils.parseQueryParams(HttpMessageUtils.requestTarget(raw)).keySet()) {
            if (SQL_CANDIDATE.matcher(name).matches()) addDistinct(out, name, max);
        }
        JsonObject obj = HttpMessageUtils.parseJsonObject(HttpMessageUtils.bodyOf(raw));
        if (obj != null) {
            for (String key : obj.keySet()) {
                if (SQL_CANDIDATE.matcher(key).matches()) addDistinct(out, key, max);
            }
        }
        return out;
    }

    /** Guess the location of a named parameter in the captured request. */
    public static String locateParam(ApiEntry entry, String paramName) {
        String raw = entry.getLastRawRequest();
        if (raw == null) return LOC_QUERY;
        if (HttpMessageUtils.parseQueryParams(HttpMessageUtils.requestTarget(raw)).containsKey(paramName)) {
            return LOC_QUERY;
        }
        JsonObject obj = HttpMessageUtils.parseJsonObject(HttpMessageUtils.bodyOf(raw));
        if (obj != null && (obj.has(paramName) || paramName.contains("."))) {
            return LOC_BODY_JSON;
        }
        String ct = HttpMessageUtils.getHeader(raw, "Content-Type");
        if (ct != null && ct.toLowerCase().contains("x-www-form-urlencoded")
                && HttpMessageUtils.bodyOf(raw).contains(paramName + "=")) {
            return LOC_BODY_FORM;
        }
        if (HttpMessageUtils.getHeader(raw, "Cookie") != null
                && HttpMessageUtils.getHeader(raw, "Cookie").contains(paramName + "=")) {
            return LOC_COOKIE;
        }
        return LOC_QUERY;
    }

    private static void addDistinct(List<String> list, String name, int max) {
        if (list.size() >= max) return;
        for (String existing : list) {
            if (existing.equalsIgnoreCase(name)) return;
        }
        list.add(name);
    }
}
