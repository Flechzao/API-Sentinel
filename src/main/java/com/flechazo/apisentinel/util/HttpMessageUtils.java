package com.flechazo.apisentinel.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared helpers for converting Montoya HTTP objects into human-readable raw
 * strings, plus raw-HTTP-text manipulation (header/body/param mutation) used
 * by the programmatic verifiers (ActiveProbeExecutor, blind-injection and
 * business-logic verifiers, WAF bypass).
 * Used by both live traffic capture (HttpTrafficHandler) and proxy history backfill (ProxyHistoryScanner).
 */
public final class HttpMessageUtils {

    private HttpMessageUtils() {}

    /**
     * P1-2 fix: Header marker for requests sent by API-Sentinel's own tools
     * (SendRequestTool, ActiveProbeExecutor, etc.). HttpTrafficHandler checks
     * this and skips processing to prevent probe payloads (like GET /etc/passwd)
     * from being registered as API entries.
     *
     * <p>P1-4 hardening: the marker value is a random 128-bit nonce
     * minted once per JVM session (instead of the pre-P1-4 constant
     * {@code "probe"}). An attacker who could reflect or guess the old
     * constant could forge the header on an external request and
     * blind {@code HttpTrafficHandler} into treating it as "our own"
     * probe — silently dropping a legitimate captured request and
     * hiding it from the agent. A session-unique nonce makes forgery
     * infeasible: the attacker has no way to learn the nonce without
     * first reading our process memory.
     */
    public static final String PROBE_MARKER_HEADER = "X-Api-Sentinel";
    private static final String PROBE_MARKER_VALUE = mintSessionNonce();

    private static String mintSessionNonce() {
        byte[] bytes = new byte[16];
        new java.security.SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder(32);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** The value we set on outgoing probes. Exposed so callers that
     *  need to correlate a captured request with a sent one (e.g. the
     *  {@code search_traffic} tool) can match on the concrete value. */
    public static String probeMarkerValue() { return PROBE_MARKER_VALUE; }

    /** Check if a request was sent by API-Sentinel's probe tools.
     *  P1-4: matches on both header name AND the session-unique value
     *  — a request with the right name but the wrong value is treated
     *  as an external forgery attempt and rejected. */
    public static boolean isProbeRequest(HttpRequest request) {
        for (HttpHeader header : request.headers()) {
            if (PROBE_MARKER_HEADER.equalsIgnoreCase(header.name())
                    && PROBE_MARKER_VALUE.equals(header.value())) {
                return true;
            }
        }
        return false;
    }

    /** Add probe marker header to a raw request string. */
    public static String addProbeMarker(String rawRequest) {
        // Insert after the first line (request line)
        int firstNewline = rawRequest.indexOf('\n');
        if (firstNewline < 0) {
            return rawRequest + "\n" + PROBE_MARKER_HEADER + ": " + PROBE_MARKER_VALUE + "\n";
        }
        return rawRequest.substring(0, firstNewline + 1)
                + PROBE_MARKER_HEADER + ": " + PROBE_MARKER_VALUE + "\n"
                + rawRequest.substring(firstNewline + 1);
    }

    public static String buildRawRequest(HttpRequest request) {
        try {
            return new String(request.toByteArray().getBytes());
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            sb.append(request.method()).append(" ").append(request.path()).append(" HTTP/1.1\n");
            for (HttpHeader header : request.headers()) {
                sb.append(header.name()).append(": ").append(header.value()).append("\n");
            }
            sb.append("\n");
            String body = request.bodyToString();
            if (body != null && !body.isEmpty()) {
                sb.append(truncate(body, 5000));
            }
            return sb.toString();
        }
    }

    public static String buildRawResponse(HttpResponse response) {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(response.statusCode()).append("\n");
        for (HttpHeader header : response.headers()) {
            sb.append(header.name()).append(": ").append(header.value()).append("\n");
        }
        sb.append("\n");
        String body = response.bodyToString();
        if (body != null && !body.isEmpty()) {
            sb.append(truncate(body, 5000));
        }
        return sb.toString();
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "\n...[truncated]";
    }

    // ======================== Raw-message structure ========================

    /** Header section of a raw HTTP message (before the blank line). */
    public static String headerSection(String raw) {
        if (raw == null) return "";
        int sep = raw.indexOf("\r\n\r\n");
        if (sep >= 0) return raw.substring(0, sep);
        int sepLf = raw.indexOf("\n\n");
        return sepLf >= 0 ? raw.substring(0, sepLf) : raw;
    }

    /** Body of a raw HTTP message (after the blank line). */
    public static String bodyOf(String raw) {
        if (raw == null) return "";
        int sep = raw.indexOf("\r\n\r\n");
        if (sep >= 0) return raw.substring(sep + 4);
        int sepLf = raw.indexOf("\n\n");
        return sepLf >= 0 ? raw.substring(sepLf + 2) : "";
    }

    /** Case-insensitive header lookup on a raw HTTP message. */
    public static String getHeader(String raw, String name) {
        if (raw == null) return null;
        String prefix = name.toLowerCase(Locale.ROOT) + ":";
        for (String line : headerSection(raw).split("\r?\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    /** Replace an existing header value or insert the header after the request line. */
    public static String replaceOrInsertHeader(String raw, String name, String value) {
        int sep = raw.indexOf("\r\n\r\n");
        String headers = sep >= 0 ? raw.substring(0, sep) : raw;
        String rest = sep >= 0 ? raw.substring(sep) : "";
        String prefix = name.toLowerCase(Locale.ROOT) + ":";
        String[] lines = headers.split("\r\n");
        boolean exists = false;
        for (String line : lines) {
            if (line.toLowerCase(Locale.ROOT).startsWith(prefix)) { exists = true; break; }
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (i == 1 && !exists) {
                sb.append(name).append(": ").append(value).append("\r\n");
            }
            if (lines[i].toLowerCase(Locale.ROOT).startsWith(prefix)) {
                sb.append(name).append(": ").append(value);
            } else {
                sb.append(lines[i]);
            }
            if (i < lines.length - 1) sb.append("\r\n");
        }
        if (!exists && lines.length < 2) {
            // Header section was only the request line.
            sb.append("\r\n").append(name).append(": ").append(value);
        }
        return sb + rest;
    }

    /** Request target (path + query) from the request line. */
    public static String requestTarget(String raw) {
        if (raw == null) return "/";
        String firstLine = raw.split("\r?\n", 2)[0];
        String[] parts = firstLine.split(" ");
        return parts.length >= 2 ? parts[1] : "/";
    }

    /** Rebuild the request with a different request target. */
    public static String replaceRequestTarget(String raw, String newTarget) {
        int eol = raw.indexOf("\r\n");
        String firstLine = eol >= 0 ? raw.substring(0, eol) : raw.split("\n", 2)[0];
        String[] parts = firstLine.split(" ");
        if (parts.length < 3) return raw;
        String rebuilt = parts[0] + " " + newTarget + " " + parts[2];
        return eol >= 0 ? rebuilt + raw.substring(eol) : rebuilt;
    }

    /** Replace the body, fixing Content-Length when present (or adding it). */
    public static String replaceBody(String raw, String newBody) {
        int sep = raw.indexOf("\r\n\r\n");
        if (sep < 0) return raw;
        String headers = raw.substring(0, sep);
        byte[] bytes = newBody.getBytes(StandardCharsets.UTF_8);
        Pattern cl = Pattern.compile("(?im)^Content-Length:\\s*\\d+\\s*$");
        Matcher m = cl.matcher(headers);
        if (m.find()) {
            headers = m.replaceFirst("Content-Length: " + bytes.length);
        } else {
            headers = headers + "\r\nContent-Length: " + bytes.length;
        }
        return headers + "\r\n\r\n" + newBody;
    }

    /** Domain without port. */
    public static String hostOnly(String domain) {
        if (domain == null || domain.isEmpty()) return "localhost";
        return domain.contains(":") ? domain.split(":")[0] : domain;
    }

    /** Parse a JSON object body; null when absent/malformed/non-object. */
    public static JsonObject parseJsonObject(String body) {
        if (body == null || body.isBlank()) return null;
        try {
            JsonElement el = JsonParser.parseString(body.trim());
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        } catch (Exception e) {
            return null;
        }
    }

    // ======================== Parameter mutation ========================

    /** Parse query params of a request target (decoded values, insertion order). */
    public static Map<String, String> parseQueryParams(String target) {
        Map<String, String> out = new LinkedHashMap<>();
        if (target == null) return out;
        int q = target.indexOf('?');
        if (q < 0 || q == target.length() - 1) return out;
        for (String pair : target.substring(q + 1).split("&")) {
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            try {
                out.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                        URLDecoder.decode(v, StandardCharsets.UTF_8));
            } catch (Exception e) {
                out.put(k, v);
            }
        }
        return out;
    }

    /** Set/replace a query parameter in the request target (value URL-encoded). */
    public static String setQueryParam(String raw, String name, String value) {
        String target = requestTarget(raw);
        int q = target.indexOf('?');
        String path = q >= 0 ? target.substring(0, q) : target;
        Map<String, String> params = parseQueryParams(target);
        params.put(name, value);
        StringBuilder sb = new StringBuilder(path).append('?');
        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (!first) sb.append('&');
            first = false;
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return replaceRequestTarget(raw, sb.toString());
    }

    /** Set/replace a top-level JSON body field with a raw JSON literal
     *  (e.g. "\"x\"", "123", "{\"$ne\":null}"). Returns raw unchanged when
     *  the body is not a JSON object. */
    public static String setJsonField(String raw, String name, String jsonLiteral) {
        String body = bodyOf(raw);
        JsonObject obj = parseJsonObject(body);
        if (obj == null) return raw;
        try {
            obj.add(name, JsonParser.parseString(jsonLiteral));
        } catch (Exception e) {
            obj.add(name, new JsonPrimitive(jsonLiteral));
        }
        return replaceBody(raw, obj.toString());
    }

    /** Set/replace a form-urlencoded body parameter (value URL-encoded). */
    public static String setFormParam(String raw, String name, String value) {
        String body = bodyOf(raw);
        Map<String, String> params = new LinkedHashMap<>();
        if (!body.isBlank()) {
            for (String pair : body.split("&")) {
                int eq = pair.indexOf('=');
                String k = eq >= 0 ? pair.substring(0, eq) : pair;
                String v = eq >= 0 ? pair.substring(eq + 1) : "";
                try {
                    params.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                            URLDecoder.decode(v, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    params.put(k, v);
                }
            }
        }
        params.put(name, value);
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (!first) sb.append('&');
            first = false;
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return replaceBody(raw, sb.toString());
    }

    /** Set/replace a cookie value inside the Cookie header (adds the header when absent). */
    public static String setCookieValue(String raw, String name, String value) {
        String cookie = getHeader(raw, "Cookie");
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;
        if (cookie != null) {
            for (String part : cookie.split(";")) {
                String p = part.trim();
                if (p.isEmpty()) continue;
                int eq = p.indexOf('=');
                String k = eq >= 0 ? p.substring(0, eq).trim() : p;
                if (k.equals(name)) {
                    sb.append(name).append('=').append(value);
                    replaced = true;
                } else {
                    sb.append(p);
                }
                sb.append("; ");
            }
        }
        if (!replaced) sb.append(name).append('=').append(value);
        else if (sb.length() >= 2) sb.setLength(sb.length() - 2);
        return replaceOrInsertHeader(raw, "Cookie", sb.toString());
    }
}
